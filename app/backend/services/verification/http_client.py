"""Client HTTP réel utilisé par l'agent de vérification.

Effectue une vraie requête réseau vers l'URL d'une source et capture tout ce dont les
niveaux technique et crédibilité ont besoin (statut, TLS, type de contenu, corps).
Aucune simulation : chaque champ reflète une réponse réelle.

Robustesse TLS : certains sites officiels (CERT nationaux, etc.) servent une chaîne de
certificats INCOMPLÈTE (« unable to get local issuer certificate »). Dans ce cas, on
retente sans vérification stricte pour récupérer le contenu : le TLS est bien présent
(`is_https`), seule la vérification de la chaîne locale échoue (`ssl_ok=False`) — la source
n'est donc PAS considérée comme « fake » pour autant.
"""
import logging
import ssl
import time
from urllib.parse import urlparse

import certifi
import httpx

logger = logging.getLogger("cyberwatch.verification.http")

TIMEOUT_SECONDS = 15.0
# User-Agent d'un vrai navigateur : certains sites rejettent les clients « robots ».
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
BODY_CAP = 300000  # nombre de caractères conservés du corps (contenu utile parfois loin en page)


class FetchResult:
    """Résultat brut d'une requête HTTP réelle."""

    def __init__(self):
        self.reached: bool = False
        self.status_code: int | None = None
        self.final_url: str | None = None
        self.host: str | None = None
        self.is_https: bool = False        # l'URL/connexion utilise https (TLS présent)
        self.ssl_ok: bool = False          # la chaîne du certificat a été VÉRIFIÉE localement
        self.ssl_note: str | None = None   # précision si TLS présent mais chaîne non vérifiée
        self.content_type: str | None = None
        self.www_authenticate: str | None = None
        self.body: str = ""
        self.latency_ms: int | None = None
        self.error: str | None = None

    @property
    def body_lower(self) -> str:
        return self.body.lower()

    @property
    def status_ok(self) -> bool:
        return self.reached and self.status_code is not None and self.status_code < 400


def _is_ssl_chain_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return "certificate_verify_failed" in msg or "unable to get local issuer" in msg or "ssl" in msg


async def _get(url: str, verify) -> httpx.Response:
    async with httpx.AsyncClient(
        timeout=TIMEOUT_SECONDS, follow_redirects=True, verify=verify,
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/json,application/xml,*/*"},
    ) as client:
        return await client.get(url)


def _apply(result: FetchResult, response: httpx.Response, started: float, verified: bool) -> None:
    result.reached = True
    result.status_code = response.status_code
    result.final_url = str(response.url)
    result.host = (response.url.host or result.host or "").lower() or None
    result.is_https = str(response.url).startswith("https://")
    result.ssl_ok = result.is_https and verified
    if result.is_https and not verified:
        result.ssl_note = "TLS présent mais chaîne du certificat non vérifiée localement (issuer manquant)."
    result.content_type = response.headers.get("content-type", "")
    result.www_authenticate = response.headers.get("www-authenticate")
    result.body = response.text[:BODY_CAP]
    result.latency_ms = int((time.perf_counter() - started) * 1000)


async def fetch(url: str) -> FetchResult:
    """Effectue une requête GET réelle et capture le résultat. Ne lève jamais.

    Journalise chaque étape (utile pour diagnostiquer pourquoi une source échoue).
    """
    result = FetchResult()
    if url:
        result.host = (urlparse(url).hostname or "").lower() or None

    started = time.perf_counter()
    # 1re tentative : vérification stricte du certificat via le CA bundle certifi.
    try:
        ctx = ssl.create_default_context(cafile=certifi.where())
        response = await _get(url, verify=ctx)
        _apply(result, response, started, verified=True)
        logger.info("[fetch] %s -> HTTP %s (TLS vérifié) len=%d", url, result.status_code, len(result.body))
        return result
    except (ssl.SSLError, httpx.ConnectError) as exc:
        if _is_ssl_chain_error(exc):
            # 2e tentative : chaîne incomplète -> on récupère quand même le contenu (TLS présent).
            logger.warning("[fetch] %s -> échec de vérification du certificat (%s) ; nouvelle tentative sans "
                           "vérification stricte de la chaîne.", url, str(exc)[:80])
            try:
                response = await _get(url, verify=False)
                _apply(result, response, started, verified=False)
                logger.info("[fetch] %s -> HTTP %s (TLS présent, chaîne NON vérifiée) len=%d",
                            url, result.status_code, len(result.body))
                return result
            except Exception as exc2:  # noqa: BLE001
                result.error = f"Connexion impossible (même sans vérification TLS) : {exc2}"
                logger.error("[fetch] %s -> injoignable après repli TLS : %s", url, str(exc2)[:120])
                return result
        result.error = f"Connexion impossible : {exc}"
        logger.error("[fetch] %s -> connexion impossible : %s", url, str(exc)[:120])
    except httpx.ConnectTimeout:
        result.error = "Délai de connexion dépassé"
        logger.error("[fetch] %s -> délai de connexion dépassé", url)
    except httpx.ReadTimeout:
        result.error = "Délai de lecture dépassé"
        logger.error("[fetch] %s -> délai de lecture dépassé", url)
    except httpx.HTTPError as exc:
        result.error = f"Erreur HTTP : {exc}"
        logger.error("[fetch] %s -> erreur HTTP : %s", url, str(exc)[:120])
    except Exception as exc:  # noqa: BLE001 - reporté dans la checklist, jamais propagé
        result.error = f"Erreur : {exc}"
        logger.error("[fetch] %s -> erreur : %s", url, str(exc)[:120])
    return result
