"""Niveau 1 — Vérification technique.

Contrôle que la source est techniquement exploitable : URL accessible, HTTPS/TLS,
code HTTP valide, et cohérence du contenu avec la méthode de collecte détectée
(API JSON / RSS / scraping HTML).
"""
import logging

from app.backend.services.verification.common import make_check, simple_score
from app.backend.services.verification.http_client import FetchResult

logger = logging.getLogger("cyberwatch.verification")


def _content_matches_method(collection_method: str | None, fetched: FetchResult, api_endpoint: str | None = None) -> bool:
    """Le corps / content-type correspond-il à la méthode de collecte détectée ?"""
    if not fetched.reached:
        return False
    ctype = fetched.content_type or ""
    body = fetched.body_lower

    if collection_method in ("api_public", "api_protected"):
        # Une API protégée peut renvoyer 401/403 sans JSON : la cohérence est admise.
        if "json" in ctype or body.strip().startswith(("{", "[")) or fetched.status_code in (401, 403):
            return True
        # Source dont l'API est sur un endpoint dédié (ex. NVD) : la page saisie est une
        # page d'accueil HTML, mais la collecte se fait via `api_endpoint` — cohérent.
        return bool(api_endpoint and api_endpoint != (fetched.final_url or ""))
    if collection_method == "rss":
        return "xml" in ctype or "rss" in ctype or "atom" in ctype or "<rss" in body or "<feed" in body
    if collection_method == "scraping":
        return "html" in ctype or "<html" in body or "<!doctype html" in body
    return True


def _detail_contenu(evalue: FetchResult, saisi: FetchResult) -> str:
    """Précise QUELLE adresse a servi au contrôle, pour un rapport lisible."""
    base = f"Content-Type : {evalue.content_type or 'inconnu'}"
    if evalue is not saisi and getattr(evalue, "final_url", None):
        return f"{base} — évalué sur {evalue.final_url}"
    return base


def verify_technical(source: dict, fetched: FetchResult | None,
                    content_fetched: FetchResult | None = None) -> dict:
    """Retourne {'score': int, 'checks': [...]} pour le niveau technique.

    `fetched` est la réponse de l'URL SAISIE : elle porte l'accessibilité et le TLS.
    `content_fetched` est le contenu que la méthode retenue lit RÉELLEMENT - flux RSS,
    endpoint d'API - souvent à une autre adresse. Sans cette distinction, une source
    dont l'accueil est en HTML et le flux en XML était annoncée « contenu incohérent »
    alors que l'analyseur venait d'y valider seize CVE : le rapport se contredisait.
    """
    collection_method = source.get("collection_method")
    api_endpoint = source.get("api_endpoint")

    if fetched is None:
        checks = [make_check("URL renseignée", False)]
        return {"score": 0, "checks": checks}

    if fetched.reached:
        reach_label = f"URL accessible — HTTP {fetched.status_code}"
    else:
        reach_label = f"URL accessible — échec : {fetched.error or 'injoignable'}"

    # Une API protégée (401/403) est considérée accessible : le serveur répond correctement.
    reachable = fetched.status_ok or fetched.status_code in (401, 403)

    # HTTPS/TLS : valide dès que la connexion TLS est PRÉSENTE (site atteint en https).
    # Une chaîne de certificat non vérifiée localement (issuer manquant) n'est pas éliminatoire
    # pour un site officiel : le TLS chiffre bien la connexion. Détail explicite dans ce cas.
    https_present = fetched.is_https and fetched.reached
    https_detail = fetched.ssl_note if (https_present and not fetched.ssl_ok) else None

    # Le contenu évalué est celui de la méthode retenue quand il diffère de la page saisie.
    evalue = content_fetched if (content_fetched is not None and content_fetched.reached) else fetched

    checks = [
        make_check("URL renseignée", True),
        make_check(reach_label, reachable, detail=fetched.error),
        make_check("Connexion sécurisée (HTTPS/TLS)", https_present, detail=https_detail),
        make_check(
            "Contenu cohérent avec la méthode de collecte",
            _content_matches_method(collection_method, evalue, api_endpoint),
            detail=_detail_contenu(evalue, fetched),
        ),
    ]
    return {"score": simple_score(checks), "checks": checks}
