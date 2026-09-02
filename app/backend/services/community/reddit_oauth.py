"""Client OAuth Reddit — accès SERVEUR À SERVEUR à l'API officielle.

Reddit a fermé son accès public : la recherche anonyme répond « 403 ». Plutôt que de tenter
de contourner ce refus — ce qui serait à la fois fragile et contraire aux conditions du
service — on emprunte le flux officiel prévu pour une application sans utilisateur final :
`client_credentials`.

    identifiants d'application ──► jeton d'accès (durée limitée) ──► oauth.reddit.com

LE JETON NE SORT JAMAIS DU SERVEUR
Il vit en mémoire, n'est jamais journalisé, jamais stocké en base, jamais renvoyé par l'API.
Le journal ne porte que des états (« jeton obtenu », « expiré ») — jamais la valeur.

SANS IDENTIFIANTS, PAS D'ERREUR
Une installation qui n'a pas configuré Reddit ne doit pas voir l'application échouer : la
source se déclare simplement NON CONFIGURÉE, ce qui est une information, pas une panne.
"""
import base64
import logging
import time

from app.backend.core.config import settings
from app.backend.services.collection import net

logger = logging.getLogger("cyberwatch.community.reddit")

TOKEN_URL = "https://www.reddit.com/api/v1/access_token"
API_BASE = "https://oauth.reddit.com"

# Marge de sécurité avant expiration : on renouvelle un peu avant l'échéance annoncée, pour
# ne pas partir en requête avec un jeton qui expire pendant le trajet.
MARGE_EXPIRATION = 60.0
TIMEOUT = 12.0


class RedditNonConfigure(RuntimeError):
    """Aucun identifiant d'application n'est renseigné. Ce n'est pas une panne."""


class RedditIndisponible(RuntimeError):
    """Reddit n'a pas pu être interrogé (réseau, quota, erreur de l'API)."""


# Cache PROCESSUS du jeton : {"valeur": str, "expire_a": float}. Jamais persisté.
_jeton: dict = {}


def est_configure() -> bool:
    """Vrai si l'application dispose d'identifiants Reddit."""
    return bool(getattr(settings, "REDDIT_CLIENT_ID", "")
                and getattr(settings, "REDDIT_CLIENT_SECRET", ""))


def _entetes_auth() -> dict:
    identifiants = f"{settings.REDDIT_CLIENT_ID}:{settings.REDDIT_CLIENT_SECRET}".encode()
    return {"Authorization": "Basic " + base64.b64encode(identifiants).decode("ascii"),
            "User-Agent": settings.REDDIT_USER_AGENT}


def oublier_jeton() -> None:
    """Invalide le jeton en cache (après un « 401 », ou pour forcer un renouvellement)."""
    _jeton.clear()


async def obtenir_jeton(force: bool = False) -> str:
    """Jeton d'accès valide, réutilisé tant qu'il n'a pas expiré.

    Un jeton Reddit dure environ une heure : le redemander à chaque recherche gaspillerait
    des appels et se heurterait vite aux limites de débit. On le conserve donc en mémoire
    jusqu'à sa date d'expiration, marge déduite.
    """
    if not est_configure():
        raise RedditNonConfigure(
            "Les identifiants OAuth Reddit ne sont pas configurés.")

    maintenant = time.monotonic()
    if not force and _jeton.get("valeur") and _jeton.get("expire_a", 0) > maintenant:
        return _jeton["valeur"]

    resp = await net.post(TOKEN_URL, data={"grant_type": "client_credentials"},
                          headers=_entetes_auth(), timeout=TIMEOUT)
    if resp is None:
        raise RedditIndisponible("Service d'authentification Reddit injoignable.")
    if resp.status_code != 200:
        # On ne journalise NI le corps NI les en-têtes : ils peuvent contenir le secret.
        raise RedditIndisponible(
            f"Authentification Reddit refusée (HTTP {resp.status_code}).")
    try:
        data = resp.json()
    except ValueError as exc:
        raise RedditIndisponible("Réponse d'authentification Reddit illisible.") from exc

    valeur = data.get("access_token")
    if not valeur:
        raise RedditIndisponible("Reddit n'a pas renvoyé de jeton d'accès.")
    duree = float(data.get("expires_in") or 3600)
    _jeton["valeur"] = valeur
    _jeton["expire_a"] = maintenant + max(0.0, duree - MARGE_EXPIRATION)
    logger.info("Jeton Reddit obtenu (valide %.0f s).", duree)   # la VALEUR n'est pas tracée
    return valeur


async def appeler(chemin: str, params: dict) -> dict | list:
    """Appel authentifié à l'API Reddit, avec UNE reprise après expiration du jeton.

    Un « 401 » signifie presque toujours que le jeton a expiré côté Reddit avant la date
    annoncée. On en redemande un et on rejoue la requête — UNE FOIS. Insister davantage
    tournerait en boucle si les identifiants eux-mêmes étaient invalides.

    Le corps est renvoyé TEL QUEL. La recherche répond par un objet, mais l'arbre de
    commentaires d'un billet répond par un TABLEAU de deux listings (le billet, puis ses
    commentaires) : imposer un dictionnaire ici interdirait de lire les commentaires.
    """
    for tentative in (1, 2):
        jeton = await obtenir_jeton(force=(tentative == 2))
        resp = await net.get(f"{API_BASE}{chemin}", params=params, timeout=TIMEOUT,
                             headers={"Authorization": f"bearer {jeton}",
                                      "User-Agent": settings.REDDIT_USER_AGENT})
        if resp is None:
            raise RedditIndisponible("Reddit injoignable.")
        if resp.status_code == 401 and tentative == 1:
            logger.info("Jeton Reddit expiré : renouvellement et nouvel essai.")
            oublier_jeton()
            continue
        if resp.status_code == 429:
            # Limite de débit : on n'insiste PAS. Réessayer aggraverait la situation et
            # retarderait les autres sources ; la recherche reprendra plus tard.
            raise RedditIndisponible("Limite de débit Reddit atteinte.")
        if resp.status_code != 200:
            raise RedditIndisponible(f"Reddit a répondu HTTP {resp.status_code}.")
        try:
            return resp.json()
        except ValueError as exc:
            raise RedditIndisponible("Réponse Reddit illisible.") from exc
    raise RedditIndisponible("Authentification Reddit impossible après renouvellement.")
