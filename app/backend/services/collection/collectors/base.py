"""Registre extensible des collecteurs, indexés par méthode de collecte.

Ajouter une nouvelle méthode = créer un collecteur et l'enregistrer avec @register("clé"),
SANS modifier l'orchestrateur ni les autres collecteurs.

Un collecteur est une coroutine : `async def collect(source: dict, since: datetime) -> list[dict]`
renvoyant une liste d'enregistrements CVE canoniques (voir schema.new_record).
"""
from urllib.parse import urlparse


class SourceUnreachable(Exception):
    """La source n'a renvoyé AUCUN contenu exploitable (réseau/rendu KO). → statut FAILED, à ré-essayer.

    À distinguer d'une source JOIGNABLE mais sans nouveauté (liste vide) qui, elle, est un
    SUCCÈS « EMPTY » : le nombre de CVE ne détermine JAMAIS l'échec d'une collecte.
    """


class SourceParseError(Exception):
    """Contenu récupéré mais impossible à analyser (structure inattendue). → statut PARSE_ERROR."""


_REGISTRY: dict[str, callable] = {}


def register(*keys):
    def deco(fn):
        for k in keys:
            _REGISTRY[k] = fn
        return fn
    return deco


def _key_for(source: dict) -> str:
    """Choisit la clé de collecteur d'après la méthode/format enregistrés sur la source."""
    method = (source.get("collection_method") or "").lower()
    fmt = (source.get("data_format") or "").lower()
    url = (source.get("api_endpoint") or source.get("url") or "").lower()

    if method == "rss" or fmt in ("rss", "atom"):
        return "rss"
    if "sitemap" in url or method == "sitemap":
        return "sitemap"
    if method in ("api_public", "api_protected"):
        return "xml" if fmt == "xml" else "json"
    if fmt == "json":
        return "json"
    if fmt == "xml":
        return "xml"
    return "html"  # défaut : scraping HTML


def target_url(source: dict) -> str:
    method = (source.get("collection_method") or "").lower()
    if method == "rss":
        return source.get("rss_url") or source.get("url") or ""
    if method in ("api_public", "api_protected"):
        return source.get("api_endpoint") or source.get("url") or ""
    return source.get("url") or source.get("api_endpoint") or ""


def resolve(source: dict):
    """Renvoie (collecteur, clé) pour une source. Charge les collecteurs à la 1re utilisation."""
    _ensure_loaded()
    key = _key_for(source)
    fn = _REGISTRY.get(key) or _REGISTRY.get("html")
    return fn, key


def host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


_loaded = False


def _ensure_loaded():
    global _loaded
    if _loaded:
        return
    # Import des collecteurs -> déclenche leur enregistrement.
    from app.backend.services.collection.collectors import api_json, rss, html, xml, sitemap  # noqa: F401
    _loaded = True
