"""Détection automatique de la méthode de collecte (API → RSS → Scraping).

Règle de priorité OBLIGATOIRE — on ne choisit JAMAIS le scraping simplement parce que
l'URL pointe vers une page HTML :

  Priorité 1 — API officielle  : endpoint d'API connu (registre), ou l'URL renvoie du
                                 JSON/XML, ou une API est déclarée/déclouverte dans la page.
  Priorité 2 — Flux RSS/Atom   : l'URL est un flux, un flux est auto-déclaré (<link>), ou
                                 trouvé sur un chemin standard.
  Priorité 3 — Web Scraping     : uniquement si aucune API ni RSS n'est disponible.

Un mécanisme de repli (`backup_method`) est renseigné : API → RSS → Web Scraping.
Le résultat porte aussi `api_endpoint`, `data_format`, une explication (`reason`) et les
méthodes alternatives pour le rapport admin.
"""
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin, urlparse

from app.backend.services.verification.http_client import FetchResult, fetch


def _nvd_recent_endpoint() -> str:
    """Endpoint NVD filtré sur les 7 derniers jours (l'endpoint brut renvoie les plus anciens)."""
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=7)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    return (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?lastModStartDate={start.strftime(fmt)}&lastModEndDate={now.strftime(fmt)}"
    )


# --------------------------------------------------------------------------------------
# Registre des API officielles connues (sources CVE de référence).
# Clé = domaine (ou sous-domaine). L'endpoint peut être sur un AUTRE hôte que la page.
# `sample_builder` (optionnel) fournit un endpoint « données récentes » pour jauger l'activité.
# --------------------------------------------------------------------------------------
_KNOWN_APIS = {
    "nvd.nist.gov": {
        "endpoint": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "data_format": "json", "auth_required": False, "auth_type": "api_key",
        "auth_optional": True, "org": "NVD", "sample_builder": _nvd_recent_endpoint,
    },
    "services.nvd.nist.gov": {
        "endpoint": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "data_format": "json", "auth_required": False, "auth_type": "api_key",
        "auth_optional": True, "org": "NVD", "sample_builder": _nvd_recent_endpoint,
    },
    "cisa.gov": {
        "endpoint": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "data_format": "json", "auth_required": False, "auth_type": None,
        "auth_optional": False, "org": "CISA KEV",
    },
    "circl.lu": {
        "endpoint": "https://cve.circl.lu/api/last",
        "data_format": "json", "auth_required": False, "auth_type": None,
        "auth_optional": False, "org": "CIRCL",
    },
    "cve.circl.lu": {
        "endpoint": "https://cve.circl.lu/api/last",
        "data_format": "json", "auth_required": False, "auth_type": None,
        "auth_optional": False, "org": "CIRCL",
    },
    "msrc.microsoft.com": {
        "endpoint": "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability",
        "data_format": "json", "auth_required": False, "auth_type": None,
        "auth_optional": False, "org": "Microsoft MSRC",
    },
    "api.msrc.microsoft.com": {
        "endpoint": "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability",
        "data_format": "json", "auth_required": False, "auth_type": None,
        "auth_optional": False, "org": "Microsoft MSRC",
    },
    "access.redhat.com": {
        "endpoint": "https://access.redhat.com/hydra/rest/securitydata/cve.json",
        "data_format": "json", "auth_required": False, "auth_type": None,
        "auth_optional": False, "org": "Red Hat Security Data",
    },
    "github.com": {
        "endpoint": "https://api.github.com/advisories",
        "data_format": "json", "auth_required": False, "auth_type": "bearer",
        "auth_optional": True, "org": "GitHub Advisory Database",
    },
    "api.github.com": {
        "endpoint": "https://api.github.com/advisories",
        "data_format": "json", "auth_required": False, "auth_type": "bearer",
        "auth_optional": True, "org": "GitHub Advisory Database",
    },
}

# Chemins standards d'auto-découverte.
RSS_PROBE_PATHS = ["/feed", "/rss", "/rss.xml", "/feed.xml", "/atom.xml", "/index.xml"]
API_PROBE_PATHS = ["/api", "/api/v1", "/api/v2", "/rest", "/api/cve", "/api/cves", "/api/vulnerabilities"]

# Familles de méthodes (pour l'affichage / le repli).
FAMILY = {"api_public": "api", "api_protected": "api", "rss": "rss", "scraping": "scraping"}
FAMILY_LABEL = {"api": "API", "rss": "RSS", "scraping": "Web Scraping"}


class DetectionResult:
    def __init__(
        self,
        collection_method: str,
        authentication_required: bool = False,
        authentication_type: str | None = None,
        detail: str | None = None,
        rss_url: str | None = None,
        api_endpoint: str | None = None,
        data_format: str | None = None,
        backup_method: str | None = None,
        reason: str | None = None,
        alternatives: list[str] | None = None,
        sample_endpoint: str | None = None,
    ):
        self.collection_method = collection_method
        self.authentication_required = authentication_required
        self.authentication_type = authentication_type
        self.detail = detail
        self.rss_url = rss_url  # URL du flux RSS effectivement trouvé
        self.api_endpoint = api_endpoint
        self.data_format = data_format
        self.backup_method = backup_method
        self.reason = reason
        self.alternatives = alternatives or []
        # Endpoint « données récentes » pour jauger l'activité (défaut : api_endpoint).
        self.sample_endpoint = sample_endpoint or api_endpoint

    def as_dict(self) -> dict:
        return {
            "collection_method": self.collection_method,
            "authentication_required": self.authentication_required,
            "authentication_type": self.authentication_type,
            "detail": self.detail,
            "api_endpoint": self.api_endpoint,
            "data_format": self.data_format,
            "backup_method": self.backup_method,
            "reason": self.reason,
            "alternatives": self.alternatives,
            "rss_url": self.rss_url,
            "sample_endpoint": self.sample_endpoint,
        }


# --------------------------------------------------------------------------------------
# Heuristiques de format
# --------------------------------------------------------------------------------------

def _auth_type_from_header(www_authenticate: str | None) -> str | None:
    if not www_authenticate:
        return None
    header = www_authenticate.lower()
    if "bearer" in header:
        return "oauth" if "oauth" in header else "bearer"
    if "basic" in header:
        return "basic"
    if "apikey" in header or "api-key" in header or "api_key" in header:
        return "api_key"
    return None


def _looks_like_json(fetched: FetchResult) -> bool:
    ctype = (fetched.content_type or "").lower()
    return "json" in ctype or fetched.body.strip().startswith(("{", "["))


def _looks_like_rss(fetched: FetchResult) -> bool:
    ctype = (fetched.content_type or "").lower()
    body = fetched.body_lower
    return (
        "rss" in ctype or "atom" in ctype
        or "<rss" in body or "<feed" in body or "<rdf" in body
    )


def _looks_like_xml_api(fetched: FetchResult) -> bool:
    """XML structuré qui n'est PAS un flux RSS/Atom (donc une API XML)."""
    ctype = (fetched.content_type or "").lower()
    body = fetched.body_lower.lstrip()
    is_xml = "xml" in ctype or body.startswith("<?xml")
    return is_xml and not _looks_like_rss(fetched)


def _looks_like_html(fetched: FetchResult) -> bool:
    ctype = (fetched.content_type or "").lower()
    body = fetched.body_lower
    return "html" in ctype or "<html" in body or "<!doctype html" in body


def _host_of(url: str, fetched: FetchResult | None) -> str | None:
    if fetched and fetched.host:
        return fetched.host
    return (urlparse(url).hostname or "").lower() or None


def _known_api_for(host: str | None) -> dict | None:
    if not host:
        return None
    host = host.lower().strip(".")
    for domain, cfg in _KNOWN_APIS.items():
        if host == domain or host.endswith("." + domain):
            return cfg
    return None


# --------------------------------------------------------------------------------------
# Auto-découverte (liens déclarés dans le HTML + chemins standards)
# --------------------------------------------------------------------------------------

def _declared_links(body: str, type_keywords: tuple[str, ...]) -> list[str]:
    """Extrait les href des <link rel="alternate" type="..."> correspondant aux types donnés."""
    out = []
    for tag in re.findall(r"<link\b[^>]*>", body, re.IGNORECASE):
        low = tag.lower()
        if "alternate" not in low and "service" not in low:
            continue
        if not any(k in low for k in type_keywords):
            continue
        m = re.search(r'href\s*=\s*["\']([^"\']+)["\']', tag, re.IGNORECASE)
        if m:
            out.append(m.group(1))
    return out


async def _confirm_api(candidate: str) -> tuple[str, str] | None:
    """Sonde un endpoint : renvoie (url, data_format) s'il répond en JSON/XML exploitable."""
    fetched = await fetch(candidate)
    if not fetched.status_ok:
        return None
    if _looks_like_json(fetched):
        return candidate, "json"
    if _looks_like_xml_api(fetched):
        return candidate, "xml"
    return None


async def _discover_api(url: str, fetched: FetchResult) -> tuple[str, str] | None:
    """Cherche une API déclarée dans le HTML puis sur des chemins standards. (url, format) ou None."""
    body = fetched.body if fetched else ""
    # 1) <link type="application/json"> déclaré dans la page.
    for href in _declared_links(body, ("json", "hal+json", "api")):
        confirmed = await _confirm_api(urljoin(url, href))
        if confirmed:
            return confirmed
    # 2) Chemins d'API standards à la racine du domaine.
    root = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    for path in API_PROBE_PATHS:
        confirmed = await _confirm_api(urljoin(root + "/", path.lstrip("/")))
        if confirmed:
            return confirmed
    return None


async def _discover_rss(url: str, fetched: FetchResult) -> str | None:
    """Cherche un flux RSS déclaré (<link>) puis sur des chemins standards. URL ou None."""
    body = fetched.body if fetched else ""
    for href in _declared_links(body, ("rss", "atom", "xml")):
        candidate = urljoin(url, href)
        probe = await fetch(candidate)
        if probe.status_ok and _looks_like_rss(probe):
            return candidate
    root = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    for path in RSS_PROBE_PATHS:
        candidate = urljoin(root + "/", path.lstrip("/"))
        probe = await fetch(candidate)
        if probe.status_ok and _looks_like_rss(probe):
            return candidate
    return None


# --------------------------------------------------------------------------------------
# Construction des résultats (avec repli + alternatives)
# --------------------------------------------------------------------------------------

def _api_result(method: str, endpoint: str, data_format: str, reason: str,
                auth_required: bool = False, auth_type: str | None = None,
                detail: str | None = None, sample_endpoint: str | None = None) -> DetectionResult:
    return DetectionResult(
        method,
        authentication_required=auth_required,
        authentication_type=auth_type,
        detail=detail or reason,
        api_endpoint=endpoint,
        data_format=data_format,
        backup_method="rss",  # API → RSS → Scraping
        reason=reason,
        alternatives=["RSS", "Web Scraping"],
        sample_endpoint=sample_endpoint,
    )


def _rss_result(url: str, reason: str) -> DetectionResult:
    return DetectionResult(
        "rss",
        detail=reason,
        rss_url=url,
        api_endpoint=None,
        data_format="xml",
        backup_method="scraping",  # RSS → Scraping
        reason=reason,
        alternatives=["Web Scraping"],
    )


def _scraping_result(reason: str, detail: str | None = None) -> DetectionResult:
    return DetectionResult(
        "scraping",
        detail=detail or reason,
        api_endpoint=None,
        data_format="html",
        backup_method=None,
        reason=reason,
        alternatives=[],
    )


# --------------------------------------------------------------------------------------
# Détection principale
# --------------------------------------------------------------------------------------

def content_family(fetched: FetchResult) -> str | None:
    """Famille de contenu d'une réponse : 'json' / 'xml' / 'rss' / 'html' / None."""
    if _looks_like_json(fetched):
        return "json"
    if _looks_like_rss(fetched):
        return "rss"
    if _looks_like_xml_api(fetched):
        return "xml"
    if _looks_like_html(fetched):
        return "html"
    return None


async def discover_rss(url: str, fetched: FetchResult | None = None) -> str | None:
    """Découvre un flux RSS/Atom pour une URL (wrapper public de `_discover_rss`)."""
    if fetched is None:
        fetched = await fetch(url)
    return await _discover_rss(url, fetched)


async def detect_collection_method(url: str, fetched: FetchResult | None = None) -> DetectionResult:
    """Détermine la méthode de collecte selon la priorité API → RSS → Scraping."""
    if fetched is None:
        fetched = await fetch(url)
    host = _host_of(url, fetched)

    # ===================== Priorité 1 : API =====================
    # 1a) API officielle connue (registre) — l'endpoint peut être sur un autre hôte.
    known = _known_api_for(host)
    if known:
        # API officielle documentée : on fait confiance au registre (pas d'appel de
        # confirmation, ce qui évite de solliciter deux fois une API à quota strict comme NVD).
        data_format = known["data_format"]
        auth_txt = "clé API optionnelle" if known.get("auth_optional") else (
            "authentification requise" if known["auth_required"] else "aucune authentification"
        )
        reason = (
            f"Une API officielle ({known['org']}) est disponible et retourne des données "
            f"structurées {data_format.upper()} — {auth_txt}."
        )
        builder = known.get("sample_builder")
        return _api_result(
            "api_protected" if known["auth_required"] else "api_public",
            endpoint=known["endpoint"], data_format=data_format, reason=reason,
            auth_required=known["auth_required"], auth_type=known.get("auth_type"),
            detail=f"API officielle {known['org']}",
            sample_endpoint=builder() if builder else known["endpoint"],
        )

    # 1b) L'URL saisie est elle-même une API protégée (401/403).
    if fetched.status_code in (401, 403):
        auth_type = _auth_type_from_header(fetched.www_authenticate)
        reason = "L'URL répond en exigeant une authentification : il s'agit d'une API protégée."
        return _api_result(
            "api_protected", endpoint=fetched.final_url or url,
            data_format="json", reason=reason, auth_required=True, auth_type=auth_type,
            detail=f"HTTP {fetched.status_code} — authentification requise",
        )

    # 1c) L'URL saisie renvoie directement du JSON/XML → API publique.
    if fetched.status_ok and _looks_like_json(fetched):
        reason = "L'URL renvoie directement des données JSON structurées : API publique."
        return _api_result("api_public", endpoint=fetched.final_url or url, data_format="json", reason=reason)
    if fetched.status_ok and _looks_like_xml_api(fetched):
        reason = "L'URL renvoie des données XML structurées (API) : API publique."
        return _api_result("api_public", endpoint=fetched.final_url or url, data_format="xml", reason=reason)

    # 1d) Une API est déclarée dans la page ou trouvée sur un chemin standard.
    if fetched.reached:
        api = await _discover_api(url, fetched)
        if api:
            endpoint, data_format = api
            reason = f"Une API renvoyant du {data_format.upper()} a été découverte pour cette source ({endpoint})."
            return _api_result("api_public", endpoint=endpoint, data_format=data_format, reason=reason)

    # ===================== Priorité 2 : RSS =====================
    if fetched.status_ok and _looks_like_rss(fetched):
        return _rss_result(url, "L'URL est un flux RSS/Atom : collecte par flux.")
    if fetched.reached:
        rss_url = await _discover_rss(url, fetched)
        if rss_url:
            return _rss_result(rss_url, f"Aucune API, mais un flux RSS/Atom a été trouvé : {rss_url}.")

    # ===================== Priorité 3 : Web Scraping =====================
    if fetched.status_ok and _looks_like_html(fetched):
        return _scraping_result(
            "Aucune API ni flux RSS disponible : collecte par scraping de la page HTML."
        )

    return _scraping_result(
        "Contenu non identifié : scraping par défaut, à revérifier.",
        detail=fetched.error or "Contenu non identifié — scraping par défaut",
    )
