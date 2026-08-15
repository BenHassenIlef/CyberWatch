"""Collection Method Analyzer — choisit la meilleure méthode de collecte en la VALIDANT.

Une méthode n'est jamais retenue simplement parce que la technologie existe : chaque
méthode candidate est réellement sondée, puis notée sur la présence de données CVE
exploitables (CVE Detection Score). La première méthode qui atteint le seuil est retenue.

Ordre de priorité (chaîne de repli) :
  1. API officielle          (registre d'API connues, ou URL renvoyant JSON/XML, ou API découverte)
  2. Flux RSS/Atom           (validé UNIQUEMENT s'il contient des identifiants CVE)
  3. API interne JavaScript  (endpoints fetch/XHR/Ajax repérés dans la page)
  4. Scraping dynamique      (rendu navigateur headless — Playwright)
  5. Scraping HTML classique (HTML brut)

CVE Detection Score : CVE présent (+50), date de publication (+20), description (+20), CVSS (+10).
Seuil de validation : 50 (au moins un CVE réel). En dessous, la méthode est jugée non adaptée.
"""
import re
from urllib.parse import urljoin, urlparse

from app.backend.services.verification import browser_client
from app.backend.services.verification import detection as det
from app.backend.services.verification.cve import extract_cve_ids
from app.backend.services.verification.cve_dates import extract_cve_dates
from app.backend.services.verification.http_client import FetchResult, fetch

VALIDATION_THRESHOLD = 50

_CVSS_RE = re.compile(r"cvss|base\s*score|basescore|score\s*de\s*base", re.IGNORECASE)
_DESC_RE = re.compile(
    r"vuln[ée]rabilit|vulnerability|advisor(?:y|ies)|exploit|remote\s+code|"
    r"privilege|denial\s+of\s+service|description|impact",
    re.IGNORECASE,
)
# Endpoints référencés dans le JavaScript (fetch/axios/XHR/url:).
_JS_ENDPOINT_RE = re.compile(
    r"""(?:fetch|axios\.(?:get|post)|\.open|url\s*[:=]|baseUrl\s*[:=])\s*\(?\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
_API_URL_RE = re.compile(r"""["'](https?://[^"']*(?:api|/v\d|/rest|graphql|\.json)[^"']*)["']""", re.IGNORECASE)

CANDIDATE_LABELS = {
    "api": "API officielle",
    "rss": "Flux RSS/Atom",
    "internal_api": "API interne (JavaScript)",
    "dynamic": "Scraping dynamique",
    "html": "Scraping HTML",
}
# Famille candidate -> méthode de collecte interne stockée.
_FAMILY_TO_METHOD = {"api": "api_public", "internal_api": "api_public", "rss": "rss",
                     "dynamic": "scraping", "html": "scraping"}
# Repli actionnable par famille retenue.
_FALLBACK = {"api": "rss", "internal_api": "scraping", "rss": "scraping", "dynamic": "scraping", "html": None}


# --------------------------------------------------------------------------------------
# Score de pertinence CVE
# --------------------------------------------------------------------------------------

def cve_detection_score(body: str | None, content_type: str | None = None, method: str | None = None) -> dict:
    """Note un contenu sur la présence de données CVE exploitables (0 à 100)."""
    body = body or ""
    ids = extract_cve_ids(body)
    cve_count = len(ids)
    score = 0
    signals: list[str] = []

    if cve_count:
        score += 50
        signals.append(f"{cve_count} CVE")
    try:
        dated = [d for d in extract_cve_dates({"body": body, "content_type": content_type, "collection_method": method})
                 if d.get("published")]
    except Exception:  # noqa: BLE001 - scoring best-effort
        dated = []
    if dated:
        score += 20
        signals.append("date de publication")
    if _DESC_RE.search(body):
        score += 20
        signals.append("description")
    if _CVSS_RE.search(body):
        score += 10
        signals.append("CVSS")
    return {"score": score, "cve_count": cve_count, "signals": signals}


# --------------------------------------------------------------------------------------
# Résolveurs de méthodes candidates : renvoient un dict de candidat, ou None si indisponible.
# --------------------------------------------------------------------------------------

async def _cand_api(url: str, page: FetchResult, host: str | None) -> dict | None:
    known = det._known_api_for(host)
    if known:
        builder = known.get("sample_builder")
        probe_url = builder() if builder else known["endpoint"]
        f = await fetch(probe_url)
        return {
            "family": "api",
            "collection_method": "api_protected" if known["auth_required"] else "api_public",
            "api_endpoint": known["endpoint"], "data_format": known["data_format"],
            "body": f.body, "content_type": f.content_type, "url": probe_url,
            "authentication_required": known["auth_required"], "authentication_type": known.get("auth_type"),
            "org": known["org"], "render_required": False,
        }
    if page.status_code in (401, 403):
        return {
            "family": "api", "collection_method": "api_protected",
            "api_endpoint": page.final_url or url, "data_format": "json",
            "body": page.body, "content_type": page.content_type, "url": url,
            "authentication_required": True,
            "authentication_type": det._auth_type_from_header(page.www_authenticate),
            "render_required": False,
        }
    if page.status_ok and (det._looks_like_json(page) or det._looks_like_xml_api(page)):
        fmt = "json" if det._looks_like_json(page) else "xml"
        return {
            "family": "api", "collection_method": "api_public",
            "api_endpoint": page.final_url or url, "data_format": fmt,
            "body": page.body, "content_type": page.content_type, "url": url, "render_required": False,
        }
    if page.reached:
        disc = await det._discover_api(url, page)
        if disc:
            endpoint, fmt = disc
            f = await fetch(endpoint)
            return {
                "family": "api", "collection_method": "api_public",
                "api_endpoint": endpoint, "data_format": fmt,
                "body": f.body, "content_type": f.content_type, "url": endpoint, "render_required": False,
            }
    return None


async def _cand_rss(url: str, page: FetchResult) -> dict | None:
    if page.status_ok and det._looks_like_rss(page):
        return {"family": "rss", "collection_method": "rss", "rss_url": url, "data_format": "xml",
                "body": page.body, "content_type": page.content_type, "url": url, "render_required": False}
    rss_url = await det._discover_rss(url, page) if page.reached else None
    if rss_url:
        f = await fetch(rss_url)
        return {"family": "rss", "collection_method": "rss", "rss_url": rss_url, "data_format": "xml",
                "body": f.body, "content_type": f.content_type, "url": rss_url, "render_required": False}
    return None


async def _cand_internal_api(url: str, page: FetchResult) -> dict | None:
    """Cherche une API interne appelée par le JavaScript de la page (fetch/XHR/Ajax)."""
    body = page.body or ""
    if not body:
        return None
    candidates: list[str] = []
    seen = set()
    for regex in (_JS_ENDPOINT_RE, _API_URL_RE):
        for m in regex.finditer(body):
            raw = m.group(1)
            if raw.startswith("//"):
                raw = "https:" + raw
            absu = urljoin(url, raw)
            if not absu.startswith("http") or absu in seen:
                continue
            if not re.search(r"api|/v\d|/rest|graphql|\.json", absu, re.IGNORECASE):
                continue
            seen.add(absu)
            candidates.append(absu)
    for absu in candidates[:6]:
        f = await fetch(absu)
        if f.status_ok and (det._looks_like_json(f) or det._looks_like_xml_api(f)) and extract_cve_ids(f.body):
            return {
                "family": "internal_api", "collection_method": "api_public",
                "api_endpoint": absu, "data_format": "json" if det._looks_like_json(f) else "xml",
                "body": f.body, "content_type": f.content_type, "url": absu, "render_required": False,
            }
    return None


async def _cand_dynamic(url: str, page: FetchResult, rendered_body: str | None) -> dict | None:
    body = rendered_body
    if body is None:
        # On ne rend au navigateur que si le HTML brut ne contient pas déjà de CVE.
        if page and extract_cve_ids(page.body):
            return None
        body = await browser_client.render_html(url)
    if not body:
        return None
    return {"family": "dynamic", "collection_method": "scraping", "data_format": "html",
            "body": body, "content_type": "text/html", "url": url, "render_required": True}


async def _cand_html(url: str, page: FetchResult) -> dict | None:
    if not page or not page.reached:
        return None
    return {"family": "html", "collection_method": "scraping", "data_format": "html",
            "body": page.body, "content_type": page.content_type, "url": url, "render_required": False}


# --------------------------------------------------------------------------------------
# Analyse principale
# --------------------------------------------------------------------------------------

def _candidate_reason(family: str, available: bool, validated: bool, sc: dict) -> str:
    if not available:
        return "Non disponible pour cette source."
    if validated:
        return f"Validé : {', '.join(sc['signals'])} (score {sc['score']})."
    if family == "rss":
        return "Flux détecté mais SANS identifiant CVE — contenu non pertinent, rejeté."
    if sc["cve_count"] == 0:
        return "Disponible mais aucun CVE détecté — rejeté."
    return f"CVE présents mais données insuffisantes (score {sc['score']} < {VALIDATION_THRESHOLD})."


async def analyze_source(url: str, page_fetched: FetchResult | None = None,
                         rendered_body: str | None = None) -> dict:
    """Analyse la source, valide chaque méthode par la présence de CVE, et choisit la meilleure."""
    page = page_fetched or await fetch(url)
    host = det._host_of(url, page)

    # Fabriques paresseuses : la coroutine n'est créée que si la méthode est effectivement testée
    # (on s'arrête à la première méthode validée, sans lancer les suivantes).
    resolvers = [
        ("api", lambda: _cand_api(url, page, host)),
        ("rss", lambda: _cand_rss(url, page)),
        ("internal_api", lambda: _cand_internal_api(url, page)),
        ("dynamic", lambda: _cand_dynamic(url, page, rendered_body)),
        ("html", lambda: _cand_html(url, page)),
    ]

    report: list[dict] = []
    chosen: dict | None = None
    best: dict | None = None

    for family, factory in resolvers:
        cand = await factory()
        if not cand:
            report.append({"method": family, "label": CANDIDATE_LABELS[family], "available": False,
                           "validated": False, "score": 0, "cve_count": 0,
                           "reason": _candidate_reason(family, False, False, {})})
            continue
        sc = cve_detection_score(cand["body"], cand.get("content_type"), cand["collection_method"])
        cand["_score"] = sc
        validated = sc["score"] >= VALIDATION_THRESHOLD
        report.append({
            "method": family, "label": CANDIDATE_LABELS[family], "available": True,
            "validated": validated, "score": sc["score"], "cve_count": sc["cve_count"],
            "endpoint": cand.get("api_endpoint") or cand.get("rss_url") or cand.get("url"),
            "reason": _candidate_reason(family, True, validated, sc),
        })
        if best is None or sc["score"] > best["_score"]["score"]:
            best = cand
        if validated:
            chosen = cand
            break  # première méthode valide dans l'ordre de priorité

    final = chosen or best
    return _build_result(url, page, final, chosen is not None, report)


def _build_result(url: str, page: FetchResult, final: dict | None, validated: bool, report: list[dict]) -> dict:
    host = det._host_of(url, page)
    if final is None:
        return {
            "collection_method": "scraping", "method_family": "html",
            "api_endpoint": None, "detected_api_endpoint": None,
            "rss_url": None, "detected_rss_url": None,
            "data_format": "html", "backup_method": None, "fallback_method": None,
            "authentication_required": False, "authentication_type": None,
            "contains_cve": False, "cve_count": 0, "validation_score": 0,
            "validation_reason": "Aucune méthode de collecte n'a pu être sondée (source injoignable).",
            "reason": "Source injoignable — à revérifier.", "alternatives": [], "render_required": False,
            "candidates": report,
            "analysis_body": page.body if page else "", "analysis_content_type": None, "analysis_url": url,
        }

    family = final["family"]
    sc = final.get("_score") or cve_detection_score(final["body"], final.get("content_type"))
    label = CANDIDATE_LABELS[family]
    rejected_rss = next((c for c in report if c["method"] == "rss" and c["available"] and not c["validated"]), None)

    # Explication de la décision.
    if validated:
        base = f"Méthode « {label} » validée : {sc['cve_count']} CVE détectées (score {sc['score']}/100)."
        if rejected_rss:
            base = ("Un flux RSS existe mais ne contient pas d'identifiants CVE ; " + base) if family != "rss" else base
        reason = base
    else:
        reason = (f"Aucune méthode ne contient de CVE exploitables ; repli sur « {label} » "
                  f"(meilleur score {sc['score']}/100).")

    fallback = _FALLBACK.get(family)
    alternatives = [CANDIDATE_LABELS[f].split(" ")[0] for f in ("rss", "dynamic", "html")
                    if _FAMILY_TO_METHOD.get(f) and f != family]
    # Alternatives lisibles simples.
    alt_map = {"api": ["RSS", "Scraping dynamique", "Scraping HTML"],
               "rss": ["API", "Scraping dynamique", "Scraping HTML"],
               "internal_api": ["RSS", "Scraping dynamique", "Scraping HTML"],
               "dynamic": ["API", "RSS", "Scraping HTML"],
               "html": ["API", "RSS", "Scraping dynamique"]}
    alternatives = alt_map.get(family, [])

    return {
        "collection_method": final["collection_method"],
        "method_family": family,
        "api_endpoint": final.get("api_endpoint"),
        "detected_api_endpoint": final.get("api_endpoint"),
        "rss_url": final.get("rss_url"),
        "detected_rss_url": next((c["endpoint"] for c in report if c["method"] == "rss" and c["available"]), None),
        "data_format": final.get("data_format"),
        "backup_method": fallback,
        "fallback_method": fallback,
        "authentication_required": final.get("authentication_required", False),
        "authentication_type": final.get("authentication_type"),
        "contains_cve": sc["cve_count"] > 0,
        "cve_count": sc["cve_count"],
        "validation_score": sc["score"],
        "validation_reason": reason,
        "reason": reason,
        "alternatives": alternatives,
        "render_required": final.get("render_required", False),
        "candidates": report,
        # Contenu réel de la méthode retenue — réutilisé par l'agent (analyse CVE/dates).
        "analysis_body": final["body"],
        "analysis_content_type": final.get("content_type"),
        "analysis_url": final.get("url") or url,
    }
