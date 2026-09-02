"""Collecteur RSS / Atom : un <item>/<entry> par CVE, enrichi via NVD pour les champs manquants.

Auto-correction : si l'URL n'est PAS un vrai flux (page HTML mal étiquetée « rss » lors de la
détection, ex. un portail d'avis CERT), on bascule AUTOMATIQUEMENT sur le collecteur HTML — qui
route lui-même vers le crawler d'avis deux niveaux si nécessaire. Aucun réglage par site.
"""
import logging
import re

from app.backend.services.collection import net, parser
from app.backend.services.collection.collectors.base import register, target_url
from app.backend.services.collection import sanitize
from app.backend.services.collection.schema import CVE_RE, new_record, parse_dt

logger = logging.getLogger("cyberwatch.collection.rss")
MAX_PER_SOURCE = 300
_ITEM_RE = re.compile(r"<(item|entry)\b[^>]*>(.*?)</\1>", re.IGNORECASE | re.DOTALL)


def _tag(item: str, tag: str):
    m = re.search(rf"<{re.escape(tag)}\b[^>]*>(.*?)</{re.escape(tag)}>", item, re.IGNORECASE | re.DOTALL)
    if not m:
        return None
    return re.sub(r"<[^>]+>", " ", m.group(1)).strip() or None


async def _fallback_to_html(source: dict, since, reason: str) -> list[dict]:
    logger.info("[rss] %s : %s — bascule automatique sur le collecteur HTML.",
                source.get("url") or source.get("rss_url"), reason)
    from app.backend.services.collection.collectors import html as html_collector
    return await html_collector.collect(source, since)


@register("rss")
async def collect(source: dict, since) -> list[dict]:
    url = target_url(source)
    resp = await net.get(url)
    if resp is None or resp.status_code != 200:
        # Injoignable en httpx simple (ex. portail CERT nécessitant un rendu) : on tente le HTML.
        return await _fallback_to_html(source, since, "flux injoignable en httpx")
    items = _ITEM_RE.findall(resp.text)
    if not items:
        # Pas de <item>/<entry> -> ce n'est pas un vrai flux RSS/Atom (page HTML mal détectée).
        return await _fallback_to_html(source, since, "aucun <item>/<entry> (pas un vrai flux)")
    out: list[dict] = []
    for _, item in items[:MAX_PER_SOURCE]:
        m = CVE_RE.search(item)
        if not m:
            continue
        rec = new_record(m.group(0))
        rec["title"] = _tag(item, "title")
        rec["description"] = _tag(item, "description") or _tag(item, "summary")
        rec["published_at"] = parse_dt(_tag(item, "pubDate") or _tag(item, "published") or _tag(item, "dc:date"))
        rec["updated_at"] = parse_dt(_tag(item, "updated"))
        link = _tag(item, "link")
        rec["detail_url"] = link if (link and link.startswith("http")) else f"https://nvd.nist.gov/vuln/detail/{rec['cve_id']}"
        rec["data_origin"] = "RSS"
        sanitize.clean_record(rec)
        out.append(rec)
    return out
