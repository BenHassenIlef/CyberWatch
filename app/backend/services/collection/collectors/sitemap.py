"""Collecteur Sitemap : lit un sitemap.xml (ou un index de sitemaps), repère les URL contenant un
identifiant CVE ET leur <lastmod>, puis complète les champs via NVD.

Méthode LÉGITIME et robuste pour les sites dont la page HTML est protégée (WAF / reCAPTCHA) mais
qui exposent un sitemap destiné aux moteurs (déclaré dans robots.txt) — ex. SecAlerts. Le
<lastmod> fournit une date ABSOLUE (ISO 8601), ce qui règle aussi le problème des temps relatifs
(« First published 2h ago »). Extensible à tout sitemap listant des pages de CVE."""
import re
from datetime import datetime, timezone

from app.backend.services.collection import net
from app.backend.services.collection.collectors.base import register, target_url
from app.backend.services.collection.schema import CVE_RE, new_record, parse_dt

MAX_PER_SOURCE = 500     # nb max de CVE retenues (les plus récentes d'abord)
MAX_SUBSITEMAPS = 20     # nb max de sous-sitemaps suivis dans un index

_URL_RE = re.compile(r"<url>(.*?)</url>", re.IGNORECASE | re.DOTALL)
_LOC_RE = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.IGNORECASE | re.DOTALL)
_LASTMOD_RE = re.compile(r"<lastmod>\s*(.*?)\s*</lastmod>", re.IGNORECASE | re.DOTALL)


def _entries(body: str) -> list[tuple[str, str | None]]:
    """(<loc>, <lastmod>) de chaque entrée <url> d'un sitemap."""
    out = []
    for block in _URL_RE.findall(body or ""):
        loc = _LOC_RE.search(block)
        if not loc:
            continue
        lm = _LASTMOD_RE.search(block)
        out.append((loc.group(1).strip(), lm.group(1).strip() if lm else None))
    return out


def _naif(valeur):
    """Date SANS fuseau — convention de toute la chaine de collecte.

    Un sitemap melange les formes : certaines entrees <lastmod> portent un decalage horaire
    (« 2026-08-19T10:00:00+02:00 »), d autres non (« 2026-08-19 »). Les comparer levait
    « can t compare offset-naive and offset-aware datetimes », et l exception faisait perdre
    la SOURCE ENTIERE — la plus prolifique du parc. Normaliser des l analyse supprime le
    probleme a la racine, pour ce sitemap comme pour tous les autres.
    """
    if valeur is None or valeur.tzinfo is None:
        return valeur
    return valeur.astimezone(timezone.utc).replace(tzinfo=None)


@register("sitemap")
async def collect(source: dict, since) -> list[dict]:
    url = target_url(source)
    resp = await net.get(url)
    if resp is None or resp.status_code != 200:
        return []
    body = resp.text or ""

    # Index de sitemaps -> on suit les sous-sitemaps (bornés). Sinon urlset direct.
    if "<sitemapindex" in body.lower():
        entries: list[tuple[str, str | None]] = []
        for sub in _LOC_RE.findall(body)[:MAX_SUBSITEMAPS]:
            r = await net.get(sub)
            if r is not None and r.status_code == 200:
                entries.extend(_entries(r.text))
    else:
        entries = _entries(body)

    # URL de CVE + date (lastmod), dédupliquées en gardant la date la plus récente.
    seen: dict[str, tuple[str, datetime | None]] = {}
    for loc, lm in entries:
        m = CVE_RE.search(loc)
        if not m:
            continue
        cid = m.group(0).upper()
        dt = _naif(parse_dt(lm)) if lm else None
        prev = seen.get(cid)
        if prev is None or (dt and (prev[1] is None or dt > prev[1])):
            seen[cid] = (loc, dt)

    # Les plus RÉCEMMENT modifiées d'abord (on capte ainsi les CVE fraîchement publiées).
    items = sorted(seen.items(), key=lambda kv: kv[1][1] or datetime.min, reverse=True)
    out = []
    for cid, (loc, dt) in items[:MAX_PER_SOURCE]:
        rec = new_record(cid)
        rec["detail_url"] = loc
        if dt is not None:
            rec["published_at"] = dt   # graine ; NVD corrigera la vraie date de publication
            rec["updated_at"] = dt     # <lastmod> = dernière modification (fiable)
        rec["data_origin"] = "sitemap"
        out.append(rec)
    return out
