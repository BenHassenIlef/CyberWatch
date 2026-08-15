"""Collecteur XML (fichiers XML / CVRF…) : extrait les identifiants CVE réels puis complète
via NVD. Fonctionne pour tout flux XML sans code spécifique à un site."""
from app.backend.services.collection import net
from app.backend.services.collection.collectors.base import register, target_url, host_of
from app.backend.services.collection.schema import CVE_RE, new_record

MAX_PER_SOURCE = 60


@register("xml")
async def collect(source: dict, since) -> list[dict]:
    url = target_url(source)
    if not url:
        return []
    resp = await net.get(url)
    if resp is None or resp.status_code != 200:
        return []
    host = host_of(url)
    seen: list[str] = []
    for m in CVE_RE.finditer(resp.text):
        cid = m.group(0).upper()
        if cid not in seen:
            seen.append(cid)
        if len(seen) >= MAX_PER_SOURCE:
            break
    out = []
    for cid in seen:
        rec = new_record(cid)
        rec["detail_url"] = f"https://nvd.nist.gov/vuln/detail/{cid}"
        rec["data_origin"] = "XML"
        out.append(rec)
    return out
