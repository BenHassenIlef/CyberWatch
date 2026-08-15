"""Parser générique de CVE (extraction site-agnostique) + normalisation canonique NVD.

- `extract_from_json_object` : extrait les champs d'un objet JSON quelconque décrivant une CVE
  (fonctionne pour NVD, CISA, GitHub, MSRC et toute API inconnue — aucun code par site).
- `record_from_nvd_cve` / `nvd_lookup` : normalisation canonique via l'API officielle NVD
  (utilisée pour compléter les champs manquants — jamais pour inventer).
"""
import json

from app.backend.services.collection import net
from app.backend.services.collection.schema import (
    CVE_RE, new_record, parse_dt, norm_severity, severity_from_score,
)

# Alias de clés reconnus (site-agnostique). NB : « dateAdded » (CISA KEV) est la date d'AJOUT
# au catalogue, PAS la date de publication de la CVE -> volontairement EXCLUE ici. La vraie
# date de publication est alors récupérée par enrichissement (NVD/MITRE...).
_PUB_KEYS = {"published", "publisheddate", "datepublished", "pubdate",
             "datecreated", "created"}
_UPD_KEYS = {"lastmodified", "updated", "datemodified", "latestrevisiondate", "modified", "updated_at"}
_TITLE_KEYS = {"title", "cvetitle", "vulnerabilityname", "headline", "name"}
_DESC_KEYS = {"description", "summary", "shortdescription", "unformatteddescription"}
_SEV_KEYS = {"baseseverity", "severity"}
_SCORE_KEYS = {"basescore", "cvssscore", "score"}
_PRODUCT_KEYS = {"product", "packagename", "affectedproduct"}
_VENDOR_KEYS = {"vendor", "vendorproject", "issuingcna"}
_CWE_KEYS = {"cwe", "cweid", "cwe_id"}
_VERSION_KEYS = {"vulnerable_version_range", "affectedversions", "versionaffected"}
_SOLUTION_KEYS = {"solution", "remediation", "requiredaction", "recommendation",
                  "mitigation", "fix", "fixinformation"}


def _deep_find(node, aliases):
    """Première valeur scalaire non vide dont la clé (minuscule) figure dans `aliases`."""
    if isinstance(node, dict):
        for k, v in node.items():
            if str(k).lower() in aliases and isinstance(v, (str, int, float)) and v != "":
                return v
        for v in node.values():
            r = _deep_find(v, aliases)
            if r is not None:
                return r
    elif isinstance(node, list):
        for v in node:
            r = _deep_find(v, aliases)
            if r is not None:
                return r
    return None


def _find_cve_id(node) -> str | None:
    if isinstance(node, dict):
        for v in node.values():
            r = _find_cve_id(v)
            if r:
                return r
    elif isinstance(node, list):
        for v in node:
            r = _find_cve_id(v)
            if r:
                return r
    elif isinstance(node, str):
        m = CVE_RE.search(node)
        if m:
            return m.group(0).upper()
    return None


def _extract_description(node):
    """Privilégie une description anglaise ({lang:'en', value:…}), sinon toute description."""
    result = {"val": None}

    def walk(n):
        if result["val"]:
            return
        if isinstance(n, dict):
            if n.get("lang") == "en" and isinstance(n.get("value"), str):
                result["val"] = n["value"]
                return
            for v in n.values():
                walk(v)
        elif isinstance(n, list):
            for v in n:
                walk(v)

    walk(node)
    return result["val"] or _deep_find(node, _DESC_KEYS)


def _extract_references(node):
    refs: list[str] = []

    def walk(n):
        if isinstance(n, dict):
            for k, v in n.items():
                if str(k).lower() in ("references", "refs") and isinstance(v, list):
                    for it in v:
                        if isinstance(it, str) and it.startswith("http"):
                            refs.append(it)
                        elif isinstance(it, dict):
                            u = it.get("url") or it.get("URL")
                            if isinstance(u, str) and u.startswith("http"):
                                refs.append(u)
                else:
                    walk(v)
        elif isinstance(n, list):
            for it in n:
                walk(it)

    walk(node)
    return list(dict.fromkeys(refs))[:12]  # dédupliquées, propres à CET objet CVE


def _extract_cwe(node):
    val = _deep_find(node, _CWE_KEYS)
    if isinstance(val, str) and val.upper().startswith("CWE-"):
        return val
    found = {"v": None}

    def walk(n):
        if found["v"]:
            return
        if isinstance(n, dict):
            v = n.get("value")
            if isinstance(v, str) and v.startswith("CWE-") and "Other" not in v and "noinfo" not in v.lower():
                found["v"] = v
                return
            for x in n.values():
                walk(x)
        elif isinstance(n, list):
            for x in n:
                walk(x)
        elif isinstance(n, str) and n.upper().startswith("CWE-"):
            found["v"] = n  # ex. CISA : cwes = ["CWE-502"]

    walk(node)
    return found["v"]


def _extract_cpe_product(node):
    """Produit/éditeur depuis une chaîne CPE (cpe:2.3:part:vendor:product:…), si présente."""
    result = {"p": None, "v": None}

    def walk(n):
        if result["p"]:
            return
        if isinstance(n, dict):
            for v in n.values():
                walk(v)
        elif isinstance(n, list):
            for v in n:
                walk(v)
        elif isinstance(n, str) and n.startswith("cpe:2.3:"):
            parts = n.split(":")
            if len(parts) >= 5 and parts[4] not in ("*", "-", ""):
                result["p"] = parts[4].replace("_", " ")
                result["v"] = parts[3].replace("_", " ") if parts[3] not in ("*", "-", "") else None

    walk(node)
    return result["p"], result["v"]


def extract_from_json_object(obj: dict, detail_url: str | None = None) -> dict | None:
    """Construit un enregistrement CVE canonique à partir d'un objet JSON quelconque."""
    cve_id = _find_cve_id(obj)
    if not cve_id:
        return None
    rec = new_record(cve_id)
    rec["title"] = _deep_find(obj, _TITLE_KEYS)
    rec["description"] = _extract_description(obj)
    rec["published_at"] = parse_dt(_deep_find(obj, _PUB_KEYS))
    rec["updated_at"] = parse_dt(_deep_find(obj, _UPD_KEYS))
    score = _deep_find(obj, _SCORE_KEYS)
    try:
        rec["cvss_score"] = float(score) if score is not None else None
    except (TypeError, ValueError):
        rec["cvss_score"] = None
    rec["severity"] = norm_severity(_deep_find(obj, _SEV_KEYS)) or severity_from_score(rec["cvss_score"])
    rec["cwe"] = _extract_cwe(obj)
    rec["vuln_type"] = rec["cwe"]
    rec["references"] = _extract_references(obj)
    product = _deep_find(obj, _PRODUCT_KEYS)
    vendor = _deep_find(obj, _VENDOR_KEYS)
    if not product:
        product, cpe_vendor = _extract_cpe_product(obj)
        vendor = vendor or cpe_vendor
    rec["product"] = product if isinstance(product, str) else None
    rec["vendor"] = vendor if isinstance(vendor, str) else None
    if rec["product"]:
        rec["affected_products"] = [rec["product"]]
    rec["affected_versions"] = _deep_find(obj, _VERSION_KEYS)
    rec["solution"] = _deep_find(obj, _SOLUTION_KEYS)
    rec["detail_url"] = detail_url
    rec["data_origin"] = "source"
    return rec


def iter_cve_objects(data):
    """Trouve les objets-CVE d'un JSON : la plus grande liste de dicts contenant chacun une CVE."""
    best: list[dict] = []

    def walk(node):
        nonlocal best
        if isinstance(node, list):
            dicts = [x for x in node if isinstance(x, dict) and _find_cve_id(x)]
            if len(dicts) > len(best):
                best = dicts
            for x in node:
                walk(x)
        elif isinstance(node, dict):
            for v in node.values():
                walk(v)

    walk(data)
    if best:
        return best
    if isinstance(data, dict) and _find_cve_id(data):
        return [data]
    return []


# --------------------------------------------------------------------------------------
# Normalisation canonique via l'API officielle NVD (complète les champs manquants)
# --------------------------------------------------------------------------------------

def record_from_nvd_cve(cve: dict) -> dict:
    rec = extract_from_json_object(cve) or new_record(cve.get("id", "CVE-0000-0000"))
    # NVD : CVSS et CWE peuvent être imbriqués -> extraction dédiée fiable.
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            data = arr[0].get("cvssData", {})
            rec["cvss_score"] = data.get("baseScore")
            rec["severity"] = norm_severity(data.get("baseSeverity") or arr[0].get("baseSeverity")) \
                or severity_from_score(rec["cvss_score"])
            break
    rec["data_origin"] = "NVD"
    return rec


async def nvd_lookup(cve_id: str) -> dict | None:
    resp = await net.nvd_get(f"{net.NVD_API}?cveId={cve_id}")
    if resp is None:
        return None
    try:
        data = resp.json()
    except (ValueError, json.JSONDecodeError):
        return None
    vulns = data.get("vulnerabilities") or []
    return record_from_nvd_cve(vulns[0]["cve"]) if vulns else None


async def enrich_missing(record: dict) -> None:
    """Complète les champs manquants (CVSS, description, CWE…) via NVD. Ne remplace jamais."""
    if record.get("cvss_score") is not None and record.get("description") and record.get("cwe"):
        return
    canon = await nvd_lookup(record["cve_id"])
    if not canon:
        return
    for key in ("description", "cvss_score", "severity", "cwe", "vuln_type",
                "product", "vendor", "affected_versions", "published_at", "updated_at", "title"):
        if not record.get(key) and canon.get(key):
            record[key] = canon[key]
    if not record.get("references"):
        record["references"] = canon.get("references") or []
