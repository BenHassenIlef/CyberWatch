"""Enrichissement multi-sources d'une CVE (croisement de sources OFFICIELLES).

Pour un identifiant CVE donné, on interroge plusieurs bases officielles de référence :
    - NVD (services.nvd.nist.gov)      — CVSS, CWE, produits (CPE), références
    - MITRE / CVE.org (cveawg)          — description, références, affected, solutions, CVSS
    - Red Hat Security Data             — CVSS, CWE, avis (RHSA), correctifs, produits
    - OSV.dev                           — vecteur CVSS, paquets/versions affectés, références
    - GitHub Security Advisories        — sévérité, CVSS, paquet, références

Chaque source est interrogée PAR IDENTIFIANT : les informations récupérées appartiennent
donc toujours à CETTE CVE (jamais à une autre). Les champs sont ensuite fusionnés selon un
ORDRE DE PRIORITÉ CONFIGURABLE (settings.CVE_SOURCE_PRIORITY). Les listes (références,
produits…) sont fusionnées par union ; les scalaires en conflit sont résolus par priorité.

Aucune donnée fictive : un champ absent partout reste None (« Non disponible »).
"""
import asyncio
import json
import logging
import re
from datetime import datetime

from app.backend.core.config import settings
from app.backend.services.collection import net
from app.backend.services.collection.schema import (
    LIST_FIELDS, new_record, parse_dt, norm_severity, severity_from_score,
)

_SCALAR_FIELDS = ("title", "description", "published_at", "updated_at", "cvss_score",
                  "cvss_vector", "severity", "cwe", "vuln_type", "impact",
                  "vendor", "product", "affected_versions", "solution")

# Debut du programme CVE : une date anterieure est une erreur de source, pas une divulgation.
_CVE_ERA_START = datetime(1999, 1, 1)

_CVSS_VECTOR_RE = re.compile(r"CVSS:\d\.\d/[A-Z:/.\d]+")


def _priority_index(source: str) -> int:
    order = settings.source_priority
    s = (source or "").lower()
    return order.index(s) if s in order else len(order)


def _score_from_vector(vector: str | None):
    """On ne DÉDUIT pas un score depuis un vecteur (ce serait une invention) — on ne garde
    que le vecteur. Le score numérique doit venir d'une source qui le fournit explicitement."""
    return None


# --------------------------------------------------------------------------------------
# Enrichisseurs par source officielle (chacun renvoie un dict partiel, ou {} si indisponible)
# --------------------------------------------------------------------------------------

async def _from_nvd(cve_id: str) -> dict:
    resp = await net.nvd_get(f"{net.NVD_API}?cveId={cve_id}")
    if resp is None:
        return {}
    try:
        vulns = resp.json().get("vulnerabilities") or []
    except (ValueError, json.JSONDecodeError):
        return {}
    if not vulns:
        return {}
    cve = vulns[0]["cve"]
    out: dict = {}
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), None)
    if desc:
        out["description"] = desc
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = cve.get("metrics", {}).get(key)
        if arr:
            data = arr[0].get("cvssData", {})
            out["cvss_score"] = data.get("baseScore")
            out["cvss_vector"] = data.get("vectorString")
            out["severity"] = norm_severity(data.get("baseSeverity") or arr[0].get("baseSeverity")) \
                or severity_from_score(out.get("cvss_score"))
            break
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-") and "Other" not in v and "noinfo" not in v.lower():
                out["cwe"] = v
                break
        if out.get("cwe"):
            break
    refs = [r["url"] for r in cve.get("references", []) if r.get("url")]
    if refs:
        out["references"] = refs
    # produit / versions depuis les CPE
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if m.get("vulnerable") and m.get("criteria", "").startswith("cpe:2.3:"):
                    parts = m["criteria"].split(":")
                    if len(parts) >= 5 and parts[4] not in ("*", "-", ""):
                        out.setdefault("product", parts[4].replace("_", " "))
                        if parts[3] not in ("*", "-", ""):
                            out.setdefault("vendor", parts[3].replace("_", " "))
    out["published_at"] = parse_dt(cve.get("published"))
    out["updated_at"] = parse_dt(cve.get("lastModified"))
    return {k: v for k, v in out.items() if v not in (None, [], "")}


async def _from_mitre(cve_id: str) -> dict:
    resp = await net.get(f"https://cveawg.mitre.org/api/cve/{cve_id}")
    if resp is None or resp.status_code != 200:
        return {}
    try:
        data = resp.json()
    except (ValueError, json.JSONDecodeError):
        return {}
    cna = (data.get("containers") or {}).get("cna") or {}
    meta = data.get("cveMetadata") or {}
    out: dict = {}
    desc = next((d["value"] for d in cna.get("descriptions", []) if d.get("lang", "").startswith("en")), None)
    if desc:
        out["description"] = desc
    title = cna.get("title")
    if title:
        out["title"] = title
    for metric in cna.get("metrics", []):
        for mk in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
            cvss = metric.get(mk)
            if cvss and cvss.get("baseScore") is not None:
                out["cvss_score"] = cvss.get("baseScore")
                out["cvss_vector"] = cvss.get("vectorString")
                out["severity"] = norm_severity(cvss.get("baseSeverity")) or severity_from_score(cvss.get("baseScore"))
                break
        if out.get("cvss_score") is not None:
            break
    for pt in cna.get("problemTypes", []):
        for d in pt.get("descriptions", []):
            cwe = d.get("cweId") or (d.get("description") if str(d.get("description", "")).startswith("CWE-") else None)
            if cwe:
                out["cwe"] = cwe
                break
        if out.get("cwe"):
            break
    products, versions = [], None
    for aff in cna.get("affected", []):
        prod = aff.get("product")
        vend = aff.get("vendor")
        if prod and prod not in ("n/a", "unspecified"):
            products.append(prod)
            out.setdefault("product", prod)
        if vend and vend not in ("n/a", "unspecified"):
            out.setdefault("vendor", vend)
        for ver in aff.get("versions", []):
            if ver.get("version") and ver.get("version") not in ("n/a", "0"):
                versions = versions or []
                lt = ver.get("lessThan") or ver.get("lessThanOrEqual")
                versions.append(f"{ver['version']} – {lt}" if lt else str(ver["version"]))
    if products:
        out["affected_products"] = list(dict.fromkeys(products))
    if versions:
        out["affected_versions"] = ", ".join(dict.fromkeys(versions))[:200]
    refs = [r["url"] for r in cna.get("references", []) if r.get("url")]
    if refs:
        out["references"] = refs
    sols = [s.get("value") for s in cna.get("solutions", []) if s.get("value")]
    if sols:
        out["solution"] = " ".join(sols)
    # DATE DE PUBLICATION — deux dates coexistent dans un enregistrement CVE, et la
    # distinction n'est pas cosmétique :
    #
    #   « datePublic »    date à laquelle le CNA a DIVULGUÉ la vulnérabilité. C'est celle
    #                     qu'affiche l'avis de l'éditeur, et celle qu'attend un consultant.
    #   « datePublished » date d'ajout de la FICHE au registre CVE, souvent bien plus tard :
    #                     une faille divulguée le 11 peut n'être enregistrée que le 19.
    #
    # Retenir « datePublished » faisait apparaître comme « publiée aujourd'hui » une
    # vulnérabilité connue depuis plus d'une semaine — et contredisait la page officielle.
    # On prend donc la divulgation quand le CNA la déclare, l'enregistrement sinon.
    out["published_at"] = parse_dt(cna.get("datePublic")) or parse_dt(meta.get("datePublished"))
    out["updated_at"] = parse_dt(meta.get("dateUpdated"))
    return {k: v for k, v in out.items() if v not in (None, [], "")}


async def _from_osv(cve_id: str) -> dict:
    resp = await net.get(f"https://api.osv.dev/v1/vulns/{cve_id}")
    if resp is None or resp.status_code != 200:
        return {}
    try:
        data = resp.json()
    except (ValueError, json.JSONDecodeError):
        return {}
    out: dict = {}
    if data.get("summary"):
        out["title"] = data["summary"]
    if data.get("details"):
        out["description"] = data["details"]
    for sev in data.get("severity", []):
        if sev.get("score") and str(sev["score"]).startswith("CVSS"):
            out["cvss_vector"] = sev["score"]
            break
    products, versions, patch_links = [], [], []
    for aff in data.get("affected", []):
        pkg = (aff.get("package") or {}).get("name")
        if pkg:
            products.append(pkg)
        for r in aff.get("ranges", []):
            for ev in r.get("events", []):
                if ev.get("fixed"):
                    versions.append(f"corrigé en {ev['fixed']}")
    if products:
        out["affected_products"] = list(dict.fromkeys(products))
    if versions:
        out["affected_versions"] = ", ".join(dict.fromkeys(versions))[:200]
    refs = [r["url"] for r in data.get("references", []) if r.get("url")]
    if refs:
        out["references"] = refs
    # liens de correctif (advisories/fix)
    for r in data.get("references", []):
        if r.get("type") in ("FIX", "PATCH") and r.get("url"):
            patch_links.append(r["url"])
    if patch_links:
        out["patch_links"] = list(dict.fromkeys(patch_links))
    out["published_at"] = parse_dt(data.get("published"))
    out["updated_at"] = parse_dt(data.get("modified"))
    return {k: v for k, v in out.items() if v not in (None, [], "")}


async def _from_redhat(cve_id: str) -> dict:
    resp = await net.get(f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json")
    if resp is None or resp.status_code != 200:
        return {}
    try:
        data = resp.json()
    except (ValueError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    out: dict = {}
    cvss3 = data.get("cvss3") or {}
    if cvss3.get("cvss3_base_score"):
        try:
            out["cvss_score"] = float(cvss3["cvss3_base_score"])
        except (TypeError, ValueError):
            pass
    if cvss3.get("cvss3_scoring_vector"):
        out["cvss_vector"] = cvss3["cvss3_scoring_vector"]
    if data.get("threat_severity"):
        out["severity"] = norm_severity(data["threat_severity"])
    cwe = data.get("cwe")
    if isinstance(cwe, str):
        m = re.search(r"CWE-\d+", cwe)
        if m:
            out["cwe"] = m.group(0)
    details = data.get("details")
    if isinstance(details, list) and details:
        out["description"] = " ".join(d for d in details if isinstance(d, str))[:2000]
    products, patch_links = [], []
    for ar in data.get("affected_release", []) or []:
        if ar.get("product_name"):
            products.append(ar["product_name"])
        if ar.get("advisory"):
            patch_links.append(f"https://access.redhat.com/errata/{ar['advisory']}")
    if products:
        out["affected_products"] = list(dict.fromkeys(products))
    if patch_links:
        out["patch_links"] = list(dict.fromkeys(patch_links))
    refs = data.get("references")
    if isinstance(refs, list):
        out["references"] = [r for r in refs if isinstance(r, str) and r.startswith("http")]
    elif isinstance(refs, str):
        out["references"] = [u for u in re.split(r"\s+", refs) if u.startswith("http")]
    out["updated_at"] = parse_dt(data.get("public_date"))
    return {k: v for k, v in out.items() if v not in (None, [], "")}


async def _from_github(cve_id: str) -> dict:
    resp = await net.get(f"https://api.github.com/advisories?cve_id={cve_id}&per_page=1")
    if resp is None:
        return {}
    # Quota épuisé (60 req/h sans jeton) : inutile d'insister sur les CVE suivantes.
    if resp.status_code in (403, 429):
        trip("github")
        return {}
    if resp.status_code != 200:
        return {}
    try:
        arr = resp.json()
    except (ValueError, json.JSONDecodeError):
        return {}
    if not isinstance(arr, list) or not arr:
        return {}
    a = arr[0]
    out: dict = {}
    if a.get("summary"):
        out["title"] = a["summary"]
    if a.get("description"):
        out["description"] = a["description"]
    cvss = a.get("cvss") or {}
    if cvss.get("score") is not None:
        out["cvss_score"] = cvss["score"]
    if cvss.get("vector_string"):
        out["cvss_vector"] = cvss["vector_string"]
    if a.get("severity"):
        out["severity"] = norm_severity(a["severity"])
    cwes = a.get("cwes") or []
    if cwes:
        first = cwes[0]
        out["cwe"] = first.get("cwe_id") if isinstance(first, dict) else first
    products, versions = [], []
    for v in a.get("vulnerabilities") or []:
        pkg = (v.get("package") or {}).get("name")
        if pkg:
            products.append(pkg)
        if v.get("vulnerable_version_range"):
            versions.append(v["vulnerable_version_range"])
    if products:
        out["affected_products"] = list(dict.fromkeys(products))
    if versions:
        out["affected_versions"] = ", ".join(dict.fromkeys(versions))[:200]
    refs = [r for r in (a.get("references") or []) if isinstance(r, str)]
    if refs:
        out["references"] = refs
    out["published_at"] = parse_dt(a.get("published_at"))
    out["updated_at"] = parse_dt(a.get("updated_at"))
    return {k: v for k, v in out.items() if v not in (None, [], "")}


_TAG_RE = re.compile(r"<[^>]+>")


def _strip_tags(text):
    if not text:
        return None
    return re.sub(r"\s+", " ", _TAG_RE.sub(" ", str(text))).strip() or None


def _msrc_cwe(d: dict) -> str | None:
    blob = json.dumps(d.get("cweList") or d.get("cweDetailsList") or d.get("cweDetailsListForSearch") or [])
    m = re.search(r"CWE-\d+", blob)
    return m.group(0) if m else None


async def _from_msrc(cve_id: str) -> dict:
    """Microsoft MSRC (éditeur officiel) : titre, description, CWE, produits, dates, correctif.

    L'endpoint par-CVE ne répond que pour les CVE Microsoft (sinon vide) — sans effet ailleurs.
    """
    base = "https://api.msrc.microsoft.com/sug/v2.0/en-US"
    resp = await net.get(f"{base}/vulnerability/{cve_id}")
    if resp is None or resp.status_code != 200:
        return {}
    try:
        d = resp.json()
    except (ValueError, json.JSONDecodeError):
        return {}
    if not isinstance(d, dict) or not d.get("cveNumber"):
        return {}
    out: dict = {"vendor": "Microsoft"}
    if d.get("cveTitle"):
        out["title"] = d["cveTitle"]
    desc = _strip_tags(d.get("description")) or d.get("unformattedDescription")
    if desc:
        out["description"] = desc
    if d.get("vulnType"):
        out["vuln_type"] = d["vulnType"]
    cwe = _msrc_cwe(d)
    if cwe:
        out["cwe"] = cwe
    out["published_at"] = parse_dt(d.get("releaseDate"))
    out["updated_at"] = parse_dt(d.get("latestRevisionDate"))
    refs = []
    if d.get("mitreUrl"):
        refs.append(d["mitreUrl"])
    refs.append(f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}")
    out["references"] = refs
    # Produits affectés + « Corrected Version » (appel best-effort).
    try:
        pr = await net.get(f"{base}/affectedProduct?%24filter=cveNumber+eq+%27{cve_id}%27")
        if pr is not None and pr.status_code == 200:
            vals = (pr.json() or {}).get("value") or []
            products = list(dict.fromkeys(v.get("product") for v in vals if v.get("product")))
            if products:
                out["affected_products"] = products
            fixed = list(dict.fromkeys(str(v["fixedBuildNumber"]) for v in vals if v.get("fixedBuildNumber")))
            if fixed:
                out["affected_versions"] = "Corrigé en build(s) : " + ", ".join(fixed[:6])
            downloads = list(dict.fromkeys(v.get("downloadUrl") for v in vals if v.get("downloadUrl")))
            if downloads:
                out["patch_links"] = downloads[:6]
    except Exception:  # noqa: BLE001
        pass
    return {k: v for k, v in out.items() if v not in (None, [], "")}


# Sources rapides (sans limite de débit stricte) exécutées en parallèle.
_FAST_ENRICHERS = {
    "mitre": _from_mitre,
    "msrc": _from_msrc,
    "osv": _from_osv,
    "redhat": _from_redhat,
    "github": _from_github,
}

# ---------------------------------------------------------------------------------------
# DISJONCTEUR de source saturée
#
# Une API qui a épuisé son quota (GitHub : 60 requêtes/heure sans jeton) répond 403/429 à
# TOUTES les requêtes suivantes. Continuer à l'interroger pour chaque CVE ne rapporte rien
# et coûte un aller-retour réseau à chaque fois — mesuré : 125 appels perdus sur une seule
# collecte. Dès qu'une source se déclare saturée, on la coupe pour le RESTE de l'exécution.
# ---------------------------------------------------------------------------------------
_TRIPPED: set[str] = set()


def trip(source: str) -> None:
    """Coupe une source pour le reste du processus (quota épuisé)."""
    if source not in _TRIPPED:
        _TRIPPED.add(source)
        logging.getLogger("cyberwatch.collection.enrichment").warning(
            "Source « %s » saturée (quota épuisé) : elle est ignorée pour le reste de cette "
            "collecte. Les autres sources continuent normalement.", source)


def reset_breakers() -> None:
    """Réarme tous les disjoncteurs (début d'une nouvelle collecte)."""
    _TRIPPED.clear()


def is_tripped(source: str) -> bool:
    return source in _TRIPPED


# --------------------------------------------------------------------------------------
# Fusion par priorité
# --------------------------------------------------------------------------------------

def _merge(cve_id: str, seed: dict | None, contributions: list[tuple[str, dict]]) -> tuple[dict, list[str]]:
    """Fusionne les contributions (source, champs) selon l'ordre de priorité configuré.

    - Scalaires : la source la PLUS PRIORITAIRE qui fournit une valeur l'emporte.
    - Listes    : union de toutes les sources (chaque valeur appartient bien à cette CVE).
    """
    record = new_record(cve_id)
    # La graine (données de collecte de la source admin) participe avec la priorité « source ».
    contribs = list(contributions)
    if seed:
        contribs.append(("source", {k: seed.get(k) for k in _SCALAR_FIELDS + LIST_FIELDS if seed.get(k)}))
    # Ordre : de la MOINS prioritaire à la PLUS prioritaire -> la plus prioritaire écrase.
    ordered = sorted(contribs, key=lambda c: _priority_index(c[0]), reverse=True)

    for _src, part in ordered:
        for key in _SCALAR_FIELDS:
            if part.get(key) not in (None, "", []):
                record[key] = part[key]

    # DATE DE PUBLICATION : la PLUS ANCIENNE des sources d'autorité, et non celle de la
    # source la mieux classée.
    #
    # Les sources ne répondent pas à la même question. NVD et MITRE datent l'entrée de la
    # fiche dans LEUR registre ; le CNA date la DIVULGATION. Pour une faille Microsoft
    # divulguée le 11 et enregistrée le 19, l'ordre de priorité retenait le 19 — la fiche
    # annonçait « publiée aujourd'hui » une vulnérabilité vieille de huit jours, en
    # contradiction directe avec l'avis officiel.
    #
    # Une vulnérabilité ne peut pas avoir été publiée APRÈS avoir été rendue publique : la
    # plus ancienne date crédible est donc la bonne. C'est la règle déjà appliquée au
    # stockage, ici étendue à la fusion.
    candidates = [part["published_at"] for _s, part in contribs
                  if isinstance(part.get("published_at"), datetime)
                  and part["published_at"].replace(tzinfo=None) >= _CVE_ERA_START]
    if candidates:
        record["published_at"] = min(candidates, key=lambda d: d.replace(tzinfo=None))
    # Listes : union sur toutes les contributions.
    for key in LIST_FIELDS:
        merged: list = []
        for _src, part in contribs:
            for v in (part.get(key) or []):
                # Certaines sources concatènent plusieurs URL dans une seule entrée : on les sépare.
                items = re.split(r"\s+", v) if (key in ("references", "patch_links") and isinstance(v, str) and " http" in v) else [v]
                for it in items:
                    it = it.strip()
                    if it and it not in merged:
                        merged.append(it)
        if merged:
            record[key] = merged

    if record.get("cvss_score") is not None and not record.get("severity"):
        record["severity"] = severity_from_score(record["cvss_score"])
    record["detail_url"] = seed.get("detail_url") if seed else record["detail_url"]

    confirmed = [src for src, part in contributions if part]

    # Conserver TOUTES les pages où la CVE est référencée : URL canonique par source confirmée
    # + CVE.org + la page de la source admin qui l'a trouvée.
    canonical = [f"https://www.cve.org/CVERecord?id={cve_id}"]
    if "nvd" in confirmed:
        canonical.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")
    if "msrc" in confirmed:
        canonical.append(f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}")
    if seed and seed.get("detail_url"):
        canonical.append(seed["detail_url"])
    refs = list(record.get("references") or [])
    for u in canonical:
        if u not in refs:
            refs.append(u)
    record["references"] = refs

    return record, confirmed


async def enrich(cve_id: str, seed: dict | None = None, use_nvd: bool = True) -> tuple[dict, list[str]]:
    """Interroge plusieurs sources officielles pour cette CVE et renvoie (fiche fusionnée,
    liste des sources ayant confirmé la CVE)."""
    # 1) Sources rapides en parallèle.
    actifs = {n: fn for n, fn in _FAST_ENRICHERS.items() if not is_tripped(n)}
    results = await asyncio.gather(*[fn(cve_id) for fn in actifs.values()], return_exceptions=True)
    contributions: list[tuple[str, dict]] = []
    for name, res in zip(actifs.keys(), results):
        if isinstance(res, dict) and res:
            contributions.append((name, res))

    # 2) NVD (source PRIORITAIRE, mais limitée en débit).
    #    - use_nvd=True  : on interroge NVD systématiquement (ex. enrichissement à l'ouverture
    #      d'une CVE) afin d'appliquer sa priorité sur description / CVSS / dates.
    #    - use_nvd=False : collecte en masse -> on n'appelle NVD que si le CVSS manque (perf).
    have_cvss = any(part.get("cvss_score") is not None for _n, part in contributions)
    if use_nvd or not have_cvss:
        try:
            nvd = await _from_nvd(cve_id)
            if nvd:
                contributions.append(("nvd", nvd))
        except Exception:  # noqa: BLE001
            pass

    merged, confirmed = _merge(cve_id, seed, contributions)
    return merged, confirmed
