"""Bulletins de sécurité GROUPÉS PAR PRODUIT / ÉDITEUR (vue « CERT »).

Transforme la liste de CVE (déjà collectées, enrichies et dédupliquées) en bulletins
professionnels regroupés par éditeur : « Vulnérabilités dans les produits Mozilla » listant
toutes les CVE récentes de Mozilla, avec systèmes affectés, sévérité, solution, références.

Choix d'architecture (non destructif) :
- On NE modifie PAS le schéma : les bulletins sont construits À LA LECTURE par agrégation de la
  collection `cves` (regroupement par éditeur normalisé, fenêtre récente, borné). La collecte,
  le planificateur, la déduplication par `cve_id` et les vues par CVE restent inchangés.
- On réutilise le moteur de bulletin existant (`advisory_bulletin`) pour le résumé analyste et
  l'extraction de produits.
"""
import re
from datetime import datetime, timedelta, timezone

from app.backend.services.collection import advisory_bulletin as ab

# Normalisation d'éditeur : fusion des casses et alias courants ; exclusion du bruit.
_VENDOR_ALIASES = {
    "apple": "Apple", "chrome": "Google Chrome", "google chrome": "Google Chrome",
    "microsoft": "Microsoft", "mozilla": "Mozilla", "red hat": "Red Hat", "redhat": "Red Hat",
    "ibm": "IBM", "php": "PHP", "f5": "F5", "vmware": "VMware", "gitlab": "GitLab",
    "node.js": "Node.js", "nodejs": "Node.js", "wordpress": "WordPress", "cisco": "Cisco",
    "adobe": "Adobe", "oracle": "Oracle", "google": "Google", "linux": "Linux",
    "apache software foundation": "Apache", "apache": "Apache", "php group": "PHP",
    "the php group": "PHP", "fortinet": "Fortinet", "sap": "SAP", "atlassian": "Atlassian",
}
_NOISE_VENDORS = {"", "n/a", "na", "none", "null", "unknown", "inconnu", "autres", "other", "-"}

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# Dérivation du RISQUE / IMPACT (FR) depuis le texte des descriptions et les CWE (déterministe,
# sans invention : uniquement si le motif apparaît réellement dans les données collectées).
_IMPACT_PATTERNS = [
    (r"remote code execution|arbitrary code|\brce\b|code arbitraire|exécution de code", "Exécution de code arbitraire à distance"),
    (r"denial of service|\bdos\b|déni de service", "Déni de service"),
    (r"information disclosure|sensitive (information|data)|data exposure|divulgation|fuite d", "Divulgation d'informations sensibles"),
    (r"privilege escalation|elevation of privilege|escalade de privil|élévation de privil", "Élévation de privilèges"),
    (r"cross-site scripting|\bxss\b", "Injection de scripts (XSS)"),
    (r"sql injection|injection sql", "Injection SQL"),
    (r"server-side request forgery|\bssrf\b", "Falsification de requêtes côté serveur (SSRF)"),
    (r"authentication bypass|security bypass|contournement", "Contournement de la politique de sécurité"),
    (r"spoofing|usurpation", "Usurpation d'identité"),
    (r"buffer overflow|out-of-bounds|dépassement de tampon|hors limites", "Corruption de mémoire"),
]
_CWE_IMPACT = {
    "CWE-79": "Injection de scripts (XSS)", "CWE-89": "Injection SQL", "CWE-352": "Falsification de requête (CSRF)",
    "CWE-918": "Falsification de requêtes côté serveur (SSRF)", "CWE-22": "Traversée de répertoire",
    "CWE-787": "Écriture hors limites (corruption mémoire)", "CWE-125": "Lecture hors limites",
    "CWE-862": "Contournement d'autorisation", "CWE-287": "Contournement d'authentification",
    "CWE-269": "Élévation de privilèges", "CWE-400": "Déni de service (épuisement de ressources)",
    "CWE-502": "Désérialisation non sécurisée", "CWE-94": "Injection de code",
}


def _derive_risks(vulns: list[dict]) -> list[str]:
    found: list[str] = []
    for v in vulns:
        blob = " ".join(x for x in (v.get("description"), v.get("impact"), v.get("vulnerability_type")) if x).lower()
        for cwe in re.findall(r"CWE-\d+", (v.get("vulnerability_type") or "").upper()):
            lab = _CWE_IMPACT.get(cwe)
            if lab and lab not in found:
                found.append(lab)
        for pat, lab in _IMPACT_PATTERNS:
            if re.search(pat, blob) and lab not in found:
                found.append(lab)
    return found[:8]
DEFAULT_DAYS = 45          # fenêtre par défaut : « nouvelles » vulnérabilités par produit
MAX_CVES_PER_BULLETIN = 80  # borne d'un bulletin produit


def _vendor_key(v) -> str | None:
    if not v:
        return None
    low = str(v).strip().lower()
    return None if low in _NOISE_VENDORS else low


def _vendor_display(v) -> str:
    low = str(v).strip().lower()
    if low in _VENDOR_ALIASES:
        return _VENDOR_ALIASES[low]
    # Garde les acronymes en majuscules (IBM), capitalise sinon (« mozilla » -> « Mozilla »).
    return v.strip() if (v.isupper() or " " in v.strip()) else v.strip()[:1].upper() + v.strip()[1:]


def _max_severity(sevs) -> str | None:
    best, rank = None, 0
    for s in sevs or []:
        r = _SEV_RANK.get((s or "").lower(), 0)
        if r > rank:
            rank, best = r, (s or "").lower()
    return best


def _cutoff(days: int) -> datetime:
    return datetime.utcnow() - timedelta(days=days)


def _recent_match(days: int) -> dict:
    """Récence tolérante (published_at OU collected_at récent ; les deux peuvent manquer)."""
    c = _cutoff(days)
    return {"$or": [{"published_at": {"$gte": c}}, {"collected_at": {"$gte": c}}]}


# --------------------------------------------------------------------------------------
# Liste des bulletins produit (cartes de synthèse)
# --------------------------------------------------------------------------------------

async def list_product_bulletins(db, days: int = DEFAULT_DAYS, severity: str | None = None,
                                 q: str | None = None, skip: int = 0, limit: int = 20) -> dict:
    match = {"vendor": {"$nin": [None, ""]}, **_recent_match(days)}
    if q:
        match["vendor"] = {"$regex": re.escape(q), "$options": "i"}
    pipeline = [
        {"$match": match},
        {"$group": {
            "_id": {"$toLower": "$vendor"},
            "vendor_sample": {"$first": "$vendor"},
            "cves": {"$addToSet": "$cve_id"},
            "products": {"$addToSet": "$product"},
            "severities": {"$addToSet": "$severity"},
            "max_cvss": {"$max": "$cvss_score"},
            "latest": {"$max": "$published_at"},
            "latest_collected": {"$max": "$collected_at"},
        }},
    ]
    groups = [g async for g in db.cves.aggregate(pipeline)]
    cards = []
    for g in groups:
        if _vendor_key(g["_id"]) is None:
            continue
        max_sev = _max_severity(g["severities"])
        if severity and max_sev != severity:
            continue
        cards.append({
            "vendor": _vendor_display(g["vendor_sample"]),
            "vendor_key": g["_id"],
            "cve_count": len(g["cves"]),
            "products": sorted(p for p in g["products"] if p)[:6],
            "severity": max_sev,
            "cvss_score": g.get("max_cvss"),
            "latest": g.get("latest") or g.get("latest_collected"),
        })
    # Tri : sévérité décroissante puis nb de CVE.
    cards.sort(key=lambda c: (_SEV_RANK.get(c["severity"] or "", 0), c["cve_count"]), reverse=True)
    total = len(cards)
    return {"total": total, "items": cards[skip: skip + limit]}


# --------------------------------------------------------------------------------------
# Bulletin produit détaillé (structure SecurityBulletin)
# --------------------------------------------------------------------------------------

def _cap(text, n: int):
    """Tronque un champ texte trop long (protège contre des champs bruités en base)."""
    if not text:
        return text
    t = str(text).strip()
    return t if len(t) <= n else t[:n].rstrip() + "…"


def _union(seq, cap=25):
    out, seen = [], set()
    for x in seq:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
        if len(out) >= cap:
            break
    return out


async def build_product_bulletin(db, vendor_key: str, days: int = DEFAULT_DAYS) -> dict | None:
    """Construit le bulletin GROUPÉ d'un éditeur (structure SecurityBulletin), à partir des CVE
    déjà en base. Aucune information inventée : uniquement l'agrégation des champs collectés."""
    docs = await db.cves.find(
        {"$expr": {"$eq": [{"$toLower": {"$ifNull": ["$vendor", ""]}}, vendor_key.lower()]},
         **_recent_match(days)},
    ).sort("published_at", -1).to_list(MAX_CVES_PER_BULLETIN)
    if not docs:
        return None

    vendor = _vendor_display(docs[0].get("vendor") or vendor_key)
    vulns, all_cves, refs, systems, products, risks, solutions, sevs, cvsss, dates = (
        [], [], [], [], [], [], [], [], [], [])
    for c in docs:
        cid = c.get("cve_id")
        if not cid:
            continue
        all_cves.append(cid)
        sevs.append(c.get("severity"))
        if c.get("cvss_score") is not None:
            cvsss.append(c["cvss_score"])
        if c.get("published_at"):
            dates.append(c["published_at"])
        # Systèmes affectés = NOMS de produits propres (pas les vidages de versions CPE de NVD,
        # illisibles). On garde les libellés courts (produits, lignes d'avis CERT).
        for p in (c.get("affected_products") or []):
            if p and len(p) <= 60:
                products.append(p)
                systems.append(p)
        for s in (c.get("affected_systems") or []):
            if s and len(s) <= 120 and s.count(",") <= 3:  # exclut les longues plages CPE
                systems.append(s)
        for r in (c.get("references") or []):
            if r and len(r) <= 300:
                refs.append(r)
        refs.append(f"https://www.cve.org/CVERecord?id={cid}")
        if c.get("impact"):
            risks.extend(ab._bullets(c["impact"]))
        sol = c.get("solution")
        if sol and len(sol) <= 400:   # ignore les champs « solution » anormalement volumineux
            solutions.append(sol)
        vulns.append({
            "cve_id": cid,
            "cvss_score": c.get("cvss_score"),
            "severity": c.get("severity"),
            "description": _cap(c.get("description"), 400),
            "vulnerability_type": c.get("vuln_type") or c.get("cwe"),
            "affected_versions": _cap(c.get("affected_versions") or ", ".join(c.get("affected_products") or []), 120),
            "solution": _cap(sol, 300),
            "references": _union((c.get("references") or []) + [f"https://www.cve.org/CVERecord?id={cid}"], 6),
            "published_at": c.get("published_at"),
        })

    max_sev = _max_severity(sevs)
    products_u = _union(products, 12) or ab._products_from_systems(systems)
    bulletin = {
        "bulletin_id": f"PROD-{vendor_key.upper()}",
        "product_name": f"Produits {vendor}",
        "vendor": vendor,
        "title": f"Vulnérabilités dans les produits {vendor}",
        "publication_date": (max(dates).isoformat() if dates and hasattr(max(dates), "isoformat") else None),
        "cves": all_cves,
        "cve_count": len(all_cves),
        "severity": max_sev,
        "cvss_score": max(cvsss) if cvsss else None,
        "products": products_u,
        "affected_systems": _union(systems, 15),
        "risk": _union(risks + _derive_risks(vulns), 8),
        "summary": None,
        "solution": (solutions[0] if solutions
                     else f"Appliquer sans délai les derniers correctifs de sécurité publiés par {vendor}."),
        "references": _union(refs, 30),
        "language": "fr",
        "vulnerabilities": vulns,   # structure SecurityBulletin.vulnerabilities[]
    }
    # SOURCE OFFICIELLE : un bulletin produit n'a pas de page d'avis d'origine (il agrège N CVE
    # d'un même éditeur). On désigne donc la meilleure source officielle présente dans l'union
    # des références — avis éditeur en priorité, sinon autorité publique, sinon fiche CVE.org.
    bulletin["official_source"] = ab.official_source(bulletin["references"], vendor,
                                                     products_u, all_cves)
    bulletin["official_url"] = bulletin["official_source"]["url"]
    # SOURCE DE COLLECTE : sans objet ici (agrégation interne de CVE déjà collectées), mais le
    # champ est présent pour que les deux notions restent explicitement distinctes côté API.
    bulletin["collection_source"] = {"name": "Base CyberWatch AI (agrégation)", "url": None}

    # Résumé analyste (déterministe, FR) — réutilise le moteur existant ; point d'extension LLM.
    bulletin["ai_summary"] = ab.generate_summary(bulletin)
    bulletin["summary"] = bulletin["ai_summary"]
    bulletin["schema_version"] = ab.BULLETIN_SCHEMA_VERSION
    return bulletin
