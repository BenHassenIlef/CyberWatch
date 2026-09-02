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
import json
import re
from datetime import datetime, timedelta, timezone

from app.backend.services.assistant import llm
from app.backend.services.collection import advisory_bulletin as ab
from app.backend.services.collection import monitored, remediation

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
_SEV_FR_LABEL = {"critical": "critique", "high": "élevée", "medium": "moyenne",
                 "low": "faible"}

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


class PeriodeInvalide(ValueError):
    """Bornes de période incohérentes (début postérieur à la fin)."""


def periode_match(debut, fin) -> dict:
    """Filtre MongoDB d'une période explicite [début, fin], bornes INCLUSES.

    Une CVE entre dans la période si elle y a été PUBLIÉE **ou** si CyberWatch l'y a
    DÉTECTÉE. Les deux dates restent strictement distinctes en base — on ne recopie jamais
    l'une dans l'autre — mais une vulnérabilité publiée la semaine dernière et découverte
    ce matin intéresse le consultant aujourd'hui : l'exclure lui ferait manquer l'essentiel.

    La borne de fin est portée à 23:59:59 pour que le jour choisi soit compté en entier ;
    sans cela, « du 18 au 20 » s'arrêtait à minuit le 20 et perdait toute la journée.
    """
    if debut and fin and debut > fin:
        raise PeriodeInvalide("La date de début est postérieure à la date de fin.")
    bornes: dict = {}
    if debut:
        bornes["$gte"] = debut
    if fin:
        bornes["$lte"] = fin.replace(hour=23, minute=59, second=59, microsecond=999999)
    if not bornes:
        return {}
    return {"$or": [{"published_at": bornes}, {"collected_at": bornes}]}


def _match_periode_ou_jours(debut, fin, days: int) -> dict:
    """Période explicite si fournie, sinon fenêtre glissante (compatibilité ascendante)."""
    return periode_match(debut, fin) if (debut or fin) else _recent_match(days)


async def _monitored_names(db) -> set[str]:
    """Noms des produits ACTUELLEMENT surveillés (activés, dans un domaine activé).

    Relu à chaque appel : un produit ajouté ou retiré dans « Produits surveillés » est
    répercuté immédiatement sur cette page, sans redémarrage.
    """
    domaines_off = [d["name"] async for d in db.domains.find({"enabled": False}, {"name": 1})]
    q: dict = {"enabled": {"$ne": False}}
    if domaines_off:
        q["domain"] = {"$nin": domaines_off}
    return {d["name"] async for d in db.monitored_products.find(q, {"name": 1}) if d.get("name")}


# --------------------------------------------------------------------------------------
# Résumé RÉDIGÉ par le modèle (ancré : uniquement les faits agrégés du bulletin)
# --------------------------------------------------------------------------------------

_SUMMARY_SYSTEM = (
    "Tu es un analyste cybersécurité qui rédige la synthèse d'un bulletin de sécurité en "
    "FRANÇAIS.\n"
    "RÈGLES ABSOLUES :\n"
    "- Tu t'appuies EXCLUSIVEMENT sur les faits JSON fournis ; tu n'ajoutes aucune "
    "information.\n"
    "- Tu n'inventes ni score CVSS, ni version, ni date, ni identifiant, ni correctif.\n"
    "- Identifiants (CVE-…, CWE-…), noms de produits et versions sont recopiés à "
    "l'identique.\n"
    "- Tu écris 4 à 6 phrases, sans titre, sans puces, sans formule d'introduction.\n"
    "- Tu ne répètes pas la liste des CVE. Registre professionnel et sobre, jamais "
    "alarmiste.\n"
    # Le résumé doit tenir lieu de lecture rapide du bulletin ENTIER : sans cette consigne,
    # le modèle s'en tenait au volume et aux risques, laissant de côté la remédiation, les
    # dates et la source — précisément ce qu'un consultant vérifie avant d'agir.
    "- Tu couvres, dans cet ordre : le produit et le nombre de failles, la sévérité et le "
    "score maximal, la nature des risques, les systèmes concernés, la remédiation, les "
    "dates de publication et de révision, enfin la source officielle.\n"
    # Une donnée absente n'est pas une donnée négative : l'affirmer serait une faute.
    "- Si « remediation » indique que l'information n'a pas pu être extraite, tu l'écris "
    "ainsi : tu n'affirmes JAMAIS qu'aucun correctif n'existe.\n"
    "- Tu termines TOUJOURS par une phrase achevée, ponctuation comprise ; jamais un "
    "fragment."
)


def _summary_facts(b: dict) -> dict:
    """Faits STRICTEMENT issus de l'agrégation — rien d'autre n'est transmis au modèle."""
    vulns = b.get("vulnerabilities") or []
    types: list[str] = []
    for v in vulns:
        t = (v.get("vulnerability_type") or "").strip()
        if t and t not in types:
            types.append(t)
    return {
        "produit_surveille": b.get("vendor"),
        "nombre_de_cve": b.get("cve_count"),
        "severite_maximale": _SEV_FR_LABEL.get(b.get("severity"), b.get("severity")),
        "score_cvss_maximal": b.get("cvss_score"),
        "risques_identifies": (b.get("risk") or [])[:6],
        "types_de_vulnerabilite": types[:6],
        "systemes_affectes": (b.get("affected_systems") or [])[:6],
        "correctif_disponible": bool(b.get("solution")),
        "remediation": (b.get("solution") or b.get("solution_message")),
        "date_de_publication": b.get("publication_date"),
        "derniere_mise_a_jour": b.get("update_date"),
        "source_officielle": (b.get("official_source") or {}).get("name"),
        "cve_les_plus_graves": [v.get("cve_id") for v in vulns[:5] if v.get("cve_id")],
    }


def _phrase_complete(texte: str) -> str | None:
    """Texte ramene a sa DERNIERE PHRASE ACHEVEE, ou None s il n en contient aucune.

    Un modele a raisonnement depense des jetons avant d ecrire : arrive au plafond, il
    s interrompt en pleine phrase. Le bulletin affichait alors « Elles impactent Oracle
    Database » — une phrase coupee net, dans un document destine a etre transmis. On coupe
    donc proprement au dernier point plutot que de publier un fragment.
    """
    texte = (texte or "").strip()
    if not texte:
        return None
    if texte[-1] in ".!?»":
        return texte
    coupe = max(texte.rfind(". "), texte.rfind(".\n"))
    return texte[:coupe + 1].strip() if coupe > 40 else None


async def generate_ai_summary(b: dict) -> tuple[str, str]:
    """Résumé du bulletin produit. Renvoie (texte, origine).

    origine = "llm" si le modèle a rédigé, "deterministe" en repli. Le repli n'est PAS un
    échec : il garantit qu'un bulletin reste exploitable même sans modèle configuré ou en
    cas de dépassement de quota.
    """
    deterministe = ab.generate_summary(b)
    if not llm.available():
        return deterministe, "deterministe"
    prompt = (
        "Faits agrégés d'un bulletin de sécurité (base CyberWatch AI) :\n\n"
        + json.dumps(_summary_facts(b), ensure_ascii=False, indent=2, default=str)
        + "\n\nRédige la synthèse de ce bulletin en respectant les règles."
    )
    try:
        # Budget large : ce modele depense des jetons en raisonnement AVANT d ecrire, si
        # bien qu un plafond serre tronquait la synthese au milieu d une phrase.
        texte = await llm.generate(prompt, system=_SUMMARY_SYSTEM, max_tokens=1200)
    except Exception:  # noqa: BLE001 - un bulletin ne doit jamais échouer à cause du modèle
        texte = None
    texte = _phrase_complete(texte) if texte else None
    if not texte or len(texte) < 40:
        return deterministe, "deterministe"
    return texte, "llm"


# --------------------------------------------------------------------------------------
# Liste des bulletins produit (cartes de synthèse)
# --------------------------------------------------------------------------------------

async def list_product_bulletins(db, days: int = DEFAULT_DAYS, severity: str | None = None,
                                 q: str | None = None, skip: int = 0, limit: int = 20,
                                 debut=None, fin=None) -> dict:
    # PÉRIMÈTRE : on ne regroupe que les CVE rattachées à un PRODUIT SURVEILLÉ. Le regroupement
    # se fait donc par produit suivi (et non par éditeur) : la page reflète exactement la liste
    # « Produits surveillés », sans y mêler d'éditeurs qu'on ne suit pas.
    match = {"monitored_products": {"$exists": True, "$ne": []},
             **_match_periode_ou_jours(debut, fin, days)}
    if q:
        match["monitored_products"] = {"$regex": re.escape(q), "$options": "i"}
    pipeline = [
        {"$match": match},
        {"$unwind": "$monitored_products"},
        {"$group": {
            "_id": "$monitored_products",
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
    noms_actifs = set(await _monitored_names(db))
    for g in groups:
        # Un produit retiré de la surveillance disparaît de la page, sans que ses CVE
        # historiques ne soient supprimées de la base.
        if g["_id"] not in noms_actifs:
            continue
        max_sev = _max_severity(g["severities"])
        if severity and max_sev != severity:
            continue
        cards.append({
            "vendor": g["_id"],
            "vendor_key": monitored.slug(g["_id"]),
            "publisher": _vendor_display(g["vendor_sample"]) if g.get("vendor_sample") else None,
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


async def build_product_bulletin(db, vendor_key: str, days: int = DEFAULT_DAYS,
                                 debut=None, fin=None) -> dict | None:
    """Construit le bulletin GROUPÉ d'un éditeur (structure SecurityBulletin), à partir des CVE
    déjà en base. Aucune information inventée : uniquement l'agrégation des champs collectés."""
    # `vendor_key` est le slug d'un PRODUIT SURVEILLÉ (ex. « google-chrome »). On le résout
    # vers son nom exact via les produits actifs, puis on cible les CVE qui lui sont rattachées.
    noms = await _monitored_names(db)
    produit = next((n for n in noms if monitored.slug(n) == vendor_key.lower()), None)
    if produit is None:
        return None
    # Éditeur DÉCLARÉ sur le produit surveillé. On ne le déduit surtout pas d'une CVE : le champ
    # `vendor` d'une CVE rattachée à « Google Chrome » peut valoir « Microsoft » (cas Edge /
    # Chromium), ce qui désignerait le mauvais portail de sécurité.
    fiche_produit = await db.monitored_products.find_one({"name": produit}, {"vendor": 1})
    editeur = (fiche_produit or {}).get("vendor") or None
    docs = await db.cves.find(
        {"monitored_products": produit, **_match_periode_ou_jours(debut, fin, days)},
    ).sort("published_at", -1).to_list(MAX_CVES_PER_BULLETIN)
    if not docs:
        return None

    vendor = produit
    vulns, all_cves, refs, systems, products, risks, solutions, sevs, cvsss, dates = (
        [], [], [], [], [], [], [], [], [], [])
    revisions = []   # dates de REVISION des CVE du bulletin
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
        if c.get("updated_at"):
            revisions.append(c["updated_at"])
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
        # UNE LIGNE = UNE CVE, avec SES PROPRES valeurs.
        #
        # Chaque champ est lu sur `c`, jamais sur une agrégation du bulletin. Les rubriques
        # groupées plus bas (systèmes affectés, risque, solution du produit) sont une SYNTHÈSE
        # destinée à l'en-tête ; les reporter sur une ligne donnerait à une vulnérabilité les
        # attributs d'une autre — un consultant appliquerait le correctif du voisin.
        vulns.append({
            "cve_id": cid,
            "cvss_score": c.get("cvss_score"),
            "severity": c.get("severity"),
            "description": _cap(c.get("description"), 400),
            "vulnerability_type": c.get("vuln_type") or c.get("cwe"),
            "affected_versions": _cap(c.get("affected_versions") or ", ".join(c.get("affected_products") or []), 120),
            "solution": _cap(sol, 300),
            "references": _union((c.get("references") or []) + [f"https://www.cve.org/CVERecord?id={cid}"], 6),
            # DEUX DATES DISTINCTES, jamais confondues : la publication officielle de la CVE,
            # et le moment où CyberWatch l'a détectée. L'une ne remplace jamais l'autre.
            "published_at": c.get("published_at"),
            # DERNIÈRE MISE À JOUR de la CVE chez l'autorité qui la publie (MITRE/NVD) —
            # une TROISIÈME date, à ne confondre ni avec la publication, ni avec la
            # détection. Une vulnérabilité révisée voit son score ou son correctif changer
            # sans être republiée : c'est cette date qui le signale au consultant.
            "updated_at": c.get("updated_at"),
            "detected_at": c.get("collected_at"),
            "impact": _cap(c.get("impact"), 300),
            "affected_systems": [s for s in (c.get("affected_systems") or []) if s][:6],
            "affected_products": [p for p in (c.get("affected_products") or []) if p][:6],
            # État du champ « Solution » PROPRE à cette CVE : une information absente ne doit
            # pas se lire comme l'absence de correctif.
            "solution_status": remediation.etat(c),
            "solution_message": remediation.MESSAGES.get(remediation.etat(c)),
            # Site officiel de CETTE vulnérabilité, déduit de SES références et de SON éditeur.
            "official_source": ab.site_officiel(c.get("references"), c.get("vendor"),
                                                [c.get("product")] if c.get("product") else None),
        })

    max_sev = _max_severity(sevs)
    products_u = _union(products, 12) or ab._products_from_systems(systems)
    bulletin = {
        "bulletin_id": f"PROD-{vendor_key.upper()}",
        "product_name": f"Produits {vendor}",
        "vendor": vendor,
        "title": f"Vulnérabilités dans les produits {vendor}",
        "publication_date": (max(dates).isoformat() if dates and hasattr(max(dates), "isoformat") else None),
        # La revision la PLUS RECENTE parmi les CVE du bulletin : elle indique depuis quand
        # l ensemble n a plus bouge. Chaque ligne du tableau garde par ailleurs SA propre date.
        "update_date": (max(revisions).isoformat()
                        if revisions and hasattr(max(revisions), "isoformat") else None),
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
    # SOURCE OFFICIELLE — un bulletin produit agrège N CVE : désigner l'avis de L'UNE d'elles
    # serait arbitraire, et la fiche CVE.org ne dit rien du produit. La source officielle d'un
    # bulletin PRODUIT est donc le PORTAIL DE SÉCURITÉ DE SON ÉDITEUR (MSRC, Red Hat Product
    # Security, Fortinet PSIRT…). Ce n'est jamais l'URL où CyberWatch a découvert l'information :
    # celle-ci reste isolée dans `collection_source`.
    bulletin["official_source"] = ab.product_official_source(
        produit, editeur, bulletin["references"])
    bulletin["official_url"] = bulletin["official_source"]["url"]
    # SOURCE DE COLLECTE : sans objet ici (agrégation interne de CVE déjà collectées), mais le
    # champ est présent pour que les deux notions restent explicitement distinctes côté API.
    bulletin["collection_source"] = {"name": "Base CyberWatch AI (agrégation)", "url": None}

    # Résumé analyste : rédigé par le modèle à partir des faits agrégés, repli déterministe.
    bulletin["ai_summary"], bulletin["summary_origin"] = await generate_ai_summary(bulletin)
    bulletin["summary"] = bulletin["ai_summary"]
    bulletin["schema_version"] = ab.BULLETIN_SCHEMA_VERSION
    return bulletin
