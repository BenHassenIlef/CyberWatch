"""Crawler d'avis (advisories) pour les portails CERT qui utilisent un identifiant d'AVIS
au lieu d'un identifiant CVE sur la page de liste.

Cas type : ANCS / tunCERT — la page de liste ne contient que des références comme
« tunCERT/Vuln.2026-454 » ; les vrais CVE ne figurent que sur la page de détail, dans la
section « Identificants du problème ».

Fonctionnement (générique, réutilisable pour d'autres CERT) :
  1. Parcourt la pagination de la page de liste (?page=0,1,2…).
  2. Détecte chaque avis (lien de détail + identifiant d'avis) — même sans CVE.
  3. Ouvre chaque page de détail (rendu navigateur si nécessaire).
  4. Extrait les champs (dates, produit, éditeur, impact, versions, plateforme, solution,
     description, références) par étiquettes (dt/dd, th/td, « Label : valeur »).
  5. Extrait TOUS les CVE de la section « Identificants du problème » (ou de la page).
  6. Produit :
       - si l'avis a des CVE : un enregistrement PAR CVE, lié à l'identifiant d'avis ;
       - sinon : un enregistrement « avis seul » (clé = identifiant d'avis).
Aucune donnée inventée : un champ absent reste None.
"""
import hashlib
import html as _html
import logging
import re
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from app.backend.services.collection import dedup, net, structure_detector
from app.backend.services.collection.schema import CVE_RE, add_source, new_record, parse_dt
from app.backend.services.verification import browser_client

logger = logging.getLogger("cyberwatch.collection.advisory")

# Identifiant d'avis d'un CERT (tunCERT/Vuln.2026-454, CERT-XX/Vuln.2026-12…). Réutilisable.
ADVISORY_ID_RE = re.compile(r"\b(?:[A-Za-z]{2,8}CERT|CERT[-/]?[A-Za-z]{0,4})\s*/\s*Vuln\.?\s*\d{4}-\d+\b", re.IGNORECASE)
_HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")
# Chemin d'une page de DÉTAIL d'avis (générique, multi-CERT). Source unique de vérité :
# le détecteur de structure (réutilisé par la vérification). Ex. /fr/bulletins/<slug>…
_ADVISORY_PATH_RE = structure_detector.ADVISORY_PATH_RE
# RACCOURCI (pas une condition) : portails d'avis déjà connus, routés sans échantillonnage.
# La détection GÉNÉRIQUE (structure_detector) prend en charge tout autre site sans code dédié ;
# ce set n'est qu'une optimisation facultative — le vider ne casse PAS la détection.
PORTAL_DOMAINS = {"ancs.tn", "tuncert.tn", "dgssi.gov.ma"}


def _is_portal_host(host: str | None) -> bool:
    h = (host or "").lower().lstrip(".")
    return any(h == d or h.endswith("." + d) for d in PORTAL_DOMAINS)


def is_known_portal_host(host: str | None) -> bool:
    """Raccourci public : l'hôte est-il un portail d'avis connu (route directe, sans échantillon) ?"""
    return _is_portal_host(host)

MAX_PAGES = 12          # nb max de pages de liste parcourues
MAX_ADVISORIES = 80     # nb max d'avis traités par exécution
# Budget temps interne (s) : le pipeline coupe une source à SOURCE_TIMEOUT=90 s ; on s'arrête
# AVANT (avis traités du plus récent au plus ancien) pour renvoyer un résultat PARTIEL plutôt
# que de déclencher le timeout et de tout perdre. Les nouveaux avis (en tête de liste) sont
# donc toujours captés ; le reste est repris à l'exécution suivante (dédup -> pas de doublon).
CRAWL_TIME_BUDGET = 110.0
# Domaines à exclure des références (réseaux sociaux / navigation, pas des sources d'avis).
_SOCIAL = ("facebook.", "twitter.", "x.com", "linkedin.", "youtube.", "instagram.", "t.me", "whatsapp.")

# Étiquettes reconnues (multilingue FR/EN), par champ canonique.
FIELD_LABELS = {
    "published_at": ["date de publication", "publié le", "date de création", "créé le", "date", "published", "release date"],
    "updated_at": ["dernière mise à jour", "date de mise à jour", "mis à jour le", "modifié le", "updated", "last updated"],
    "product": ["produits affectés", "produits concernés", "produit", "logiciels affectés", "affected products", "product"],
    "vendor": ["éditeur", "editeur", "fournisseur", "constructeur", "vendor"],
    "impact": ["impact", "conséquences", "consequences"],
    "affected_versions": ["versions affectées", "versions concernées", "versions vulnérables", "affected versions"],
    "fixed_version": ["versions corrigées", "version corrigée", "correctifs", "correctif", "fixed version", "patched"],
    "platform": ["plateformes", "plateforme", "systèmes affectés", "systèmes", "platform", "os"],
    "solution": ["solutions", "solution", "recommandations", "recommandation", "mesures", "remédiation", "remediation"],
    "description": ["description", "résumé", "resume", "synthèse", "summary"],
    "title": ["titre", "objet", "title"],
}
# Section contenant les CVE (ANCS : « Identificants du problème » ; maCERT : « Identificateurs externes »).
CVE_SECTION_LABELS = [
    "identificateurs externes", "identifiants externes", "external identifiers",
    "identificants du problème", "identifiants du problème", "identifiant du problème",
    "identifiants cve", "références cve", "cve", "problem identifiers", "identifiers",
]


def _clean(html: str | None) -> str | None:
    if not html:
        return None
    txt = re.sub(r"\s+", " ", _TAG_RE.sub(" ", html)).strip()
    return txt or None


# --------------------------------------------------------------------------------------
# Extraction de champs par étiquette (plusieurs stratégies de mise en forme)
# --------------------------------------------------------------------------------------

def _dt_dd(html: str, label: str):
    m = re.search(rf"<dt[^>]*>\s*{re.escape(label)}\s*:?\s*</dt>\s*<dd[^>]*>(.*?)</dd>", html, re.I | re.S)
    return _clean(m.group(1)) if m else None


def _th_td(html: str, label: str):
    m = re.search(rf"<t[hd][^>]*>\s*{re.escape(label)}\s*:?\s*</t[hd]>\s*<td[^>]*>(.*?)</td>", html, re.I | re.S)
    return _clean(m.group(1)) if m else None


def _inline(html: str, label: str):
    # « <strong>Label :</strong> valeur » ou « Label : valeur » jusqu'au prochain saut/bloc.
    m = re.search(
        rf"{re.escape(label)}\s*:?\s*</[^>]+>\s*(.*?)(?:<br|</p>|</div>|</li>|<strong|<dt|<th|$)",
        html, re.I | re.S,
    )
    if m and _clean(m.group(1)):
        return _clean(m.group(1))[:600]
    m = re.search(rf"{re.escape(label)}\s*:\s*(.*?)(?:<br|</p>|</div>|</li>|\n|$)", html, re.I | re.S)
    return (_clean(m.group(1))[:600] if m and _clean(m.group(1)) else None)


def _field(html: str, labels: list[str]):
    for lab in labels:
        for strat in (_dt_dd, _th_td, _inline):
            val = strat(html, lab)
            if val:
                return val
    return None


def _extract_cves(html: str) -> list[str]:
    """CVE de la section « Identificants du problème » ; à défaut, de toute la page."""
    low = html.lower()
    for lab in CVE_SECTION_LABELS:
        i = low.find(lab)
        if i != -1:
            seg = html[i: i + 1500]
            ids = list(dict.fromkeys(m.group(0).upper() for m in CVE_RE.finditer(seg)))
            if ids:
                return ids
    return list(dict.fromkeys(m.group(0).upper() for m in CVE_RE.finditer(html)))


def _advisory_id(html: str, url: str) -> str | None:
    m = ADVISORY_ID_RE.search(html) or ADVISORY_ID_RE.search(url)
    if not m:
        return None
    return re.sub(r"\s+", "", m.group(0))  # « tunCERT/Vuln.2026-454 »


# --------------------------------------------------------------------------------------
# Analyse par LIGNES du texte rendu (robuste pour les portails type Drupal : ANCS…)
#   Structure « étiquette » puis « valeur(s) » sur les lignes suivantes.
# --------------------------------------------------------------------------------------

# Étiquette (minuscule) -> champ canonique. Réutilisable / extensible pour d'autres CERT.
LABEL_MAP = {
    "titre": "title", "objet": "title", "title": "title",
    "refer": "advisory_id", "référence": "advisory_id", "reference": "advisory_id",
    "numéro de référence": "advisory_id", "numero de reference": "advisory_id",
    "n° de référence": "advisory_id", "n°de référence": "advisory_id",
    "date de publication": "published_at", "publié le": "published_at", "published": "published_at",
    "date version": "updated_at", "dernière mise à jour": "updated_at", "mis à jour le": "updated_at",
    # maCERT distingue « Niveau de Risque » (criticité) et « Niveau d'Impact ».
    "niveau de risque": "risk_level", "niveau de gravité": "risk_level", "criticité": "risk_level",
    "risk level": "risk_level",
    # « Impact » = description des conséquences (ANCS) ; « Risque » = liste des conséquences (DGSSI).
    "impact": "impact", "risque": "impact", "risques": "impact",
    "description du risque": "impact", "risk": "impact", "risk description": "impact",
    # Le NIVEAU d'impact (« Critique »…) est un niveau, PAS une description -> champ séparé.
    "niveau d'impact": "impact_level", "niveau d’impact": "impact_level", "impact level": "impact_level",
    "plateforme": "platform", "plate-forme": "platform",
    # maCERT : « Systèmes affectés » = liste produits + versions -> bloc dédié.
    "systèmes affectés": "affected_block", "systemes affectes": "affected_block",
    "systèmes": "affected_block", "affected systems": "affected_block",
    "produits impactés": "product", "produits affectés": "product", "produits concernés": "product", "produit": "product",
    "versions corrigées": "fixed_version", "version corrigée": "fixed_version", "correctif": "fixed_version",
    "identificants du problème": "cve_block", "identifiants du problème": "cve_block",
    "identificateurs externes": "cve_block", "identifiants externes": "cve_block",
    "external identifiers": "cve_block", "identifiants cve": "cve_block", "cve": "cve_block",
    "bilan de la vulnérabilité": "description", "bilan": "description",
    "résumé de la vulnérabilité": "description", "vulnerability summary": "description",
    "solution vulnérabilités": "solution", "solution": "solution", "solutions": "solution",
    "recommandation": "solution", "recommandations": "solution",
    "source d'information": "references_block", "sources d'information": "references_block", "références": "references_block",
}
# Correspondance « niveau de risque » (FR) -> sévérité canonique (fallback avant enrichissement NVD).
_RISK_SEVERITY = {
    "critique": "critical", "critical": "critical",
    "élevé": "high", "eleve": "high", "élevée": "high", "haut": "high", "important": "high", "high": "high",
    "moyen": "medium", "moyenne": "medium", "modéré": "medium", "modere": "medium", "medium": "medium",
    "faible": "low", "bas": "low", "low": "low",
}
# Lignes qui terminent une valeur (autres étiquettes + pied de page / navigation).
_FOOTER = {
    "version", "adresse", "téléphone", "telephone", "email", "e-mail", "pied de page",
    "aller au contenu principal", "fil d'ariane", "select your language", "déclarer un incident",
    "l'ancs", "tuncert", "actualités", "accueil",
}


def _to_text_lines(html: str) -> list[str]:
    """Approxime `innerText` : convertit les blocs en sauts de ligne puis retire les balises."""
    h = re.sub(r"(?i)<(?:br|/p|/div|/li|/h[1-6]|/tr|/dt|/dd|/td|/th|/section|/article)[^>]*>", "\n", html)
    h = re.sub(r"<[^>]+>", " ", h)
    h = _html.unescape(h)
    out = []
    for raw in h.split("\n"):
        line = re.sub(r"\s+", " ", raw).strip()
        if line:
            out.append(line)
    return out


def _norm(line: str) -> str:
    return line.strip().lower().rstrip(":").strip()


def _parse_lines(lines: list[str]) -> dict:
    """Associe chaque étiquette connue aux lignes de valeur qui la suivent."""
    stop = set(LABEL_MAP) | _FOOTER
    out: dict[str, list[str]] = {}
    i = 0
    while i < len(lines):
        key = _norm(lines[i])
        if key in LABEL_MAP:
            field = LABEL_MAP[key]
            vals, j = [], i + 1
            while j < len(lines) and _norm(lines[j]) not in stop:
                vals.append(lines[j].strip())
                j += 1
            if vals and field not in out:
                out[field] = vals
            i = j
        else:
            i += 1
    return out


def _title(html: str) -> str | None:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if m:
        t = _html.unescape(re.sub(r"\s+", " ", m.group(1))).strip()
        return t.split("|")[0].strip() or None  # « Node.js | ANCS » -> « Node.js »
    return None


def _meta_description(html: str) -> str | None:
    m = re.search(r'<meta[^>]+(?:name|property)=["\'](?:description|og:description)["\'][^>]+content=["\']([^"\']+)["\']',
                  html, re.I)
    return _html.unescape(m.group(1)).strip() if m else None


def _description_from_lines(lines: list[str]) -> str | None:
    """La description est le paragraphe précédant l'étiquette « REFER » (ou la plus longue ligne)."""
    for idx, ln in enumerate(lines):
        if _norm(ln) in ("refer", "référence", "reference"):
            for k in range(idx - 1, max(idx - 5, -1), -1):
                cand = lines[k].strip()
                if len(cand) > 40 and _norm(cand) not in _FOOTER:
                    return cand
            break
    longs = [l for l in lines if len(l) > 60 and _norm(l) not in _FOOTER and not l.startswith("http")]
    return longs[0] if longs else None


# --------------------------------------------------------------------------------------
# Récupération réseau (avec repli navigateur pour les pages dynamiques)
# --------------------------------------------------------------------------------------

# Délai court du sondage httpx : certains portails (DGSSI…) font PENDRE la connexion ~28 s
# avant d'échouer ; on échoue vite pour basculer sans attendre sur le rendu navigateur.
FETCH_HTTP_TIMEOUT = 8.0


async def _fetch(url: str, expect_cve: bool = True, session=None) -> str:
    """Récupère le HTML d'une page (rendu navigateur si le contenu est dynamique).

    `expect_cve` : pour une page de DÉTAIL d'avis, on attend l'apparition des CVE au rendu ;
    pour une page de LISTE (sans CVE), on ne l'attend pas (rendu plus rapide).
    `session` : session de rendu RÉUTILISABLE (un seul navigateur pour tout le crawl) ; si None,
    un navigateur éphémère est utilisé.
    """
    resp = await net.get(url, timeout=FETCH_HTTP_TIMEOUT)
    body = resp.text if (resp is not None and resp.status_code == 200) else ""
    if not (ADVISORY_ID_RE.search(body) or CVE_RE.search(body) or "<article" in body.lower()):
        if session is not None:
            rendered = await session.render(url, wait_for_cve=expect_cve)
        else:
            rendered = await browser_client.render_html(url, wait_for_cve=expect_cve)
        body = rendered or body
    return body


def _with_page(url: str, page: int) -> str:
    parts = urlparse(url)
    q = parse_qs(parts.query)
    q["page"] = [str(page)]
    return urlunparse(parts._replace(query=urlencode({k: v[-1] for k, v in q.items()})))


def _advisory_links(body: str, base_url: str, host: str) -> list[str]:
    """Liens vers les pages de détail d'avis.

    Délègue au détecteur de structure GÉNÉRIQUE (enfant de la page liste, motif « rubrique
    d'avis », ou ancre « en savoir plus »), afin qu'une seule logique host-agnostique serve à
    la fois au routage, à l'échantillonnage et au crawl — aucun code par site.
    """
    return structure_detector.candidate_links(body, base_url, host)


# --------------------------------------------------------------------------------------
# Construction des enregistrements
# --------------------------------------------------------------------------------------

def parse_advisory(html: str, url: str) -> dict:
    """Extrait tous les champs d'une page de détail d'avis CERT.

    Stratégie principale : analyse par LIGNES du texte rendu (étiquette -> valeur), robuste
    pour ANCS/Drupal. Fallback : extraction HTML par étiquettes (dt/dd, th/td) pour d'autres CERT.
    """
    lines = _to_text_lines(html)
    f = _parse_lines(lines)
    host = (urlparse(url).hostname or "")

    def _join(field, sep=" "):
        return sep.join(f[field]).strip() if f.get(field) else None

    adv: dict = {"advisory_url": url}
    adv["advisory_id"] = (f["advisory_id"][0].strip() if f.get("advisory_id") else None) or _advisory_id(html, url)
    adv["published_at"] = parse_dt(f["published_at"][0]) if f.get("published_at") else None
    adv["updated_at"] = parse_dt(f["updated_at"][0]) if f.get("updated_at") else None
    adv["impact"] = _join("impact", " ; ")
    # Niveau de risque (maCERT) -> sévérité canonique (repli avant enrichissement NVD).
    risk = _join("risk_level")
    adv["risk_level"] = risk
    adv["severity"] = _RISK_SEVERITY.get(risk.strip().lower()) if risk else None
    # « Systèmes affectés » (maCERT) : liste produits/versions ; sinon « Plateforme » (ANCS).
    affected = list(f.get("affected_block") or [])
    adv["platform"] = _join("platform") or (affected[0] if affected else None)
    adv["affected_systems"] = affected
    product_block = _join("product")
    adv["product"] = _title(html) or product_block        # ANCS : titre = produit (Node.js…)
    adv["affected_versions"] = product_block or (" ; ".join(affected) if affected else None)
    adv["fixed_version"] = _join("fixed_version")
    adv["solution"] = _join("solution")
    adv["title"] = (f["title"][0].strip() if f.get("title") else None) or _title(html)
    adv["description"] = _join("description") or _description_from_lines(lines) or _meta_description(html)
    adv["vendor"] = None                               # non exposé par ANCS/maCERT (complété par NVD/MITRE)

    # CVE : de la section « Identificants du problème » (ligne), sinon de la page.
    cves = []
    if f.get("cve_block"):
        cves = list(dict.fromkeys(m.group(0).upper() for m in CVE_RE.finditer(" ".join(f["cve_block"]))))
    if not cves:
        cves = _extract_cves(html)
    adv["cves"] = cves

    # Références : URLs de la section « Source d'information » (les vraies sources de l'avis),
    # + liens externes de la page en excluant les réseaux sociaux / la navigation.
    refs: list[str] = []
    for ln in f.get("references_block", []):
        for m in re.finditer(r"https?://[^\s\"'<>]+", ln):
            if m.group(0) not in refs:
                refs.append(m.group(0))
    for href in _HREF_RE.findall(html):
        h = (urlparse(href).hostname or "").lower()
        if href.startswith("http") and h != host and not any(x in h for x in _SOCIAL) and href not in refs:
            refs.append(href)
    adv["references"] = refs[:12]

    # Fallback HTML pour les champs restés vides (autres portails CERT).
    for field, labels in FIELD_LABELS.items():
        if not adv.get(field):
            val = _field(html, labels)
            if val:
                adv[field] = parse_dt(val) if field in ("published_at", "updated_at") else val
    return adv


def _apply_common(rec: dict, adv: dict, source: dict) -> None:
    rec["description"] = adv.get("description")
    rec["product"] = adv.get("product")
    rec["vendor"] = adv.get("vendor")
    rec["impact"] = adv.get("impact")
    if adv.get("severity"):
        rec["severity"] = adv["severity"]              # criticité maCERT (repli avant NVD)
    rec["affected_versions"] = adv.get("affected_versions")
    if adv.get("affected_systems"):
        rec["affected_systems"] = list(adv["affected_systems"])
    rec["fixed_version"] = adv.get("fixed_version")
    rec["platform"] = adv.get("platform")
    rec["solution"] = adv.get("solution")
    rec["published_at"] = adv.get("published_at")
    rec["updated_at"] = adv.get("updated_at")
    rec["advisory_id"] = adv.get("advisory_id")
    if adv.get("advisory_id"):
        rec["advisory_ids"] = [adv["advisory_id"]]
    refs = list(adv.get("references") or [])
    if adv.get("advisory_url") and adv["advisory_url"] not in refs:
        refs.append(adv["advisory_url"])
    rec["references"] = refs
    rec["detail_url"] = adv.get("advisory_url")
    rec["data_origin"] = "CERT advisory"
    add_source(rec, source)


def advisory_to_records(adv: dict, source: dict) -> list[dict]:
    """Un avis -> un enregistrement par CVE liée, ou un enregistrement « avis seul »."""
    cves = adv.get("cves") or []
    out: list[dict] = []
    if cves:
        for cid in cves:
            rec = new_record(cid)
            _apply_common(rec, adv, source)
            rec["associated_cves"] = cves  # toutes les CVE de l'avis (traçabilité)
            rec["title"] = adv.get("title") or f"{cid} — {adv.get('advisory_id') or 'avis CERT'}"
            out.append(rec)
    elif adv.get("advisory_id"):
        # Avis sans CVE : on le conserve quand même (information de sécurité utile).
        rec = new_record(adv["advisory_id"])
        rec["cve_id"] = adv["advisory_id"]  # garde la casse d'origine de l'identifiant d'avis
        rec["is_advisory"] = True
        _apply_common(rec, adv, source)
        rec["title"] = adv.get("title") or adv["advisory_id"]
        out.append(rec)
    return out


# --------------------------------------------------------------------------------------
# Point d'entrée : crawl d'un portail d'avis
# --------------------------------------------------------------------------------------

def looks_like_advisory_portal(body: str, host: str | None = None) -> bool:
    """Faut-il router cette source vers le crawler d'avis ?

    Vrai si l'hôte est un portail d'avis connu (maCERT, ANCS…) OU si la page de liste expose
    des identifiants d'avis tunCERT sans aucun CVE (un avis = plusieurs CVE sur la page détail).
    """
    if _is_portal_host(host):
        return True
    return bool(ADVISORY_ID_RE.search(body)) and not CVE_RE.search(body)


# File de RE-SYNCHRONISATION par ÂGE (comme OpenCVE) : plus un bulletin est récent, plus on le
# revérifie souvent (les éditeurs enrichissent leurs avis des heures/jours après publication).
def _sync_interval_priority(published_at) -> tuple[timedelta, int]:
    now = datetime.utcnow()
    pub = published_at
    if isinstance(pub, datetime):
        if pub.tzinfo is not None:
            pub = pub.replace(tzinfo=None)
        age = now - pub
    else:
        age = timedelta(0)
    if age <= timedelta(hours=24):
        return timedelta(hours=1), 1     # 0-24 h : toutes les heures
    if age <= timedelta(days=7):
        return timedelta(hours=6), 2     # 1-7 j : toutes les 6 h
    if age <= timedelta(days=30):
        return timedelta(days=1), 3      # 7-30 j : une fois par jour
    return timedelta(days=7), 4          # > 30 j : une fois par semaine


def _naive(dt):
    if isinstance(dt, datetime) and dt.tzinfo is not None:
        return dt.replace(tzinfo=None)
    return dt


def _bulletin_hash(adv: dict) -> str:
    """Empreinte du CONTENU d'un bulletin (points 3-5) : change si des CVE sont ajoutées/retirées
    ou si les champs clés sont modifiés → sert à détecter une mise à jour / republication."""
    payload = "|".join([
        ";".join(sorted(adv.get("cves") or [])),
        (adv.get("title") or "").strip(),
        (adv.get("severity") or "") or "",
        (adv.get("solution") or "").strip(),
        (adv.get("impact") or "").strip(),
    ])
    return hashlib.sha1(payload.encode("utf-8", "ignore")).hexdigest()


async def _load_fingerprints(db, source_id) -> dict:
    if db is None:
        return {}
    docs = await db.bulletin_fingerprints.find({"source_id": source_id}).to_list(5000)
    return {d["url"]: d for d in docs}


async def crawl_report(source: dict, since) -> dict:
    """Crawl deux niveaux AVEC empreintes de bulletins (idempotent) et métriques détaillées.

    - Chaque bulletin est identifié par une EMPREINTE de contenu. S'il est INCHANGÉ, on le saute
      (traitement idempotent). S'il est NOUVEAU ou MODIFIÉ (CVE ajoutées, republié…), on le
      (re)traite — jamais ignoré à cause d'une date de publication « ancienne ».
    - Réachabilité : si la page LISTE est totalement injoignable → `SourceUnreachable` (à
      ré-essayer). Reçue mais aucun bulletin analysable → `SourceParseError`. Reçue et rien de
      neuf → succès « vide ».
    """
    import time
    from app.backend.db.mongodb import get_database
    from app.backend.services.collection.collectors.base import SourceParseError, SourceUnreachable

    db = get_database()
    deadline = time.monotonic() + CRAWL_TIME_BUDGET
    rep: dict = {"records": [], "list_pages": 0, "bulletin_links": 0, "details_crawled": 0,
                 "cve_extracted": 0, "duplicates_removed": 0, "errors": [],
                 "bulletins_new": 0, "bulletins_updated": 0, "bulletins_unchanged": 0,
                 "list_unknown": 0, "boundary_reached": False}
    base = source.get("url") or source.get("api_endpoint") or ""
    if not base:
        rep["errors"].append("URL de source vide.")
        return rep
    host = (urlparse(base).hostname or "").lower()
    fingerprints = await _load_fingerprints(db, source.get("_id"))
    # BORD « CONNU » : URL des bulletins DÉJÀ enregistrés en base (empreintes). Sert à arrêter la
    # pagination dès qu'une page n'apporte plus AUCUN bulletin inconnu → collecte incrémentale
    # quotidienne SANS re-parcourir l'historique (le rattrapage continue tant qu'il y a du nouveau).
    known_urls = set(fingerprints)
    reached = False

    async with browser_client.RenderSession() as session:
        advisory_urls: list[str] = []
        if _ADVISORY_PATH_RE.search(urlparse(base).path):
            advisory_urls.append(f"{urlparse(base).scheme}://{urlparse(base).netloc}{urlparse(base).path}")

        for page in range(MAX_PAGES):
            if time.monotonic() > deadline:
                break
            listing = _with_page(base, page)
            try:
                body = await _fetch(listing, expect_cve=False, session=session)
            except Exception as exc:  # noqa: BLE001
                rep["errors"].append(f"page liste {page} ({listing}) : {str(exc)[:100]}")
                break
            rep["list_pages"] += 1
            if not body:
                break
            reached = True
            links = _advisory_links(body, listing, host)
            new_links = [u for u in links if u not in advisory_urls]
            advisory_urls.extend(new_links)
            # Bulletins de cette page ENCORE INCONNUS de la base (jamais enregistrés).
            unknown_to_db = [u for u in links if u not in known_urls]
            rep["list_unknown"] += len(unknown_to_db)
            logger.info("[advisory] %s : page liste %d → %d lien(s) (%d inconnu(s) de la base, total %d).",
                        host, page, len(new_links), len(unknown_to_db), len(advisory_urls))
            if len(advisory_urls) >= MAX_ADVISORIES:
                break
            if not new_links:
                break  # plus aucun lien nouveau dans le crawl (fin de la pagination du site)
            # ARRÊT AU BORD CONNU : cette page n'apporte AUCUN bulletin inconnu de la base. En run
            # NORMAL on s'arrête ici (pas de re-parcours de l'historique) ; en run de RATTRAPAGE,
            # tant que des bulletins inconnus apparaissent (jours manqués), on continue page+1.
            if not unknown_to_db:
                rep["boundary_reached"] = True
                logger.info("[advisory] %s : page %d entièrement connue → bord atteint, arrêt pagination.",
                            host, page)
                break
        rep["bulletin_links"] = len(advisory_urls)

        records: list[dict] = []
        all_cves: set[str] = set()
        fp_writes: list = []
        for url in advisory_urls[:MAX_ADVISORIES]:
            if time.monotonic() > deadline:
                logger.info("[advisory] %s : budget temps atteint après %d/%d bulletin(s) (partiel).",
                            host, rep["details_crawled"], len(advisory_urls))
                rep["errors"].append(f"budget temps atteint ({rep['details_crawled']}/{len(advisory_urls)}).")
                break
            try:
                prev = fingerprints.get(url)
                now = datetime.utcnow()
                # FILE DE RE-SYNCHRO PAR ÂGE : on ne re-télécharge PAS un bulletin pas encore « dû ».
                if prev and prev.get("next_sync_at") and _naive(prev["next_sync_at"]) > now:
                    rep["skipped_not_due"] = rep.get("skipped_not_due", 0) + 1
                    continue
                html = await _fetch(url, expect_cve=True, session=session)
                if html:
                    reached = True
                adv = parse_advisory(html, url)
                rep["details_crawled"] += 1
                new_hash = _bulletin_hash(adv)
                interval, priority = _sync_interval_priority(adv.get("published_at"))
                sched = {"next_sync_at": now + interval, "sync_priority": priority,
                         "last_sync": now, "retry_count": 0}
                if prev and prev.get("hash") == new_hash:
                    rep["bulletins_unchanged"] += 1
                    fp_writes.append((url, sched))  # inchangé : on reprogramme juste la prochaine synchro
                    continue
                # NOUVEAU ou MODIFIÉ (l'EMPREINTE prime sur l'horodatage « Updated » du site) → (re)traitement.
                recs = advisory_to_records(adv, source)
                records.extend(recs)
                all_cves.update(adv.get("cves") or [])
                if prev:
                    rep["bulletins_updated"] += 1
                    logger.info("[advisory] %s : bulletin MODIFIÉ %s (%d→%d CVE) → retraité.",
                                host, adv.get("advisory_id") or url, prev.get("cve_count", 0), len(adv.get("cves") or []))
                else:
                    rep["bulletins_new"] += 1
                fp_writes.append((url, {
                    "source_id": source.get("_id"), "bulletin_id": adv.get("advisory_id"), "url": url,
                    "publication_date": adv.get("published_at"), "hash": new_hash,
                    "cve_count": len(adv.get("cves") or []), "processed_at": _now_utc(), **sched,
                }))
            except Exception as exc:  # noqa: BLE001 - un avis illisible n'interrompt pas le crawl
                rep["errors"].append(f"{url} : {str(exc)[:100]}")
                logger.error("[advisory] échec parsing %s : %s", url, str(exc)[:100])

    # Persistance des empreintes (nouvelles / modifiées).
    if db is not None and fp_writes:
        for url, doc in fp_writes:
            await db.bulletin_fingerprints.update_one(
                {"_id": f"{source.get('_id')}::{url}"},
                {"$set": doc, "$setOnInsert": {"first_seen": _now_utc()}}, upsert=True)

    # Classification de réachabilité (le nombre de CVE ne détermine PAS l'échec).
    if not reached:
        raise SourceUnreachable(f"portail {host} injoignable (aucune page récupérée).")
    # Portail d'avis CONNU atteint mais AUCUN bulletin : structure changée/bloquée -> SUSPECT.
    # Pour un site générique mal classé « deux niveaux » (liste plate type cvefind), on renvoie
    # vide sans erreur : le collecteur HTML bascule alors sur la collecte simple (harvest de CVE).
    if rep["bulletin_links"] == 0:
        if is_known_portal_host(host):
            raise SourceParseError(f"{host} : page liste atteinte mais AUCUN bulletin détecté "
                                   f"(structure changée / contenu bloqué ?).")
        rep["records"] = []
        return rep
    if rep["details_crawled"] == 0 and rep["errors"] and is_known_portal_host(host):
        raise SourceParseError(f"{host} : {rep['bulletin_links']} bulletin(s) mais aucun analysable.")

    rep["cve_extracted"] = len(all_cves)
    before = len(records)
    unique = dedup.deduplicate(records)
    rep["duplicates_removed"] = before - len(unique)
    rep["records"] = unique
    logger.info("[advisory] %s : %d liste, %d bulletin(s) (%d nouveau(x), %d modifié(s), %d inchangé(s)), "
                "%d détail(s), %d CVE, %d erreur(s).",
                host, rep["list_pages"], rep["bulletin_links"], rep["bulletins_new"],
                rep["bulletins_updated"], rep["bulletins_unchanged"], rep["details_crawled"],
                rep["cve_extracted"], len(rep["errors"]))
    return rep


def _now_utc():
    from app.backend.utils import utcnow
    return utcnow()


async def crawl(source: dict, since) -> list[dict]:
    """Parcourt le portail (pagination), ouvre chaque avis, en extrait CVE + métadonnées."""
    return (await crawl_report(source, since))["records"]
