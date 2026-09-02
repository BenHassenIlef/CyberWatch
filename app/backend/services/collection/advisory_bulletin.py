"""Moteur GÉNÉRIQUE de génération de bulletins de sécurité normalisés.

À partir de N'IMPORTE QUELLE page d'avis (DGSSI, ANCS, CERT-FR, CISA, MSRC, Cisco, Red Hat,
VMware…), produit un modèle interne UNIFIÉ (même schéma quelle que soit la source), sans
sélecteurs codés par site :

  Phase 1 — Analyse    : langue, titre, date, référence, sévérité, impact, systèmes affectés,
                         identifiants (CVE/GHSA), remédiation, références, PDF éventuels.
                         (réutilise l'extraction sémantique multilingue de `advisory.parse_advisory`)
  Phase 2 — Normalisation : conversion vers un schéma JSON commun.
  Phase 3 — Complétion : champs manquants complétés depuis les CVE déjà enrichies en base,
                         sinon en direct via NVD/MITRE/éditeurs (enrichment.enrich).
  Phase 4 — Résumé      : résumé professionnel concis (déterministe, FR/EN ; brancher un LLM ici
                         si disponible).
  Phase 5 — Rendu       : le front rend ce modèle au format « Bulletin Advancia » (+ export PDF).

PDF : si l'avis pointe un PDF, son TEXTE est extrait (pypdf) et fusionné à la page HTML. L'OCR
(images scannées) est un point d'extension optionnel (non requis ici).
"""
import asyncio
import io
import logging
import re
from urllib.parse import urljoin, urlparse

from app.backend.services.collection import enrichment, net, remediation, sanitize
from app.backend.services.collection.collectors import advisory
from app.backend.services.collection.schema import CVE_RE, parse_dt
from app.backend.services.verification import metadata_extraction
from app.backend.utils import utcnow

logger = logging.getLogger("cyberwatch.collection.bulletin")

# Identifiants externes (au-delà des CVE) : avis GitHub (GHSA). Extensible (CSAF, VU#, etc.).
GHSA_RE = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.IGNORECASE)
_ARABIC_RE = re.compile(r"[؀-ۿ]")
_PDF_RE = re.compile(r'href=["\']([^"\']+\.pdf(?:\?[^"\']*)?)["\']', re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")

_SEV_FR = {"critical": "critiques", "high": "élevées", "medium": "moyennes", "low": "faibles"}
_SEV_FR_SINGULIER = {"critical": "critique", "high": "élevée", "medium": "moyenne",
                     "low": "faible"}
# Mots de NIVEAU (pas de vraies descriptions d'impact) à ne PAS présenter comme « risque ».
_SEV_WORDS = {"critique", "critiques", "élevé", "élevée", "eleve", "elevee", "haut", "haute",
              "moyen", "moyenne", "faible", "important", "importante",
              "critical", "high", "medium", "moderate", "low", "severe"}

MAX_ENRICH_SAMPLE = 3   # nb de CVE interrogées en direct pour agréger CVSS/vendor/type (perf)
MAX_PDF = 2             # nb de PDF joints analysés

# Version du MODÈLE de bulletin. À incrémenter dès que la structure change : les bulletins mis
# en cache dans `bulletins` (TTL 24 h) portant une version antérieure sont alors reconstruits
# automatiquement, sans purge manuelle de la collection.
#   2 = source officielle distincte de la source de collecte ; « Vecteur d'attaque » et
#       « Référence de l'avis » retirés ; résumé toujours en français.
#   3 = un champ « produit » pollué (titre de page, nom de base publique) ne peut plus faire
#       passer une base pour l'éditeur — l'avis de l'éditeur reprend la priorité.
#   4 = le bulletin s'aligne sur la FICHE CVE : une valeur inexploitable extraite de la page de
#       collecte (titre de page, message de redirection) ne masque plus la donnée enrichie.
#   5 = filtres étendus aux pages d'erreur HTTP, aux fragments de code (CSS/JS/JSON-LD) et aux
#       titres de rubrique de portail (« Newest CVEs »).
#   6 = la CVE d'origine est toujours listée (page injoignable comprise) ; le champ « Solution »
#       est filtré comme les autres textes.
# v7 : la fiche verifiee prime sur la page de collecte (editeur, produit, resume,
# references), le bulletin ne porte plus que SA CVE, la source officielle ne peut plus
# renvoyer vers une autre vulnerabilite, et les liens d habillage sont ecartes.
# Incrementer ce numero INVALIDE les bulletins deja en cache, qui portent l ancienne faute.
# v8 : la page de COLLECTE ne peut plus etre presentee comme source officielle (la regle
# etait documentee mais l URL ne parvenait jamais a la fonction) ; la navigation du portail
# de collecte et les racines de sites sortent des references ; la date de la fiche prime.
# v9 : le PDF joint n injecte plus les identifiants d autres vulnerabilites ; un editeur
# porte par la fiche n est plus remplace par celui lu sur la page ; les textes du bulletin
# passent par le filtre commun (un menu ne peut plus s afficher comme remediation).
# v10 : « Site officiel » designe desormais l EDITEUR du produit vulnerable — son avis de
# securite, sinon son portail, sinon son domaine. Une base de vulnerabilites (NVD, CVE.org,
# avis GitHub, agregateur) ne peut plus y figurer : elle reste en « References ». Sans
# editeur verifiable, le champ affiche « Non identifie » plutot qu une adresse plausible.
# v11 : le champ « Solution / Correctif » porte son ETAT (solution_status). Une fiche sans
# remediation ne declare plus qu il n en existe pas : elle distingue l information manquante
# d une absence constatee apres lecture des pages officielles.
# v12 : le bulletin porte « Derniere mise a jour » (update_date), date de REVISION de la
# fiche chez l autorite qui la publie — distincte de sa publication et de sa collecte.
# v13 : « Resume » est desormais REDIGE a partir des faits du bulletin (gravite, score,
# nature, portee, remediation, dates, source) au lieu de recopier la description technique.
# Celle-ci reste disponible dans le modele, sous sa propre cle.
# Passee de 13 a 14 : la SOURCE OFFICIELLE etait mal resolue.
# Un champ « produit » contenant « Linux Mac OS Windows » attribuait kernel.org a
# une vulnerabilite Google Chrome, et un editeur nomme par son PRODUIT (« Chrome »
# au lieu de « Google ») rendait l'avis officiel introuvable. Les bulletins deja en
# cache portent ces erreurs : la version force leur reconstruction.
BULLETIN_SCHEMA_VERSION = 14


# --------------------------------------------------------------------------------------
# Phase 1 — helpers d'analyse (génériques, multilingues)
# --------------------------------------------------------------------------------------

# Blocs dont le CONTENU n'est pas du texte de page. `_TAG_RE` retire les balises mais laisse
# ce qu'elles entourent : sans ce nettoyage préalable, le code d'un portail moderne (Oracle,
# NVD…) se retrouvait en tête du texte extrait et occupait tout le budget de lecture — la page
# paraissait alors « sans information exploitable » alors que l'avis était bien là, plus bas.
_NON_TEXTE_RE = re.compile(r"<(script|style|noscript|template|svg)\b[^>]*>.*?</\1\s*>",
                           re.I | re.S)


def _text(html: str) -> str:
    return re.sub(r"\s+", " ", _TAG_RE.sub(" ", _NON_TEXTE_RE.sub(" ", html or ""))).strip()


def detect_language(text: str) -> str:
    """Langue dominante : ar (script arabe), sinon fr/en par mots-outils. Générique."""
    sample = text[:6000]
    if _ARABIC_RE.search(sample):
        return "ar"
    low = sample.lower()
    fr = sum(low.count(w) for w in (" le ", " la ", " les ", " des ", " une ", " dans ",
                                    "vulnérab", "affect", "sécurité", "correctif"))
    en = sum(low.count(w) for w in (" the ", " and ", " with ", " allows ", " affected ",
                                    "vulnerab", "security", "update", "patch"))
    return "fr" if fr >= en else "en"


def extract_identifiers(text: str) -> dict:
    """Tous les identifiants externes présents (CVE robuste + GHSA). Extensible."""
    cve = list(dict.fromkeys(m.group(0).upper() for m in CVE_RE.finditer(text or "")))
    ghsa = list(dict.fromkeys(m.group(0).upper() for m in GHSA_RE.finditer(text or "")))
    return {"cve": cve, "ghsa": ghsa}


def extract_pdf_links(html: str, base_url: str) -> list[str]:
    out: list[str] = []
    for m in _PDF_RE.finditer(html or ""):
        u = urljoin(base_url, m.group(1))
        if u not in out:
            out.append(u)
    return out[:5]


async def _pdf_text(url: str) -> str:
    """Extrait le TEXTE d'un PDF d'avis (pypdf). Best-effort ; renvoie '' en cas d'échec."""
    try:
        resp = await net.get(url, timeout=25)
        if not resp or resp.status_code != 200 or not resp.content:
            return ""
        import pypdf
        reader = pypdf.PdfReader(io.BytesIO(resp.content))
        return "\n".join((page.extract_text() or "") for page in reader.pages[:20])
    except Exception as exc:  # noqa: BLE001 - PDF illisible : on continue avec le HTML seul
        logger.warning("[bulletin] extraction PDF %s : %s", url, str(exc)[:90])
        return ""


def _date_iso(valeur):
    """Date au format ISO, quelle que soit sa forme d origine (datetime ou chaine)."""
    if not valeur:
        return None
    if hasattr(valeur, "isoformat"):
        return valeur.isoformat()
    analysee = parse_dt(str(valeur))
    return analysee.isoformat() if analysee else None


def _bullets(value) -> list[str]:
    if isinstance(value, list):
        items = [v for v in value if v]
    elif not value:
        items = []
    else:
        parts = re.split(r"\s*[;•\n]\s*|\.\s+(?=[A-ZÀ-Ý])", str(value))
        items = [p.strip().rstrip(".") for p in parts if p.strip()]
    # Écarte les simples mots de niveau (« Critique », « High »…) : ce ne sont pas des risques.
    return [i for i in items if i.strip().lower() not in _SEV_WORDS]


# --------------------------------------------------------------------------------------
# Phase 3 — complétion des champs manquants
# --------------------------------------------------------------------------------------

# Un « vendor » qui contient ces termes est en réalité une description de risque -> rejeté.
_BAD_VENDOR = ("élévation", "elevation", "privilèg", "privileg", "déni", "denial", "exécution",
               "execution", "contournement", "bypass", "injection", "dépassement", "overflow",
               "divulgation", "disclosure", "cross-site", "traversal", "spoofing", "vulnérab")


# Textes renvoyés par une page NON RENDUE (coquille récupérée avant exécution du JavaScript) ou
# par une protection anti-robot. Ce ne sont jamais des descriptions de vulnérabilité.
_JUNK_TEXT_RE = re.compile(
    r"you are being redirected|potential security issue|enable javascript|javascript is disabled|"
    r"access denied|just a moment|checking your browser|attention required|"
    r"activez le javascript|redirection en cours", re.I)

# Fragments de CODE (CSS, JavaScript, JSON-LD) captés quand l'extraction a mordu sur le gabarit
# du site au lieu du contenu de l'avis.
_CODE_BLOB_RE = re.compile(
    r'\{\s*"@context"|:root\s*\{|window\.[A-Za-z]|NREUM|--[a-z-]+\s*:\s*#|<!--|'
    r'function\s*\(|\bvar\s+\w+\s*=', re.I)

# Page d'ERREUR HTTP servie à la place de l'avis (403/404/5xx, blocage anti-robot).
_HTTP_ERROR_RE = re.compile(
    r"^\s*[45]\d\d\b|^\s*(forbidden|not found|access denied|error|unauthorized|"
    r"service unavailable|bad gateway)\b", re.I)

# Titre de PAGE générique d'un portail de veille (« Newest CVEs », « Latest trending… ») :
# c'est le nom de la rubrique du site, jamais celui d'un produit ou d'un avis.
_PORTAL_TITLE_RE = re.compile(
    r"^\s*(newest|latest|recent|trending|all)\b.{0,60}\b(cves?|vulnerabilit)", re.I)


def _usable_text(value: str | None, min_len: int = 40) -> str | None:
    """Description EXPLOITABLE, ou None. Écarte les messages techniques d'une page non rendue :
    sans ce filtre, « This is a potential security issue, you are being redirected to » (NVD)
    remplacerait la vraie description de la fiche CVE."""
    s = (value or "").strip()
    if len(s) < min_len:
        return None
    if _JUNK_TEXT_RE.search(s) or _CODE_BLOB_RE.search(s) or _HTTP_ERROR_RE.search(s):
        return None
    # Filtre COMMUN à toute la chaîne : `sanitize` est la source unique de vérité sur
    # « cette valeur est-elle exploitable ». Les motifs locaux ci-dessus, plus anciens,
    # laissaient passer les menus de navigation — un bulletin a présenté « BY COMPANY SIZE
    # Enterprises Small and medium teams » comme la remédiation à appliquer.
    return sanitize.clean_text(s, min_len=min_len)


def _usable_product(value: str | None) -> str | None:
    """Nom de produit EXPLOITABLE, ou None. Un nom de produit ne contient jamais d'identifiant
    CVE, n'est jamais le nom d'une base publique, ni un titre de rubrique (« Newest CVEs »),
    ni une page d'erreur HTTP (« 403 Forbidden »)."""
    s = (value or "").strip()
    if len(s) < 2 or CVE_RE.search(s):
        return None
    if _HTTP_ERROR_RE.search(s) or _PORTAL_TITLE_RE.search(s) or _CODE_BLOB_RE.search(s):
        return None
    first = re.sub(r"[^a-z0-9]+", "", s.split()[0].lower())
    return None if first in _NON_VENDOR_TOKENS else s


def _usable_title(value: str | None) -> str | None:
    """Titre EXPLOITABLE, ou None. Un titre LÉGITIME peut citer la CVE (« CVE-2026-0290 Prisma
    Browser: … ») ; on ne rejette que ceux qui, l'identifiant retiré, ne portent plus aucune
    information — typiquement « NVD - CVE-2026-0290 »."""
    s = (value or "").strip()
    if not s:
        return None
    if _HTTP_ERROR_RE.search(s) or _PORTAL_TITLE_RE.search(s) or _CODE_BLOB_RE.search(s):
        return None
    rest = re.sub(r"[^0-9A-Za-zÀ-ÿ]+", " ", CVE_RE.sub(" ", s)).strip()
    if len(rest) < 3:
        return None
    words = rest.split()
    if words[0].lower() in _NON_VENDOR_TOKENS and len(words) <= 2:
        return None
    return s


def _valid_vendor(v) -> str | None:
    if not v or not isinstance(v, str):
        return None
    low = v.strip().lower()
    # 90 caracteres : une raison sociale complete en compte souvent plus de 60
    # (« Innotim Software, Telecommunications and Consulting Trade Ltd. Co. »). La rejeter
    # faisait retomber le bulletin sur l editeur lu sur la page — « Microsoft » a la place
    # d une societe turque. Un nom long est disgracieux ; un editeur faux est une erreur.
    if len(low) < 2 or len(v) > 90 or any(w in low for w in _BAD_VENDOR):
        return None
    return v.strip()


# Éditeurs répandus (universels, NON spécifiques à un site) : le titre d'un avis est le signal
# vendor le plus fiable (« …dans les produits IBM » -> IBM), surtout pour les avis multi-CVE.
_KNOWN_VENDORS = {
    "apache", "ibm", "microsoft", "cisco", "oracle", "vmware", "google", "mozilla", "adobe",
    "fortinet", "citrix", "gitlab", "atlassian", "red hat", "redhat", "sap", "apple", "samsung",
    "juniper", "f5", "palo alto", "siemens", "schneider", "wordpress", "drupal", "joomla",
    "jenkins", "node.js", "nodejs", "php", "linux", "kubernetes", "docker", "nginx", "openssl",
    "zimbra", "sonicwall", "veeam", "splunk", "elastic", "grafana", "jetbrains", "progress",
    "moveit", "exim", "samba", "bind", "xen", "curl", "chrome", "firefox", "thunderbird",
}
_VENDOR_DISPLAY = {
    "redhat": "Red Hat", "red hat": "Red Hat", "ibm": "IBM", "sap": "SAP", "php": "PHP",
    "f5": "F5", "vmware": "VMware", "nodejs": "Node.js", "node.js": "Node.js", "gitlab": "GitLab",
    "jetbrains": "JetBrains", "openssl": "OpenSSL", "bind": "BIND", "xen": "Xen",
    "palo alto": "Palo Alto Networks", "sonicwall": "SonicWall", "moveit": "MOVEit",
}


_VERSION_CUT = re.compile(
    r"\b(versions?|versoions?|all\s+versions|ant[ée]rieures?|avant|before|prior\s+to|jusqu|"
    r"[àa]\s+la\s+version)\b|[<>]", re.IGNORECASE)


def _products_from_systems(systems: list[str], limit: int = 15) -> list[str]:
    """Extrait les NOMS de produits distincts depuis les lignes « systèmes affectés » (produit +
    versions). Ex. « Apache Apache Atlas versions 0.8.0… » → « Apache Atlas ». Petit repli quand la
    source ne liste pas les produits séparément."""
    out: list[str] = []
    seen: set[str] = set()
    for line in systems or []:
        m = _VERSION_CUT.search(line)
        name = (line[:m.start()] if m else line).strip(" -–:·,;")
        words = name.split()
        # Retire les répétitions consécutives (« Apache Apache Atlas » → « Apache Atlas »).
        name = " ".join(w for i, w in enumerate(words) if i == 0 or w.lower() != words[i - 1].lower()).strip()
        if len(name) >= 2 and name.lower() not in seen:
            seen.add(name.lower())
            out.append(name)
        if len(out) >= limit:
            break
    return out


def _vendor_from_title(title: str | None) -> str | None:
    if not title:
        return None
    low = title.lower()
    for v in sorted(_KNOWN_VENDORS, key=len, reverse=True):
        if re.search(r"\b" + re.escape(v) + r"\b", low):
            return _VENDOR_DISPLAY.get(v, v.title())
    m = re.search(r"produits?\s+([A-Z][\w.\-]+)|products?\s+([A-Z][\w.\-]+)", title)
    return (m.group(1) or m.group(2)) if m else None


# --------------------------------------------------------------------------------------
# Source OFFICIELLE déduite des références (quand l'avis d'origine ne la fournit pas)
# --------------------------------------------------------------------------------------

# Hébergeurs de code/suivi où l'éditeur possède un ESPACE nommé (github.com/mongodb/…).
_CODE_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "sourceforge.net")

# Autorités publiques : font foi, mais restent moins spécifiques qu'un avis d'éditeur.
_AUTHORITY_SCORE = {
    "nvd.nist.gov": 50, "cve.org": 45, "www.cve.org": 45, "cisa.gov": 42, "www.cisa.gov": 42,
    "cert.ssi.gouv.fr": 40, "www.cert.ssi.gouv.fr": 40, "kb.cert.org": 38, "cert.europa.eu": 36,
}

# Chemins typiques d'une page d'avis/correctif : départage deux URL du même éditeur
# (« /releases/tag/v1.4.9 » l'emporte sur la racine du dépôt).
_OFFICIAL_PATH_HINT = re.compile(
    r"/(security|advisor|advisories|bulletin|release|download|patch|errata|"
    r"kb|support|update|vuln|announce)", re.I)

# Suivi de tickets de l'éditeur (jira.…/browse/, bugzilla, /issues/) : c'est bien un domaine
# officiel, mais un ticket n'est PAS un avis de sécurité — on le déclasse au profit d'une page
# de correctif ou de release, tout en le gardant devant les autorités génériques.
_TRACKER_RE = re.compile(r"^(jira|bugs?|bugzilla|tracker)\.|(/browse/|/issues?/|/ticket/|/bug/)", re.I)


# Mots d'habillage d'une raison sociale : jamais discriminants dans un nom de domaine
# (« Palo Alto Networks » ne doit pas rendre « networks.example.com » officiel).
_GENERIC_VENDOR_WORDS = {"networks", "systems", "software", "technologies", "technology", "group",
                         "corporation", "corp", "inc", "ltd", "labs", "security", "solutions",
                         "international", "company", "project", "foundation", "team", "open",
                         "source", "server", "cloud", "data", "digital", "global", "enterprise"}

# Noms de BASES et d'AGRÉGATEURS publics : ce ne sont jamais des éditeurs de produit. Sans ce
# garde-fou, un champ « produit » pollué par un titre de page (« NVD - CVE-2026-0298 » récupéré
# tel quel) produirait le jeton « nvd », et « nvd.nist.gov » serait promu domaine de l'éditeur —
# devançant l'avis réel de l'éditeur.
_NON_VENDOR_TOKENS = {"nvd", "nist", "cve", "cwe", "mitre", "cisa", "cert", "vuln", "vulndb",
                      "opencve", "tenable", "vulners", "packetstorm", "exploit", "advisory",
                      "advisories", "bulletin", "detail", "record", "database"}


# PLATEFORMES — jamais des éditeurs lorsqu'elles apparaissent dans un champ PRODUIT.
#
# Les portails d'avis renseignent souvent le produit par les systèmes concernés :
# « Linux Mac OS Windows ». Le premier mot devenait alors un identifiant d'éditeur, et une
# vulnérabilité Google Chrome se voyait attribuer « Linux Kernel (kernel.org) » comme site
# officiel. Un lien FAUX est pire qu'un lien absent : il envoie le consultant chercher un
# correctif là où il n'y en aura jamais, et il n'a aucune raison de s'en méfier.
#
# L'exclusion ne vaut QUE pour les mots tirés du champ produit. Si l'éditeur lui-même est
# « Linux », kernel.org reste la bonne réponse.
_PLATEFORMES = {"linux", "windows", "macos", "mac", "unix", "android", "ios", "ipados",
                "solaris", "freebsd", "openbsd", "netbsd", "aix", "debian", "ubuntu",
                "multiple", "divers", "tous", "all"}


# PRODUIT -> ÉDITEUR. Les collecteurs renseignent souvent le champ « éditeur » avec le nom du
# PRODUIT : « Chrome » au lieu de « Google », « Firefox » au lieu de « Mozilla ». Le portail
# de l'éditeur devenait alors introuvable, et l'avis officiel présent dans les références —
# « support.google.com/chrome/… » — obtenait un score de 0 parce que son domaine ne
# contenait pas « chrome ».
#
# Table FERMÉE : elle se trompe par omission, jamais par invention.
_EDITEUR_DU_PRODUIT = {
    "chrome": "google", "chromium": "google", "android": "google", "chromeos": "google",
    "firefox": "mozilla", "thunderbird": "mozilla",
    "edge": "microsoft", "windows": "microsoft", "office": "microsoft",
    "sharepoint": "microsoft", "exchange": "microsoft", "outlook": "microsoft",
    "azure": "microsoft", "teams": "microsoft", "iis": "microsoft",
    "safari": "apple", "macos": "apple", "ios": "apple", "ipados": "apple",
    "fortios": "fortinet", "fortiweb": "fortinet", "fortimanager": "fortinet",
    "ios-xe": "cisco", "nx-os": "cisco", "asa": "cisco",
    "pan-os": "paloalto", "tomcat": "apache", "httpd": "apache", "log4j": "apache",
    "openshift": "redhat", "rhel": "redhat", "jboss": "redhat",
    "vcenter": "vmware", "esxi": "vmware", "vsphere": "vmware",
    "zimbra": "zimbra", "gitlab": "gitlab", "jenkins": "jenkins",
}


def _vendor_slugs(vendor: str | None, products: list[str] | None = None) -> list[str]:
    """Jetons identifiant l'éditeur dans une URL. « Red Hat » → {redhat, red-hat} ; « Node.js » →
    {nodejs, node-js}. Le premier mot d'un produit sert de repli quand l'éditeur est inconnu.

    Un nom COMPOSÉ produit aussi ses mots significatifs pris isolément (« Google Chrome » →
    {googlechrome, google-chrome, google, chrome}) : le domaine réel de l'éditeur ne reprend
    presque jamais le nom complet (`support.google.com`). Les mots d'habillage et les mots de
    moins de 4 lettres sont écartés — un jeton trop générique retiendrait une URL tierce.
    """
    names = [vendor] if vendor else []
    for p in (products or [])[:3]:
        # Un « produit » contenant un identifiant CVE est un titre de page mal extrait, pas un
        # nom de produit : il ne dit rien de l'éditeur et n'a donc rien à faire ici.
        if not p or CVE_RE.search(p):
            continue
        mots = p.strip().split()
        # LE PREMIER MOT QUI N'EST PAS UNE PLATEFORME. « Linux Mac OS Windows » décrit les
        # systèmes concernés, pas l'éditeur : en retenir « Linux » attribuait kernel.org à
        # une vulnérabilité Google Chrome.
        for mot in mots:
            if re.sub(r"[^a-z0-9]+", "", mot.lower()) not in _PLATEFORMES:
                names.append(mot)
                break
    slugs: list[str] = []

    def _add(form: str) -> None:
        if form and form not in slugs and form not in _NON_VENDOR_TOKENS:
            slugs.append(form)

    for n in names:
        low = re.sub(r"[^a-z0-9 ]+", "", (n or "").lower()).strip()
        if len(low) < 3:            # « f5 », « hp » : trop court, risque de faux positif
            continue
        _add(low.replace(" ", ""))
        _add(low.replace(" ", "-"))
        words = low.split()
        if len(words) > 1:
            for w in words:
                if len(w) >= 4 and w not in _GENERIC_VENDOR_WORDS:
                    _add(w)
        # L'ÉDITEUR DERRIÈRE LE PRODUIT. Les collecteurs renseignent souvent « Chrome » là où
        # l'éditeur est « Google » : sans cette table, le portail de l'éditeur reste
        # introuvable et son avis officiel — « support.google.com/chrome/… » — obtient un
        # score de 0, faute de contenir le mot « chrome » dans son domaine.
        for forme in (low.replace(" ", ""), *low.split()):
            editeur = _EDITEUR_DU_PRODUIT.get(forme)
            if editeur:
                _add(editeur)
                break
    return slugs


def _score_reference(url: str, slugs: list[str]) -> int:
    """Note une référence : > 0 = utilisable comme source officielle, 0 = jamais retenue."""
    try:
        parts = urlparse(url)
    except ValueError:
        return 0
    host, path = (parts.netloc or "").lower(), (parts.path or "").lower()
    if not host:
        return 0
    bonus = 6 if _OFFICIAL_PATH_HINT.search(path) else 0
    if _TRACKER_RE.search(host) or _TRACKER_RE.search(path):
        bonus -= 20

    # 1) Domaine de l'ÉDITEUR (mongodb.com, jira.mongodb.org, msrc.microsoft.com…).
    if any(re.search(r"(^|[.-])" + re.escape(s) + r"([.-]|$)", host) for s in slugs):
        return 100 + bonus
    # 2) Espace de l'éditeur sur un hébergeur de code (github.com/mongodb/…).
    if any(host == h or host.endswith("." + h) for h in _CODE_HOSTS):
        owner = path.strip("/").split("/")[0] if path.strip("/") else ""
        if owner and owner in slugs:
            return 90 + bonus
        return 0        # github.com/CVEProject, github.com/advisories… : agrégateurs, pas l'éditeur
    # 3) Autorité publique.
    for h, score in _AUTHORITY_SCORE.items():
        if host == h or host.endswith("." + h):
            return score + bonus
    # 4) Blog, chercheur, revue de presse : jamais présenté comme « source officielle ».
    return 0


# L'habillage de page est defini dans `sanitize`, filtre COMMUN a toute la chaine :
# les collecteurs l'appliquent desormais a l'ecriture, le bulletin a l'affichage.
# Une seule implementation, donc un seul comportement.
est_habillage = sanitize.est_habillage


def _domaine(url: str) -> str:
    """Domaine enregistrable approché : « nvd.nist.gov » et « csrc.nist.gov » -> « nist.gov »."""
    hote = (urlparse(url).netloc or "").lower()
    morceaux = hote.split(".")
    return ".".join(morceaux[-2:]) if len(morceaux) >= 2 else hote


def _navigation_du_portail(url: str, url_collecte: str | None, cve_id: str | None) -> bool:
    """Vrai si l'URL est un lien INTERNE du portail de collecte, sans rapport avec la CVE.

    Lire la page NVD d'une vulnérabilité ramène tout son menu : « www.nist.gov »,
    « ncp.nist.gov/cce », « csrc.nist.gov/Projects/… », le formulaire d'abonnement à la
    lettre d'information. Ces liens partagent le domaine du portail et ne mentionnent pas la
    CVE : ils documentent l'organisme, pas la faille.
    """
    if not url_collecte:
        return False
    if _domaine(url) != _domaine(url_collecte):
        return False
    if _meme_page(url, url_collecte):
        return False          # la page de collecte elle-même reste une référence légitime
    return not (cve_id and cve_id.upper() in url.upper())


def _references_utiles(fiche, page, url_collecte=None, cve_id=None) -> list[str]:
    """Références de la fiche EN TÊTE, puis celles de la page, sans doublon ni habillage."""
    out: list[str] = []
    for source in (fiche or [], page or []):
        for url in source:
            if not isinstance(url, str):
                continue
            url = url.strip()
            if not url or est_habillage(url):
                continue
            if _navigation_du_portail(url, url_collecte, cve_id):
                continue
            # « https://x.test » et « https://x.test/ » sont la même page : un seul lien.
            if any(_meme_page(url, deja) for deja in out):
                continue
            out.append(url)
    return out


_CVE_DANS_URL = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def cite_une_autre_cve(url: str, cve_id: str | None) -> bool:
    """Vrai si l'URL porte un identifiant CVE DIFFÉRENT de celui de la fiche.

    Une page d'avis cite des dizaines de vulnérabilités ; ses références contiennent donc des
    liens NVD ou CVE.org qui concernent d'AUTRES failles. Présenter l'un d'eux comme « source
    officielle » de la CVE consultée est une erreur factuelle : le consultant ouvrirait la
    fiche d'une vulnérabilité sans rapport avec celle qu'il analyse.
    """
    if not cve_id:
        return False
    cites = _CVE_DANS_URL.findall(url or "")
    return bool(cites) and cve_id.upper() not in {c.upper() for c in cites}


def official_reference(references: list[str] | None, vendor: str | None = None,
                       products: list[str] | None = None,
                       cve_id: str | None = None) -> str | None:
    """Choisit, parmi les références, l'URL qui fait le mieux office de SOURCE OFFICIELLE.

    Ordre de confiance : avis de l'ÉDITEUR > autorité publique (NVD, CVE.org, CISA, CERT-FR).
    Une référence de blog, d'agrégateur ou de chercheur n'est JAMAIS retenue : mieux vaut
    afficher « — » qu'une URL présentée à tort comme officielle. Renvoie None si rien ne
    qualifie.

    `cve_id` écarte les références qui traitent d'une AUTRE vulnérabilité (cf. ci-dessus).
    """
    slugs = _vendor_slugs(vendor, products)
    best, best_score = None, 0
    for ref in references or []:
        if not isinstance(ref, str) or not ref.startswith(("http://", "https://")):
            continue
        ref = ref.strip()
        if cite_une_autre_cve(ref, cve_id):
            continue
        score = _score_reference(ref, slugs)
        if score > best_score:        # « > » : à égalité, la PREMIÈRE référence l'emporte
            best, best_score = ref, score
    return best


# Nom lisible de l'autorité, déduit du domaine (affiché en regard de l'URL officielle).
_SOURCE_NAMES = {
    "msrc.microsoft.com": "Microsoft Security Response Center (MSRC)",
    "portal.msrc.microsoft.com": "Microsoft Security Response Center (MSRC)",
    "security.paloaltonetworks.com": "Palo Alto Networks Security Advisories",
    "mozilla.org": "Mozilla Security Advisories",
    "sec.cloudapps.cisco.com": "Cisco Security Advisories",
    "tools.cisco.com": "Cisco Security Advisories",
    "access.redhat.com": "Red Hat Product Security",
    "helpx.adobe.com": "Adobe Security Bulletins",
    "support.apple.com": "Apple Security Updates",
    "fortiguard.fortinet.com": "Fortinet PSIRT",
    "chromereleases.googleblog.com": "Google Chrome Releases",
    "git.kernel.org": "Linux Kernel (kernel.org)",
    "lists.apache.org": "Apache Security Announcements",
    "nvd.nist.gov": "NVD (NIST)",
    "cve.org": "Programme CVE (CVE.org)",
    "cisa.gov": "CISA",
    "cert.ssi.gouv.fr": "CERT-FR",
    "kb.cert.org": "CERT/CC",
}


def _source_name(url: str, vendor: str | None) -> str:
    """Libellé de l'autorité derrière une URL officielle (jamais inventé : domaine en dernier repli)."""
    host = (urlparse(url).netloc or "").lower()
    for h, name in _SOURCE_NAMES.items():
        if host == h or host.endswith("." + h):
            return name
    if vendor:
        return f"Avis de sécurité {vendor}"
    return host or "Source officielle"


def _meme_page(a: str | None, b: str | None) -> bool:
    """Deux URL désignant la même page (fragment et barre finale ignorés)."""
    if not a or not b:
        return False
    def _cle(u):
        p = urlparse(u)
        # « www. » est ignore : cve.org et www.cve.org servent la meme page, et les compter
        # deux fois donnait une liste de references artificiellement doublee.
        hote = (p.netloc or "").lower()
        if hote.startswith("www."):
            hote = hote[4:]
        return (hote, (p.path or "/").rstrip("/").lower(), p.query)
    return _cle(a) == _cle(b)


def official_source(references: list[str] | None, vendor: str | None = None,
                    products: list[str] | None = None,
                    cve_ids: list[str] | None = None,
                    url_collecte: str | None = None) -> dict:
    """SOURCE OFFICIELLE de la VULNÉRABILITÉ — à ne pas confondre avec la source de COLLECTE.

    La source de collecte (page ANCS/DGSSI/NVD où CyberWatch a découvert l'information) n'est
    JAMAIS retenue à ce titre, sauf si cette page est elle-même l'avis officiel de l'éditeur —
    auquel cas elle figure de toute façon dans les références et sera sélectionnée sur ses
    propres mérites.

    Ordre : avis de l'ÉDITEUR > autorité publique présente dans les références > fiche CVE.org
    construite depuis l'identifiant (repli sûr, cf. règles de repli). Renvoie {name, url} avec
    des valeurs nulles si rien ne qualifie — mieux vaut « — » qu'une source erronée.
    """
    # La CVE du bulletin est la PREMIÈRE de la liste (cf. `build_bulletin`) : c'est elle qui
    # sert de garde-fou contre les références portant sur une autre vulnérabilité.
    principale = next((c for c in (cve_ids or []) if c), None)
    slugs = _vendor_slugs(vendor, products)

    # LA PAGE DE COLLECTE N'EST PAS UNE SOURCE OFFICIELLE.
    #
    # Quand CyberWatch découvre une CVE sur un portail public, ce portail se retrouve dans
    # les références et, noté comme autorité, il remportait la sélection : le bulletin
    # présentait alors comme « source officielle » la page même où l'information avait été
    # ramassée. C'est un raisonnement circulaire, et c'est précisément ce que cette fonction
    # promettait d'éviter depuis toujours — sans jamais recevoir l'URL nécessaire pour le
    # faire. SEULE exception, déjà documentée : si cette page appartient à l'ÉDITEUR du
    # produit, elle EST l'avis officiel et reste éligible.
    exclues = []
    if url_collecte and _score_reference(url_collecte, slugs) < 90:
        exclues = [r for r in (references or [])
                   if isinstance(r, str) and _meme_page(r, url_collecte)]

    candidates = [r for r in (references or []) if r not in exclues]
    url = official_reference(candidates, vendor, products, cve_id=principale)
    if not url and principale:
        url = f"https://www.cve.org/CVERecord?id={principale}"
    if not url:
        return {"name": None, "url": None}
    return {"name": _source_name(url, vendor), "url": url}


# --------------------------------------------------------------------------------------
# Page de sécurité OFFICIELLE d'un ÉDITEUR (pour un bulletin PRODUIT, qui agrège N CVE)
#
# Un bulletin produit ne peut pas désigner l'avis d'UNE de ses N vulnérabilités : ce serait
# arbitraire. Sa source officielle est le PORTAIL DE SÉCURITÉ de l'éditeur du produit.
# --------------------------------------------------------------------------------------

_VENDOR_PORTALS: dict[str, tuple[str, str]] = {
    "microsoft": ("Microsoft Security Response Center", "https://msrc.microsoft.com/update-guide"),
    "google": ("Google Chrome Releases", "https://chromereleases.googleblog.com/"),
    "mozilla": ("Mozilla Security Advisories", "https://www.mozilla.org/en-US/security/advisories/"),
    "apple": ("Apple Security Releases", "https://support.apple.com/en-us/HT201222"),
    "adobe": ("Adobe Security Bulletins", "https://helpx.adobe.com/security/security-bulletin.html"),
    "redhat": ("Red Hat Product Security", "https://access.redhat.com/security/security-updates/"),
    "cisco": ("Cisco Security Advisories", "https://sec.cloudapps.cisco.com/security/center/publicationListing.x"),
    "fortinet": ("Fortinet PSIRT", "https://fortiguard.fortinet.com/psirt"),
    "paloaltonetworks": ("Palo Alto Networks Security Advisories", "https://security.paloaltonetworks.com/"),
    "oracle": ("Oracle Critical Patch Updates", "https://www.oracle.com/security-alerts/"),
    "vmware": ("Broadcom/VMware Security Advisories", "https://support.broadcom.com/security-advisory"),
    "ibm": ("IBM Product Security", "https://www.ibm.com/support/pages/bulletin"),
    "linux": ("Linux Kernel (kernel.org)", "https://www.kernel.org/category/releases.html"),
    "apache": ("Apache Security Reports", "https://www.apache.org/security/"),
    "canonical": ("Ubuntu Security Notices", "https://ubuntu.com/security/notices"),
    "debian": ("Debian Security Advisories", "https://www.debian.org/security/"),
    "mongodb": ("MongoDB Security Alerts", "https://www.mongodb.com/resources/products/capabilities/alerts"),
    "postgresql": ("PostgreSQL Security", "https://www.postgresql.org/support/security/"),
    "wordpress": ("WordPress Security", "https://wordpress.org/news/category/security/"),
    "drupal": ("Drupal Security Advisories", "https://www.drupal.org/security"),
    "joomla": ("Joomla Security Announcements", "https://developer.joomla.org/security-centre.html"),
    "openssl": ("OpenSSL Vulnerabilities", "https://openssl-library.org/news/vulnerabilities/"),
    "openbsd": ("OpenSSH Security", "https://www.openssh.com/security.html"),
    "docker": ("Docker Security", "https://docs.docker.com/security/"),
    "cncf": ("Kubernetes Security", "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/"),
    "hpe": ("HPE Security Bulletins", "https://support.hpe.com/connect/s/securitybulletinlibrary"),
    "dell": ("Dell Security Advisories", "https://www.dell.com/support/security/"),
    "juniper": ("Juniper Security Advisories", "https://supportportal.juniper.net/JSA"),
    "f5": ("F5 Security Advisories", "https://my.f5.com/manage/s/security-advisories"),
    "sophos": ("Sophos Security Advisories", "https://www.sophos.com/en-us/security-advisories"),
    "checkpoint": ("Check Point Security Advisories", "https://support.checkpoint.com/results/sk/sk179432"),
    "synacor": ("Zimbra Security Advisories", "https://wiki.zimbra.com/wiki/Security_Center"),
}


def _portal_from_references(references, slugs) -> str | None:
    """Repli : hôte le plus fréquent parmi les références QUI APPARTIENT à l'éditeur.

    Le filtre sur le domaine de l'éditeur est indispensable : sans lui, un portail de veille
    très cité (dgssi.gov.ma, 384 occurrences pour Microsoft Edge) serait pris pour la source
    officielle du produit — c'est-à-dire exactement une source de COLLECTE.
    """
    compte: dict[str, int] = {}
    for ref in references or []:
        if not isinstance(ref, str) or not ref.startswith(("http://", "https://")):
            continue
        host = (urlparse(ref).netloc or "").lower()
        if not host or _TRACKER_RE.search(host):
            continue
        if any(re.search(r"(^|[.-])" + re.escape(x) + r"([.-]|$)", host) for x in slugs):
            compte[host] = compte.get(host, 0) + 1
    if not compte:
        return None
    meilleur = max(compte, key=compte.get)
    return f"https://{meilleur}/"


# Score minimal pour qu'une URL soit reconnue comme APPARTENANT à l'éditeur.
# `_score_reference` attribue 100 au domaine de l'éditeur et 90 à son espace nommé sur un
# hébergeur de code ; les autorités génériques (NVD 50, CVE.org 45, CISA 42, CERT-FR 40)
# restent en dessous, et les agrégateurs sont à 0. Le seuil suffit donc à les écarter tous
# sans avoir à énumérer un seul nom de site — et il vaudra pour les sources futures.
SEUIL_APPARTENANCE_EDITEUR = 90

# Un éditeur EST parfois un nom de domaine (« yootheme.com », « nlnetlabs.nl ») : c'est alors
# l'information la plus directe sur son site officiel.
_VENDOR_EST_DOMAINE_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*\.[a-z]{2,24}$")


def _domaine_de_l_editeur(vendor: str | None) -> str | None:
    """URL du site de l'éditeur quand son nom est lui-même un domaine, sinon None."""
    v = (vendor or "").strip().lower().rstrip("/")
    if v.startswith(("http://", "https://")):
        v = (urlparse(v).netloc or "").lower()
    return f"https://{v}/" if v and _VENDOR_EST_DOMAINE_RE.match(v) else None


# Dépôt d'extensions de la plateforme WordPress, sous ses deux formes d'adresse.
_EXTENSION_WP_RE = re.compile(
    r"https?://(?:plugins\.trac\.wordpress\.org/browser|wordpress\.org/plugins)/"
    r"([a-z0-9][a-z0-9-]{2,60})(?:[/?#]|$)", re.I)


def _extension_wordpress(references: list[str] | None) -> str | None:
    """Nom canonique de l'extension WordPress citée par les références, ou None.

    Exige que PLUSIEURS références désignent la même extension, ou qu'une seule le fasse
    sans ambiguïté : une page du dépôt citée en passant ne suffit pas à conclure que la
    vulnérabilité porte sur cette extension.
    """
    trouves: dict[str, int] = {}
    for reference in references or []:
        if not isinstance(reference, str):
            continue
        correspondance = _EXTENSION_WP_RE.search(reference)
        if correspondance:
            nom = correspondance.group(1).lower()
            trouves[nom] = trouves.get(nom, 0) + 1
    if not trouves:
        return None
    # Plusieurs extensions citées : on ne devine pas laquelle est vulnérable.
    if len(trouves) > 1:
        return None
    return next(iter(trouves))


def site_officiel(references: list[str] | None, vendor: str | None = None,
                  products: list[str] | None = None) -> dict:
    """SITE OFFICIEL du produit vulnérable — celui de son ÉDITEUR, et de personne d'autre.

    À ne confondre ni avec la page de collecte, ni avec une base de vulnérabilités. NVD,
    CVE.org, les avis GitHub, Vulners ou un portail de veille RÉFÉRENCENT la vulnérabilité ;
    ils ne la publient pas au nom de l'éditeur. Les présenter comme « site officiel »
    revenait à renvoyer un consultant vers un annuaire quand il cherche le correctif.

    ORDRE DE PRÉFÉRENCE
      1. l'AVIS DE SÉCURITÉ de l'éditeur, trouvé dans les références et vérifié comme lui
         appartenant (page de correctif, bulletin, errata) ;
      2. une autre page de l'éditeur présente dans les références ;
      3. le PORTAIL DE SÉCURITÉ connu de cet éditeur ;
      4. son site, lorsque son nom est lui-même un domaine.

    L'appartenance est VÉRIFIÉE dans tous les cas : une URL n'est jamais retenue parce
    qu'elle figure dans les références, mais parce que son domaine est celui de l'éditeur.
    Si rien ne se vérifie, on renvoie des valeurs nulles — le bulletin affichera
    « Non identifié » plutôt qu'une adresse plausible.
    """
    slugs = _vendor_slugs(vendor, products)

    # 1 & 2 — pages de l'éditeur présentes dans les références, avis de sécurité d'abord.
    appartenant = [r.strip() for r in (references or [])
                   if isinstance(r, str) and r.strip().startswith(("http://", "https://"))
                   and _score_reference(r.strip(), slugs) >= SEUIL_APPARTENANCE_EDITEUR]
    if appartenant:
        avis = [u for u in appartenant if _OFFICIAL_PATH_HINT.search(urlparse(u).path or "")]
        choisi = (avis or appartenant)[0]
        return {"name": _source_name(choisi, vendor), "url": choisi}

    # 3 bis — EXTENSION WORDPRESS. Les références pointent alors le dépôt de la plateforme
    # (« plugins.trac.wordpress.org/browser/<extension>/… ») et non un domaine appartenant à
    # l'auteur — qui, le plus souvent, n'a pas de site. La règle stricte les écartait toutes,
    # et c'était la DERNIÈRE classe de CVE récentes sans source officielle : 3 % du total,
    # exclusivement des extensions.
    #
    # La page canonique de l'extension EST sa source officielle : c'est là que la version
    # corrigée est publiée, et c'est là qu'un consultant doit aller.
    extension = _extension_wordpress(references)
    if extension:
        return {"name": f"Extension WordPress « {extension} »",
                "url": f"https://wordpress.org/plugins/{extension}/"}

    # 3 — portail de sécurité connu de l'éditeur.
    for slug in slugs:
        if slug in _VENDOR_PORTALS:
            nom, url = _VENDOR_PORTALS[slug]
            return {"name": nom, "url": url}

    # 4 — l'éditeur est un nom de domaine.
    domaine = _domaine_de_l_editeur(vendor)
    if domaine:
        return {"name": vendor, "url": domaine}

    return {"name": None, "url": None}


def product_official_source(product: str | None, vendor: str | None,
                            references: list[str] | None = None) -> dict:
    """SOURCE OFFICIELLE d'un bulletin PRODUIT : le portail de sécurité de l'éditeur.

    Ni la page où CyberWatch a collecté l'information, ni l'avis d'une CVE particulière.
    Renvoie {name, url} — valeurs nulles si l'éditeur n'est pas identifiable, plutôt qu'une
    URL approximative.
    """
    slugs = _vendor_slugs(vendor, [product] if product else None)
    for slug in slugs:
        if slug in _VENDOR_PORTALS:
            nom, url = _VENDOR_PORTALS[slug]
            return {"name": nom, "url": url}
    url = _portal_from_references(references, slugs)
    if url:
        return {"name": _source_name(url, vendor), "url": url}
    # Même dernier recours que pour un bulletin de CVE : quand le nom de l'éditeur EST un
    # domaine, il désigne son site. Sans cette ligne, un bulletin produit affichait
    # « Non identifié » là où le bulletin de la CVE, lui, trouvait le site — deux réponses
    # différentes à la même question, dans la même application.
    domaine = _domaine_de_l_editeur(vendor)
    if domaine:
        return {"name": vendor, "url": domaine}
    return {"name": None, "url": None}


def _collection_source(seed: dict | None, url: str | None) -> dict:
    """Source de COLLECTE : d'où CyberWatch AI tient l'information (traçabilité, jamais présentée
    comme l'autorité officielle)."""
    name = None
    for s in (seed or {}).get("sources") or []:
        if s.get("name"):
            name = s["name"]
            break
    if not name:
        name = (seed or {}).get("source_name") or ((urlparse(url).netloc or None) if url else None)
    return {"name": name, "url": url}


def _aggregate(parts: list[dict]) -> dict:
    """Agrège des fiches CVE (en base ou enrichies) : CVSS max, sévérité associée, vendor, type…"""
    agg: dict = {"cvss_score": None, "severity": None, "cvss_vector": None,
                 "vendor": None, "vuln_type": None, "cwe": None, "published_at": None,
                 "descriptions": [], "references": []}
    for p in parts:
        cs = p.get("cvss_score")
        if cs is not None and (agg["cvss_score"] is None or cs > agg["cvss_score"]):
            agg.update(cvss_score=cs, severity=p.get("severity") or agg["severity"],
                       cvss_vector=p.get("cvss_vector") or agg["cvss_vector"])
        if not agg["vendor"] and _valid_vendor(p.get("vendor")):
            agg["vendor"] = _valid_vendor(p.get("vendor"))
        for k in ("vuln_type", "cwe"):
            if not agg[k] and p.get(k):
                agg[k] = p[k]
        pub = p.get("published_at")
        pub = pub.isoformat() if hasattr(pub, "isoformat") else pub
        if pub and (agg["published_at"] is None or str(pub) < agg["published_at"]):
            agg["published_at"] = str(pub)
        if p.get("description"):
            agg["descriptions"].append(p["description"])
        for u in p.get("references") or []:
            if u not in agg["references"]:
                agg["references"].append(u)
    return agg


async def _complete_from_db(db, cves: list[str]) -> dict:
    """Complétion RAPIDE depuis les CVE déjà enrichies en base (aucun appel réseau)."""
    if db is None or not cves:
        return {}
    docs = await db.cves.find(
        {"cve_id": {"$in": cves[:60]}},
        {"cvss_score": 1, "cvss_vector": 1, "severity": 1, "vendor": 1, "vuln_type": 1,
         "cwe": 1, "description": 1, "references": 1, "published_at": 1},
    ).to_list(60)
    return _aggregate(docs) if docs else {}


async def _complete_online(cves: list[str]) -> dict:
    """Complétion en DIRECT (NVD/MITRE/éditeurs) sur un échantillon de CVE (source arbitraire)."""
    if not cves:
        return {}
    sample = cves[:MAX_ENRICH_SAMPLE]
    results = await asyncio.gather(*[enrichment.enrich(c, use_nvd=True) for c in sample],
                                   return_exceptions=True)
    parts = [merged for r in results if isinstance(r, tuple) for merged, _ in [r]]
    return _aggregate(parts) if parts else {}


# --------------------------------------------------------------------------------------
# Phase 4 — résumé professionnel (déterministe, multilingue). Brancher un LLM ici si dispo.
# --------------------------------------------------------------------------------------

def generate_summary(b: dict) -> str:
    """Résumé analyste du bulletin — TOUJOURS en français.

    L'interface CyberWatch AI est intégralement francophone : la langue de la page d'avis
    d'origine (`b["language"]`, qui peut être « en » ou « ar ») ne doit donc PAS déterminer
    celle du résumé. Les données factuelles restituées telles quelles (nom de produit,
    éditeur, identifiants, versions) ne sont jamais traduites.
    """
    n = len(b.get("cves") or []) or (b.get("cve_count") or 0)
    subject = b.get("vendor") or (b["products"][0] if b.get("products") else None) \
        or b.get("title") or "les produits concernés"
    phrases: list[str] = []

    # 1. PORTÉE — quoi, combien, à quel niveau de gravité.
    # Accord en nombre : `_SEV_FR` ne porte que les formes plurielles, d'où le « 1
    # vulnérabilité moyennes » qui s'affichait sur toute fiche isolée.
    sev_l = (_SEV_FR.get(b.get("severity"), "") if n > 1
             else _SEV_FR_SINGULIER.get(b.get("severity"), ""))
    score = b.get("cvss_score")
    tete = (f"{n} vulnérabilités {sev_l}" if n > 1
            else f"Une vulnérabilité {sev_l}").replace("  ", " ").strip()
    ouverture = f"{tete} {'affectent' if n > 1 else 'affecte'} {subject}"
    if isinstance(score, (int, float)):
        ouverture += (f", le score CVSS le plus élevé atteignant {float(score):.1f}"
                      if n > 1 else f", avec un score CVSS de {float(score):.1f}")
    phrases.append(ouverture + ".")

    # NATURE de la faille — la seule chose que la description apportait vraiment. Elle vient
    # du champ structuré (CWE ou type), donc d'une source d'autorité, et non d'une analyse
    # du texte libre qui reviendrait à deviner.
    nature = (b.get("vulnerability_type") or "").strip()
    if nature:
        phrases.append(f"{'Elles relèvent' if n > 1 else 'Elle relève'} de la catégorie "
                       f"{nature}.")

    # 2. RISQUE — ce qu'un attaquant peut en faire.
    # Les libellés de risque sont des groupes nominaux (« Élévation de privilèges ») : les
    # introduire par deux-points évite l'article manquant de « permettre exécution de code »
    # et préserve leur casse d'origine, qu'un passage en minuscules abîmait.
    risks = [r.rstrip(".") for r in (b.get("risk") or []) if r][:4]
    possessif = "Leur" if n > 1 else "Son"
    phrases.append(f"{possessif} exploitation pourrait conduire à : "
                   + _join(risks, "et") + "." if risks else
                   f"{possessif} exploitation pourrait compromettre la confidentialité, "
                   "l'intégrité ou la disponibilité des systèmes affectés.")

    # 3. PÉRIMÈTRE — ce qui est concerné, nommément.
    systemes = [s for s in (b.get("affected_systems") or []) if s][:4]
    if systemes:
        reste = len(b.get("affected_systems") or []) - len(systemes)
        phrases.append(f"Sont concernés {_join(systemes, 'ainsi que')}"
                       + (f", et {reste} autre(s) élément(s)." if reste > 0 else "."))

    # 4. REMÉDIATION — l'état EXACT de l'information, jamais une affirmation non fondée.
    #    Dire « aucun correctif » sans avoir lu les avis serait une faute : on distingue
    #    l'absence constatée de l'information manquante.
    if b.get("solution"):
        phrases.append("Un correctif est disponible : il est recommandé de l'appliquer sans "
                       "délai après validation sur un environnement de test.")
    elif b.get("solution_status") == remediation.AUCUN_CORRECTIF:
        phrases.append("Les sources officielles consultées ne décrivent à ce jour aucune "
                       "mesure de remédiation ; la surveillance doit être maintenue.")
    else:
        phrases.append("La remédiation n'a pas pu être établie de façon fiable : il convient "
                       "de consulter l'avis de l'éditeur avant toute action.")

    # 5. REPÈRES TEMPORELS — publication et dernière révision, jamais confondues.
    jalons = []
    if b.get("publication_date"):
        jalons.append(f"publiée le {_jour(b['publication_date'])}")
    if b.get("update_date") and _jour(b["update_date"]) != _jour(b.get("publication_date")):
        jalons.append(f"révisée le {_jour(b['update_date'])}")
    if jalons:
        phrases.append("Information " + _join(jalons, "puis") + ".")

    # 6. SOURCE — où vérifier, ce qui rend le bulletin opposable.
    officielle = (b.get("official_source") or {}).get("name")
    if officielle:
        phrases.append(f"Source officielle : {officielle}.")

    return " ".join(phrases)


def _jour(valeur) -> str:
    """Date au format « 20/08/2026 », ou chaîne vide si elle est absente ou illisible."""
    analysee = parse_dt(str(valeur)) if valeur else None
    return analysee.strftime("%d/%m/%Y") if analysee else ""


def _join(items: list[str], conj: str) -> str:
    items = [i for i in items if i]
    if len(items) <= 1:
        return items[0] if items else ""
    return ", ".join(items[:-1]) + f" {conj} " + items[-1]


# --------------------------------------------------------------------------------------
# Point d'entrée : construit le bulletin normalisé
# --------------------------------------------------------------------------------------

async def _completer_depuis_avis_officiel(b: dict, url_collecte: str) -> None:
    """Complète les champs VIDES du bulletin en lisant l'avis officiel de l'éditeur.

    Trois garanties, dans un outil où une remédiation fausse a des conséquences réelles :
      • on ne lit l'avis que s'il DIFFÈRE de la page de collecte — sinon rien de nouveau ;
      • on n'écrit que dans les champs vides : aucune valeur établie n'est écrasée ;
      • la remédiation trouvée est ATTRIBUÉE à cette page, comme toute autre solution.
    """
    officielle = (b.get("official_source") or {}).get("url")
    manquants = (not b.get("solution"), not b.get("risk"), not b.get("affected_systems"))
    if not officielle or not any(manquants) or officielle == url_collecte:
        return
    try:
        html = await advisory._fetch(officielle, expect_cve=False)
        if not html:
            return
        avis = advisory.parse_advisory(html, officielle)
    except Exception as exc:  # noqa: BLE001 - un avis illisible ne casse pas le bulletin
        logger.info("Avis officiel illisible (%s) : %s", officielle[:70], str(exc)[:100])
        return

    if not b.get("risk"):
        b["risk"] = _bullets(avis.get("impact"))
    if not b.get("affected_systems"):
        b["affected_systems"] = list(avis.get("affected_systems") or [])
    if not b.get("solution"):
        remede = _usable_text(avis.get("solution"), min_len=12)
        if remede:
            b["solution"] = remede
            b["solution_source"] = {"name": (b["official_source"] or {}).get("name"),
                                    "url": officielle}
    if not b.get("description"):
        b["description"] = _usable_text(avis.get("description"))


async def build_bulletin(url: str, seed: dict | None = None, db=None,
                         complete: bool = True) -> dict:
    """Construit le modèle de bulletin unifié pour une page d'avis (toute source)."""
    html = await advisory._fetch(url, expect_cve=True)
    adv = advisory.parse_advisory(html, url)
    plain = _text(html)
    lang = detect_language(plain)

    ids = extract_identifiers(html)
    cves = list(dict.fromkeys((adv.get("cves") or []) + ids["cve"]))
    # La CVE à l'origine du bulletin est TOUJOURS listée, même si la page d'avis est
    # injoignable (403/404) ou rendue en JavaScript : sans elle, le bulletin perdrait son
    # identifiant et le repli « fiche CVE.org » de la source officielle ne s'appliquerait pas.
    if seed and seed.get("cve_id"):
        # UN BULLETIN DE FICHE NE PARLE QUE DE SA CVE.
        #
        # La page de collecte peut etre un billet de blog ou une revue de presse qui cite
        # une dizaine de vulnerabilites sans rapport entre elles. Les conserver ici avait
        # trois consequences, toutes visibles a l ecran : le bulletin listait des
        # identifiants etrangers, l agregation fusionnait LEURS editeurs (un avis Dell
        # affiche « Editeur : Microsoft »), et la source officielle pointait vers la fiche
        # NVD d une autre faille. On s en tient donc a l identifiant de la fiche.
        cves = [seed["cve_id"]]
    pdf_links = extract_pdf_links(html, url)

    # PDF : fusion du texte (identifiants + éventuels champs manquants).
    for pdf in pdf_links[:MAX_PDF]:
        text = await _pdf_text(pdf)
        if not text:
            continue
        pids = extract_identifiers(text)
        # Le PDF d'un bulletin d'autorité recense des centaines de vulnérabilités. Il complète
        # la liste UNIQUEMENT quand le bulletin n'est rattaché à aucune fiche : sinon il
        # réintroduirait, juste après la restriction ci-dessus, tous les identifiants
        # étrangers qu'elle vient d'écarter.
        if not (seed and seed.get("cve_id")):
            cves = list(dict.fromkeys(cves + pids["cve"]))
        ids["ghsa"] = list(dict.fromkeys(ids["ghsa"] + pids["ghsa"]))
        if not adv.get("solution") and re.search(r"solution|remédiation|correctif|patch|update", text, re.I):
            adv["solution"] = adv.get("solution")  # laissé au HTML ; le PDF sert surtout aux identifiants

    # COHÉRENCE AVEC LA FICHE CVE — le bulletin est construit en rescannant la page de collecte,
    # mais celle-ci peut être une application JavaScript (NVD…) dont on ne récupère que la
    # coquille : titre « NVD - CVE-… », description « you are being redirected to »… La FICHE en
    # base, elle, a été enrichie par identifiant (MITRE, OSV, Red Hat, MSRC) et fait foi. On ne
    # retient donc une valeur de la page que si elle est EXPLOITABLE, sinon on prend celle du seed.
    _seed = seed or {}
    b = {
        "title": _usable_title(adv.get("title")) or _seed.get("title"),
        # DATE DE PUBLICATION : celle de la FICHE d'abord. Elle provient d'une source
        # d'autorité et porte sa provenance ; la date lue sur une page de portail n'a pas ce
        # statut. Sans cette priorité, le bulletin d'une CVE parfaitement datée en base
        # affichait « — » simplement parce que la page de collecte n'exposait pas de date.
        "publication_date": (_date_iso(_seed.get("published_at"))
                             or _date_iso(adv.get("published_at"))),
        # DERNIÈRE MISE À JOUR de la CVE chez l'autorité qui la publie — une date DISTINCTE
        # de la publication. Une fiche révisée voit son score ou son correctif changer sans
        # être republiée ; sans cette information, un consultant peut s'appuyer sur un score
        # périmé en croyant la fiche à jour. Comme pour la publication, la valeur de la
        # FICHE prime : elle porte une provenance, ce que la page de collecte n'a pas.
        "update_date": (_date_iso(_seed.get("updated_at"))
                        or _date_iso(adv.get("updated_at"))),
        # ÉDITEUR et PRODUIT : la fiche prime sur la page moissonnée. Ces deux champs ont été
        # confirmés par une source d'autorité (MITRE, NVD, éditeur) et portent une provenance ;
        # ce qu'un billet de blog laisse deviner n'a pas ce statut et ne doit pas s'y substituer.
        # La page ne sert donc qu'à COMBLER un manque.
        # Si la fiche PORTE un editeur mais qu il est juge inexploitable, on n y substitue
        # PAS celui de la page : ce serait attribuer la faille au mauvais editeur. Le champ
        # reste vide et la completion pourra le renseigner depuis une source d autorite.
        "vendor": (_valid_vendor(_seed.get("vendor")) if _seed.get("vendor")
                   else _valid_vendor(adv.get("vendor"))),
        "products": [p for p in [_usable_product(_seed.get("product"))
                                 or _usable_product(adv.get("product"))] if p],
        "cves": cves,
        "identifiers": ids,
        "severity": adv.get("severity") or _seed.get("severity"),
        "cvss_score": _seed.get("cvss_score"),
        "cvss_vector": _seed.get("cvss_vector"),
        # RÉSUMÉ : la description de la fiche prime. Elle vient de MITRE/NVD et décrit LA
        # vulnérabilité ; la « description » d'une page de collecte se réduit souvent à son
        # titre (« … – TheHackerWire »), qui n'apprend rien de plus que l'en-tête du bulletin.
        # DESCRIPTION TECHNIQUE de la vulnérabilité, telle que publiée par l'autorité.
        # Elle alimente la synthèse ; elle n'EST pas la synthèse. Recopiée telle quelle dans
        # « Résumé », elle donnait un pavé anglophone qui répétait ce que les autres
        # rubriques disaient déjà, sans jamais dire l'essentiel : gravité, portée, conduite
        # à tenir. Le « Résumé » est désormais rédigé plus bas, à partir des faits établis.
        "description": _usable_text(_seed.get("description")) or _usable_text(adv.get("description")),
        "summary": None,
        "affected_systems": (adv.get("affected_systems")
                             or ([adv["platform"]] if adv.get("platform") else [])
                             or _seed.get("affected_systems") or []),
        "risk": _bullets(adv.get("impact")) or _bullets(_seed.get("impact")),
        "vulnerability_type": _seed.get("vuln_type") or _seed.get("cwe"),
        # SOLUTION — priorité à la synthèse approfondie lorsqu'elle existe : elle provient de la
        # lecture des pages officielles et porte l'attribution de sa source, alors que la page de
        # collecte n'en donne souvent aucune (36 % de remplissage seulement).
        "solution": (((_seed.get("deep_synthesis") or {}).get("solution") or "").strip() or None)
                    or _usable_text(adv.get("solution"), min_len=12)
                    or _usable_text(_seed.get("solution"), min_len=12),
        "solution_source": ((_seed.get("deep_synthesis") or {}).get("solution_source")
                            if (_seed.get("deep_synthesis") or {}).get("solution") else None),
        # RÉFÉRENCES : celles de la fiche d'abord — elles ont survécu à la collecte et à
        # l'enrichissement — puis celles de la page, débarrassées de son habillage.
        "references": _references_utiles(_seed.get("references"), adv.get("references"),
                                         url_collecte=url,
                                         cve_id=(cves[0] if cves else None)),
        "pdf_links": pdf_links,
        # SOURCE DE COLLECTE : d'où CyberWatch AI tient l'information (traçabilité). Elle n'est
        # JAMAIS présentée comme la source officielle — celle-ci est déterminée plus bas, une
        # fois les références complétées par la phase 3.
        "collection_source": _collection_source(seed, url),
        "official_source": {"name": None, "url": None},
        "official_url": None,
        "language": lang,
    }

    # Produits : noms distincts extraits des « systèmes affectés » (Apache Atlas, Kyuubi, Airflow…).
    # Repli conservé (titre/seed) si la source ne détaille pas les systèmes.
    _prods = [p for p in _products_from_systems(b["affected_systems"]) if _usable_product(p)]
    if _prods:
        b["products"] = _prods

    # Date manquante : extracteur générique (JSON-LD / meta / texte visible FR-EN) sur la page.
    if not b["publication_date"]:
        det = metadata_extraction.extract_publication_date(html)
        if det and det.get("value"):
            parsed = parse_dt(det["value"])
            b["publication_date"] = parsed.isoformat() if parsed else det["value"]

    # Vendor : déduit du TITRE quand la fiche n'en porte pas. Le titre d'une page de collecte
    # est une chaîne libre — celui d'un agrégateur mentionne souvent un éditeur qui n'est pas
    # celui du produit concerné. Il ne remplace donc jamais un éditeur déjà établi.
    if not b["vendor"]:
        b["vendor"] = _vendor_from_title(b["title"])

    # Phase 3 : complétion (base d'abord — rapide, puis en ligne si toujours incomplet).
    if complete and cves:
        agg = await _complete_from_db(db, cves)
        if not agg.get("cvss_score") and not agg.get("vendor"):
            agg = await _complete_online(cves)
        if b["cvss_score"] is None:
            b["cvss_score"] = agg.get("cvss_score")
        if not b["severity"]:
            b["severity"] = agg.get("severity")
        # Vendor : l'enrichissement (NVD) ne l'affine que s'il est COHÉRENT avec le titre
        # (évite qu'un avis multi-CVE « IBM » hérite du vendor d'une CVE tierce échantillonnée).
        av = agg.get("vendor")
        if av and not b["vendor"]:
            b["vendor"] = av
        elif av and b["vendor"] and b["vendor"].lower() in av.lower():
            b["vendor"] = av  # ex. titre « Apache » -> « Apache Software Foundation »
        if not b["vulnerability_type"]:
            b["vulnerability_type"] = agg.get("vuln_type") or agg.get("cwe")
        if not b.get("description") and agg.get("descriptions"):
            b["description"] = agg["descriptions"][0]
        for u in agg.get("references") or []:
            if u not in b["references"] and not est_habillage(u):
                b["references"].append(u)

    # SITE OFFICIEL — déterminé APRÈS la phase 3 : c'est elle qui apporte les références des
    # avis éditeur (MSRC, PSIRT, access.redhat…). Le calculer plus tôt reviendrait à ne voir
    # que les liens de la page de collecte.
    #
    # Seul l'ÉDITEUR du produit vulnérable qualifie. NVD, CVE.org et les avis GitHub
    # demeurent dans « Références » : ils documentent la vulnérabilité, ils ne sont pas le
    # site du produit affecté.
    b["official_source"] = site_officiel(b["references"], b["vendor"], b["products"])
    b["official_url"] = b["official_source"]["url"]   # compat. des consommateurs existants

    # Phase 3 ter : LIRE L'AVIS OFFICIEL pour ce qui manque encore.
    #
    # La page de collecte est souvent une revue de presse qui annonce la faille sans la
    # documenter : impact, systèmes affectés et remédiation y sont absents. L'avis de
    # l'éditeur, lui, les publie. On va donc le lire — mais seulement pour COMBLER les
    # champs vides, jamais pour remplacer une valeur déjà établie, et sans aucun modèle de
    # langage : seul l'analyseur d'avis intervient, ce qui exclut toute reformulation
    # inventée.
    if complete:
        await _completer_depuis_avis_officiel(b, url)

    # ÉTAT DU CHAMP « Solution / Correctif » — calculé EN DERNIER, une fois la complétion
    # par l'avis officiel terminée.
    #
    # Trois situations qu'il ne faut jamais confondre : une remédiation existe, l'information
    # n'a pas pu être extraite, ou les pages officielles ont été lues sans en trouver aucune.
    # Seule la troisième autorise une affirmation. Le calcul est délégué à `remediation` pour
    # que la fiche, le bulletin et le PDF donnent la même réponse.
    _pour_etat = {"solution": b.get("solution"),
                  "deep_synthesis": (seed or {}).get("deep_synthesis")}
    b["solution_status"] = remediation.etat(_pour_etat)
    b["solution_message"] = remediation.MESSAGES.get(b["solution_status"])

    # Phase 4 : RÉSUMÉ RÉDIGÉ, en français, à partir des faits établis du bulletin.
    #
    # Calculé en dernier : il a besoin de la sévérité, du score, de la remédiation, des
    # dates et de la source officielle, tous renseignés par les phases précédentes.
    b["summary"] = generate_summary(b)
    # Le bandeau « Résumé analyste » ferait double emploi : il portait le même texte que la
    # rubrique « Résumé ». Un bulletin ne doit pas dire deux fois la même chose.
    b["ai_summary"] = None
    b["schema_version"] = BULLETIN_SCHEMA_VERSION
    b["built_at"] = utcnow()
    return b
