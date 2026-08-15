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

from app.backend.services.collection import enrichment, net
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
BULLETIN_SCHEMA_VERSION = 6


# --------------------------------------------------------------------------------------
# Phase 1 — helpers d'analyse (génériques, multilingues)
# --------------------------------------------------------------------------------------

def _text(html: str) -> str:
    return re.sub(r"\s+", " ", _TAG_RE.sub(" ", html or "")).strip()


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
    return s


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
    if len(low) < 2 or len(v) > 60 or any(w in low for w in _BAD_VENDOR):
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
        first = p.strip().split()
        if first:
            names.append(first[0])
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


def official_reference(references: list[str] | None, vendor: str | None = None,
                       products: list[str] | None = None) -> str | None:
    """Choisit, parmi les références, l'URL qui fait le mieux office de SOURCE OFFICIELLE.

    Ordre de confiance : avis de l'ÉDITEUR > autorité publique (NVD, CVE.org, CISA, CERT-FR).
    Une référence de blog, d'agrégateur ou de chercheur n'est JAMAIS retenue : mieux vaut
    afficher « — » qu'une URL présentée à tort comme officielle. Renvoie None si rien ne
    qualifie.
    """
    slugs = _vendor_slugs(vendor, products)
    best, best_score = None, 0
    for ref in references or []:
        if not isinstance(ref, str) or not ref.startswith(("http://", "https://")):
            continue
        score = _score_reference(ref.strip(), slugs)
        if score > best_score:        # « > » : à égalité, la PREMIÈRE référence l'emporte
            best, best_score = ref.strip(), score
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


def official_source(references: list[str] | None, vendor: str | None = None,
                    products: list[str] | None = None,
                    cve_ids: list[str] | None = None) -> dict:
    """SOURCE OFFICIELLE de la VULNÉRABILITÉ — à ne pas confondre avec la source de COLLECTE.

    La source de collecte (page ANCS/DGSSI/NVD où CyberWatch a découvert l'information) n'est
    JAMAIS retenue à ce titre, sauf si cette page est elle-même l'avis officiel de l'éditeur —
    auquel cas elle figure de toute façon dans les références et sera sélectionnée sur ses
    propres mérites.

    Ordre : avis de l'ÉDITEUR > autorité publique présente dans les références > fiche CVE.org
    construite depuis l'identifiant (repli sûr, cf. règles de repli). Renvoie {name, url} avec
    des valeurs nulles si rien ne qualifie — mieux vaut « — » qu'une source erronée.
    """
    url = official_reference(references, vendor, products)
    if not url:
        first = next((c for c in (cve_ids or []) if c), None)
        if first:
            url = f"https://www.cve.org/CVERecord?id={first}"
    if not url:
        return {"name": None, "url": None}
    return {"name": _source_name(url, vendor), "url": url}


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
    cves = b.get("cves") or []
    n = len(cves)
    subject = b.get("vendor") or (b["products"][0] if b.get("products") else None) \
        or b.get("title") or "les produits concernés"
    risks = [r.lower() for r in (b.get("risk") or []) if r][:3]
    sev = b.get("severity")

    sev_l = _SEV_FR.get(sev, "")
    head = f"{n} vulnérabilité{'s' if n > 1 else ''} {sev_l}".replace("  ", " ").strip()
    verb = "affectent" if n > 1 else "affecte"
    s = f"{head} {verb} {subject}."
    if risks:
        s += " Leur exploitation pourrait permettre " + _join(risks, "et") + "."
    else:
        s += (" Leur exploitation pourrait compromettre la confidentialité, l'intégrité ou la "
              "disponibilité des systèmes affectés.")
    s += " Il est recommandé d'appliquer sans délai les dernières mises à jour de sécurité."
    return s


def _join(items: list[str], conj: str) -> str:
    items = [i for i in items if i]
    if len(items) <= 1:
        return items[0] if items else ""
    return ", ".join(items[:-1]) + f" {conj} " + items[-1]


# --------------------------------------------------------------------------------------
# Point d'entrée : construit le bulletin normalisé
# --------------------------------------------------------------------------------------

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
    if seed and seed.get("cve_id") and seed["cve_id"] not in cves:
        cves.insert(0, seed["cve_id"])
    pdf_links = extract_pdf_links(html, url)

    # PDF : fusion du texte (identifiants + éventuels champs manquants).
    for pdf in pdf_links[:MAX_PDF]:
        text = await _pdf_text(pdf)
        if not text:
            continue
        pids = extract_identifiers(text)
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
        "publication_date": adv["published_at"].isoformat() if adv.get("published_at") else None,
        "vendor": _valid_vendor(adv.get("vendor")) or _valid_vendor(_seed.get("vendor")),
        "products": [p for p in [_usable_product(adv.get("product"))
                                 or _usable_product(_seed.get("product"))] if p],
        "cves": cves,
        "identifiers": ids,
        "severity": adv.get("severity") or _seed.get("severity"),
        "cvss_score": _seed.get("cvss_score"),
        "cvss_vector": _seed.get("cvss_vector"),
        "summary": _usable_text(adv.get("description")) or _seed.get("description"),
        "affected_systems": (adv.get("affected_systems")
                             or ([adv["platform"]] if adv.get("platform") else [])
                             or _seed.get("affected_systems") or []),
        "risk": _bullets(adv.get("impact")) or _bullets(_seed.get("impact")),
        "vulnerability_type": _seed.get("vuln_type") or _seed.get("cwe"),
        "solution": _usable_text(adv.get("solution"), min_len=12)
                    or _usable_text(_seed.get("solution"), min_len=12),
        "references": list(adv.get("references") or []),
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

    # Vendor : le TITRE prime (avis mono-produit) ; l'enrichissement l'affine s'il est cohérent.
    title_vendor = _vendor_from_title(b["title"])
    if title_vendor:
        b["vendor"] = title_vendor

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
        if not b["summary"] and agg.get("descriptions"):
            b["summary"] = agg["descriptions"][0]
        for u in agg.get("references") or []:
            if u not in b["references"]:
                b["references"].append(u)

    # SOURCE OFFICIELLE — déterminée APRÈS la phase 3 : c'est elle qui apporte les références
    # des avis éditeur (MSRC, PSIRT, access.redhat…). La calculer plus tôt reviendrait à ne
    # voir que les liens de la page de collecte.
    b["official_source"] = official_source(b["references"], b["vendor"], b["products"], b["cves"])
    b["official_url"] = b["official_source"]["url"]   # compat. des consommateurs existants

    # Phase 4 : résumé professionnel (toujours en français).
    b["ai_summary"] = generate_summary(b)
    b["schema_version"] = BULLETIN_SCHEMA_VERSION
    b["built_at"] = utcnow()
    return b
