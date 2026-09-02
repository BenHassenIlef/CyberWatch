"""AGENT DE VEILLE COMMUNAUTAIRE — analyse d'une publication externe (forum, blog, avis).

Place dans la chaîne :

    sources communautaires -> collecteur -> ★ AGENT ★ -> community_publications -> interface

RESPONSABILITÉ : à partir du TEXTE réellement collecté, l'agent extrait des faits vérifiables
(identifiants CVE, produits surveillés concernés), classe la publication, évalue un NIVEAU DE
CONFIANCE et rédige un résumé français.

RÈGLE FONDATRICE — une publication communautaire n'est JAMAIS un fait établi. L'agent sépare
donc systématiquement :
  • les FAITS CONFIRMÉS  : ce qu'une source officielle ou la base CyberWatch corroborent ;
  • l'INFORMATION COMMUNAUTAIRE : hypothèses, revendications, rapports non confirmés.

Aucune information n'est inventée : l'extraction est déterministe (regex + catalogue produits),
le LLM ne sert qu'à REFORMULER en français ce qui a été extrait.
"""
import logging
import re
from urllib.parse import urlparse

from app.backend.services.collection import monitored
from app.backend.services.collection.schema import CVE_RE

logger = logging.getLogger("cyberwatch.community.agent")

# --------------------------------------------------------------------------------------
# Catégories (une publication peut en porter plusieurs)
# --------------------------------------------------------------------------------------

CATEGORIES = ("vulnerability", "exploit", "active_exploitation", "poc", "patch",
              "workaround", "zero_day", "technical_analysis", "threat_intelligence", "other")

CATEGORY_FR = {
    "vulnerability": "Vulnérabilité", "exploit": "Exploit", "poc": "Preuve de concept",
    "active_exploitation": "Exploitation active", "patch": "Correctif",
    "workaround": "Contournement", "zero_day": "Zero-day",
    "technical_analysis": "Analyse technique", "threat_intelligence": "Renseignement menace",
    "other": "Autre",
}

# Motifs de classification. Volontairement explicites : un mot isolé ne suffit pas à conclure
# à une exploitation active, qui est l'information la plus lourde de conséquences.
_PATTERNS = {
    "active_exploitation": r"activement exploit|exploited in the wild|in-the-wild|active exploitation|"
                           r"under active attack|exploitation active|attaques? en cours|"
                           r"observed exploitation|being exploited",
    "zero_day": r"zero[- ]?day|0[- ]?day|jour z[ée]ro|unpatched vulnerability|no patch available",
    "poc": r"\bpoc\b|proof[- ]of[- ]concept|preuve de concept|exploit code published|code d.exploitation",
    "exploit": r"\bexploit\b|exploitation|metasploit|weaponi[sz]ed|module d.exploitation",
    "patch": r"\bpatch(ed|es)?\b|correctif|security update|mise à jour de sécurité|hotfix|fixed in",
    "workaround": r"workaround|contournement|mitigation|mesure de contournement|atténuation",
    "technical_analysis": r"analys(e|is)|deep[- ]dive|reverse engineering|r[ée]tro[- ]ing[ée]nierie|"
                          r"technical breakdown|write[- ]?up",
    "threat_intelligence": r"threat actor|\bapt\b|ransomware group|campaign|campagne|"
                           r"groupe de menace|acteur malveillant",
    "vulnerability": r"vulnerabilit|vuln[ée]rabilit|\bcve\b|\bflaw\b|faille|security issue",
}

# Signaux justifiant une ALERTE consultant (cf. §8 du cahier des charges).
ALERT_CATEGORIES = {"active_exploitation", "zero_day", "poc", "exploit"}

# --------------------------------------------------------------------------------------
# Niveaux de confiance
# --------------------------------------------------------------------------------------

CONFIRMED = "confirmed"           # source officielle, ou CVE déjà confirmée en base
CORROBORATED = "corroborated"     # plusieurs sources indépendantes concordantes
NEEDS_VERIFICATION = "needs_verification"   # source communautaire, non confirmée
UNCONFIRMED = "unconfirmed"       # signal faible, rien d'exploitable

CONFIDENCE_FR = {
    CONFIRMED: "Confirmé", CORROBORATED: "Corroboré",
    NEEDS_VERIFICATION: "À vérifier", UNCONFIRMED: "Non confirmé",
}

# Types de source (portés par `sources.intel_type`).
OFFICIAL = "official"
SPECIALIZED = "specialized"
COMMUNITY = "community"


def _text_of(pub: dict) -> str:
    return " ".join(str(pub.get(k) or "") for k in ("title", "content", "summary_raw"))


def extract_cves(pub: dict) -> list[str]:
    """Identifiants CVE cités. Extraction déterministe : aucun modèle n'intervient."""
    return list(dict.fromkeys(m.group(0).upper() for m in CVE_RE.finditer(_text_of(pub))))


def classify(pub: dict) -> list[str]:
    """Catégories de la publication, par motifs sur le texte RÉELLEMENT collecté."""
    texte = _text_of(pub).lower()
    trouves = [cat for cat, motif in _PATTERNS.items() if re.search(motif, texte, re.I)]
    return trouves or ["other"]


def match_products(pub: dict) -> list[tuple[str, str]]:
    """Produits SURVEILLÉS concernés, via le catalogue actif (même moteur que la collecte CVE).

    Permet de rattacher une publication qui ne cite AUCUN CVE mais parle d'un produit suivi.
    """
    return monitored.classify_all({
        "title": pub.get("title") or "",
        "description": (pub.get("content") or "")[:6000],
    })


def assess_confidence(pub: dict, source_type: str, cve_confirme: bool,
                      nb_sources: int = 1) -> tuple[str, list[str]]:
    """Niveau de confiance + justification LISIBLE. Renvoie (niveau, motifs).

    Une publication communautaire ne peut JAMAIS atteindre « confirmé » par elle-même : seul
    un adossement officiel (source officielle, ou CVE déjà confirmée en base) le permet.
    """
    motifs: list[str] = []
    if source_type == OFFICIAL:
        motifs.append("Source officielle")
        return CONFIRMED, motifs
    if cve_confirme:
        motifs.append("CVE déjà confirmée dans la base CyberWatch AI")
        return CONFIRMED, motifs
    if nb_sources >= 2:
        motifs.append(f"{nb_sources} sources indépendantes rapportent la même information")
        return CORROBORATED, motifs
    if source_type == SPECIALIZED:
        motifs.append("Source spécialisée reconnue, information non recoupée")
        return NEEDS_VERIFICATION, motifs
    if extract_cves(pub) or match_products(pub):
        motifs.append("Source communautaire ; élément identifiable (CVE ou produit suivi)")
        return NEEDS_VERIFICATION, motifs
    motifs.append("Source communautaire ; aucun élément vérifiable identifié")
    return UNCONFIRMED, motifs


def needs_alert(categories: list[str], has_scope: bool) -> bool:
    """Alerte consultant ? Uniquement si le sujet est SENSIBLE ET dans le périmètre suivi."""
    return has_scope and bool(set(categories) & ALERT_CATEGORIES)


def source_label(url: str | None) -> str:
    return (urlparse(url or "").netloc or "").lower() or "source inconnue"
