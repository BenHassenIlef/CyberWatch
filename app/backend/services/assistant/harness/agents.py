"""AGENTS ET PLANIFICATION — qui répond, et avec quels outils.

Le harness n'invente pas d'agent. Il DÉCLARE ceux que le projet possède déjà et leur attache
un périmètre d'outils :

    assistant_general      l'assistant existant (rag.py) — le seul à parler au consultant
    agent_vulnerabilites   lecture approfondie d'une vulnérabilité (deep_synthesis.py)
    agent_communautaire    discussions publiques (community/discussions.py, community/agent.py)
    agent_verification     authenticité et crédibilité d'une source (verification/agent.py)

UN SEUL INTERLOCUTEUR
Les trois agents spécialisés ne s'adressent JAMAIS au consultant. Ils produisent de la matière
que l'assistant existant intègre à sa réponse. Sans cette règle, l'application aurait plusieurs
voix, chacune avec son ton et ses garde-fous — c'est-à-dire plusieurs assistants.

PLANIFICATION DÉTERMINISTE
Le choix de l'agent se lit dans la question, à l'aide de l'analyse que `rag.parse_query`
effectue DÉJÀ. Aucun appel de modèle n'est ajouté pour décider : un appel supplémentaire
coûterait du quota, ajouterait une latence, et introduirait de l'aléa là où une règle lisible
suffit. Le modèle sert à RÉDIGER, pas à router.
"""
import re
from dataclasses import dataclass

from app.backend.services.assistant.harness import outils as registre

GENERAL = "assistant_general"
VULNERABILITES = "agent_vulnerabilites"
COMMUNAUTAIRE = "agent_communautaire"
VERIFICATION = "agent_verification"


@dataclass(frozen=True)
class Agent:
    nom: str
    role: str
    outils: tuple[str, ...]


AGENTS: dict[str, Agent] = {
    GENERAL: Agent(
        nom=GENERAL,
        role="Assistant conversationnel existant : comprend la question, interroge la base et "
             "rédige la réponse finale. C'est le seul agent qui s'adresse au consultant.",
        outils=("recherche_cve", "fiche_cve", "synthese_produit", "connaissance_generale")),
    VULNERABILITES: Agent(
        nom=VULNERABILITES,
        role="Approfondit UNE vulnérabilité en lisant les pages qu'elle référence, quand la "
             "fiche ne porte pas de remédiation.",
        outils=("recherche_cve", "fiche_cve", "synthese_produit", "synthese_approfondie",
                "connaissance_generale")),
    COMMUNAUTAIRE: Agent(
        nom=COMMUNAUTAIRE,
        role="Rapporte ce que les communautés publiques disent d'une vulnérabilité, sans "
             "jamais le présenter comme un fait établi.",
        outils=("recherche_cve", "discussions_communautaires")),
    VERIFICATION: Agent(
        nom=VERIFICATION,
        role="Établit si une adresse est fiable et authentique avant qu'elle n'alimente la veille.",
        outils=("recherche_cve", "verification_source")),
}


def outils_autorises(agent: str) -> list[str]:
    """Intersection des deux déclarations : le profil de l'agent ET le registre des outils.

    La double barrière est délibérée. Ajouter un outil au profil d'un agent sans l'autoriser
    dans le registre — ou l'inverse — ne suffit pas à lui en ouvrir l'accès : les deux
    déclarations doivent concorder. Un oubli produit un refus, jamais une permission.
    """
    profil = AGENTS.get(agent)
    if profil is None:
        return []
    return [nom for nom in profil.outils
            if (o := registre.obtenir(nom)) is not None and o.autorise(agent)]


# --------------------------------------------------------------------------------------
# Détection d'intention — sur la question, jamais sur du contenu externe
# --------------------------------------------------------------------------------------

_COMMUNAUTE_RE = re.compile(
    r"\bcommunaut|\bforum|\breddit\b|\bhacker\s*news\b|stack\s*exchange|"
    r"qu.est.ce (?:qu.)?on (?:en )?dit|retours? d.exp[ée]rience|discussions?\b", re.I)

_REMEDIATION_RE = re.compile(
    r"\bcorrig|\bcorrectif|\brem[ée]diation|\bpatch|\bcontournement|\bworkaround|"
    r"comment (?:la |le |les )?(?:corriger|traiter|r[ée]soudre)|\bque faire\b|"
    r"\bmise[s]? [àa] jour [àa] appliquer|\bversion corrig", re.I)

_VERIFICATION_RE = re.compile(
    r"\bv[ée]rifi|\bfiable\b|\bauthenti|\bcontrefa|\bfaux site\b|\busurpation|"
    r"\bce lien\b|\bcette source\b|\btyposquat", re.I)

_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+")


@dataclass(frozen=True)
class Plan:
    """Décision du harness : qui répond, avec quels appels d'outils, et pourquoi."""
    agent: str
    appels: list[tuple[str, dict]]        # [(nom_outil, arguments)]
    motif: str


def planifier(question: str, parsed: dict) -> Plan:
    """Choisit l'agent et les outils COMPLÉMENTAIRES à l'assistant existant.

    Principe directeur : ne jamais refaire ce que l'assistant fait déjà. `rag.answer_question`
    interroge la base et rédige seul ; lui imposer un outil de recherche par-dessus doublerait
    la requête sans rien apporter. Un outil n'est donc planifié que lorsqu'il apporte une
    capacité que l'assistant N'A PAS : lire les pages référencées, interroger les communautés,
    vérifier une adresse.
    """
    cve_ids = parsed.get("cve_ids") or []
    cible = cve_ids[0] if cve_ids else None

    liens = _URL_RE.findall(question or "")
    if liens and _VERIFICATION_RE.search(question or ""):
        return Plan(VERIFICATION, [("verification_source", {"url": liens[0]})],
                    "une adresse est soumise à vérification")

    if cible and _COMMUNAUTE_RE.search(question or ""):
        return Plan(COMMUNAUTAIRE, [("discussions_communautaires", {"cve_id": cible})],
                    "la question porte sur ce que la communauté rapporte")

    if cible and _REMEDIATION_RE.search(question or ""):
        return Plan(VULNERABILITES, [("synthese_approfondie", {"cve_id": cible})],
                    "la remédiation demandée figure rarement dans la fiche : "
                    "les pages référencées sont lues")

    return Plan(GENERAL, [], "l'assistant répond à partir de la base, sans outil externe")
