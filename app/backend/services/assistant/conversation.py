"""MÉMOIRE DE CONVERSATION de l'assistant — comprendre une question qui s'appuie sur la précédente.

Chaque question était jusqu'ici analysée SEULE. Un consultant qui écrit « et pour Microsoft ? »
après « affiche les CVE critiques d'aujourd'hui » posait, du point de vue du moteur, une
question sans éditeur, sans date et sans sévérité : la recherche repartait de zéro et
répondait à côté. C'est la première cause de réponses décevantes dans un assistant de ce type,
avant même la qualité du modèle.

DEUX MÉCANISMES, volontairement séparés :

  1. CONDENSATION — une question de SUIVI est réécrite en question AUTONOME à partir des
     échanges précédents (« et pour Microsoft ? » -> « affiche les CVE critiques d'aujourd'hui
     chez Microsoft »). Le moteur de recherche continue de ne voir que des questions
     complètes : ni `parse_query`, ni la récupération Mongo ne changent.

  2. CONTEXTE DE RÉDACTION — les derniers échanges sont fournis au modèle au moment de
     rédiger, pour qu'il ne répète pas ce qu'il vient de dire et enchaîne naturellement.

PRUDENCE DÉLIBÉRÉE : la condensation n'est tentée QUE si la question ressemble vraiment à un
suivi (courte, sans identifiant CVE ni éditeur, ou introduite par une conjonction). Réécrire
une question déjà autonome la déformerait, et une réécriture ratée est pire qu'une absence de
mémoire — le consultant ne verrait pas pourquoi la réponse ne correspond pas.
"""
import logging
import re

logger = logging.getLogger("cyberwatch.assistant.conversation")

# Nombre d'échanges précédents pris en compte. Au-delà, le contexte coûte des jetons sans
# améliorer la compréhension : une conversation d'assistance dérive vite de sujet.
MAX_ECHANGES = 4

# Longueur maximale d'une réponse rappelée dans le contexte : on résume, on ne rejoue pas.
EXTRAIT_REPONSE = 400

# Ouvertures typiques d'une question qui s'appuie sur la précédente.
_CONNECTEURS = re.compile(
    r"^\s*(et\s|mais\s|alors\s|donc\s|aussi\b|idem\b|pareil\b|même\s|meme\s|"
    r"and\s|what about|how about|et pour\b|et chez\b|et les\b|et la\b|et le\b)", re.I)

# Références à un élément mentionné plus haut, sans le nommer.
_ANAPHORES = re.compile(
    r"\b(celle|celui|celles|ceux|ça|ca|cela|ces|cette|ce dernier|la première|le premier|"
    r"la deuxième|le deuxième|la dernière|le dernier|lesquelles|lesquels|"
    r"la même|le même|precedent|précédent|pr[ée]c[ée]dente|ci-dessus|"
    r"it|them|those|that one|the first|the last)\b", re.I)


def normaliser_historique(messages: list[dict]) -> list[dict]:
    """Ne garde que ce qui sert : la question posée et la réponse rendue, du plus ancien au plus récent."""
    echanges = []
    for m in messages or []:
        question = (m.get("question") or "").strip()
        reponse = (m.get("answer") or "").strip()
        if question:
            echanges.append({"question": question, "answer": reponse})
    return echanges[-MAX_ECHANGES:]


# Éléments qui donnent à une question un SUJET PROPRE. Leur présence signifie que la question
# se comprend seule, quelle que soit sa brièveté.
_CRITERES_AUTONOMES = ("cve_ids", "vendor", "keywords", "severity", "cvss_min", "date_from",
                       "exploit")


def est_question_de_suivi(question: str, parsed: dict) -> bool:
    """La question s'appuie-t-elle sur un échange précédent pour être comprise ?

    Une question qui porte déjà son sujet — un identifiant CVE, un éditeur, une sévérité, une
    période — se suffit à elle-même : la réécrire ne pourrait que l'abîmer.
    """
    q = (question or "").strip()
    if not q:
        return False
    if parsed.get("cve_ids"):
        return False                       # une CVE nommée est un sujet complet
    if _CONNECTEURS.search(q) or _ANAPHORES.search(q):
        return True
    # Question très courte ET SANS AUCUN CRITÈRE PROPRE : « les critiques ? », « et hier ? ».
    #
    # Le seul décompte de mots ne suffisait pas : « Affiche les CVE critiques d'aujourd'hui »
    # tient en cinq mots tout en portant une sévérité ET une période. Elle était réécrite à
    # partir du contexte, donc déformée — précisément ce que la condensation doit éviter.
    if len(q.split()) <= 5 and not any(parsed.get(c) for c in _CRITERES_AUTONOMES):
        return True
    return False


def _contexte_texte(echanges: list[dict]) -> str:
    lignes = []
    for i, e in enumerate(echanges, 1):
        lignes.append(f"[Échange {i}]")
        lignes.append(f"Consultant : {e['question']}")
        reponse = e["answer"][:EXTRAIT_REPONSE]
        if reponse:
            lignes.append(f"Assistant : {reponse}{'…' if len(e['answer']) > EXTRAIT_REPONSE else ''}")
    return "\n".join(lignes)


_CONDENSATION_SYSTEM = (
    "Tu réécris une question de suivi en une question AUTONOME, compréhensible sans le "
    "contexte. Règles strictes :\n"
    "- Tu produis UNIQUEMENT la question réécrite, sans guillemets, sans préambule, sans "
    "explication.\n"
    "- Tu conserves l'intention exacte et la langue d'origine.\n"
    "- Tu reprends du contexte SEULEMENT ce qui manque à la question (produit, éditeur, "
    "période, sévérité).\n"
    "- Tu n'ajoutes AUCUN critère que le consultant n'a pas exprimé, ni identifiant, ni score.\n"
    "- Si la question se suffit déjà à elle-même, tu la recopies à l'identique."
)


async def condenser(question: str, echanges: list[dict]) -> str:
    """Réécrit une question de suivi en question autonome. Renvoie la question d'origine en cas d'échec.

    Le repli est SILENCIEUX et sûr : sans modèle disponible, ou si la réécriture paraît
    aberrante, on garde la question telle que le consultant l'a posée. La mémoire est un
    confort, jamais une dépendance.
    """
    from app.backend.services.assistant import llm

    if not echanges or not llm.available():
        return question
    prompt = (
        "Échanges précédents :\n"
        + _contexte_texte(echanges)
        + f"\n\nNouvelle question du consultant : « {question.strip()} »\n\n"
        "Réécris-la en question autonome."
    )
    try:
        reecrite = await llm.generate(prompt, system=_CONDENSATION_SYSTEM, max_tokens=250)
    except Exception:  # noqa: BLE001 - la mémoire ne doit jamais faire échouer la réponse
        reecrite = None

    reecrite = (reecrite or "").strip().strip('"«»').strip()
    # GARDE-FOUS : une réécriture vide, bavarde ou démesurée trahit un modèle qui a commenté
    # sa tâche au lieu de l'exécuter. On préfère alors la question d'origine, qui au pire
    # manque de contexte — au lieu d'une question inventée, qui envoie chercher autre chose.
    if not reecrite or len(reecrite) > 300 or "\n" in reecrite:
        return question
    logger.info("Question de suivi condensée : « %s » -> « %s »", question, reecrite)
    return reecrite


def bloc_de_contexte(echanges: list[dict]) -> str:
    """Rappel des échanges précédents à insérer dans un prompt de RÉDACTION (pas de recherche)."""
    if not echanges:
        return ""
    return ("\n\nÉchanges précédents de cette conversation (pour enchaîner naturellement et "
            "ne pas te répéter ; ils ne sont PAS une source de données) :\n"
            + _contexte_texte(echanges) + "\n")
