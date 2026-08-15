"""Réponses EXTERNES de l'assistant IA — hors base de connaissances CyberWatch AI.

Quand une question ne porte pas sur les CVE réellement collectées en base (définition,
méthodologie, bonne pratique, norme, outil, ou CVE absente de la base), l'assistant délègue
au LLM configuré (Grok / xAI par défaut) avec le prompt `EXTERNAL_SYSTEM`.

Garde-fous :
  • la réponse est TOUJOURS marquée `scope: "external"` et `generated_by: "llm_external"` ;
  • une clause d'avertissement est ajoutée en dernière section (traçabilité analyste) ;
  • `confidence` vaut « external » : l'interface ne doit jamais la présenter comme une donnée
    vérifiée de la base ;
  • si le LLM est indisponible, on retombe sur le message « non disponible » historique —
    aucune invention côté serveur.
"""
from app.backend.core.config import settings
from app.backend.services.assistant import llm
from app.backend.services.assistant.summary import _parse_sections

# Libellé affiché dans la liste des sources d'une réponse externe.
_PROVIDER_LABEL = {"groq": "Groq", "xai": "Grok (xAI)",
                   "anthropic": "Claude (Anthropic)", "openai": "OpenAI"}

DISCLAIMER = (
    "Cette réponse provient des connaissances générales du modèle d'IA et NON de la base "
    "CyberWatch AI. Aucune CVE de la base interne n'a été utilisée pour la produire : "
    "recoupez toute donnée opérationnelle (score CVSS, version corrigée, date) avec une "
    "source officielle (NVD, éditeur, CERT)."
)

# Message renvoyé quand le mode externe est demandé mais indisponible (pas de clé API).
UNAVAILABLE = (
    "Cette information ne figure pas dans la base de connaissances CyberWatch AI, et "
    "l'assistant n'est pas autorisé à répondre hors base (aucun modèle d'IA n'est configuré). "
    "Renseignez LLM_PROVIDER et LLM_API_KEY dans le fichier .env pour activer les réponses "
    "sur des questions générales de cybersécurité."
)


def provider_label() -> str:
    return _PROVIDER_LABEL.get(settings.llm_provider, "Modèle d'IA externe")


def enabled() -> bool:
    return settings.external_answers_enabled


def _sections(text: str) -> list[dict]:
    """Découpe la réponse en sections ; à défaut, une seule section « Réponse »."""
    sections = _parse_sections(text)
    if not sections:
        sections = [{"title": "Réponse", "body": text.strip()}]
    return sections + [{"title": "Portée de la réponse", "body": DISCLAIMER}]


def _result(text: str | None) -> dict:
    """Enveloppe commune d'une réponse externe (ou du refus si le LLM est indisponible)."""
    if not text:
        return {"answer": UNAVAILABLE, "sections": [], "results": [], "sources": [],
                "confidence": "none", "count": 0, "scope": "external",
                "generated_by": "unavailable"}
    sections = _sections(text)
    return {
        "answer": "\n\n".join(f"### {s['title']}\n{s['body']}" for s in sections),
        "sections": sections,
        "results": [],
        "sources": [provider_label()],
        "confidence": "external",
        "count": 0,
        "scope": "external",
        "generated_by": "llm_external",
    }


# --------------------------------------------------------------------------------------
# Question générale de cybersécurité (aucun rapport avec le contenu de la base).
# --------------------------------------------------------------------------------------

async def answer_general(question: str) -> dict:
    """Répond à une question externe (définition, méthodo, outil, norme, actualité…)."""
    if not enabled():
        return _result(None)
    prompt = (
        "Question posée par un consultant en cybersécurité :\n\n"
        f"« {question.strip()} »\n\n"
        "Réponds directement à cette question avec tes connaissances générales. "
        "Une recherche dans la base interne CyberWatch AI a déjà été effectuée et n'a renvoyé "
        "aucune vulnérabilité correspondante : ne prétends donc PAS citer la base, et n'invente "
        "aucun identifiant CVE, score CVSS, date ni URL que tu ne connais pas avec certitude."
    )
    return _result(await llm.generate(prompt, system=llm.EXTERNAL_SYSTEM, max_tokens=1100))


# --------------------------------------------------------------------------------------
# CVE citée par le consultant mais ABSENTE de la base collectée.
# --------------------------------------------------------------------------------------

async def answer_unknown_cve(cve_id: str, question: str) -> dict:
    """Explique une CVE qui n'a pas (encore) été collectée, en le disant explicitement."""
    if not enabled():
        return _result(None)
    prompt = (
        f"Un consultant interroge l'assistant au sujet de {cve_id}. Cette vulnérabilité n'est "
        "PAS présente dans la base CyberWatch AI (elle n'a pas encore été collectée par les "
        "sources configurées).\n\n"
        f"Question exacte : « {question.strip()} »\n\n"
        "Commence par indiquer clairement que cette CVE ne figure pas dans la base interne. "
        f"Ensuite, si tu connais {cve_id}, décris-la avec tes connaissances propres en "
        "respectant ce plan Markdown :\n"
        "### Statut dans la base CyberWatch AI\n### Description\n### Produits concernés\n"
        "### Sévérité\n### Recommandation\n\n"
        f"Si tu ne connais pas {cve_id} de façon fiable, dis-le franchement et invite à "
        "consulter la fiche NVD (https://nvd.nist.gov/vuln/detail/" + cve_id + ") plutôt que "
        "de produire des valeurs approximatives. N'invente jamais un score CVSS ni une date."
    )
    result = _result(await llm.generate(prompt, system=llm.EXTERNAL_SYSTEM, max_tokens=1100))
    result["scope"] = "external"
    if result["generated_by"] == "unavailable":
        result["answer"] = (
            f"{cve_id} ne figure pas dans la base de connaissances CyberWatch AI (elle n'a pas "
            f"été collectée par les sources configurées). {UNAVAILABLE}")
    return result
