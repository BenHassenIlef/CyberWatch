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

# La clause dit CE QU'ELLE DOIT DIRE : que la reponse ne vient pas de la base. Elle citait
# aussi « score CVSS, version corrigee, date » et « NVD, editeur, CERT » — pertinent sur une
# question de vulnerabilite, absurde sous une reponse qui ne l'est pas. Un avertissement hors
# sujet finit par ne plus etre lu, y compris la fois ou il comptait.
DISCLAIMER = (
    "Cette réponse provient des connaissances générales du modèle d'IA et NON de la base "
    "CyberWatch AI. Aucune donnée interne n'a été utilisée pour la produire : avant toute "
    "décision, recoupez les éléments opérationnels avec une source officielle."
)

# Message renvoyé quand le mode externe est demandé mais indisponible (pas de clé API).
# DEUX CAUSES D'INDISPONIBILITÉ, DEUX MESSAGES — les confondre égare celui qui dépanne.
#
# Un seul message existait, celui de gauche : il invitait à renseigner LLM_PROVIDER et
# LLM_API_KEY. Or il s'affichait AUSSI quand la clé était parfaitement configurée et que le
# fournisseur avait simplement épuisé son quota de la minute. Le consultant lisait alors qu'il
# fallait configurer un modèle déjà configuré, et un administrateur pouvait passer un long
# moment à vérifier un fichier `.env` irréprochable.
NON_CONFIGURE = (
    "Cette information ne figure pas dans la base de connaissances CyberWatch AI, et "
    "l'assistant n'est pas autorisé à répondre hors base (aucun modèle d'IA n'est configuré). "
    "Renseignez LLM_PROVIDER et LLM_API_KEY dans le fichier .env pour activer les réponses "
    "sur des questions générales de cybersécurité."
)

INDISPONIBLE_MOMENTANEMENT = (
    "Cette information ne figure pas dans la base de connaissances CyberWatch AI. Le modèle "
    "d'IA qui répond aux questions hors base est momentanément indisponible — le plus souvent "
    "parce que le quota de requêtes du fournisseur est atteint. Reposez la question dans une "
    "minute : la configuration est correcte, aucune action n'est requise de votre part."
)

# Conservé sous son ancien nom : d'autres modules le référencent pour composer leurs propres
# messages, et cette constante y désigne toujours le cas « pas de modèle configuré ».
UNAVAILABLE = NON_CONFIGURE


def _message_indisponible() -> str:
    """Message correspondant à la cause RÉELLE de l'indisponibilité."""
    return NON_CONFIGURE if not settings.llm_enabled else INDISPONIBLE_MOMENTANEMENT


# BUDGET DE REDACTION d'une reponse hors base.
#
# 1 100 jetons ne suffisaient pas : une question comparative (« difference entre CVE et
# zero-day ») produit plusieurs tableaux, tres couteux en jetons, et la reponse s'arretait
# en plein mot — « 4. **Rec » a l'ecran. Une reponse tronquee est pire qu'une reponse
# courte : le consultant ignore ce qui manquait.
#
# Reste borne : le fournisseur limite le debit a quelques milliers de jetons par MINUTE,
# et un budget illimite se paierait en attente sur la question suivante.
BUDGET_REPONSE = 1700

# SECONDE CHANCE quand la premiere redaction a ete interrompue par le plafond.
#
# Relever le plafond d'emblee serait payer sur CHAQUE question le cout du cas rare : le
# fournisseur borne le debit a 8 000 jetons par minute, et ce credit se paierait en attente
# sur la question suivante. On garde donc un budget courant sobre, et on ne depense le
# supplement que lorsqu'on a la preuve qu'il manquait.
BUDGET_SECONDE_CHANCE = 3200

CONSIGNE_CONCISION = (
    "\n\nIMPORTANT : une premiere redaction a ete interrompue faute de place. Traite la meme "
    "question de facon COMPLETE mais plus dense : va a l'essentiel, limite les tableaux, et "
    "assure-toi d'arriver a la conclusion."
)

AVERTISSEMENT_ECOURTEE = (
    "Le modèle a atteint sa limite de longueur avant d'avoir terminé. Le texte ci-dessus a "
    "été ramené à sa dernière partie complète : rien ne manque au milieu, mais la fin n'a "
    "pas été rédigée. Reposez la question sur un point précis pour obtenir la suite."
)


async def _rediger(prompt: str) -> llm.Reponse:
    """Rédige une réponse hors base, avec UNE seconde chance si la première est interrompue.

    Une seule relance, jamais davantage : au-delà, on ferait patienter le consultant sur un
    budget de débit qui ne reviendrait pas, pour un gain de moins en moins probable.
    """
    reponse = await llm.generer(prompt, system=llm.EXTERNAL_SYSTEM, max_tokens=BUDGET_REPONSE)
    if not (reponse.texte and reponse.tronquee):
        return reponse
    seconde = await llm.generer(prompt + CONSIGNE_CONCISION, system=llm.EXTERNAL_SYSTEM,
                                max_tokens=BUDGET_SECONDE_CHANCE)
    # La seconde tentative disposait d'un budget superieur : si elle a produit du texte, il
    # est au moins aussi complet. Si elle a echoue (debit epuise), la premiere reste utile.
    return seconde if seconde.texte else reponse


def provider_label() -> str:
    return _PROVIDER_LABEL.get(settings.llm_provider, "Modèle d'IA externe")


def enabled() -> bool:
    return settings.external_answers_enabled


def _sections(text: str, ecourtee: bool = False) -> list[dict]:
    """Découpe la réponse en sections ; à défaut, une seule section « Réponse »."""
    sections = _parse_sections(text)
    if not sections:
        sections = [{"title": "Réponse", "body": text.strip()}]
    if ecourtee:
        # Section a part entiere, et non note en bas de page : le consultant doit pouvoir
        # constater l'incompletude sans avoir a comparer la fin du texte a ce qu'il attendait.
        sections = sections + [{"title": "Réponse écourtée", "body": AVERTISSEMENT_ECOURTEE}]
    return sections + [{"title": "Portée de la réponse", "body": DISCLAIMER}]


def _result(reponse: "llm.Reponse | None") -> dict:
    """Enveloppe commune d'une réponse externe (ou du refus si le LLM est indisponible)."""
    text = reponse.texte if reponse else None
    if not text:
        return {"answer": _message_indisponible(), "sections": [], "results": [], "sources": [],
                "confidence": "none", "count": 0, "scope": "external",
                "generated_by": "unavailable"}
    ecourtee = bool(reponse and reponse.tronquee)
    if ecourtee:
        text = llm.couper_proprement(text)
    sections = _sections(text, ecourtee)
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
    return _result(await _rediger(prompt))


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
    result = _result(await _rediger(prompt))
    result["scope"] = "external"
    if result["generated_by"] == "unavailable":
        result["answer"] = (
            f"{cve_id} ne figure pas dans la base de connaissances CyberWatch AI (elle n'a pas "
            f"été collectée par les sources configurées). {_message_indisponible()}")
    return result
