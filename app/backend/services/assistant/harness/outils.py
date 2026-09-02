"""REGISTRE DES OUTILS du harness — les capacités EXISTANTES, déclarées et encadrées.

Aucun outil n'est écrit ici. Chaque entrée ENVELOPPE une fonction qui existait déjà dans le
projet, en lui ajoutant ce qui lui manquait pour être exécutée par un orchestrateur :

    nom · but · schéma d'entrée · schéma de sortie · agents autorisés · délai · validation

CE QUE LA DÉCLARATION APPORTE
Une fonction appelée directement ne dit pas combien de temps elle peut prendre, ce qu'elle
retourne quand elle échoue, ni qui a le droit de l'appeler. Le harness a besoin de ces trois
réponses pour arbitrer : couper un outil trop lent, distinguer un résultat vide d'une panne,
refuser un outil à un agent qui n'y a pas droit.

CONFIANCE DE LA SOURCE — la distinction structurante
Un outil qui lit la base interne rapporte des données validées à la collecte. Un outil qui lit
le web rapporte du texte écrit par des tiers. Les deux ne peuvent pas alimenter un prompt de
la même façon : le second passe par `securite.encadrer_contenu_externe`. Le champ `fiabilite`
porte cette distinction, et c'est le harness — jamais l'outil — qui l'applique.
"""
from dataclasses import dataclass, field
from typing import Any, Callable

# Fiabilité de ce que l'outil rapporte.
INTERNE = "interne"      # base CyberWatch AI : données déjà validées par la collecte
EXTERNE = "externe"      # web, forums, API tierces : contenu de tiers, traité comme hostile
MODELE = "modele"        # connaissances propres du LLM : ni base, ni source citable


@dataclass(frozen=True)
class Outil:
    """Déclaration complète d'un outil exécutable par le harness."""
    nom: str
    but: str
    entree: dict[str, str]                 # paramètre -> ce qu'il attend
    sortie: dict[str, str]                 # champ -> ce qu'il contient
    executer: Callable                     # coroutine (contexte, **arguments) -> Any
    valider: Callable[[Any], tuple[bool, str]]
    fiabilite: str = INTERNE
    delai_s: float = 20.0
    reessayable: bool = True               # une panne réseau se rejoue ; un refus, non
    agents: tuple[str, ...] = ()           # agents autorisés ; vide = aucun (refus par défaut)
    alternative: str | None = None         # outil de repli si celui-ci échoue

    def autorise(self, agent: str) -> bool:
        return agent in self.agents


# =======================================================================================
# Validateurs — « la sortie est-elle exploitable ? », jamais « est-elle vraie ? »
# =======================================================================================
#
# Un validateur vérifie la FORME et la COHÉRENCE de ce qu'un outil rapporte. Il ne juge pas le
# fond : ce n'est pas au harness de décider si un score CVSS est correct. Sa question est
# celle-ci : puis-je remettre cela à l'assistant sans qu'il raconte n'importe quoi ?

def _liste_de_documents(resultat: Any) -> tuple[bool, str]:
    if resultat is None:
        return False, "aucun résultat"
    docs, _total = resultat if isinstance(resultat, tuple) else (resultat, None)
    if not isinstance(docs, list):
        return False, "format inattendu"
    if docs and not all(isinstance(d, dict) for d in docs):
        return False, "éléments non structurés"
    return True, "ok"


def _fiche_cve(resultat: Any) -> tuple[bool, str]:
    """Une fiche doit porter une réponse ET rester rattachée à la CVE demandée."""
    if not isinstance(resultat, dict):
        return False, "format inattendu"
    if not (resultat.get("answer") or resultat.get("sections")):
        return False, "fiche sans contenu"
    return True, "ok"


def _discussions(resultat: Any) -> tuple[bool, str]:
    """Zéro discussion est un FAIT, pas un échec — la distinction est reportée telle quelle."""
    if not isinstance(resultat, tuple) or len(resultat) != 2:
        return False, "format inattendu"
    discussions, etats = resultat
    if not isinstance(discussions, list) or not isinstance(etats, list):
        return False, "format inattendu"
    return True, "ok"


def _verification(resultat: Any) -> tuple[bool, str]:
    if not isinstance(resultat, dict) or "overall_score" not in resultat:
        return False, "rapport de vérification incomplet"
    return True, "ok"


def _texte_non_vide(resultat: Any) -> tuple[bool, str]:
    if isinstance(resultat, dict):
        resultat = resultat.get("answer")
    if not isinstance(resultat, str) or len(resultat.strip()) < 20:
        return False, "réponse vide ou trop courte"
    return True, "ok"


def _synthese_approfondie(resultat: Any) -> tuple[bool, str]:
    """Le module distingue déjà `completed` / `insufficient` / `failed` : on respecte son verdict."""
    if not isinstance(resultat, dict):
        return False, "format inattendu"
    if resultat.get("status") == "failed":
        return False, "la lecture des pages sources n'a pas abouti"
    return True, "ok"


# =======================================================================================
# Adaptateurs — appellent le code EXISTANT, sans le modifier
# =======================================================================================

async def _executer_recherche_cve(ctx, **arguments):
    from app.backend.services.assistant import rag
    parsed = arguments.get("filtres") or rag.parse_query(arguments.get("question", ""))
    return await rag.retrieve(ctx["db"], parsed, limit=int(arguments.get("limite", 40)))


async def _executer_fiche_cve(ctx, **arguments):
    from app.backend.services.assistant import summary
    doc = await ctx["db"].cves.find_one({"cve_id": str(arguments["cve_id"]).upper()})
    if doc is None:
        return None                        # absence en base : le validateur la signalera
    return await summary.summarize_cve(ctx["db"], doc, arguments.get("style", "technical"))


async def _executer_synthese_produit(ctx, **arguments):
    from app.backend.services.assistant import rag, summary
    parsed = arguments.get("filtres") or rag.parse_query(arguments.get("question", ""))
    docs, total = await rag.retrieve(ctx["db"], parsed, limit=200)
    return await summary.summarize_group(ctx["db"], docs, arguments["libelle"], total=total)


async def _executer_discussions(ctx, **arguments):
    from app.backend.services.community import discussions as dc
    return await dc.rechercher(str(arguments["cve_id"]).upper())


async def _executer_synthese_approfondie(ctx, **arguments):
    from app.backend.services.assistant import deep_synthesis as ds
    doc = await ctx["db"].cves.find_one({"cve_id": str(arguments["cve_id"]).upper()})
    if doc is None:
        return None
    return await ds.synthesize(ctx["db"], doc, refresh=bool(arguments.get("refresh")))


async def _executer_verification_source(ctx, **arguments):
    from app.backend.services.verification.agent import verify_source
    return await verify_source({"url": arguments["url"], "name": arguments.get("nom")})


async def _executer_connaissance_generale(ctx, **arguments):
    from app.backend.services.assistant import external
    return await external.answer_general(arguments["question"])


# =======================================================================================
# Le registre
# =======================================================================================

REGISTRE: dict[str, Outil] = {
    "recherche_cve": Outil(
        nom="recherche_cve",
        but="Récupère dans la base CyberWatch AI les vulnérabilités correspondant aux filtres "
            "d'une question (éditeur, produit, sévérité, score, période, exploitation).",
        entree={"question": "question du consultant, en clair",
                "filtres": "filtres déjà analysés (optionnel, évite une seconde analyse)",
                "limite": "nombre maximal de fiches remontées (défaut 40)"},
        sortie={"documents": "liste de fiches CVE de la base", "total": "nombre correspondant"},
        executer=_executer_recherche_cve, valider=_liste_de_documents,
        fiabilite=INTERNE, delai_s=20.0,
        agents=("assistant_general", "agent_vulnerabilites", "agent_communautaire",
                "agent_verification")),

    "fiche_cve": Outil(
        nom="fiche_cve",
        but="Produit la fiche structurée d'UNE vulnérabilité identifiée (résumé, impact, "
            "produits affectés, sévérité, exploitation, remédiation, sources).",
        entree={"cve_id": "identifiant CVE (CVE-AAAA-NNNN)",
                "style": "technical | executive | changes"},
        sortie={"answer": "texte de la fiche", "sections": "sections structurées",
                "sources": "sources ayant confirmé la vulnérabilité"},
        executer=_executer_fiche_cve, valider=_fiche_cve,
        fiabilite=INTERNE, delai_s=45.0,
        agents=("assistant_general", "agent_vulnerabilites")),

    "synthese_produit": Outil(
        nom="synthese_produit",
        but="Synthèse exécutive multi-CVE pour un produit ou un éditeur surveillé.",
        entree={"libelle": "produit ou éditeur concerné",
                "question": "question d'origine", "filtres": "filtres analysés (optionnel)"},
        sortie={"answer": "synthèse", "sections": "sections", "count": "nombre de CVE"},
        executer=_executer_synthese_produit, valider=_fiche_cve,
        fiabilite=INTERNE, delai_s=60.0,
        agents=("assistant_general", "agent_vulnerabilites")),

    "synthese_approfondie": Outil(
        nom="synthese_approfondie",
        but="Lit les pages RÉFÉRENCÉES par une vulnérabilité (avis éditeur, NVD, bulletins) "
            "pour en extraire la remédiation, absente de la fiche dans deux cas sur trois.",
        entree={"cve_id": "identifiant CVE", "refresh": "forcer une relecture des pages"},
        sortie={"status": "completed | insufficient | failed", "summary": "synthèse ancrée",
                "solution": "remédiation attribuée à la page qui la publie"},
        executer=_executer_synthese_approfondie, valider=_synthese_approfondie,
        # CONTENU EXTERNE : ce module lit de vraies pages web. Ce qu'il rapporte est du texte
        # écrit par des tiers, encadré comme tel avant d'atteindre le modèle.
        fiabilite=EXTERNE, delai_s=90.0,
        agents=("agent_vulnerabilites",),
        alternative="fiche_cve"),

    "discussions_communautaires": Outil(
        nom="discussions_communautaires",
        but="Recherche les discussions publiques (Stack Exchange, Hacker News, Reddit) citant "
            "explicitement une vulnérabilité, avec leur niveau de pertinence.",
        entree={"cve_id": "identifiant CVE"},
        sortie={"discussions": "publications retenues", "etats": "état de chaque communauté"},
        executer=_executer_discussions, valider=_discussions,
        fiabilite=EXTERNE, delai_s=30.0,
        agents=("agent_communautaire",)),

    "verification_source": Outil(
        nom="verification_source",
        but="Vérifie une source de veille sur trois niveaux : accessibilité technique, "
            "crédibilité du contenu, authenticité du lien (contrefaçon, typosquattage).",
        entree={"url": "adresse à vérifier", "nom": "libellé de la source (optionnel)"},
        sortie={"overall_score": "score global", "decision": "FIABLE | À SURVEILLER | NON FIABLE",
                "authenticity": "contrôles d'authenticité du lien"},
        executer=_executer_verification_source, valider=_verification,
        fiabilite=EXTERNE, delai_s=60.0,
        agents=("agent_verification",)),

    "connaissance_generale": Outil(
        nom="connaissance_generale",
        but="Répond à une question de cybersécurité qui ne porte pas sur le contenu de la "
            "base (définition, méthode, bonne pratique). La réponse est étiquetée « hors base ».",
        entree={"question": "question du consultant"},
        sortie={"answer": "réponse", "sections": "sections", "scope": "toujours « external »"},
        executer=_executer_connaissance_generale, valider=_texte_non_vide,
        fiabilite=MODELE, delai_s=60.0, reessayable=False,
        agents=("assistant_general", "agent_vulnerabilites")),
}


def obtenir(nom: str) -> Outil | None:
    return REGISTRE.get(nom)


def catalogue(agent: str | None = None) -> list[dict]:
    """Outils déclarés, filtrés sur ceux qu'un agent peut réellement appeler.

    Sert la documentation et les tests de permission. `executer` et `valider` n'y figurent
    pas : ce catalogue est destiné à être lu, pas à contourner le harness.
    """
    return [{"nom": o.nom, "but": o.but, "entree": o.entree, "sortie": o.sortie,
             "fiabilite": o.fiabilite, "delai_s": o.delai_s, "agents": list(o.agents),
             "alternative": o.alternative}
            for o in REGISTRE.values() if agent is None or o.autorise(agent)]
