"""ÉTAT DU CHAMP « Solution / Correctif » — trois situations, jamais confondues.

LA FAUTE CORRIGÉE

Une fiche sans remédiation affichait :

    « Non disponible — aucune source officielle ne prescrit de remédiation. »

C'est une AFFIRMATION FACTUELLE. Or, dans l'immense majorité des cas, l'application n'avait
tout simplement pas lu les avis de l'éditeur : elle ne pouvait rien affirmer. Sur 11 448
fiches, 7 331 portaient cette phrase et 2 seulement reposaient sur une lecture réelle.

Un consultant y lisait « l'éditeur n'a rien publié » et pouvait renoncer à chercher un
correctif qui existe. Une donnée absente n'est pas une donnée négative.

LES TROIS ÉTATS

    DISPONIBLE            une remédiation vérifiée existe : on l'affiche, avec sa source.
    EXTRACTION_INCOMPLETE aucune remédiation en base, et les sources n'ont pas été lues de
                          façon concluante. On dit que l'INFORMATION MANQUE, pas qu'elle
                          n'existe pas.
    AUCUN_CORRECTIF       les pages officielles ONT été lues et n'en décrivent aucune.
                          C'est le seul cas où une affirmation est légitime.

Ce module est la source unique de vérité : la fiche, le bulletin et le PDF s'y réfèrent tous,
pour qu'une même vulnérabilité ne reçoive pas trois réponses différentes selon l'écran.
"""

DISPONIBLE = "disponible"
EXTRACTION_INCOMPLETE = "extraction_incomplete"
AUCUN_CORRECTIF = "aucun_correctif"

MESSAGES = {
    EXTRACTION_INCOMPLETE:
        "Les informations de remédiation n'ont pas pu être extraites de manière fiable.",
    AUCUN_CORRECTIF:
        "Aucun correctif ou mesure de remédiation officielle identifié.",
}

# Statut de synthèse signifiant que les pages officielles ont RÉELLEMENT été lues.
_LECTURE_ABOUTIE = "completed"


def etat(cve: dict) -> str:
    """État du champ pour cette fiche. Ne lève jamais, ne modifie rien."""
    synthese = cve.get("deep_synthesis") or {}
    if (synthese.get("solution") or "").strip() or (cve.get("solution") or "").strip():
        return DISPONIBLE
    # Sans lecture aboutie des pages officielles, rien ne permet de conclure à l'absence
    # de correctif : l'information manque, un point c'est tout.
    if synthese.get("status") == _LECTURE_ABOUTIE:
        return AUCUN_CORRECTIF
    return EXTRACTION_INCOMPLETE


def texte(cve: dict) -> str | None:
    """Remédiation à afficher, ou None quand il n'y en a pas.

    La solution RÉSOLUE prime : elle provient de la lecture des pages officielles et porte
    l'attribution de sa source, alors que celle recopiée d'une page de collecte n'en a
    souvent aucune.
    """
    synthese = cve.get("deep_synthesis") or {}
    return ((synthese.get("solution") or "").strip()
            or (cve.get("solution") or "").strip() or None)


def source(cve: dict) -> dict | None:
    """Page qui PRESCRIT la remédiation affichée, quand elle est connue."""
    synthese = cve.get("deep_synthesis") or {}
    if (synthese.get("solution") or "").strip():
        return synthese.get("solution_source") or None
    return None


def message(cve: dict) -> str | None:
    """Phrase à afficher lorsqu'aucune remédiation n'est disponible."""
    return MESSAGES.get(etat(cve))


def resume(cve: dict) -> dict:
    """Vue complète du champ, prête à être rendue par n'importe quel support."""
    situation = etat(cve)
    return {"status": situation,
            "text": texte(cve),
            "source": source(cve),
            "message": MESSAGES.get(situation)}
