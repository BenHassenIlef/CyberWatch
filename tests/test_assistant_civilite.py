"""UN BONJOUR N'EST PAS UNE RECHERCHE.

Le consultant écrit « hello ». L'assistant répondait par une priorisation de trois CVE —
CVE-2026-55953, CVE-2026-61928, CVE-2026-13074 — assortie du bandeau « Confiance : élevée »
et de la mention « Base interne ». Aucune des trois n'avait le moindre rapport avec quoi que
ce soit : « hello » était devenu un mot-clé PRODUIT, et la requête avait trouvé
« Windows Hello » plus deux fiches dont la description contient le mot.

Le cas silencieux était pire. « hi », « ok » et « ça va ? » sont trop courts ou tenus pour
des mots vides : aucun filtre n'en sortait, et la recherche portait alors sur les 11 813 CVE
de la base. L'assistant résumait le catalogue entier à quelqu'un qui avait dit bonjour.

Aucun appel réseau, aucune base : la civilité se tranche avant toute recherche.
"""
import pytest

from app.backend.services.assistant import rag


# ---------------------------------------------------------------------------------------
# 1. Ce qui doit être reconnu comme une civilité
# ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("message", [
    "hello", "Hello", "hello !", "HELLO", "  hello  ",
    "bonjour", "Bonjour !", "bonsoir", "salut", "coucou", "hey", "hi", "yo",
    "good morning", "good evening", "ça va ?", "ca va", "comment ça va ?",
    # SALUTATION EN PLUSIEURS MOTS — c'est la forme qui a été signalée à l'écran.
    # « hello » seul était reconnu, « hello how are you » ne l'était pas : le mot devenait
    # un mot-clé PRODUIT, la requête trouvait « Windows Hello », et l'assistant rendait une
    # priorisation de trois CVE à quelqu'un qui demandait comment il allait.
    "hello how are you", "Hello, how are you?", "hi how are you",
    "bonjour comment ça va", "bonjour, comment ca va ?", "salut ça va ?",
    "hello how are you doing", "bonjour tout va bien ?", "hey quoi de neuf",
    "comment allez-vous ?", "coucou vous êtes là ?",
])
def test_une_salutation_recoit_un_accueil(message):
    reponse = rag._reponse_de_civilite(message)
    assert reponse is not None, f"« {message} » partait en recherche produit"
    assert reponse["answer"] == rag.ACCUEIL


@pytest.mark.parametrize("message", ["merci", "Merci beaucoup", "thanks", "thank you",
                                     "ok", "okay", "d'accord", "parfait", "super"])
def test_un_remerciement_recoit_un_acquiescement(message):
    assert rag._reponse_de_civilite(message)["answer"] == rag.REMERCIEMENT


@pytest.mark.parametrize("message", ["au revoir", "à bientôt", "bye", "goodbye",
                                     "bonne journée", "bonne soirée"])
def test_un_adieu_recoit_un_adieu(message):
    """Répondre « n'hésitez pas si vous avez une autre question » à quelqu'un qui prend
    congé ne répond pas à ce qu'il a dit."""
    assert rag._reponse_de_civilite(message)["answer"] == rag.ADIEU


# ---------------------------------------------------------------------------------------
# 2. Ce qui ne doit JAMAIS l'être — une question polie reste une question
# ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("message", [
    "bonjour, quelles sont les CVE critiques cette semaine ?",
    "Bonjour ! Explique CVE-2026-55953",
    "salut, combien de vulnérabilités Fortinet ?",
    "merci de me lister les CVE de ce mois",
    "hello world plugin vulnerabilite",
    "ok pour les CVE Microsoft ?",
    "Qu'est-ce qu'un score CVSS ?",
    "Les CVE collectées aujourd'hui",
])
def test_une_vraie_question_n_est_jamais_confondue(message):
    """L'ancrage ^…$ est ce qui sépare « bonjour » de « bonjour, les CVE critiques ? »."""
    assert rag._reponse_de_civilite(message) is None


# ---------------------------------------------------------------------------------------
# 3. Ce que voit le consultant
# ---------------------------------------------------------------------------------------

def test_aucune_confiance_n_est_affichee_sur_une_civilite():
    """« Confiance : élevée » sur un bonjour certifie ce qui n'a jamais été cherché.

    L'interface n'affiche le bandeau que si `confidence` est renseignée, et n'affiche
    l'origine que si `generated_by` figure dans sa table — « civilite » n'y est pas.
    """
    reponse = rag._reponse_de_civilite("bonjour")
    assert reponse["confidence"] is None
    assert reponse["generated_by"] == "civilite"
    assert reponse["scope"] == "conversation"


def test_une_civilite_ne_montre_ni_cve_ni_source():
    reponse = rag._reponse_de_civilite("hello")
    assert reponse["results"] == []
    assert reponse["sources"] == []
    assert reponse["count"] == 0


def test_l_accueil_explique_comment_interroger():
    """Un accueil qui n'apprend rien vaut à peine mieux qu'une réponse hors sujet."""
    assert "CVE" in rag.ACCUEIL
    assert rag.ACCUEIL.count("\n- ") >= 3, "l'accueil doit proposer des exemples concrets"


# ---------------------------------------------------------------------------------------
# 4. Aucune recherche déclenchée
# ---------------------------------------------------------------------------------------

class _CollectionInterdite:
    """Toute interrogation de la base sur un bonjour est un défaut."""

    async def count_documents(self, _requete):
        raise AssertionError("une civilité ne doit déclencher aucune requête")

    def find(self, *_a, **_k):
        raise AssertionError("une civilité ne doit déclencher aucune requête")

    async def find_one(self, *_a, **_k):
        raise AssertionError("une civilité ne doit déclencher aucune requête")


class _BaseInterdite:
    cves = _CollectionInterdite()


async def test_une_civilite_n_interroge_pas_la_base():
    reponse = await rag.answer_question(_BaseInterdite(), "hello")
    assert reponse["generated_by"] == "civilite"


async def test_un_mode_explicite_reste_prioritaire():
    """Le bouton « Résumé exécutif » demande un travail sur la base, quel que soit le texte."""
    assert rag._reponse_de_civilite("bonjour") is not None
    with pytest.raises(AssertionError):
        await rag.answer_question(_BaseInterdite(), "bonjour", mode="executive")


# ---------------------------------------------------------------------------------------
# 5. Une question hors sujet mérite une réponse, pas un renvoi
# ---------------------------------------------------------------------------------------
#
# Le prompt externe enfermait le modèle dans la cybersécurité : « adopte le point de vue d'un
# analyste SOC », « utilise tes connaissances générales EN CYBERSÉCURITÉ ». Une question sur
# un footballeur ou sur une capitale se heurtait donc à un refus poli — alors que le
# consultant qui la pose sait très bien ce qu'est cet outil.
#
# Ces tests portent sur le CONTRAT du prompt, pas sur la réponse du modèle : aucun appel
# réseau n'est fait ici.

def test_le_prompt_externe_interdit_le_refus_hors_sujet():
    from app.backend.services.assistant import llm

    consigne = llm.EXTERNAL_SYSTEM.lower()
    assert "jamais un refus" in consigne
    assert "hors sujet" in consigne


def test_la_clause_de_portee_reste_lisible_hors_cybersecurite():
    """Elle citait « score CVSS » et « NVD » : absurde sous une réponse qui n'en parle pas.

    Un avertissement hors sujet finit par ne plus être lu — y compris la fois où il compte.
    """
    from app.backend.services.assistant import external

    assert "CVSS" not in external.DISCLAIMER
    assert "NVD" not in external.DISCLAIMER
    # Ce qu'elle doit continuer de dire, en revanche : la réponse ne vient pas de la base.
    assert "NON de la base" in external.DISCLAIMER
