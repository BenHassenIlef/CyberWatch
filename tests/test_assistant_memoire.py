"""MÉMOIRE DE CONVERSATION et LECTURE DU VECTEUR CVSS — la qualité des réponses de l'assistant.

Deux défauts rendaient l'assistant décevant sans que le modèle y soit pour quoi que ce soit :

  1. chaque question était analysée SEULE — « et pour Microsoft ? » arrivait au moteur sans
     éditeur, sans période et sans sévérité, et la recherche repartait de zéro ;
  2. deux sections de la fiche étaient structurellement vides — « Impact » et surtout
     « Exploitation », dont le champ source est vide sur la TOTALITÉ des fiches collectées.

Ces tests verrouillent les deux corrections, et surtout leurs garde-fous : une mémoire qui
réécrit une question autonome, ou un décodage qui invente un impact, feraient plus de dégâts
que l'absence de l'un et de l'autre.

Aucun appel réseau : le modèle de langage est simulé.
"""
import asyncio

import pytest

from app.backend.services.assistant import conversation, cvss, llm


# ---------------------------------------------------------------------------------------
# 1. Détection d'une question de suivi
# ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("question, parsed, attendu, pourquoi", [
    ("et pour Microsoft ?",        {}, True,  "connecteur d'enchaînement"),
    ("et les critiques ?",         {}, True,  "connecteur d'enchaînement"),
    ("explique la première",       {}, True,  "référence à un élément listé plus haut"),
    ("celle-ci est exploitée ?",   {}, True,  "anaphore"),
    ("et hier ?",                  {}, True,  "question très courte sans sujet propre"),
    ("les critiques ?",            {}, True,  "question très courte sans sujet propre"),
    # Cinq mots, mais deux critères propres : la question se comprend seule.
    ("Affiche les CVE critiques d'aujourd'hui",
     {"severity": "critical", "date_from": "2026-08-23"}, False,
     "brève mais porteuse de ses propres critères"),
    ("Explique CVE-2021-44228",
     {"cve_ids": ["CVE-2021-44228"]}, False, "un identifiant CVE est un sujet complet"),
    ("Quelles vulnérabilités affectent Apache ?",
     {"vendor": "Apache"},         False, "un éditeur nommé est un sujet complet"),
])
def test_detection_question_de_suivi(question, parsed, attendu, pourquoi):
    assert conversation.est_question_de_suivi(question, parsed) is attendu, pourquoi


# ---------------------------------------------------------------------------------------
# 2. Condensation — et surtout ses garde-fous
# ---------------------------------------------------------------------------------------

ECHANGES = [{"question": "Affiche les CVE critiques de cette année",
             "answer": "1474 vulnérabilités critiques trouvées."}]


def _modele(reponse):
    async def _generate(prompt, system=None, max_tokens=0):
        return reponse
    return _generate


def test_condensation_produit_une_question_autonome(monkeypatch):
    monkeypatch.setattr(llm, "available", lambda: True)
    monkeypatch.setattr(llm, "generate",
                        _modele("Quelles sont les CVE critiques de cette année chez Microsoft ?"))
    resultat = asyncio.run(conversation.condenser("et pour Microsoft ?", ECHANGES))
    assert resultat == "Quelles sont les CVE critiques de cette année chez Microsoft ?"


@pytest.mark.parametrize("reponse_du_modele, pourquoi", [
    ("", "réponse vide"),
    (None, "aucune réponse"),
    ("Voici la question réécrite :\nQuelles CVE ?", "le modèle a commenté sa tâche"),
    ("x" * 400, "réécriture démesurée — le modèle a divagué"),
])
def test_condensation_retombe_sur_la_question_posee(monkeypatch, reponse_du_modele, pourquoi):
    """Une réécriture douteuse est PIRE que pas de mémoire du tout.

    Sans mémoire, la question manque de contexte et le consultant le voit. Avec une
    réécriture inventée, il reçoit une réponse cohérente à une question qu'il n'a pas posée —
    et rien à l'écran ne lui indique pourquoi.
    """
    monkeypatch.setattr(llm, "available", lambda: True)
    monkeypatch.setattr(llm, "generate", _modele(reponse_du_modele))
    assert asyncio.run(conversation.condenser("et pour Microsoft ?", ECHANGES)) \
        == "et pour Microsoft ?", pourquoi


def test_condensation_sans_modele_ni_historique(monkeypatch):
    monkeypatch.setattr(llm, "available", lambda: False)
    assert asyncio.run(conversation.condenser("et pour Microsoft ?", ECHANGES)) == "et pour Microsoft ?"
    monkeypatch.setattr(llm, "available", lambda: True)
    assert asyncio.run(conversation.condenser("et pour Microsoft ?", [])) == "et pour Microsoft ?"


def test_condensation_absorbe_une_panne_du_modele(monkeypatch):
    async def _explose(prompt, system=None, max_tokens=0):
        raise RuntimeError("fournisseur indisponible")
    monkeypatch.setattr(llm, "available", lambda: True)
    monkeypatch.setattr(llm, "generate", _explose)
    assert asyncio.run(conversation.condenser("et pour Microsoft ?", ECHANGES)) == "et pour Microsoft ?"


def test_historique_borne_et_ordonne():
    """On ne garde que les derniers échanges : au-delà, le contexte coûte sans éclairer."""
    brut = [{"question": f"q{i}", "answer": f"r{i}"} for i in range(10)]
    garde = conversation.normaliser_historique(brut)
    assert len(garde) == conversation.MAX_ECHANGES
    assert garde[-1]["question"] == "q9"          # le plus récent en dernier
    # Un message sans question (incident d'écriture) ne doit pas entrer dans le contexte.
    assert conversation.normaliser_historique([{"answer": "orpheline"}]) == []


# ---------------------------------------------------------------------------------------
# 3. Lecture du vecteur CVSS — décoder n'est pas déduire
# ---------------------------------------------------------------------------------------

def test_vecteur_v3_entierement_decode():
    texte = cvss.impact_lisible("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    assert "à distance depuis le réseau" in texte
    assert "sans aucun privilège préalable" in texte
    assert "confidentialité entièrement compromise" in texte
    assert "déborde du composant" in texte


def test_vecteur_v4_ramene_aux_memes_libelles():
    """CVSS 4.0 renomme les métriques d'impact (VC/VI/VA) : le rendu doit rester identique."""
    v4 = cvss.impact_lisible("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H")
    assert "confidentialité entièrement compromise" in v4
    assert "intégrité entièrement compromise" in v4


def test_vecteur_local_et_peu_severe():
    texte = cvss.impact_lisible("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
    assert "en accès local" in texte and "privilèges élevés" in texte
    assert "aucune atteinte à l'intégrité" in texte
    assert "circonscrit au composant" in texte


@pytest.mark.parametrize("entree", [None, "", "pas un vecteur", "CVSS:3.1/", 42])
def test_vecteur_illisible_ne_produit_rien(entree):
    """Sans vecteur exploitable, on ne raconte RIEN : la section redevient honnêtement vide."""
    assert cvss.impact_lisible(entree) is None


# ---------------------------------------------------------------------------------------
# 4. Exploitation — attestée par les données, jamais supposée
# ---------------------------------------------------------------------------------------

def test_catalogue_kev_reconnu():
    nature, texte = cvss.exploitation(
        {"references": ["https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=X"]})
    assert nature == cvss.KEV
    assert "activement exploitées" in texte


def test_preuve_de_faisabilite_ne_vaut_pas_exploitation_active():
    """Une preuve publique atteste la FAISABILITÉ, pas une campagne en cours.

    Les confondre ferait sur-prioriser des vulnérabilités qui ne sont pas attaquées, au
    détriment de celles qui le sont réellement.
    """
    nature, texte = cvss.exploitation({"references": ["https://www.exploit-db.com/exploits/51234"]})
    assert nature == cvss.POC
    assert "sans établir qu'elle est activement menée" in texte


def test_statut_de_la_source_prioritaire():
    nature, texte = cvss.exploitation(
        {"exploit_status": "Exploitation active confirmée par l'éditeur",
         "references": ["https://www.exploit-db.com/exploits/1"]})
    assert texte == "Exploitation active confirmée par l'éditeur"


@pytest.mark.parametrize("doc", [
    {},
    {"references": []},
    {"references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-1"]},
    {"references": ["https://www.cve.org/CVERecord?id=CVE-2021-1"]},
])
def test_aucune_exploitation_attestee(doc):
    """Une référence NVD ou CVE.org n'atteste rien : ce sont des fiches, pas des constats."""
    assert cvss.exploitation(doc) is None
