"""Tests de l'agent de traduction (anglais -> français).

Aucun appel réseau : l'adaptateur LLM est remplacé par une fausse implémentation, ce qui permet
de couvrir aussi les cas de panne (timeout, JSON invalide, réponse incomplète).
"""
import json

import pytest

from app.backend.services.collection import translation as tr


# --------------------------------------------------------------------------------------
# Outils : faux LLM
# --------------------------------------------------------------------------------------

class FakeLLM:
    """Remplace `llm.generate` / `llm.available` le temps d'un test."""

    def __init__(self, reponse=None, disponible=True, exception=None):
        self.reponse, self.disponible, self.exception = reponse, disponible, exception
        self.appels = 0

    async def generate(self, prompt, system=None, max_tokens=None):
        self.appels += 1
        if self.exception:
            raise self.exception
        if callable(self.reponse):
            return self.reponse(prompt)
        return self.reponse

    def available(self):
        return self.disponible


@pytest.fixture
def faux_llm(monkeypatch):
    def _installer(**kwargs):
        fake = FakeLLM(**kwargs)
        monkeypatch.setattr(tr.llm, "generate", fake.generate)
        monkeypatch.setattr(tr.llm, "available", fake.available)
        return fake
    return _installer


CVE_EN = {
    "cve_id": "CVE-2026-68820",
    "title": "Buffer overflow in Microsoft Outlook",
    "description": ("A heap-based buffer overflow in Microsoft Outlook 2019 before version "
                    "16.0.1 allows a remote attacker to execute arbitrary code. See "
                    "https://msrc.microsoft.com/update-guide for details. This is CWE-787."),
}


# --------------------------------------------------------------------------------------
# 1. Traduction nominale
# --------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_traduction_anglais_vers_francais(faux_llm):
    fake = faux_llm(reponse=json.dumps({
        "title": "Dépassement de tampon dans Microsoft Outlook",
        "description": ("Un dépassement de tampon dans le tas de Microsoft Outlook 2019 avant la "
                        "version 16.0.1 permet à un attaquant distant d'exécuter du code "
                        "arbitraire. Voir https://msrc.microsoft.com/update-guide pour les "
                        "détails. Il s'agit de CWE-787."),
    }, ensure_ascii=False))

    res = await tr.translate_record(dict(CVE_EN))

    assert res["translation_status"] == tr.COMPLETED
    assert res["title_fr"].startswith("Dépassement")
    assert "attaquant distant" in res["description_fr"]
    assert fake.appels == 1, "un SEUL appel LLM par CVE (tous les champs groupés)"


# --------------------------------------------------------------------------------------
# 2 & 3. Pas de traduction inutile
# --------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cve_deja_en_francais_non_traduite(faux_llm):
    fake = faux_llm(reponse="{}")
    rec = {"cve_id": "CVE-2026-1", "title": "Élévation de privilèges dans le noyau Linux",
           "description": ("Une vulnérabilité permet à un attaquant local d'obtenir les droits "
                           "administrateur sur les systèmes affectés par cette faille.")}

    res = await tr.translate_record(rec)

    assert res["translation_status"] == tr.NOT_REQUIRED
    assert fake.appels == 0, "aucun appel LLM pour un contenu déjà français"


@pytest.mark.asyncio
async def test_cve_deja_traduite_ignoree(faux_llm):
    fake = faux_llm(reponse="{}")
    rec = {**CVE_EN, "translation_status": tr.COMPLETED, "title_fr": "Déjà traduit"}

    assert tr.already_translated(rec) is True
    assert await tr.translate_record(rec) == {}
    assert fake.appels == 0


@pytest.mark.asyncio
async def test_statut_completed_sans_champ_fr_est_retraduit(faux_llm):
    """« completed » sans aucun champ français est incohérent : on retraduit."""
    faux_llm(reponse=json.dumps({"title": "Titre traduit", "description":
                                 "Description traduite suffisamment longue pour le test."}))
    rec = {**CVE_EN, "translation_status": tr.COMPLETED}

    assert tr.already_translated(rec) is False
    assert (await tr.translate_record(rec))["translation_status"] == tr.COMPLETED


# --------------------------------------------------------------------------------------
# 4, 5, 15. Pannes
# --------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_llm_indisponible(faux_llm):
    faux_llm(disponible=False)
    res = await tr.translate_record(dict(CVE_EN))
    assert res["translation_status"] == tr.FAILED
    assert "title_fr" not in res


@pytest.mark.asyncio
async def test_reponse_json_invalide(faux_llm):
    faux_llm(reponse="Voici la traduction : bonjour !")
    res = await tr.translate_record(dict(CVE_EN))
    assert res["translation_status"] == tr.FAILED


@pytest.mark.asyncio
async def test_reponse_vide(faux_llm):
    faux_llm(reponse=None)
    assert (await tr.translate_record(dict(CVE_EN)))["translation_status"] == tr.FAILED


@pytest.mark.asyncio
async def test_json_dans_bloc_de_code(faux_llm):
    """Le modèle encadre souvent sa réponse d'un bloc ```json : on doit le tolérer."""
    faux_llm(reponse='```json\n{"title": "Dépassement de tampon dans Microsoft Outlook"}\n```')
    res = await tr.translate_record(dict(CVE_EN))
    assert res["translation_status"] == tr.COMPLETED
    assert res["title_fr"] == "Dépassement de tampon dans Microsoft Outlook"


@pytest.mark.asyncio
async def test_reponse_incomplete_conserve_ce_qui_est_valide(faux_llm):
    """Un seul champ traduit sur deux : on garde ce champ, l'autre reste en anglais."""
    faux_llm(reponse=json.dumps({"title": "Dépassement de tampon dans Microsoft Outlook"}))
    res = await tr.translate_record(dict(CVE_EN))
    assert res["translation_status"] == tr.COMPLETED
    assert "title_fr" in res and "description_fr" not in res


@pytest.mark.asyncio
async def test_nouvelle_tentative(faux_llm):
    """Premier appel illisible, second correct -> la traduction aboutit."""
    etat = {"n": 0}

    def _reponse(_prompt):
        etat["n"] += 1
        return "pas du json" if etat["n"] == 1 else json.dumps({"title": "Titre traduit"})

    fake = faux_llm(reponse=_reponse)
    res = await tr.translate_record(dict(CVE_EN), retries=1)
    assert res["translation_status"] == tr.COMPLETED
    assert fake.appels == 2


@pytest.mark.asyncio
async def test_exception_reseau_ne_casse_pas_le_lot(faux_llm):
    faux_llm(exception=TimeoutError("délai dépassé"))
    lot = [dict(CVE_EN)]
    stats = await tr.translate_batch(lot)
    assert stats["failed"] == 1
    assert lot[0]["translation_status"] == tr.FAILED
    assert lot[0]["description"] == CVE_EN["description"], "l'original est intact"


# --------------------------------------------------------------------------------------
# 6-9, 14. Préservation des informations techniques
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize("source,traduit,valide", [
    ("Affects CVE-2026-68820", "Concerne CVE-2026-68820", True),
    ("Affects CVE-2026-68820", "Concerne CVE-2026-68821", False),      # identifiant altéré
    ("This is CWE-787", "Il s'agit de CWE-787", True),
    ("This is CWE-787", "Il s'agit d'un dépassement", False),          # CWE perdu
    ("See https://nvd.nist.gov/x", "Voir https://nvd.nist.gov/x", True),
    ("See https://nvd.nist.gov/x", "Voir le site du NVD", False),      # URL perdue
    ("Before version 16.0.1", "Avant la version 16.0.1", True),
    ("Before version 16.0.1", "Avant la version 16.0.2", False),       # version altérée
    ("CVSS:3.1/AV:N/AC:L", "CVSS:3.1/AV:N/AC:L", True),
])
def test_validation_des_valeurs_techniques(source, traduit, valide):
    assert tr.validate(source, traduit)[0] is valide


@pytest.mark.asyncio
async def test_champ_avec_technique_alteree_est_rejete(faux_llm):
    """Le score/identifiant est modifié : le champ est écarté, l'original reste affiché."""
    faux_llm(reponse=json.dumps({
        "title": "Dépassement de tampon dans Microsoft Outlook",
        "description": "Un dépassement affecte Microsoft Outlook 2019 avant la version 99.9.9.",
    }, ensure_ascii=False))

    res = await tr.translate_record(dict(CVE_EN))

    assert "description_fr" not in res, "traduction altérant une version -> rejetée"
    assert res["title_fr"]
    assert "translation_warning" in res


@pytest.mark.asyncio
async def test_produits_multiples_preserves(faux_llm):
    src = ("Affects Windows 11, Microsoft Outlook 2019 and Apache Tomcat 9.0.50 "
           "as described in the vendor advisory published recently.")
    faux_llm(reponse=json.dumps({
        "description": ("Affecte Windows 11, Microsoft Outlook 2019 et Apache Tomcat 9.0.50 "
                        "comme décrit dans l'avis de l'éditeur publié récemment."),
    }, ensure_ascii=False))
    res = await tr.translate_record({"cve_id": "CVE-2026-2", "description": src})
    assert res["translation_status"] == tr.COMPLETED
    for produit in ("Windows 11", "Microsoft Outlook 2019", "Apache Tomcat 9.0.50"):
        assert produit in res["description_fr"]


# --------------------------------------------------------------------------------------
# 10, 11, 12. Lot, repli d'affichage
# --------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_lot_mixte(faux_llm):
    faux_llm(reponse=json.dumps({"title": "Titre traduit", "description":
                                 "Description traduite assez longue pour être retenue."}))
    lot = [
        dict(CVE_EN),                                                     # à traduire
        {**CVE_EN, "cve_id": "CVE-2026-3", "translation_status": tr.COMPLETED,
         "title_fr": "déjà"},                                             # ignorée
        {"cve_id": "CVE-2026-4", "title": "Faille dans le noyau",
         "description": "Une vulnérabilité permet à un attaquant local d'élever ses privilèges "
                        "sur les systèmes concernés par cette faille."},  # déjà en français
    ]
    stats = await tr.translate_batch(lot)
    assert stats == {"translated": 1, "not_required": 1, "failed": 0, "skipped": 1}


def test_repli_sur_original_quand_pas_de_traduction():
    rec = {"title": "Buffer overflow", "description": "An attacker can..."}
    assert tr.localized(rec, "title") == "Buffer overflow"
    assert tr.apply_localization(rec)["title"] == "Buffer overflow"


def test_affichage_privilegie_le_francais_et_conserve_l_original():
    rec = {"title": "Buffer overflow", "title_fr": "Dépassement de tampon"}
    out = tr.apply_localization(rec)
    assert out["title"] == "Dépassement de tampon"
    assert out["title_original"] == "Buffer overflow"


def test_champ_vide_jamais_affiche_a_cause_d_un_echec():
    rec = {"title": "Buffer overflow", "translation_status": tr.FAILED}
    out = tr.apply_localization(rec)
    assert out["title"] == "Buffer overflow"


# --------------------------------------------------------------------------------------
# Détection de langue
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize("texte,anglais", [
    ("A remote attacker could execute arbitrary code on the affected system.", True),
    ("Un attaquant distant pourrait exécuter du code arbitraire sur le système affecté.", False),
    ("CVE-2026-1", False),        # trop court pour trancher
    ("", False),
])
def test_detection_langue(texte, anglais):
    assert tr.looks_english(texte) is anglais
