"""Réponses du modèle INTERROMPUES par le plafond de jetons.

Le fournisseur signale dans « finish_reason » qu'il a cessé d'écrire faute de place, et non
parce qu'il avait fini. Cette distinction n'était pas lue : une réponse coupée en plein mot
remontait au consultant avec les mêmes atours qu'une réponse aboutie.

C'est la défaillance la plus coûteuse qui soit, parce qu'elle ne se voit pas. Une panne fait
recommencer ; un plan de mise en conformité amputé de ses trois dernières étapes se lit, se
cite et s'applique — l'absence n'a laissé aucune trace à l'écran.

Aucun appel réseau : l'adaptateur HTTP et la couche LLM sont remplacés.
"""
import httpx
import pytest

from app.backend.services.assistant import external, llm


# --------------------------------------------------------------------------------------
# Outils
# --------------------------------------------------------------------------------------

class FausseReponseHTTP:
    """Réponse du fournisseur, réduite à ce que lit `_chat_completions`."""

    def __init__(self, contenu: str, finish_reason: str):
        self._contenu, self._finish = contenu, finish_reason
        self.headers = {}

    def raise_for_status(self):
        return None

    def json(self):
        return {"choices": [{"message": {"content": self._contenu},
                             "finish_reason": self._finish}],
                "usage": {"total_tokens": 10, "prompt_tokens": 4, "completion_tokens": 6}}


@pytest.fixture
def faux_transport(monkeypatch):
    """Remplace httpx par un client qui rend la réponse voulue, sans réseau."""

    def _installer(contenu: str, finish_reason: str):
        class FauxClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_):
                return False

            async def post(self, *_, **__):
                return FausseReponseHTTP(contenu, finish_reason)

        monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: FauxClient())

    return _installer


@pytest.fixture
def faux_modele(monkeypatch):
    """Remplace `llm.generer` par une suite de réponses prédéfinies, et compte les appels."""

    def _installer(*reponses: llm.Reponse):
        journal = {"appels": [], "budgets": []}
        restantes = list(reponses)

        async def generer(prompt, system=None, max_tokens=None, effort=None):
            journal["appels"].append(prompt)
            journal["budgets"].append(max_tokens)
            return restantes.pop(0) if restantes else llm.Reponse(None)

        monkeypatch.setattr(external.llm, "generer", generer)
        return journal

    return _installer


# --------------------------------------------------------------------------------------
# 1. Lecture de « finish_reason »
# --------------------------------------------------------------------------------------

async def test_une_reponse_interrompue_est_signalee(faux_transport):
    faux_transport("Texte coupé en plein", "length")
    reponse = await llm._chat_completions("sys", "question", 100)
    assert reponse.tronquee is True
    assert reponse.texte == "Texte coupé en plein"


async def test_une_reponse_achevee_n_est_pas_signalee(faux_transport):
    faux_transport("Texte complet.", "stop")
    reponse = await llm._chat_completions("sys", "question", 100)
    assert reponse.tronquee is False


async def test_generate_rend_toujours_une_chaine(faux_transport, monkeypatch):
    """La forme historique reste intacte : sept appelants en dépendent."""
    monkeypatch.setattr(llm.settings, "LLM_PROVIDER", "groq")
    monkeypatch.setattr(type(llm.settings), "llm_enabled", property(lambda _: True))
    faux_transport("Texte complet.", "stop")
    assert await llm.generate("question") == "Texte complet."


# --------------------------------------------------------------------------------------
# 2. Coupure propre du texte interrompu
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize("brut, attendu", [
    # La dernière ligne est celle que le modèle n'a pas fini d'écrire : elle part.
    ("### Plan\n- **NIS2** : registre\n- **PCI** : désigner un **",
     "### Plan\n- **NIS2** : registre"),
    # Un titre sans corps annonce une section que le lecteur chercherait en vain.
    ("### A\nCorps complet.\n\n### B suivante", "### A\nCorps complet."),
    # Réponse d'un seul tenant : pas de ligne à retirer, on coupe à la phrase.
    ("Première phrase complète. Seconde phrase interrom", "Première phrase complète."),
    # Un bloc de code laissé ouvert avalerait toute la suite de la page.
    ("Exemple :\n```bash\nnmap -sV cible\nssh user@", "Exemple :\n```bash\nnmap -sV cible\n```"),
    # Texte déjà achevé : on n'y touche pas.
    ("Phrase une.\nPhrase deux.\n", "Phrase une.\nPhrase deux."),
    # Aucune ponctuation exploitable : mieux vaut rendre le texte que rendre le vide.
    ("motmotmot", "motmotmot"),
    ("", ""),
])
def test_coupure_a_la_derniere_unite_complete(brut, attendu):
    assert llm.couper_proprement(brut) == attendu


def test_le_gras_reste_ouvert_est_referme():
    """Un « ** » orphelin met en gras tout ce qui suit — y compris l'avertissement."""
    assert llm.couper_proprement("Un **mot en gras** puis **autre").count("**") % 2 == 0


# --------------------------------------------------------------------------------------
# 3. Seconde chance
# --------------------------------------------------------------------------------------

async def test_une_reponse_interrompue_declenche_une_relance_plus_large(faux_modele):
    journal = faux_modele(llm.Reponse("début coupé", tronquee=True),
                          llm.Reponse("réponse entière.", tronquee=False))
    reponse = await external._rediger("question")
    assert reponse.texte == "réponse entière."
    assert reponse.tronquee is False
    assert journal["budgets"] == [external.BUDGET_REPONSE, external.BUDGET_SECONDE_CHANCE]


async def test_une_reponse_complete_ne_declenche_aucune_relance(faux_modele):
    """Le supplément de débit ne se dépense que sur preuve qu'il manquait."""
    journal = faux_modele(llm.Reponse("réponse entière.", tronquee=False))
    await external._rediger("question")
    assert len(journal["appels"]) == 1


async def test_la_relance_ne_se_repete_pas(faux_modele):
    """Une seule relance : au-delà, on ferait patienter sur un gain improbable."""
    journal = faux_modele(llm.Reponse("a", tronquee=True), llm.Reponse("b", tronquee=True))
    reponse = await external._rediger("question")
    assert len(journal["appels"]) == 2
    assert reponse.tronquee is True


async def test_la_premiere_reponse_survit_a_l_echec_de_la_relance(faux_modele):
    """Débit épuisé pendant la relance : rendre le texte partiel vaut mieux que rien."""
    faux_modele(llm.Reponse("texte partiel", tronquee=True), llm.Reponse(None))
    reponse = await external._rediger("question")
    assert reponse.texte == "texte partiel"


# --------------------------------------------------------------------------------------
# 4. Ce que voit le consultant
# --------------------------------------------------------------------------------------

def test_une_reponse_ecourtee_le_dit_dans_une_section_dediee():
    resultat = external._result(llm.Reponse("### A\nCorps.\n- item coupé en", tronquee=True))
    titres = [s["title"] for s in resultat["sections"]]
    assert "Réponse écourtée" in titres
    # L'aveu précède la clause de portée : c'est l'information la plus urgente des deux.
    assert titres.index("Réponse écourtée") < titres.index("Portée de la réponse")


def test_une_reponse_ecourtee_ne_montre_pas_le_mot_coupe():
    resultat = external._result(llm.Reponse("### A\nCorps.\n- item coupé en", tronquee=True))
    assert "item coupé en" not in resultat["answer"]


def test_une_reponse_complete_ne_porte_aucun_avertissement():
    resultat = external._result(llm.Reponse("### A\nCorps complet.", tronquee=False))
    assert "Réponse écourtée" not in [s["title"] for s in resultat["sections"]]


def test_l_absence_de_reponse_reste_traitee_comme_avant():
    """Le repli « indisponible » ne doit pas régresser : c'est le seul filet du mode externe."""
    for vide in (None, llm.Reponse(None), llm.Reponse("")):
        assert external._result(vide)["generated_by"] == "unavailable"
