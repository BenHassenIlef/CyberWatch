"""Résolution de la MEILLEURE solution : budget d'envoi, reprise sur quota, non-invention.

Ces trois garde-fous répondent à une exigence unique : la remédiation affichée dans la fiche
et le bulletin doit être VRAIE, ATTRIBUÉE et EN FRANÇAIS — ou absente. Jamais approximative.
"""
import httpx
import pytest

from app.backend.services.assistant import deep_synthesis as ds
from app.backend.services.assistant import llm
from app.backend.services.collection import translation


def _pages(n, taille):
    return [{"url": f"https://exemple.test/{i}", "source": f"src{i}", "texte": "x" * taille}
            for i in range(n)]


# ---------------------------------------------------------------------------------------
# Budget d'envoi — un prompt trop volumineux faisait répondre « 413 Payload Too Large »
# et la synthèse échouait ENTIÈREMENT : aucune solution, pour une raison purement technique.
# ---------------------------------------------------------------------------------------

def test_budget_respecte_le_plafond():
    retenues = ds._budget(_pages(6, 6000))
    assert sum(len(p["texte"]) for p in retenues) <= ds.MAX_TOTAL_TEXT


def test_budget_preserve_la_page_la_plus_autoritaire():
    """`select_pages` classe par autorité : la première page doit rester intacte."""
    retenues = ds._budget(_pages(6, 6000))
    assert retenues[0]["texte"] == "x" * 6000
    assert retenues[0]["url"] == "https://exemple.test/0"


def test_budget_ne_tronque_pas_ce_qui_tient_deja():
    pages = _pages(2, 1000)
    assert ds._budget(pages) == pages


def test_budget_ignore_les_miettes():
    """Sous 500 caractères restants, un extrait n'apprend plus rien : on s'arrête."""
    retenues = ds._budget(_pages(40, 1000))
    assert len(retenues) < 40


def test_budget_supporte_une_page_vide():
    assert ds._budget([{"url": "u", "source": "s", "texte": None}])[0]["texte"] == ""


# ---------------------------------------------------------------------------------------
# Reprise sur limite de débit — un « 429 » est transitoire ; sans reprise, la fonctionnalité
# retombait en mode dégradé alors qu'il suffisait d'attendre quelques secondes.
# ---------------------------------------------------------------------------------------

def _erreur(code, retry_after=None):
    entetes = {"retry-after": retry_after} if retry_after else {}
    reponse = httpx.Response(code, headers=entetes,
                             request=httpx.Request("POST", "https://exemple.test"))
    return httpx.HTTPStatusError("x", request=reponse.request, response=reponse)


@pytest.mark.parametrize("code", [429, 500, 502, 503])
def test_reprise_sur_erreurs_transitoires(code):
    assert llm._delai_avant_reprise(_erreur(code), 1) is not None


@pytest.mark.parametrize("code", [400, 401, 403, 404, 413, 422])
def test_pas_de_reprise_sur_erreurs_definitives(code):
    """Une clé invalide ou une charge trop grande se reproduirait à l'identique."""
    assert llm._delai_avant_reprise(_erreur(code), 1) is None


def test_retry_after_du_serveur_est_respecte():
    assert llm._delai_avant_reprise(_erreur(429, "5"), 1) == 5.0


def test_quota_epuise_abandonne_sans_reessayer():
    """Un delai annonce tres long signale un quota QUOTIDIEN epuise, pas un pic de trafic.

    Le fournisseur repond alors « try again in 19m40s » : reessayer trois fois echouerait a
    l identique en bloquant l appelant. On rend la main immediatement.
    """
    assert llm._delai_avant_reprise(_erreur(429, "1181"), 1) is None


def test_delai_court_annonce_est_respecte_tel_quel():
    assert llm._delai_avant_reprise(_erreur(429, "12"), 1) == 12.0


def test_retry_after_illisible_retombe_sur_le_defaut():
    assert llm._delai_avant_reprise(_erreur(429, "bientot"), 1) == llm.ATTENTE_PAR_DEFAUT


def test_attente_croissante_entre_tentatives():
    d1 = llm._delai_avant_reprise(_erreur(429), 1)
    d2 = llm._delai_avant_reprise(_erreur(429), 2)
    assert d2 > d1


def test_erreur_sans_reponse_http_nest_pas_reessayee():
    assert llm._delai_avant_reprise(ValueError("panne"), 1) is None


# ---------------------------------------------------------------------------------------
# Non-invention — le champ le plus dangereux de la fiche. Une version corrective inventée
# enverrait un consultant appliquer un correctif qui n'existe pas.
# ---------------------------------------------------------------------------------------

CORPUS = ("Red Hat build of Keycloak 26.6.6 fixes CVE-2026-15571. "
          "See https://access.redhat.com/errata/RHSA-2026:56523 for details.")


def test_traduction_fidele_acceptee():
    """Traduire n'est pas inventer : la solution française fidèle doit passer."""
    ok, _ = translation.validate("Mettre à jour vers Keycloak 26.6.6.", CORPUS)
    assert ok


def test_version_inventee_rejetee():
    ok, inventes = translation.validate("Mettre à jour vers Keycloak 27.9.9.", CORPUS)
    assert not ok and inventes


def test_identifiant_invente_rejete():
    ok, _ = translation.validate("Correctif publié pour CVE-2099-99999.", CORPUS)
    assert not ok


def test_url_inventee_rejetee():
    ok, _ = translation.validate("Voir https://exemple-invente.test/patch", CORPUS)
    assert not ok


def test_url_reelle_conservee_acceptee():
    ok, _ = translation.validate(
        "Voir https://access.redhat.com/errata/RHSA-2026:56523", CORPUS)
    assert ok


# ---------------------------------------------------------------------------------------
# Consigne de rédaction — l'application doit être intégralement en français, y compris
# les remédiations issues de pages éditeur anglophones.
# ---------------------------------------------------------------------------------------

def test_consigne_impose_le_francais_pour_la_solution():
    assert "REDIGEE EN FRANCAIS" in ds.SYNTHESIS_SYSTEM


def test_consigne_interdit_le_conseil_generique():
    assert "generique" in ds.SYNTHESIS_SYSTEM


def test_consigne_exige_une_url_de_source():
    assert "solution_source_url" in ds.SYNTHESIS_SYSTEM
