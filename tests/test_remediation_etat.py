"""Solution / Correctif : une donnée absente n'est pas une donnée négative.

LA FAUTE CORRIGÉE

Toute fiche sans remédiation affichait :

    « Non disponible — aucune source officielle ne prescrit de remédiation. »

C'est une AFFIRMATION. Sur 11 448 fiches, 7 331 la portaient — et 2 seulement reposaient sur
une lecture effective des pages officielles. Un consultant y lisait « l'éditeur n'a rien
publié » et pouvait renoncer à chercher un correctif qui existe.

TROIS ÉTATS, JAMAIS CONFONDUS

    disponible              une remédiation vérifiée existe
    extraction_incomplete   les sources n'ont pas été lues de façon concluante
    aucun_correctif         elles l'ont été, et n'en décrivent aucune

Seul le troisième autorise une affirmation.
"""
import pytest

from app.backend.services.collection import remediation as r


def _lue(solution=None):
    """Fiche dont les pages officielles ONT été lues."""
    return {"deep_synthesis": {"status": "completed", "solution": solution}}


# ---------------------------------------------------------------------------------------
# 1. Une remédiation existe : on l'affiche.
# ---------------------------------------------------------------------------------------

def test_remediation_resolue_affichee():
    cve = _lue("Mettre à jour Docker Desktop vers la version 4.86.0.")
    assert r.etat(cve) == r.DISPONIBLE
    assert "4.86.0" in r.texte(cve)


def test_remediation_de_la_page_de_collecte_affichee():
    cve = {"solution": "Appliquer le correctif publié par l'éditeur."}
    assert r.etat(cve) == r.DISPONIBLE


def test_remediation_resolue_prime_sur_celle_de_collecte():
    """La résolue vient des pages officielles et porte l'attribution de sa source."""
    cve = {"solution": "consigne generique",
           "deep_synthesis": {"status": "completed", "solution": "Passer en 26.6.6."}}
    assert r.texte(cve) == "Passer en 26.6.6."


def test_source_de_la_remediation_exposee():
    cve = {"deep_synthesis": {"status": "completed", "solution": "Passer en 26.6.6.",
                              "solution_source": {"name": "Red Hat",
                                                  "url": "https://access.redhat.com/errata/X"}}}
    assert r.source(cve)["name"] == "Red Hat"


def test_pas_de_source_pour_une_remediation_de_collecte():
    """Non attribuée : on ne lui invente pas une source."""
    assert r.source({"solution": "Appliquer les correctifs."}) is None


def test_aucun_message_quand_la_remediation_existe():
    assert r.message(_lue("Passer en 4.86.0.")) is None


# ---------------------------------------------------------------------------------------
# 2. L'extraction n'a pas abouti : ne RIEN affirmer.
# ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("synthese", [
    None,                                             # jamais analysée
    {"status": "insufficient", "solution": None},     # pages illisibles
    {"status": "failed"},                             # appel en échec
    {"status": "insufficient"},                       # sans clé « solution »
])
def test_extraction_non_aboutie_ne_conclut_pas(synthese):
    cve = {"deep_synthesis": synthese} if synthese is not None else {}
    assert r.etat(cve) == r.EXTRACTION_INCOMPLETE
    assert r.message(cve) == (
        "Les informations de remédiation n'ont pas pu être extraites de manière fiable.")


def test_le_message_d_extraction_n_affirme_aucune_absence():
    """Le libellé ne doit contenir aucune négation portant sur l'existence d'un correctif."""
    message = r.MESSAGES[r.EXTRACTION_INCOMPLETE].lower()
    assert "aucun" not in message and "n'existe" not in message


def test_fiche_vide_ne_conclut_pas():
    assert r.etat({}) == r.EXTRACTION_INCOMPLETE


def test_solution_vide_traitee_comme_absente():
    assert r.etat({"solution": "   ", "deep_synthesis": {"status": "insufficient"}}) \
        == r.EXTRACTION_INCOMPLETE


# ---------------------------------------------------------------------------------------
# 3. Les sources ont été lues : l'affirmation devient légitime.
# ---------------------------------------------------------------------------------------

def test_lecture_aboutie_sans_correctif():
    cve = _lue(None)
    assert r.etat(cve) == r.AUCUN_CORRECTIF
    assert r.message(cve) == "Aucun correctif ou mesure de remédiation officielle identifié."


def test_affirmation_reservee_a_la_lecture_aboutie():
    """La phrase affirmative ne doit JAMAIS sortir d'une extraction non aboutie."""
    affirmative = r.MESSAGES[r.AUCUN_CORRECTIF]
    for synthese in (None, {"status": "insufficient"}, {"status": "failed"}):
        cve = {"deep_synthesis": synthese} if synthese else {}
        assert r.message(cve) != affirmative


# ---------------------------------------------------------------------------------------
# 4. Même logique pour tout produit surveillé, sans particularisation.
# ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("editeur,produit,correctif", [
    ("Microsoft", "Windows 10", "Installer la mise à jour cumulative de sécurité."),
    ("Docker", "Docker Desktop", "Mettre à jour vers Docker Desktop 4.86.0."),
    ("Red Hat", "Keycloak", "Appliquer l'errata RHSA-2026:56523."),
    ("yootheme.com", "Zoo extension for Joomla", "Passer en version 4.1.64."),
    ("Apache", "Tomcat", "Mettre à jour vers 9.0.100."),
])
def test_meme_logique_quel_que_soit_le_produit(editeur, produit, correctif):
    presente = {"vendor": editeur, "product": produit,
                "deep_synthesis": {"status": "completed", "solution": correctif}}
    absente = {"vendor": editeur, "product": produit,
               "deep_synthesis": {"status": "insufficient"}}
    assert r.etat(presente) == r.DISPONIBLE
    assert r.etat(absente) == r.EXTRACTION_INCOMPLETE


def test_resume_complet():
    cve = _lue("Passer en 4.86.0.")
    vue = r.resume(cve)
    assert vue["status"] == r.DISPONIBLE and vue["text"] and vue["message"] is None


def test_resume_sur_extraction_incomplete():
    vue = r.resume({})
    assert vue["text"] is None and vue["message"]
