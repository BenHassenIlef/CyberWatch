"""Tests de l'agent de veille communautaire.

Point capital vérifié ici : une publication issue d'une source COMMUNAUTAIRE ne peut jamais
être promue « confirmée » par elle-même. Seul un adossement officiel le permet.
"""
import pytest

from app.backend.services.community import agent as ca


def pub(titre="", contenu=""):
    return {"title": titre, "content": contenu}


# ---------------------------------------------------------------- extraction déterministe

def test_extraction_des_cve():
    p = pub("Analyse de CVE-2026-1234", "Voir aussi CVE-2026-5678 et cve-2026-1234.")
    assert ca.extract_cves(p) == ["CVE-2026-1234", "CVE-2026-5678"]


def test_aucune_cve_citee():
    assert ca.extract_cves(pub("Faille dans un serveur mail", "Pas d'identifiant.")) == []


# ---------------------------------------------------------------- classification

@pytest.mark.parametrize("texte,attendu", [
    ("This flaw is being exploited in the wild since Monday", "active_exploitation"),
    ("A new zero-day affects the product", "zero_day"),
    ("Public PoC released on GitHub", "poc"),
    ("Vendor published a security update", "patch"),
    ("A workaround is available: disable the service", "workaround"),
    ("Deep dive reverse engineering of the bug", "technical_analysis"),
    ("Ransomware group targets the flaw", "threat_intelligence"),
])
def test_classification(texte, attendu):
    assert attendu in ca.classify(pub("", texte))


def test_classification_par_defaut():
    assert ca.classify(pub("Réunion mensuelle", "Compte rendu interne.")) == ["other"]


def test_categories_multiples():
    cats = ca.classify(pub("", "PoC published and actively exploited in the wild; patch available"))
    for c in ("poc", "active_exploitation", "patch"):
        assert c in cats


# ---------------------------------------------------------------- confiance

def test_source_officielle_confirmee():
    niveau, motifs = ca.assess_confidence(pub("", "exploit"), ca.OFFICIAL, False)
    assert niveau == ca.CONFIRMED and motifs


def test_communautaire_jamais_confirmee_seule():
    """RÈGLE CENTRALE : le communautaire ne s'auto-confirme jamais."""
    niveau, _ = ca.assess_confidence(
        pub("CVE-2026-1234", "Actively exploited, PoC available!"), ca.COMMUNITY, False)
    assert niveau != ca.CONFIRMED
    assert niveau == ca.NEEDS_VERIFICATION


def test_communautaire_confirmee_si_cve_deja_confirmee():
    niveau, _ = ca.assess_confidence(pub("CVE-2026-1234"), ca.COMMUNITY, True)
    assert niveau == ca.CONFIRMED


def test_corroboration_par_sources_multiples():
    niveau, motifs = ca.assess_confidence(pub("CVE-2026-1"), ca.COMMUNITY, False, nb_sources=3)
    assert niveau == ca.CORROBORATED
    assert "3 sources" in motifs[0]


def test_signal_faible_non_confirme():
    niveau, _ = ca.assess_confidence(pub("Divers", "Discussion sans element."), ca.COMMUNITY, False)
    assert niveau == ca.UNCONFIRMED


def test_specialisee_reste_a_verifier():
    niveau, _ = ca.assess_confidence(pub("CVE-2026-1"), ca.SPECIALIZED, False)
    assert niveau == ca.NEEDS_VERIFICATION


# ---------------------------------------------------------------- alertes

def test_alerte_seulement_dans_le_perimetre():
    cats = ["active_exploitation", "poc"]
    assert ca.needs_alert(cats, has_scope=True) is True
    assert ca.needs_alert(cats, has_scope=False) is False, "hors périmètre : pas d'alerte"


def test_pas_d_alerte_pour_sujet_anodin():
    assert ca.needs_alert(["technical_analysis"], has_scope=True) is False


# ---------------------------------------------------------------- libellés français

def test_libelles_francais_complets():
    for c in ca.CATEGORIES:
        assert c in ca.CATEGORY_FR
    for n in (ca.CONFIRMED, ca.CORROBORATED, ca.NEEDS_VERIFICATION, ca.UNCONFIRMED):
        assert n in ca.CONFIDENCE_FR


def test_libelle_de_source():
    assert ca.source_label("https://blog.exemple.fr/post/1") == "blog.exemple.fr"
    assert ca.source_label(None) == "source inconnue"
