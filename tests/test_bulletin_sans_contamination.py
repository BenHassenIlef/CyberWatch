"""Un bulletin de fiche ne doit porter QUE les données de sa propre vulnérabilité.

Cas réel à l'origine de ces tests : la page de collecte d'une faille Dell était un billet
d'agrégateur citant neuf CVE sans rapport. Le bulletin affichait « Éditeur : Microsoft »,
listait les neuf identifiants, désignait comme source officielle la fiche NVD d'une AUTRE
vulnérabilité, et mêlait aux références des liens de polices, de partage et d'affiliation.
"""
from app.backend.services.collection.advisory_bulletin import (_references_utiles,
                                                               est_habillage)

AVIS_DELL = ("https://www.dell.com/support/kbdoc/en-us/000500910/"
             "dsa-2026-359-security-update-for-dell-openmanage-enterprise-vulnerabilities")


# ---------------------------------------------------------------------------------------
# Habillage de page : ni documentation, ni source — du décor.
# ---------------------------------------------------------------------------------------

def test_polices_et_feuilles_de_style_ecartees():
    for url in ("https://fonts.googleapis.com",
                "https://fonts.gstatic.com",
                "https://fonts.googleapis.com/css2?family=Inter:wght@400",
                "https://cdn.jsdelivr.net/npm/chart.js"):
        assert est_habillage(url), url


def test_profils_de_site_et_liens_de_partage_ecartes():
    for url in ("https://gmpg.org/xfn/11",
                "https://reddit.com/submit?url=https%3A%2F%2Fexemple.test",
                "https://www.reddit.com/r/TheHackerWireMag/",
                "https://twitter.com/intent/tweet?url=x"):
        assert est_habillage(url), url


def test_lien_d_affiliation_ecarte():
    assert est_habillage("https://s.click.aliexpress.com/e/_m0lQg2K")


def test_avis_editeur_conserve():
    assert not est_habillage(AVIS_DELL)


def test_autorites_publiques_conservees():
    for url in ("https://nvd.nist.gov/vuln/detail/CVE-2026-71176",
                "https://www.cve.org/CVERecord?id=CVE-2026-71176",
                "https://access.redhat.com/errata/RHSA-2026:56523",
                "https://github.com/advisories/GHSA-8cp6-c94h-9538"):
        assert not est_habillage(url), url


def test_discussion_communautaire_precise_conservee():
    """La veille communautaire s'appuie sur des fils identifiés — pas sur des profils."""
    assert not est_habillage(
        "https://www.reddit.com/r/netsec/comments/abc123/analyse_de_la_faille/")


def test_valeurs_non_exploitables_ecartees():
    for url in (None, 42, "", "ftp://exemple.test/f", "pas-une-url"):
        assert est_habillage(url)


# ---------------------------------------------------------------------------------------
# Fusion des références : la fiche fait foi, la page complète.
# ---------------------------------------------------------------------------------------

def test_references_de_la_fiche_en_tete():
    out = _references_utiles([AVIS_DELL], ["https://autre.test/page"])
    assert out[0] == AVIS_DELL


def test_habillage_de_la_page_jamais_ajoute():
    out = _references_utiles([AVIS_DELL], ["https://fonts.gstatic.com",
                                           "https://s.click.aliexpress.com/e/_x"])
    assert out == [AVIS_DELL]


def test_pas_de_doublon():
    out = _references_utiles([AVIS_DELL], [AVIS_DELL, AVIS_DELL])
    assert out == [AVIS_DELL]


def test_espaces_superflus_normalises():
    out = _references_utiles(["  " + AVIS_DELL + "  "], [])
    assert out == [AVIS_DELL]


def test_fusion_supporte_des_listes_absentes():
    assert _references_utiles(None, None) == []


def test_reference_utile_de_la_page_bien_ajoutee():
    """La page de collecte peut apporter un lien que la fiche n'a pas : on le garde."""
    out = _references_utiles([AVIS_DELL], ["https://msrc.microsoft.com/update-guide/x"])
    assert len(out) == 2
