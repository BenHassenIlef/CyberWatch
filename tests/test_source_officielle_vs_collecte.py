"""La page où l'information a été TROUVÉE n'est pas la source officielle de la faille.

Cette règle figurait depuis toujours dans la documentation de `official_source` — mais la
fonction ne recevait pas l'URL de collecte, elle ne pouvait donc pas l'appliquer. Résultat :
une CVE découverte sur NVD affichait « Source officielle : NVD », c'est-à-dire la page même
où CyberWatch l'avait ramassée. Un raisonnement circulaire, sans valeur pour un consultant.

EXCEPTION, elle aussi déjà documentée : si la page de collecte appartient à l'ÉDITEUR du
produit, elle EST l'avis officiel et doit être conservée.
"""
from app.backend.services.collection.advisory_bulletin import (_meme_page,
                                                               _references_utiles,
                                                               est_habillage,
                                                               official_source)

CVE = "CVE-2026-75114"
NVD = f"https://nvd.nist.gov/vuln/detail/{CVE}"
CVEORG = f"https://www.cve.org/CVERecord?id={CVE}"
GHSA = "https://github.com/advisories/GHSA-5w5r-gpcr-x5pw"


# ---------------------------------------------------------------------------------------
# La page de collecte est écartée…
# ---------------------------------------------------------------------------------------

def test_portail_public_de_collecte_ecarte():
    res = official_source([NVD, CVEORG], "yootheme.com", ["Zoo"], [CVE], url_collecte=NVD)
    assert res["url"] == CVEORG


def test_blog_de_collecte_ecarte_au_profit_de_l_avis_editeur():
    dell = ("https://www.dell.com/support/kbdoc/en-us/000500910/"
            "dsa-2026-359-security-update")
    blog = "https://www.thehackerwire.com/dell-openmanage-cve-2026-71176/"
    res = official_source([dell, NVD], "Dell", ["OpenManage Enterprise"],
                          ["CVE-2026-71176"], url_collecte=blog)
    assert res["url"] == dell


def test_repli_sur_la_fiche_cve_quand_il_ne_reste_rien():
    res = official_source([NVD], "yootheme.com", ["Zoo"], [CVE], url_collecte=NVD)
    assert res["url"] == f"https://www.cve.org/CVERecord?id={CVE}"


def test_sans_url_de_collecte_le_comportement_reste_inchange():
    """Bulletin construit hors contexte de fiche : aucune exclusion ne s'applique."""
    assert official_source([NVD, CVEORG], "yootheme.com", ["Zoo"], [CVE])["url"] == NVD


# ---------------------------------------------------------------------------------------
# …sauf si elle est l'avis de l'éditeur.
# ---------------------------------------------------------------------------------------

def test_avis_de_l_editeur_conserve_meme_s_il_est_la_page_de_collecte():
    palo = "https://security.paloaltonetworks.com/CVE-2026-0290"
    res = official_source([palo, "https://nvd.nist.gov/vuln/detail/CVE-2026-0290"],
                          "Palo Alto Networks", ["Prisma Browser"],
                          ["CVE-2026-0290"], url_collecte=palo)
    assert res["url"] == palo


# ---------------------------------------------------------------------------------------
# Comparaison d'URL : même page malgré la barre finale, le fragment ou « www. ».
# ---------------------------------------------------------------------------------------

def test_barre_finale_ignoree():
    assert _meme_page("https://x.test/a/", "https://x.test/a")


def test_prefixe_www_ignore():
    assert _meme_page("https://cve.org/CVERecord?id=X", "https://www.cve.org/CVERecord?id=X")


def test_chemins_differents_distingues():
    assert not _meme_page("https://x.test/a", "https://x.test/b")


def test_requete_differente_distinguee():
    assert not _meme_page("https://x.test/p?id=1", "https://x.test/p?id=2")


# ---------------------------------------------------------------------------------------
# Références : la navigation du portail de collecte n'est pas de la documentation.
# ---------------------------------------------------------------------------------------

def test_navigation_du_portail_ecartee():
    page = [NVD, "https://www.nist.gov/itl/nvd", "https://ncp.nist.gov/cce",
            "https://csrc.nist.gov/projects/security-content-automation-protocol", CVEORG]
    out = _references_utiles([], page, url_collecte=NVD, cve_id=CVE)
    assert out == [NVD, CVEORG]


def test_page_de_collecte_reste_une_reference():
    """Écartée comme SOURCE OFFICIELLE, elle garde sa valeur de référence."""
    out = _references_utiles([], [NVD], url_collecte=NVD, cve_id=CVE)
    assert out == [NVD]


def test_lien_du_meme_domaine_citant_la_cve_conserve():
    autre = f"https://nvd.nist.gov/vuln/detail/{CVE}/references"
    out = _references_utiles([], [autre], url_collecte=NVD, cve_id=CVE)
    assert out == [autre]


def test_racine_de_site_ecartee():
    for url in ("https://www.yootheme.com/", "https://www.nist.gov", "https://ncp.nist.gov"):
        assert est_habillage(url), url


def test_formulaire_d_abonnement_ecarte():
    assert est_habillage(
        "https://public.govdelivery.com/accounts/USNIST/subscriber/new?qsp=USNIST_3")


def test_doublon_www_supprime():
    out = _references_utiles([], [CVEORG, f"https://cve.org/CVERecord?id={CVE}"],
                             url_collecte=NVD, cve_id=CVE)
    assert len(out) == 1


def test_avis_tiers_conserve():
    out = _references_utiles([], [GHSA], url_collecte=NVD, cve_id=CVE)
    assert out == [GHSA]
