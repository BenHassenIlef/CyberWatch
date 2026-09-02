"""« Site officiel » = celui de l'ÉDITEUR du produit vulnérable. Rien d'autre.

NVD, CVE.org, les avis GitHub, Vulners et les portails de veille RÉFÉRENCENT une
vulnérabilité ; ils ne la publient pas au nom de l'éditeur. Les afficher comme site officiel
renvoyait un consultant vers un annuaire alors qu'il cherche le correctif du produit.

La règle ne repose sur AUCUNE liste de sites interdits : on vérifie l'APPARTENANCE du domaine
à l'éditeur du produit. Une base de vulnérabilités échoue à ce test par construction — celles
d'aujourd'hui comme celles qui apparaîtront demain.
"""
import pytest

from app.backend.services.collection.advisory_bulletin import (_domaine_de_l_editeur,
                                                               _extension_wordpress,
                                                               _vendor_slugs,
                                                               site_officiel)

NVD = "https://nvd.nist.gov/vuln/detail/CVE-2026-75114"
CVEORG = "https://www.cve.org/CVERecord?id=CVE-2026-75114"
GHSA = "https://github.com/advisories/GHSA-5w5r-gpcr-x5pw"
CWE = "http://cwe.mitre.org/data/definitions/601.html"
BASES = [NVD, CVEORG, GHSA, CWE]


# ---------------------------------------------------------------------------------------
# Ce qui NE PEUT JAMAIS être le site officiel.
# ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("url", BASES + [
    "https://vulners.com/cve/CVE-2026-75114",
    "https://www.cvedetails.com/cve/CVE-2026-75114/",
    "https://www.opencve.io/cve/CVE-2026-75114",
    "https://secalerts.co/vulnerability/CVE-2026-75114",
    "https://vuldb.com/?id.123456",
])
def test_base_de_vulnerabilites_jamais_retenue(url):
    """Aucune de ces pages n'appartient à l'éditeur : le champ doit rester vide."""
    assert site_officiel([url], "yootheme.com", ["Zoo"])["url"] != url


def test_editeur_inconnu_donne_non_identifie():
    """Sans éditeur identifiable, on n'invente pas d'adresse."""
    assert site_officiel(BASES, None, None) == {"name": None, "url": None}


def test_page_tierce_non_retenue():
    """Un blog qui parle du produit n'est pas le site du produit."""
    assert site_officiel(["https://blog-securite.test/faille-zoo"],
                         "yootheme.com", ["Zoo"])["url"] == "https://yootheme.com/"


def test_domaine_d_un_autre_editeur_ignore():
    """Une CVE Dell ne doit pas hériter du site de Microsoft présent dans les références."""
    res = site_officiel(["https://msrc.microsoft.com/update-guide/vulnerability/CVE-X"],
                        "Dell", ["OpenManage Enterprise"])
    assert "microsoft" not in (res["url"] or "")


# ---------------------------------------------------------------------------------------
# Ce qui DOIT être retenu, dans l'ordre de préférence.
# ---------------------------------------------------------------------------------------

def test_avis_de_securite_de_l_editeur_prioritaire():
    """Une page d'avis de l'éditeur prime sur ses autres pages."""
    avis = "https://www.dell.com/support/kbdoc/en-us/000500910/dsa-2026-359-security-update"
    res = site_officiel([NVD, avis], "Dell", ["OpenManage Enterprise"])
    assert res["url"] == avis


def test_avis_msrc_retenu_pour_microsoft():
    msrc = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62727"
    assert site_officiel([msrc, NVD], "Microsoft", ["Windows 10"])["url"] == msrc


def test_portail_editeur_en_repli():
    """Sans avis dans les références, on renvoie vers le portail de sécurité de l'éditeur."""
    res = site_officiel([NVD, CVEORG], "Microsoft", ["Windows 10"])
    assert "msrc.microsoft.com" in res["url"]


def test_errata_red_hat_retenu():
    errata = "https://access.redhat.com/errata/RHSA-2026:56523"
    assert site_officiel([errata, NVD], "Red Hat", ["Keycloak"])["url"] == errata


def test_editeur_designe_par_son_domaine():
    """« yootheme.com » EST le site de l'éditeur : l'information la plus directe qui soit."""
    res = site_officiel(BASES, "yootheme.com", ["Zoo extension for Joomla"])
    assert res["url"] == "https://yootheme.com/"


def test_nom_toujours_renseigne_avec_une_url():
    res = site_officiel([NVD], "Microsoft", ["Windows 10"])
    assert res["url"] and res["name"]


# ---------------------------------------------------------------------------------------
# Reconnaissance d'un éditeur désigné par un domaine.
# ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("vendor,attendu", [
    ("yootheme.com", "https://yootheme.com/"),
    ("NLnetLabs.nl", "https://nlnetlabs.nl/"),
    ("https://exemple.test/", "https://exemple.test/"),
])
def test_domaine_reconnu(vendor, attendu):
    assert _domaine_de_l_editeur(vendor) == attendu


@pytest.mark.parametrize("vendor", ["Microsoft", "Red Hat", "Palo Alto Networks", "", None,
                                    "Innotim Software, Telecommunications and Consulting"])
def test_raison_sociale_n_est_pas_un_domaine(vendor):
    assert _domaine_de_l_editeur(vendor) is None


# ---------------------------------------------------------------------------------------
# Les bases de vulnérabilités restent des RÉFÉRENCES.
# ---------------------------------------------------------------------------------------

def test_les_bases_ne_sont_pas_supprimees_des_references():
    """Écartées du champ « site officiel », elles gardent toute leur valeur documentaire."""
    from app.backend.services.collection.advisory_bulletin import est_habillage
    for url in (NVD, CVEORG, GHSA, CWE):
        assert not est_habillage(url), url


# ---------------------------------------------------------------------------------------
# Défauts constatés sur les données réelles — source officielle absente ou FAUSSE
# ---------------------------------------------------------------------------------------

def test_une_plateforme_citee_comme_produit_n_attribue_pas_son_editeur():
    """LE DÉFAUT LE PLUS GRAVE : un lien faux, pire qu'un lien absent.

    Les portails d'avis renseignent souvent le produit par les systèmes concernés :
    « Linux Mac OS Windows ». Le premier mot devenait un identifiant d'éditeur, et une
    vulnérabilité Google Chrome se voyait attribuer « Linux Kernel (kernel.org) » comme site
    officiel — envoyant le consultant chercher un correctif là où il n'y en aura jamais,
    sans aucune raison de s'en méfier.
    """
    resultat = site_officiel(
        ["https://support.google.com/chrome/answer/95414",
         "https://www.kernel.org/category/releases.html"],
        vendor="Chrome", products=["Linux Mac OS Windows"])

    assert "kernel.org" not in (resultat["url"] or "")
    assert "google.com" in (resultat["url"] or "")


def test_un_vrai_noyau_linux_reste_sur_kernel_org():
    """L'exclusion ne vaut que pour les mots tirés du champ PRODUIT.

    Si l'éditeur lui-même est « Linux », kernel.org est la bonne réponse — et le correctif
    ne doit pas l'avoir emportée.
    """
    resultat = site_officiel([], vendor="Linux", products=["Linux Kernel"])
    assert "kernel.org" in (resultat["url"] or "")


def test_un_editeur_nomme_par_son_produit_retrouve_son_avis():
    """Les collecteurs écrivent « Chrome » là où l'éditeur est « Google ».

    L'avis officiel — « support.google.com/chrome/… » — obtenait alors un score de 0, faute
    de contenir le mot « chrome » dans son domaine : la source la plus utile était présente
    dans les références et systématiquement ignorée.
    """
    for produit, attendu in (("Chrome", "google.com"), ("Firefox", "mozilla"),
                             ("SharePoint", "microsoft")):
        slugs = _vendor_slugs(produit, None)
        assert any(s in ("google", "mozilla", "microsoft") for s in slugs), (
            f"« {produit} » ne ramène pas aux identifiants de son éditeur : {slugs}")


def test_une_extension_wordpress_pointe_sa_page_canonique():
    """Dernière classe de CVE récentes sans source : 3 % du total, toutes des extensions.

    Leurs références pointent le dépôt de la plateforme, jamais un domaine appartenant à
    l'auteur — qui le plus souvent n'en a pas. La page canonique de l'extension EST sa
    source officielle : c'est là que la version corrigée est publiée.
    """
    resultat = site_officiel(
        ["https://plugins.trac.wordpress.org/browser/mailgun/trunk/mailgun.php",
         "https://nvd.nist.gov/vuln/detail/CVE-2026-78003"],
        vendor="mailgun", products=["Mailgun"])

    assert resultat["url"] == "https://wordpress.org/plugins/mailgun/"
    assert "mailgun" in (resultat["name"] or "")


def test_deux_extensions_citees_ne_permettent_pas_de_conclure():
    """On ne devine pas laquelle est vulnérable : mieux vaut n'en désigner aucune."""
    assert _extension_wordpress([
        "https://plugins.trac.wordpress.org/browser/extension-a/trunk/a.php",
        "https://plugins.trac.wordpress.org/browser/extension-b/trunk/b.php"]) is None


def test_une_base_de_vulnerabilites_n_est_jamais_la_source_officielle():
    """NVD et CVE.org RÉFÉRENCENT la vulnérabilité ; ils ne la publient pas pour l'éditeur."""
    resultat = site_officiel(
        ["https://nvd.nist.gov/vuln/detail/CVE-2026-1", "https://www.cve.org/CVERecord?id=CVE-2026-1"],
        vendor="EditeurInconnuXYZ", products=None)
    assert "nvd.nist.gov" not in (resultat["url"] or "")
    assert "cve.org" not in (resultat["url"] or "")
