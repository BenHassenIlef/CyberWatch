"""La SOURCE OFFICIELLE d'un bulletin doit concerner LA CVE du bulletin — et aucune autre.

Une page d'avis (ANCS, DGSSI, CERT-FR…) cite des dizaines de vulnérabilités. Ses références
contiennent donc des liens NVD/CVE.org qui portent sur d'AUTRES failles. Sans garde-fou, le
bulletin de la CVE consultée affichait la fiche officielle d'une vulnérabilité sans rapport :
le consultant cliquait et lisait le mauvais avis.
"""
import pytest

from app.backend.services.collection.advisory_bulletin import (cite_une_autre_cve,
                                                               official_reference,
                                                               official_source)

CIBLE = "CVE-2026-46325"
AUTRE = "https://nvd.nist.gov/vuln/detail/CVE-2026-31636"
BONNE = "https://nvd.nist.gov/vuln/detail/CVE-2026-46325"


# ---------------------------------------------------------------------------------------
# Détection : l'URL parle-t-elle d'une autre vulnérabilité ?
# ---------------------------------------------------------------------------------------

def test_url_portant_un_autre_identifiant_est_detectee():
    assert cite_une_autre_cve(AUTRE, CIBLE)


def test_url_portant_le_bon_identifiant_est_acceptee():
    assert not cite_une_autre_cve(BONNE, CIBLE)


def test_comparaison_insensible_a_la_casse():
    assert not cite_une_autre_cve("https://www.cve.org/CVERecord?id=cve-2026-46325", CIBLE)


def test_url_sans_identifiant_nest_pas_ecartee():
    """Un avis éditeur ne porte souvent aucun CVE dans son URL : il reste éligible."""
    assert not cite_une_autre_cve("https://ubuntu.com/security/notices/USN-8636-1", CIBLE)


def test_sans_cve_de_reference_aucun_filtrage():
    """Bulletin produit (N vulnérabilités) : le garde-fou ne doit pas s'appliquer."""
    assert not cite_une_autre_cve(AUTRE, None)


def test_url_citant_plusieurs_cve_dont_la_bonne_est_acceptee():
    url = "https://exemple.test/avis?ids=CVE-2026-31636,CVE-2026-46325"
    assert not cite_une_autre_cve(url, CIBLE)


# ---------------------------------------------------------------------------------------
# Sélection : la mauvaise référence ne doit jamais être retenue.
# ---------------------------------------------------------------------------------------

def test_reference_dune_autre_cve_est_ecartee():
    assert official_reference([AUTRE], cve_id=CIBLE) is None


def test_la_bonne_reference_est_retenue_malgre_lautre():
    """L'URL fautive apparaît EN PREMIER : sans le garde-fou, elle gagnait à score égal."""
    assert official_reference([AUTRE, BONNE], cve_id=CIBLE) == BONNE


def test_sans_garde_fou_lancienne_faute_se_reproduit():
    """Vérifie que le test ci-dessus teste bien quelque chose (le défaut existait)."""
    assert official_reference([AUTRE, BONNE]) == AUTRE


def test_avis_editeur_prime_sur_lautorite_publique():
    refs = [BONNE, "https://access.redhat.com/errata/RHSA-2026:56523"]
    choisi = official_reference(refs, vendor="Red Hat", cve_id=CIBLE)
    assert "redhat" in choisi


def test_aucune_reference_valable_renvoie_none():
    assert official_reference(["https://blog-perso.test/analyse"], cve_id=CIBLE) is None


def test_references_non_http_ignorees():
    assert official_reference([None, 42, "ftp://x.test/f", ""], cve_id=CIBLE) is None


# ---------------------------------------------------------------------------------------
# Repli : construire une fiche CVE.org — avec le BON identifiant.
# ---------------------------------------------------------------------------------------

def test_repli_utilise_la_cve_du_bulletin():
    """La CVE du bulletin est la PREMIÈRE de la liste (garanti par `build_bulletin`)."""
    res = official_source([], cve_ids=[CIBLE, "CVE-2026-31636"])
    assert CIBLE in res["url"] and "31636" not in res["url"]


def test_repli_absent_sans_identifiant():
    assert official_source([], cve_ids=[]) == {"name": None, "url": None}


def test_source_officielle_ecarte_la_reference_etrangere():
    res = official_source([AUTRE], cve_ids=[CIBLE])
    assert res["url"] == f"https://www.cve.org/CVERecord?id={CIBLE}"


def test_source_officielle_porte_toujours_un_nom():
    res = official_source([BONNE], cve_ids=[CIBLE])
    assert res["name"] and res["url"] == BONNE
