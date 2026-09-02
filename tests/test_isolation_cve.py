"""ISOLATION DES CVE — une vulnérabilité ne porte jamais les données d'une autre.

CONTAMINATION D'ORIGINE, reproduite ici

Trois vulnérabilités sans rapport se retrouvaient rangées sous « Microsoft Windows » :

    CVE-2026-17106   moby / go-archive                                   (Docker)
    CVE-2026-40145   BeyondTrust / Endpoint Privilege Management (Windows deployment)
    CVE-2026-40144   BeyondTrust / Endpoint Privilege Management (Windows deployments)

Deux causes, toutes deux corrigées et verrouillées par ces tests :

  1. le jeton « windows » du QUALIFICATIF « (Windows deployment) » servait à identifier le
     produit affecté — or il nomme la plateforme de déploiement, pas le produit ;
  2. « Systèmes affectés » (« Docker Desktop sur Windows… ») énumère des plateformes
     d'exécution, et servait pourtant à attribuer un produit.

Le système d'exploitation n'est ni le produit affecté, ni son éditeur.
"""
import pytest

from app.backend.services.collection import isolation, monitored


def _cve(cve_id, vendor, product, **extra):
    """Fiche minimale, indépendante des autres — comme le pipeline doit la produire."""
    return {"cve_id": cve_id, "vendor": vendor, "product": product, **extra}


@pytest.fixture
def catalogue(monkeypatch):
    """Périmètre de surveillance réduit et explicite, indépendant de la base."""
    def _installer(produits):
        compiles = [monitored._Product(nom, editeur, "Test", alias, alias)
                    for nom, editeur, alias in produits]
        monkeypatch.setattr(monitored, "_active", compiles)
        monkeypatch.setattr(monitored, "PRODUCTS", compiles)
        return compiles
    return _installer


def _produits(rec):
    return {h["product"] for h in monitored.classify_detailed(rec)
            if h["confidence"] != monitored.REJECTED}


WINDOWS = ("Microsoft Windows", "Microsoft", ["microsoft windows", "windows", "microsoft"])
DOCKER = ("Docker", "Docker", ["docker", "docker desktop", "docker engine"])
JOOMLA = ("Joomla", "Joomla", ["joomla"])


# ---------------------------------------------------------------------------------------
# Les quatre vulnérabilités nommées.
# ---------------------------------------------------------------------------------------

def test_beyondtrust_n_est_pas_microsoft(catalogue):
    """« (Windows deployment) » est une plateforme de déploiement, pas le produit affecté."""
    catalogue([WINDOWS])
    rec = _cve("CVE-2026-40145", "BeyondTrust",
               "Endpoint Privilege Management (Windows deployment)")
    assert "Microsoft Windows" not in _produits(rec)


def test_beyondtrust_pluriel_non_plus(catalogue):
    catalogue([WINDOWS])
    rec = _cve("CVE-2026-40144", "BeyondTrust",
               "Endpoint Privilege Management (Windows deployments)")
    assert "Microsoft Windows" not in _produits(rec)


def test_docker_reste_docker(catalogue):
    """Le produit surveillé porte le nom de son éditeur : cela ne doit pas le disqualifier."""
    catalogue([WINDOWS, DOCKER])
    rec = _cve("CVE-2026-17106", "moby", "go-archive",
               affected_products=["go-archive", "Docker Desktop", "Docker Engine"],
               affected_systems=["Docker Desktop sur Windows versions antérieures à 4.86.0"])
    assert _produits(rec) == {"Docker"}


def test_yootheme_reste_joomla(catalogue):
    catalogue([WINDOWS, JOOMLA])
    rec = _cve("CVE-2026-75114", "yootheme.com", "Zoo extension for Joomla")
    assert _produits(rec) == {"Joomla"}


def test_vraie_cve_microsoft_toujours_reconnue(catalogue):
    """La correction ne doit pas faire perdre les vulnérabilités réellement Windows."""
    catalogue([WINDOWS])
    rec = _cve("CVE-2026-62727", "Microsoft", "Windows 10 Version 1607")
    assert "Microsoft Windows" in _produits(rec)


# ---------------------------------------------------------------------------------------
# Le système d'exploitation n'est pas le produit.
# ---------------------------------------------------------------------------------------

def test_plateforme_d_execution_n_attribue_pas_un_produit(catalogue):
    catalogue([WINDOWS])
    rec = _cve("CVE-2026-1001", "Docker", "Docker Desktop",
               affected_systems=["Docker Desktop sur Windows", "Docker Desktop sur MacOS"])
    assert "Microsoft Windows" not in _produits(rec)


def test_systemes_affectes_utilises_en_dernier_recours(catalogue):
    """Sans éditeur ni produit, cette rubrique reste le seul indice : elle sert alors."""
    catalogue([WINDOWS])
    rec = {"cve_id": "CVE-2026-1002", "affected_systems": ["Microsoft Windows 11"]}
    assert "Microsoft Windows" in _produits(rec)


def test_qualificatif_retire_du_nom_de_produit():
    assert monitored._sans_qualificatif(
        "Endpoint Privilege Management (Windows deployment)") == "Endpoint Privilege Management"


def test_nom_sans_parenthese_intact():
    assert monitored._sans_qualificatif("Docker Desktop") == "Docker Desktop"


def test_nom_entierement_entre_parentheses_conserve():
    """Rien ne doit disparaître entièrement : mieux vaut le nom brut qu'une chaîne vide."""
    assert monitored._sans_qualificatif("(Windows)") == "(Windows)"


# ---------------------------------------------------------------------------------------
# Un avis contenant plusieurs CVE : trois fiches indépendantes.
# ---------------------------------------------------------------------------------------

def test_avis_multi_cve_produit_des_fiches_independantes(catalogue):
    catalogue([WINDOWS, DOCKER, JOOMLA])
    avis = [
        _cve("CVE-2026-1100", "Docker", "Docker Desktop"),
        _cve("CVE-2026-1101", "BeyondTrust", "Endpoint Privilege Management (Windows)"),
        _cve("CVE-2026-1102", "Microsoft", "Windows 11"),
    ]
    resultats = {r["cve_id"]: _produits(r) for r in avis}
    assert resultats["CVE-2026-1100"] == {"Docker"}
    assert resultats["CVE-2026-1101"] == set()
    assert resultats["CVE-2026-1102"] == {"Microsoft Windows"}


def test_deux_cve_gardent_des_scores_distincts():
    """Deux vulnérabilités d'un même avis ne partagent pas leur score."""
    a = _cve("CVE-2026-40145", "BeyondTrust", "EPM", cvss_score=7.1)
    b = _cve("CVE-2026-40144", "BeyondTrust", "EPM", cvss_score=7.3)
    assert a["cvss_score"] != b["cvss_score"]


def test_aucun_partage_d_objet_entre_fiches(catalogue):
    """Deux fiches traitées à la suite ne doivent partager aucune structure mutable."""
    catalogue([DOCKER])
    a = _cve("CVE-2026-1200", "Docker", "Docker Desktop", references=[])
    b = _cve("CVE-2026-1201", "BeyondTrust", "EPM (Windows)", references=[])
    a["references"].append("https://docker.test/avis")
    assert b["references"] == []


# ---------------------------------------------------------------------------------------
# Validation d'isolation avant publication.
# ---------------------------------------------------------------------------------------

def test_fiche_saine_est_publiable():
    rec = _cve("CVE-2026-40145", "BeyondTrust", "Endpoint Privilege Management")
    assert isolation.appliquer(rec) is True
    assert "isolation_issues" not in rec


def test_solution_citant_une_autre_cve_est_signalee():
    rec = _cve("CVE-2026-40145", "BeyondTrust", "EPM",
               solution="Mettre a jour Docker Desktop (CVE-2026-17106) vers 4.86.0.")
    assert isolation.appliquer(rec) is False
    assert rec["validation_status"] == "needs_review"


def test_reference_d_une_autre_cve_est_signalee():
    rec = _cve("CVE-2026-40145", "BeyondTrust", "EPM",
               references=["https://nvd.nist.gov/vuln/detail/CVE-2026-17106"])
    assert isolation.appliquer(rec) is False


def test_reference_de_la_bonne_cve_acceptee():
    rec = _cve("CVE-2026-40145", "BeyondTrust", "EPM",
               references=["https://nvd.nist.gov/vuln/detail/CVE-2026-40145"])
    assert isolation.appliquer(rec) is True


def test_titre_d_avis_en_guise_de_produit_signale():
    rec = _cve("CVE-2026-1001", "Oracle", "Mises à jour de sécurité pour plusieurs produits")
    assert "produit est un titre d'avis" in " ".join(isolation.valider(rec))


def test_identifiant_invalide_signale():
    assert isolation.valider({"cve_id": "pas-un-identifiant"}) == ["identifiant CVE invalide"]


def test_fiche_signalee_reste_collectee():
    """Marquer, pas supprimer : une vulnérabilité réelle ne disparaît pas."""
    rec = _cve("CVE-2026-40145", "BeyondTrust", "EPM",
               references=["https://nvd.nist.gov/vuln/detail/CVE-2026-17106"])
    isolation.appliquer(rec)
    assert rec["cve_id"] == "CVE-2026-40145" and rec["vendor"] == "BeyondTrust"
