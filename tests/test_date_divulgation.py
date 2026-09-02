"""La date affichée doit être celle de la DIVULGATION, pas celle de l'enregistrement.

Cas réel : la page MSRC de CVE-2026-62727 annonce « Released: Aug 11, 2026 ». L'application
affichait le 19 août — la date à laquelle la fiche est entrée au registre CVE. Pour un
cabinet de conseil, l'écart n'est pas cosmétique : la vulnérabilité remontait dans la veille
du jour huit jours après sa divulgation, et contredisait l'avis officiel sous les yeux du
consultant.

Un enregistrement CVE porte les deux dates :
    containers.cna.datePublic       divulgation par le CNA        <- celle qui compte
    cveMetadata.datePublished       enregistrement au registre
"""
from datetime import datetime, timedelta

from app.backend.services.collection import provenance as pv
from app.backend.services.collection.enrichment import _merge

DIVULGATION = datetime(2026, 8, 11, 14, 0)
ENREGISTREMENT = datetime(2026, 8, 19, 20, 58)


def _fusion(contributions):
    fusion, _ = _merge("CVE-2026-62727", None, contributions)
    return fusion


# ---------------------------------------------------------------------------------------
# Fusion : la plus ancienne date d'autorité l'emporte, quel que soit le rang de sa source.
# ---------------------------------------------------------------------------------------

def test_divulgation_prime_sur_enregistrement():
    fusion = _fusion([("nvd", {"published_at": ENREGISTREMENT}),
                      ("mitre", {"published_at": DIVULGATION})])
    assert fusion["published_at"] == DIVULGATION


def test_ordre_des_contributions_sans_effet():
    """La source la mieux classée ne doit pas imposer sa date : seul l'antériorité compte."""
    fusion = _fusion([("mitre", {"published_at": DIVULGATION}),
                      ("nvd", {"published_at": ENREGISTREMENT})])
    assert fusion["published_at"] == DIVULGATION


def test_source_unique_conservee():
    fusion = _fusion([("nvd", {"published_at": ENREGISTREMENT})])
    assert fusion["published_at"] == ENREGISTREMENT


def test_date_absurde_ecartee():
    """Antérieure au programme CVE (1999) : erreur de source, pas une divulgation."""
    fusion = _fusion([("osv", {"published_at": datetime(1970, 1, 1)}),
                      ("nvd", {"published_at": ENREGISTREMENT})])
    assert fusion["published_at"] == ENREGISTREMENT


def test_aucune_date_reste_vide():
    fusion = _fusion([("nvd", {"description": "x" * 60})])
    assert fusion.get("published_at") is None


def test_trois_sources_la_plus_ancienne_gagne():
    fusion = _fusion([("nvd", {"published_at": ENREGISTREMENT}),
                      ("osv", {"published_at": datetime(2026, 8, 15)}),
                      ("mitre", {"published_at": DIVULGATION})])
    assert fusion["published_at"] == DIVULGATION


# ---------------------------------------------------------------------------------------
# Priorité de provenance : le CNA déclare la divulgation, NVD date son propre registre.
# ---------------------------------------------------------------------------------------

def test_le_cna_prime_sur_nvd_pour_la_date():
    ancienne = pv.entry(ENREGISTREMENT, "nvd")
    nouvelle = pv.entry(DIVULGATION, "cna")
    assert pv.should_replace("cve_published_at", ancienne, nouvelle)


def test_nvd_ne_remplace_pas_le_cna():
    ancienne = pv.entry(DIVULGATION, "cna")
    nouvelle = pv.entry(ENREGISTREMENT, "nvd")
    assert not pv.should_replace("cve_published_at", ancienne, nouvelle)


# ---------------------------------------------------------------------------------------
# Migration : la règle de remplacement appliquée aux fiches déjà en base.
# ---------------------------------------------------------------------------------------

def test_migration_accepte_une_date_anterieure():
    from repair_disclosure_dates import _acceptable
    assert _acceptable(DIVULGATION, ENREGISTREMENT)


def test_migration_refuse_de_reculer_vers_une_date_plus_tardive():
    """On ne remplace jamais une date par une PLUS RÉCENTE : ce serait une régression."""
    from repair_disclosure_dates import _acceptable
    assert not _acceptable(ENREGISTREMENT, DIVULGATION)


def test_migration_refuse_une_date_future():
    from repair_disclosure_dates import _acceptable
    futur = datetime.now() + timedelta(days=30)
    assert not _acceptable(futur, ENREGISTREMENT)


def test_migration_refuse_une_date_pre_cve():
    from repair_disclosure_dates import _acceptable
    assert not _acceptable(datetime(1990, 1, 1), ENREGISTREMENT)


def test_migration_renseigne_une_fiche_sans_date():
    from repair_disclosure_dates import _acceptable
    assert _acceptable(DIVULGATION, None)


def test_migration_ignore_une_absence_de_divulgation():
    """Tous les CNA ne déclarent pas `datePublic` : on garde alors la date existante."""
    from repair_disclosure_dates import _acceptable
    assert not _acceptable(None, ENREGISTREMENT)
