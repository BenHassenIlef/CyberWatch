"""Tests de la date de publication : un avis récent ne rajeunit jamais une vieille CVE."""
from datetime import datetime, timedelta

import pytest

from app.backend.routers.consultant import _day_bounds
from app.backend.services.collection.storage import _diff, accept_publication_date
from repair_publication_dates import classer


def _fenetre_du_jour():
    return _day_bounds()


def _publie_aujourdhui(d):
    debut, fin = _fenetre_du_jour()
    return isinstance(d, datetime) and debut <= d < fin


def _collecte_aujourdhui(d):
    debut, fin = _fenetre_du_jour()
    return isinstance(d, datetime) and debut <= d < fin


AUJ = _day_bounds()[0] + timedelta(hours=6)      # dans la fenêtre du jour
MAI = datetime(2026, 5, 29, 8, 8, 10)


# ---------------------------------------------------------------- TEST 1 & 5
def test_vieille_cve_citee_par_un_avis_du_jour():
    """CVE publiée en mai, avis + collecte aujourd'hui -> collectée oui, publiée NON."""
    existant = {"published_at": MAI}
    nouveau = {"published_at": AUJ}                  # date de L'AVIS, pas de la CVE
    champs, _chg, _imp = _diff(existant, nouveau)

    assert "published_at" not in champs, "la date de l'avis ne doit pas écraser celle de la CVE"
    final = champs.get("published_at", existant["published_at"])
    assert _publie_aujourdhui(final) is False
    assert _collecte_aujourdhui(AUJ) is True


# ---------------------------------------------------------------- TEST 2
def test_cve_reellement_publiee_aujourdhui():
    champs, _c, _i = _diff({"published_at": None}, {"published_at": AUJ})
    assert champs["published_at"] == AUJ
    assert _publie_aujourdhui(AUJ) is True


# ---------------------------------------------------------------- TEST 3
def test_date_existante_non_ecrasee_par_plus_recente():
    champs, _c, _i = _diff({"published_at": MAI}, {"published_at": datetime(2026, 8, 18)})
    assert "published_at" not in champs


# ---------------------------------------------------------------- TEST 4
def test_correction_vers_une_date_anterieure_acceptee():
    champs, _c, _i = _diff({"published_at": datetime(2026, 6, 10)}, {"published_at": MAI})
    assert champs["published_at"] == MAI, "une date antérieure vérifiée doit corriger"


# ---------------------------------------------------------------- TEST 6
@pytest.mark.parametrize("valeur", [None, "", "pas une date", []])
def test_aucune_date_fiable_rien_n_est_invente(valeur):
    champs, _c, _i = _diff({"published_at": MAI}, {"published_at": valeur})
    assert "published_at" not in champs


def test_date_future_refusee():
    futur = datetime.utcnow() + timedelta(days=30)
    assert accept_publication_date(futur, None) is False


def test_date_anterieure_au_programme_cve_refusee():
    assert accept_publication_date(datetime(1990, 1, 1), datetime(2026, 8, 18)) is False


# ---------------------------------------------------------------- premier_publie suit la correction
def test_first_published_suit_une_correction():
    from app.backend.services.collection import storage
    champs, _c, _i = storage._diff({"published_at": datetime(2026, 6, 10),
                                    "first_published": datetime(2026, 6, 10)},
                                   {"published_at": MAI})
    assert champs["published_at"] == MAI


# ---------------------------------------------------------------- classement de réparation
def test_classement_reparation():
    maintenant = datetime(2026, 8, 18)
    ok, motif = classer(datetime(2026, 8, 18), MAI, maintenant)
    assert ok is True and "reparable" in motif

    ok, motif = classer(MAI, datetime(2026, 8, 18), maintenant)
    assert ok is False and motif == "coherent"

    ok, motif = classer(datetime(2026, 8, 18), datetime(1990, 1, 1), maintenant)
    assert ok is False and motif.startswith("AMBIGU")

    ok, motif = classer(datetime(2026, 8, 18), None, maintenant)
    assert ok is False and motif == "date manquante"
