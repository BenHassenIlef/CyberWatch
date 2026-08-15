"""Tests du filtre « CVE PUBLIÉES aujourd'hui ».

Le filtre porte sur `published_at` — la date OFFICIELLE de publication issue de la source —
et jamais sur `collected_at`, `updated_at` ou `last_collected`, qui décrivent l'activité de
CyberWatch AI.

Aucune base requise : on vérifie le critère MongoDB produit et la logique de bornes.
"""
from datetime import datetime, timedelta, timezone

import pytest

from app.backend.routers.consultant import _day_bounds, published_today_filter
from app.backend.services.collection.schema import parse_dt


# --------------------------------------------------------------------------------------
# Outils
# --------------------------------------------------------------------------------------

def borne():
    """Fenêtre [début, fin[ de la journée courante, en UTC naïf (format stocké)."""
    return _day_bounds()


def retenue(publiee) -> bool:
    """La CVE serait-elle retenue par le filtre ? Applique le critère Mongo à la main."""
    critere = published_today_filter()["published_at"]
    if publiee is None:
        return False                      # champ absent -> jamais retenu par $gte/$lt
    return critere["$gte"] <= publiee < critere["$lt"]


# --------------------------------------------------------------------------------------
# 1-3, 5. Cas de publication
# --------------------------------------------------------------------------------------

def test_publiee_aujourdhui_est_affichee():
    debut, fin = borne()
    assert retenue(debut) is True                        # tout début de journée
    assert retenue(debut + timedelta(hours=12)) is True   # milieu
    assert retenue(fin - timedelta(seconds=1)) is True    # dernière seconde


def test_publiee_hier_non_affichee():
    debut, _ = borne()
    assert retenue(debut - timedelta(seconds=1)) is False
    assert retenue(debut - timedelta(hours=12)) is False


def test_publiee_il_y_a_sept_jours_non_affichee():
    debut, _ = borne()
    assert retenue(debut - timedelta(days=7)) is False


def test_publiee_demain_non_affichee():
    """Date future (erreur de source) : exclue par la borne haute."""
    _, fin = borne()
    assert retenue(fin) is False
    assert retenue(fin + timedelta(hours=1)) is False


def test_publiee_hier_mais_mise_a_jour_aujourdhui_non_affichee():
    """LE piège : `updated_at` d'aujourd'hui ne rend pas la CVE « publiée aujourd'hui »."""
    debut, _ = borne()
    cve = {"published_at": debut - timedelta(hours=6),   # hier
           "updated_at": debut + timedelta(hours=2)}      # aujourd'hui
    assert retenue(cve["published_at"]) is False


def test_publiee_aujourdhui_meme_si_collectee_plus_tard():
    """La date de COLLECTE n'intervient pas : seule `published_at` compte."""
    debut, _ = borne()
    cve = {"published_at": debut + timedelta(hours=3),
           "collected_at": debut + timedelta(days=1)}     # collectée demain
    assert retenue(cve["published_at"]) is True


# --------------------------------------------------------------------------------------
# 6-7. Normalisation des formats de date
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize("brut", [
    "2026-08-14",
    "2026-08-14T10:35:00",
    "2026-08-14T10:35:00Z",
    "2026-08-14T10:35:00+00:00",
])
def test_formats_iso_reconnus(brut):
    d = parse_dt(brut)
    assert isinstance(d, datetime)
    assert (d.year, d.month, d.day) == (2026, 8, 14)


def test_horodatage_utc_converti():
    """« Z » (UTC) est bien interprété comme un fuseau, pas ignoré."""
    d = parse_dt("2026-08-14T10:35:00Z")
    assert d.tzinfo is not None
    assert d.astimezone(timezone.utc).hour == 10


# --------------------------------------------------------------------------------------
# 8-9. Dates manquantes ou invalides
# --------------------------------------------------------------------------------------

def test_date_absente_traitee_sans_erreur():
    assert retenue(None) is False
    filtre = published_today_filter()
    # Un document sans `published_at` ne satisfait jamais $gte/$lt : exclusion implicite.
    assert "$gte" in filtre["published_at"] and "$lt" in filtre["published_at"]


@pytest.mark.parametrize("brut", ["", "pas une date", "0000-00-00", None, "N/A"])
def test_date_invalide_traitee_sans_erreur(brut):
    assert parse_dt(brut) is None


# --------------------------------------------------------------------------------------
# Bornes et fuseau
# --------------------------------------------------------------------------------------

def test_fenetre_couvre_exactement_24h():
    debut, fin = borne()
    assert fin - debut == timedelta(days=1)


def test_bornes_naives_comme_en_base():
    """Les dates stockées sont naïves : comparer avec des dates « aware » lèverait TypeError."""
    debut, fin = borne()
    assert debut.tzinfo is None and fin.tzinfo is None


def test_jours_precedents_ne_se_chevauchent_pas():
    hier_debut, hier_fin = _day_bounds(-1)
    debut, _ = borne()
    assert hier_fin == debut
    assert hier_debut < hier_fin


def test_filtre_porte_bien_sur_published_at():
    """Garde-fou : le filtre ne doit JAMAIS viser une date d'activité interne."""
    filtre = published_today_filter()
    assert list(filtre) == ["published_at"]
    for interdit in ("collected_at", "updated_at", "last_collected", "created_at", "last_sync"):
        assert interdit not in filtre
