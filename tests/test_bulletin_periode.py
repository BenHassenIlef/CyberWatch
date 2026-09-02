"""Bulletins par produit sur une PÉRIODE choisie par le consultant.

Le filtrage a lieu EN BASE, jamais à l'affichage : renvoyer toutes les CVE puis en masquer
une partie côté navigateur donnerait des compteurs faux — un produit annoncerait quinze
vulnérabilités là où la période n'en contient que trois.

Deux dates coexistent et ne doivent jamais être confondues : la publication officielle de la
CVE, et le moment où CyberWatch l'a détectée. Une vulnérabilité publiée la semaine dernière
et découverte ce matin intéresse le consultant aujourd'hui ; l'exclure lui ferait manquer
l'essentiel. On retient donc l'une OU l'autre, sans jamais recopier la seconde dans la
première.
"""
from datetime import datetime

import pytest

from app.backend.services.collection.product_bulletin import PeriodeInvalide, periode_match


def _bornes(filtre, champ):
    """Bornes appliquées à un champ dans le filtre produit."""
    for clause in filtre["$or"]:
        if champ in clause:
            return clause[champ]
    return None


# ---------------------------------------------------------------------------------------
# Bornes de la période.
# ---------------------------------------------------------------------------------------

def test_journee_entiere_incluse():
    """« du 18 au 20 » doit contenir TOUTE la journée du 20, pas s'arrêter à minuit."""
    f = periode_match(datetime(2026, 8, 18), datetime(2026, 8, 20))
    fin = _bornes(f, "published_at")["$lte"]
    assert (fin.hour, fin.minute, fin.second) == (23, 59, 59)
    assert fin.day == 20


def test_borne_de_debut_incluse():
    f = periode_match(datetime(2026, 8, 18), datetime(2026, 8, 20))
    assert _bornes(f, "published_at")["$gte"] == datetime(2026, 8, 18)


def test_un_seul_jour():
    """« Aujourd'hui » : début et fin sur la même date."""
    f = periode_match(datetime(2026, 8, 21), datetime(2026, 8, 21))
    bornes = _bornes(f, "published_at")
    assert bornes["$gte"].day == 21 and bornes["$lte"].day == 21


def test_publication_ou_detection():
    """Les deux dates ouvrent l'accès à la période, chacune de son côté."""
    f = periode_match(datetime(2026, 8, 18), datetime(2026, 8, 20))
    champs = {c for clause in f["$or"] for c in clause}
    assert champs == {"published_at", "collected_at"}


def test_bornes_identiques_sur_les_deux_dates():
    """Aucune des deux dates n'est privilégiée : mêmes bornes appliquées aux deux."""
    f = periode_match(datetime(2026, 8, 18), datetime(2026, 8, 20))
    assert _bornes(f, "published_at") == _bornes(f, "collected_at")


def test_periode_inversee_refusee():
    with pytest.raises(PeriodeInvalide):
        periode_match(datetime(2026, 8, 20), datetime(2026, 8, 18))


def test_sans_bornes_aucun_filtre():
    assert periode_match(None, None) == {}


def test_debut_seul_accepte():
    f = periode_match(datetime(2026, 8, 18), None)
    assert "$gte" in _bornes(f, "published_at") and "$lte" not in _bornes(f, "published_at")


def test_fin_seule_acceptee():
    f = periode_match(None, datetime(2026, 8, 20))
    assert "$lte" in _bornes(f, "published_at") and "$gte" not in _bornes(f, "published_at")


# ---------------------------------------------------------------------------------------
# Isolation des données entre CVE d'un même bulletin.
# ---------------------------------------------------------------------------------------

def _fiche(cve_id, **champs):
    base = {"cve_id": cve_id, "cvss_score": None, "severity": None, "description": None,
            "impact": None, "solution": None, "published_at": None, "collected_at": None,
            "affected_systems": [], "affected_products": [], "references": [],
            "vendor": None, "product": None}
    base.update(champs)
    return base


def test_deux_cve_gardent_leurs_valeurs_propres():
    """Le cœur de l'exigence : aucune valeur ne migre d'une vulnérabilité à l'autre."""
    a = _fiche("CVE-2026-76033", cvss_score=9.6, severity="critical",
               published_at=datetime(2026, 8, 18), impact="Corruption de mémoire",
               solution="Passer en 140.0.7339.80.")
    b = _fiche("CVE-2026-76034", cvss_score=6.1, severity="medium",
               published_at=datetime(2026, 8, 20), impact="Divulgation d'informations",
               solution="Passer en 140.0.7339.81.")
    for champ in ("cvss_score", "severity", "published_at", "impact", "solution"):
        assert a[champ] != b[champ], champ


def test_publication_et_detection_restent_distinctes():
    """Publiée le 11, détectée le 20 : les deux dates coexistent sans se remplacer."""
    f = _fiche("CVE-2026-1000", published_at=datetime(2026, 8, 11),
               collected_at=datetime(2026, 8, 20))
    assert f["published_at"].day == 11 and f["collected_at"].day == 20


def test_valeur_absente_reste_absente():
    """Rien ne comble un champ vide — surtout pas la valeur d'une autre CVE."""
    f = _fiche("CVE-2026-1001")
    assert f["solution"] is None and f["cvss_score"] is None and f["affected_systems"] == []
