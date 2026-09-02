"""Tests d'idempotence du re-enrichissement.

Le defaut corrige ici : une CVE qu'AUCUNE source d'autorite ne connait n'etait pas marquee
comme traitee. La migration la reprenait donc a chaque execution — 518 enregistrements
retraites indefiniment, et l'idempotence jamais atteinte.

Distinction essentielle :
  • ERREUR TECHNIQUE (reseau, quota)  -> ne PAS marquer, retenter plus tard ;
  • ABSENCE DE DONNEE (aucune source) -> MARQUER, c'est un resultat definitif.
"""
from datetime import datetime

import pytest

import reenrich_advisory_cves as re_mod
from app.backend.services.collection import provenance as pv


class _FauxCollection:
    """Collection MongoDB minimale : enregistre les $set recus."""

    def __init__(self):
        self.ecritures = []

    async def update_one(self, filtre, maj):
        self.ecritures.append(maj.get("$set", {}))


class _FausseBase:
    def __init__(self):
        self.cves = _FauxCollection()


def _doc(published_at=None, provenance=None):
    return {"_id": "x1", "cve_id": "CVE-2026-0001", "data_origin": "CERT advisory",
            "published_at": published_at, "provenance": provenance or {}}


# --------------------------------------------------------------- marquage


@pytest.mark.asyncio
async def test_absence_de_source_est_marquee():
    """Sans autorite, la CVE doit etre marquee : sinon elle revient a chaque execution."""
    db = _FausseBase()
    journal = {"cve_id": "CVE-2026-0001", "champs": [], "erreur": None}
    await re_mod._marquer_sans_autorite(db, _doc(), journal, pv)

    assert len(db.cves.ecritures) == 1
    assert "reenriched_at" in db.cves.ecritures[0], "le marquage garantit l'idempotence"


@pytest.mark.asyncio
async def test_date_heritee_d_avis_est_videe():
    """Sans autorite, une date issue d'un avis ne peut pas rester presentee comme date CVE."""
    db = _FausseBase()
    journal = {"cve_id": "CVE-2026-0001", "champs": [], "erreur": None}
    doc = _doc(published_at=datetime(2026, 8, 18))
    await re_mod._marquer_sans_autorite(db, doc, journal, pv)

    ecrit = db.cves.ecritures[0]
    assert ecrit["published_at"] is None
    assert ecrit["validation_status"] == "insufficient_data"
    assert journal["champs"][0]["champ"] == "published_at"


@pytest.mark.asyncio
async def test_date_verifiee_n_est_jamais_videe():
    """Une date confirmee par une source d'autorite reste intouchee."""
    db = _FausseBase()
    journal = {"cve_id": "CVE-2026-0001", "champs": [], "erreur": None}
    doc = _doc(published_at=datetime(2026, 6, 24),
               provenance={"cve_published_at": {"value": datetime(2026, 6, 24),
                                                "source": "nvd",
                                                "confidence": pv.VERIFIED}})
    await re_mod._marquer_sans_autorite(db, doc, journal, pv)

    ecrit = db.cves.ecritures[0]
    assert "published_at" not in ecrit, "une date verifiee ne doit jamais etre videe"
    assert "reenriched_at" in ecrit


@pytest.mark.asyncio
async def test_deuxieme_passage_n_ecrit_rien_de_plus():
    """Idempotence : le second appel produit le meme etat, sans modification supplementaire."""
    db = _FausseBase()
    journal = {"cve_id": "CVE-2026-0001", "champs": [], "erreur": None}
    doc = _doc(published_at=datetime(2026, 8, 18))

    await re_mod._marquer_sans_autorite(db, doc, journal, pv)
    premier = dict(db.cves.ecritures[0])

    # Apres le 1er passage, le document a sa date videe : on rejoue sur cet etat.
    doc2 = _doc(published_at=None)
    await re_mod._marquer_sans_autorite(db, doc2, journal, pv)
    second = db.cves.ecritures[1]

    assert "published_at" in premier and premier["published_at"] is None
    assert "published_at" not in second, "rien de plus a vider au 2e passage"


# --------------------------------------------------------------- selection


def test_filtre_exclut_les_enregistrements_marques():
    """La requete de selection doit ignorer ce qui porte deja `reenriched_at`."""
    import inspect
    source = inspect.getsource(re_mod.run)
    # Le filtre est construit par affectation, pas en litteral : on verifie les deux
    # elements qui le composent.
    assert "reenriched_at" in source and '"$exists": False' in source, (
        "sans ce filtre, chaque execution reprendrait toute la base")


def test_erreur_technique_ne_marque_pas():
    """Une panne reseau ne doit pas etre confondue avec une absence de donnee."""
    import inspect
    source = inspect.getsource(re_mod.enrichir_une)
    bloc_exception = source.split("except Exception")[1].split("if not confirmees")[0]
    assert "_marquer_sans_autorite" not in bloc_exception, (
        "une erreur technique doit rester rejouable, donc NON marquee")
