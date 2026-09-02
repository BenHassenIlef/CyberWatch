"""Tests : un avis multi-CVE ne contamine plus les CVE qu'il cite.

Aucun identifiant de CVE codé en dur dans la logique testée : les cas ci-dessous sont
fabriques et le comportement doit valoir pour toute CVE, presente ou future.
"""
from datetime import datetime

import pytest

from app.backend.services.collection import provenance as pv
from app.backend.services.collection.collectors.advisory import advisory_to_records

AVIS = {
    "advisory_id": "tunCERT/Vuln.2026-494",
    "advisory_url": "https://www.ancs.tn/fr/vulnerabilites/exemple",
    "title": "Vulnerabilites dans les systemes Linux",
    "description": "Plusieurs vulnerabilites ont ete corrigees.",
    "published_at": datetime(2026, 8, 18),
    "product": "Systemes Linux Ubuntu",
    "vendor": "Linux",
    "impact": "Execution de code arbitraire",
    "severity": "critical",
    "affected_versions": "Ubuntu 20.04, 24.04",
    "cves": ["CVE-2026-52914", "CVE-2026-46113", "CVE-2026-53359"],
}
SOURCE = {"_id": "s1", "name": "ancs", "url": "https://www.ancs.tn/"}


def _records():
    return advisory_to_records(dict(AVIS), SOURCE)


# ---------------------------------------------------------------- TEST B : dates
def test_date_avis_ne_devient_pas_date_cve():
    for rec in _records():
        assert rec.get("published_at") in (None, ""), (
            "la date de l'avis ne doit JAMAIS servir de date de publication de la CVE")
        assert rec["advisory_published_at"] == datetime(2026, 8, 18)


# ---------------------------------------------------------------- TEST A : contamination
def test_avis_multi_cve_marque_tout_comme_non_verifie():
    recs = _records()
    assert len(recs) == 3
    for rec in recs:
        prov = rec["provenance"]
        for champ in ("description", "product", "vendor", "impact", "affected_versions"):
            assert prov[champ]["confidence"] == pv.UNVERIFIED
            assert prov[champ]["source"] == "advisory"
        assert rec["validation_status"] == "needs_review"


# ---------------------------------------------------------------- TEST C & D : independance
def test_chaque_cve_peut_diverger_apres_enrichissement():
    """Deux CVE du meme avis recoivent des faits DIFFERENTS d'une source d'autorite."""
    a, b, _c = _records()
    pv.apply(a, "cve_published_at", datetime(2026, 6, 24), "nvd")
    pv.apply(a, "cvss_score", 7.8, "nvd")
    pv.apply(a, "cwe", "CWE-130", "nvd")
    pv.apply(b, "cve_published_at", datetime(2026, 5, 29), "nvd")
    pv.apply(b, "cvss_score", 9.8, "nvd")
    pv.apply(b, "cwe", "CWE-787", "nvd")

    assert a["cve_published_at"] != b["cve_published_at"]
    assert a["cvss_score"] != b["cvss_score"]
    assert a["cwe"] != b["cwe"]
    assert a["advisory_id"] == b["advisory_id"], "elles partagent le meme avis"


def test_autorite_ecrase_avis_mais_jamais_l_inverse():
    rec = _records()[0]
    assert pv.apply(rec, "description", "Description officielle NVD.", "nvd") is True
    assert rec["description"] == "Description officielle NVD."
    # L'avis repasse : il ne doit plus rien ecraser.
    assert pv.apply(rec, "description", "Texte generique de l'avis.", "advisory",
                    confidence=pv.UNVERIFIED) is False
    assert rec["description"] == "Description officielle NVD."


# ---------------------------------------------------------------- TEST E : le LLM n'ecrit pas
def test_llm_n_ecrit_aucun_champ_factuel():
    from app.backend.services.collection.translation import TRANSLATABLE_FIELDS
    factuels = {"cvss_score", "cwe", "cve_published_at", "vendor", "product",
                "affected_versions", "fixed_version", "severity"}
    assert not (set(TRANSLATABLE_FIELDS) & factuels)


# ---------------------------------------------------------------- TEST F : rien d'invente
@pytest.mark.parametrize("valeur", [None, "", []])
def test_valeur_absente_non_inventee(valeur):
    rec = {}
    assert pv.apply(rec, "cwe", valeur, "nvd") is False
    assert "cwe" not in rec


def test_avis_sans_donnees_ne_fabrique_rien():
    avis = {"advisory_id": "X/1", "advisory_url": "https://x/1",
            "cves": ["CVE-2026-1"], "published_at": datetime(2026, 8, 18)}
    rec = advisory_to_records(avis, SOURCE)[0]
    for champ in ("description", "product", "vendor", "impact"):
        assert rec.get(champ) in (None, "", [])


# ---------------------------------------------------------------- priorite par champ
def test_priorite_specifique_au_champ():
    """L'editeur fait autorite sur les versions corrigees, NVD sur le CVSS."""
    assert pv.field_rank("fixed_version", "msrc") < pv.field_rank("fixed_version", "nvd")
    assert pv.field_rank("cvss_score", "nvd") < pv.field_rank("cvss_score", "osv")


def test_statut_de_validation():
    rec = _records()[0]
    assert pv.validation_status(rec) == "needs_review"
    pv.apply(rec, "cve_published_at", datetime(2026, 6, 24), "nvd")
    pv.apply(rec, "description", "Officielle.", "nvd")
    pv.apply(rec, "cvss_score", 7.8, "nvd")
    assert pv.validation_status(rec) == "validated"
