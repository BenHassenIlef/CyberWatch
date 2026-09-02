"""Tests d'intégrité globale : identité CVE, CVSS, provenance, absence de contamination.

Aucun identifiant de CVE codé en dur dans la LOGIQUE testée : les cas sont fabriqués et le
comportement doit valoir pour toute CVE, présente ou future.
"""
from datetime import datetime

import pytest

from app.backend.services.collection import provenance as pv
from app.backend.services.collection import sanitize as sz
from app.backend.services.collection.collectors.advisory import advisory_to_records


# --------------------------------------------------------------- RÈGLE D'IDENTITÉ

@pytest.mark.asyncio
async def test_enrichissement_utilise_l_identifiant_exact(monkeypatch):
    """Aucune requête ne doit partir avec un advisory_id, un titre ou une autre CVE."""
    from app.backend.services.collection import enrichment

    appels = []

    async def _faux(cve_id):
        appels.append(cve_id)
        return {}

    monkeypatch.setattr(enrichment, "_from_nvd", _faux)
    monkeypatch.setattr(enrichment, "_FAST_ENRICHERS",
                        {"mitre": _faux, "osv": _faux, "redhat": _faux})

    cible = "CVE-2026-11111"
    await enrichment.enrich(cible, seed=None, use_nvd=True)

    assert appels, "aucune source interrogée"
    assert all(a == cible for a in appels), "chaque requête doit porter le CVE ID exact"


def test_advisory_id_n_est_jamais_un_identifiant_de_cve():
    from app.backend.services.collection.schema import CVE_RE
    for faux in ("tunCERT/Vuln.2026-494", "67052907/26", "DGSSI-2026-01"):
        assert not CVE_RE.fullmatch(faux)


# --------------------------------------------------------------- CVSS

@pytest.mark.parametrize("ancien,nouveau,autorise", [
    ("CVSS:4.0/AV:N/AC:L", "CVSS:3.1/AV:N/AC:L", False),
    ("CVSS:3.1/AV:N/AC:L", "CVSS:4.0/AV:N/AC:L", True),
    ("CVSS:3.1/AV:N/AC:L", "CVSS:3.1/AV:L/AC:H", True),
    (None, "CVSS:3.1/AV:N/AC:L", True),
    ("CVSS:4.0/AV:N", None, False),
])
def test_bareme_cvss_jamais_degrade(ancien, nouveau, autorise):
    assert pv.allows_cvss_replacement(ancien, nouveau) is autorise


def test_version_cvss_lue_correctement():
    assert pv.cvss_version("CVSS:4.0/AV:N/AC:L") == 4.0
    assert pv.cvss_version("CVSS:3.1/AV:N") == 3.1
    assert pv.cvss_version("texte sans vecteur") == 0.0
    assert pv.cvss_version(None) == 0.0


# --------------------------------------------------------------- ISOLATION AVIS / CVE

def _avis_40():
    cves = ["CVE-2026-" + str(9000 + i) for i in range(40)]
    return {"advisory_id": "AVIS/2026-1", "advisory_url": "https://cert.example/a1",
            "title": "Vulnerabilites multiples", "description": "Texte generique du bulletin.",
            "published_at": datetime(2026, 8, 18), "updated_at": datetime(2026, 8, 19),
            "product": "Produit generique", "vendor": "Editeur", "cves": cves}, cves


def test_avis_de_40_cve_donne_40_fiches_independantes():
    avis, cves = _avis_40()
    recs = advisory_to_records(avis, {"_id": "s", "name": "cert"})
    assert len(recs) == 40
    assert {r["cve_id"] for r in recs} == set(cves)
    # Objets DISTINCTS : modifier une fiche ne doit en toucher aucune autre.
    recs[0]["cvss_score"] = 9.8
    assert all(r.get("cvss_score") is None for r in recs[1:])


def test_les_40_peuvent_diverger_totalement():
    avis, _ = _avis_40()
    recs = advisory_to_records(avis, {"_id": "s", "name": "cert"})
    for i, rec in enumerate(recs[:5]):
        pv.apply(rec, "cve_published_at", datetime(2026, 1, 1 + i), "nvd")
        pv.apply(rec, "cvss_score", 5.0 + i, "nvd")
        pv.apply(rec, "cwe", "CWE-" + str(100 + i), "nvd")
    assert len({r["cve_published_at"] for r in recs[:5]}) == 5
    assert len({r["cvss_score"] for r in recs[:5]}) == 5
    assert len({r["cwe"] for r in recs[:5]}) == 5


def test_dates_avis_ne_deviennent_jamais_dates_cve():
    avis, _ = _avis_40()
    for rec in advisory_to_records(avis, {"_id": "s", "name": "cert"}):
        assert rec.get("published_at") in (None, "")
        assert rec.get("updated_at") in (None, "")
        assert rec["advisory_published_at"] == datetime(2026, 8, 18)
        assert rec["advisory_updated_at"] == datetime(2026, 8, 19)


def test_associated_cves_ne_contamine_pas():
    avis, cves = _avis_40()
    recs = advisory_to_records(avis, {"_id": "s", "name": "cert"})
    a, b = recs[0], recs[1]
    pv.apply(a, "description", "Description propre a la premiere.", "mitre")
    assert set(a["associated_cves"]) == set(cves)
    assert b.get("description") != "Description propre a la premiere."


# --------------------------------------------------------------- PROVENANCE

def test_valeur_verifiee_resiste_a_l_avis():
    rec = {}
    pv.apply(rec, "description", "Description officielle NVD.", "nvd", confidence=pv.VERIFIED)
    for source in ("advisory", "ancs", "dgssi", "cert"):
        assert pv.apply(rec, "description", "Texte du bulletin.", source,
                        confidence=pv.UNVERIFIED) is False
    assert rec["description"] == "Description officielle NVD."


def test_avis_ne_peut_jamais_etre_verified():
    assert pv.entry("valeur", "advisory")["confidence"] == pv.UNVERIFIED
    for s in pv.ADVISORY_SOURCES:
        assert pv.entry("v", s)["confidence"] == pv.UNVERIFIED


def test_cve_avec_donnees_d_avis_seules_n_est_pas_validated():
    avis, _ = _avis_40()
    rec = advisory_to_records(avis, {"_id": "s", "name": "cert"})[0]
    assert pv.validation_status(rec) != "validated"


def test_absence_de_source_laisse_null():
    rec = {}
    for valeur in (None, "", []):
        assert pv.apply(rec, "cvss_score", valeur, "nvd") is False
    assert rec.get("cvss_score") is None


# --------------------------------------------------------------- ASSAINISSEMENT

@pytest.mark.parametrize("texte", [
    "@media screen and (max-width:640px){.PageFooter{display:none}}",
    "<script>var x = 1;</script> some more text to reach the minimum length here",
    "<style>.a{color:red}</style> additional filler text to reach minimum length",
    "You are being redirected to the vulnerability detail page in a few seconds.",
    "Access denied. Please enable JavaScript to continue browsing this website.",
])
def test_description_bruit_rejetee(texte):
    assert sz.clean_description(texte) is None


@pytest.mark.parametrize("nom", [
    "CVE-2025-24293 - Overview, Insights & Trends",
    "Newest CVEs",
    "Latest trending vulnerabilities - SecAlerts",
])
def test_produit_titre_de_page_rejete(nom):
    assert sz.clean_product(nom) is None


@pytest.mark.parametrize("nom", ["Linux Kernel", "Microsoft Exchange Server", "FortiOS"])
def test_produit_legitime_conserve(nom):
    assert sz.clean_product(nom) == nom


def test_description_legitime_conservee():
    t = ("A heap-based buffer overflow in the batman-adv module allows a local attacker "
         "to escalate privileges on affected systems.")
    assert sz.clean_description(t) == t


def test_donnee_rejetee_devient_null_pas_devinee():
    rec = {"description": "@media screen and (max-width:640px){}", "product": "Newest CVEs"}
    sz.clean_record(rec)
    assert rec["description"] is None
    assert rec["product"] is None


# --------------------------------------------------------------- LLM

def test_llm_ne_touche_aucun_champ_factuel():
    from app.backend.services.collection.translation import TRANSLATABLE_FIELDS
    interdits = {"cve_id", "published_at", "updated_at", "cvss_score", "cvss_vector",
                 "severity", "cwe", "vendor", "product", "affected_versions",
                 "fixed_version", "advisory_id", "advisory_published_at",
                 "advisory_updated_at"}
    assert not (set(TRANSLATABLE_FIELDS) & interdits)


def test_traduction_ecrit_uniquement_des_champs_fr():
    from app.backend.services.collection import translation as tr
    original = "An attacker can execute arbitrary code on the affected host."
    sortie = tr.apply_localization({"description": original,
                                    "description_fr": "Un attaquant peut executer du code."})
    assert sortie["description"] == "Un attaquant peut executer du code."
    assert sortie["description_original"] == original


# --------------------------------------------------------------- PRIORITÉ PAR CHAMP

def test_priorite_est_specifique_au_champ():
    assert pv.field_rank("fixed_version", "msrc") < pv.field_rank("fixed_version", "nvd")
    assert pv.field_rank("cvss_score", "nvd") < pv.field_rank("cvss_score", "osv")
    assert pv.field_rank("description", "mitre") < pv.field_rank("description", "osv")
    assert pv.field_rank("affected_versions", "msrc") < pv.field_rank("affected_versions", "nvd")
