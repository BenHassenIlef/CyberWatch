"""Tests de la synthèse approfondie (lecture des pages sources d'une CVE).

Aucun accès réseau ni LLM réel : les deux sont remplacés. On vérifie surtout les GARDE-FOUS,
car une remédiation erronée présentée comme officielle est dangereuse en cybersécurité.
"""
import json

import pytest

from app.backend.services.assistant import deep_synthesis as ds

CVE = {
    "_id": None,
    "cve_id": "CVE-2026-0290",
    "vendor": "Palo Alto Networks",
    "product": "Prisma Browser",
    "official_source": {"url": "https://security.paloaltonetworks.com/CVE-2026-0290"},
    "references": ["https://security.paloaltonetworks.com/CVE-2026-0290",
                   "https://nvd.nist.gov/vuln/detail/CVE-2026-0290",
                   "https://www.cve.org/CVERecord?id=CVE-2026-0290",
                   "https://github.com/CVEProject/cvelistV5/tree/main/x.json",
                   "https://blog-perso.example/analyse"],
}

PAGES = [{"url": "https://security.paloaltonetworks.com/CVE-2026-0290",
          "source": "Palo Alto Networks Security Advisories",
          "texte": "Prisma Browser 148.18.3 and earlier. Upgrade to 148.18.4.217 or later."}]


@pytest.fixture
def faux(monkeypatch):
    def _installer(reponse, pages=PAGES, dispo=True):
        async def _gen(prompt, system=None, max_tokens=None):
            return reponse
        # `cve_id` est transmis à la lecture pour cadrer les avis volumineux sur
        # l'identifiant recherché ; la doublure doit accepter le même appel.
        async def _read(urls, cve_id=None):
            return list(pages)
        monkeypatch.setattr(ds.llm, "generate", _gen)
        monkeypatch.setattr(ds.llm, "available", lambda: dispo)
        monkeypatch.setattr(ds, "read_pages", _read)
    return _installer


# --------------------------------------------------------------------------------------
# Sélection des pages
# --------------------------------------------------------------------------------------

def test_source_officielle_lue_en_premier():
    urls = ds.select_pages(CVE)
    assert urls[0] == "https://security.paloaltonetworks.com/CVE-2026-0290"


def test_pages_sans_contenu_exploitable_ecartees():
    urls = ds.select_pages(CVE)
    assert not any("cvelistV5" in u or u.endswith(".json") for u in urls)
    assert not any("blog-perso" in u for u in urls), "une source non qualifiante n'est pas lue"


def test_nombre_de_pages_borne():
    cve = {**CVE, "references": [f"https://exemple{i}.com/a" for i in range(50)]}
    assert len(ds.select_pages(cve)) <= ds.MAX_PAGES


# --------------------------------------------------------------------------------------
# Nominal
# --------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_synthese_nominale(faux):
    faux(json.dumps({
        "resume": "Une divulgation d'informations affecte Prisma Browser 148.18.3 et anterieures.",
        "solution": "Mettre a jour vers Prisma Browser 148.18.4.217 ou ulterieur.",
        "solution_source_url": "https://security.paloaltonetworks.com/CVE-2026-0290",
        "conflits": [],
    }, ensure_ascii=False))
    r = await ds.synthesize(None, dict(CVE))
    assert r["status"] == ds.COMPLETED
    assert "148.18.4.217" in r["solution"]
    assert r["solution_source"]["url"].startswith("https://security.paloaltonetworks.com")
    assert r["solution_source"]["name"] == "Palo Alto Networks Security Advisories"


# --------------------------------------------------------------------------------------
# GARDE-FOUS — le cœur du sujet
# --------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_solution_non_attribuee_est_rejetee(faux):
    """Une remédiation qui ne cite aucune page lue est écartée : elle n'est pas vérifiable."""
    faux(json.dumps({"resume": "Prisma Browser 148.18.3 est affecte.",
                     "solution": "Appliquez les correctifs de securite.",
                     "solution_source_url": None, "conflits": []}))
    r = await ds.synthesize(None, dict(CVE))
    assert r["solution"] is None
    assert r["solution_source"] is None


@pytest.mark.asyncio
async def test_solution_citant_une_page_non_lue_est_rejetee(faux):
    faux(json.dumps({"resume": "Prisma Browser 148.18.3 est affecte.",
                     "solution": "Mettre a jour.",
                     "solution_source_url": "https://site-jamais-lu.example/x",
                     "conflits": []}))
    r = await ds.synthesize(None, dict(CVE))
    assert r["solution"] is None


@pytest.mark.asyncio
async def test_resume_inventant_une_version_est_rejete(faux):
    """La version 99.9.9 n'apparait dans aucune page : le resume est ecarte."""
    faux(json.dumps({"resume": "Prisma Browser 99.9.9 est affecte par cette vulnerabilite grave.",
                     "solution": None, "solution_source_url": None, "conflits": []}))
    r = await ds.synthesize(None, dict(CVE))
    assert r["summary"] is None
    assert r["status"] == ds.INSUFFICIENT


@pytest.mark.asyncio
async def test_conflits_exposes(faux):
    faux(json.dumps({"resume": "Prisma Browser 148.18.3 est affecte.",
                     "solution": "Passer en 148.18.4.217.",
                     "solution_source_url": "https://security.paloaltonetworks.com/CVE-2026-0290",
                     "conflits": ["NVD indique CVSS 5.2, l'editeur 0.5"]}))
    r = await ds.synthesize(None, dict(CVE))
    assert len(r["conflicts"]) == 1


# --------------------------------------------------------------------------------------
# Pannes
# --------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_llm_indisponible(faux):
    faux("", dispo=False)
    r = await ds.synthesize(None, dict(CVE))
    assert r["status"] == ds.FAILED and r["solution"] is None


@pytest.mark.asyncio
async def test_aucune_page_lisible(faux):
    faux("{}", pages=[])
    r = await ds.synthesize(None, dict(CVE))
    assert r["status"] == ds.INSUFFICIENT
    assert r["pages_read"] == []


@pytest.mark.asyncio
async def test_reponse_illisible(faux):
    faux("desole, je ne peux pas repondre")
    r = await ds.synthesize(None, dict(CVE))
    assert r["status"] == ds.FAILED


@pytest.mark.asyncio
async def test_bloc_json_tolere(faux):
    faux('```json\n{"resume": "Prisma Browser 148.18.3 est affecte.", "solution": null, '
         '"solution_source_url": null, "conflits": []}\n```')
    r = await ds.synthesize(None, dict(CVE))
    assert r["status"] == ds.COMPLETED and r["summary"]


# --------------------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------------------

def test_cache_recent_reutilise():
    from app.backend.utils import utcnow
    cve = {**CVE, "deep_synthesis": {"status": ds.COMPLETED, "generated_at": utcnow()}}
    assert ds.is_fresh(cve) is True


def test_cache_perime_recalcule():
    from datetime import timedelta
    from app.backend.utils import utcnow
    vieux = utcnow() - timedelta(days=ds.CACHE_DAYS + 1)
    assert ds.is_fresh({**CVE, "deep_synthesis": {"status": ds.COMPLETED,
                                                  "generated_at": vieux}}) is False


def test_echec_non_mis_en_cache():
    from app.backend.utils import utcnow
    assert ds.is_fresh({**CVE, "deep_synthesis": {"status": ds.FAILED,
                                                  "generated_at": utcnow()}}) is False
