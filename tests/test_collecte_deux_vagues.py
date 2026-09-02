"""COLLECTE EN DEUX VAGUES — empêcher les portails HTML d'étouffer les sources d'API.

Toutes les sources partaient ensemble. Les portails HTML ouvrent un navigateur Chromium et
parcourent plusieurs pages ; les API se contentent d'une requête. Lancés simultanément, les
premiers saturaient la machine et les secondes expiraient.

Mesuré sur l'installation avant correction : NVD, le catalogue KEV de la CISA et l'API MSRC
échouaient TOUS LES TROIS en collecte complète (0 CVE, « délai HTTP dépassé »), alors que
lancés seuls ils répondent en 20 secondes et rapportent 2 210 vulnérabilités. On perdait
exactement les trois sources qui font autorité — et le rapport accusait les serveurs distants.

Après correction : 14 sources sur 14 abouties, 2 890 CVE détectées contre 106.

Ces tests verrouillent les trois propriétés dont dépend la correction :
  • les sources d'API passent AVANT tout portail HTML ;
  • jamais plus de `SOURCES_HTML_SIMULTANEES` portails en parallèle ;
  • les résultats restent APPARIÉS à leur source — un décalage attribuerait les CVE
    d'une source à une autre.

Aucun appel réseau : les collecteurs sont simulés.
"""
import asyncio

import pytest

from app.backend.services.collection import pipeline as P
from app.backend.services.collection.collectors import base as collectors


class _JournalMuet:
    def info(self, *a, **k):
        pass

    def error(self, *a, **k):
        pass


def _sources():
    """Deux API, un flux, et quatre portails HTML — l'ordre mélange volontairement les deux."""
    return [
        {"name": "portail-a", "collection_method": "scraping"},
        {"name": "nvd", "collection_method": "api_public", "data_format": "json"},
        {"name": "portail-b", "collection_method": "scraping"},
        {"name": "flux", "collection_method": "rss"},
        {"name": "portail-c", "collection_method": "scraping"},
        {"name": "msrc", "collection_method": "api_public", "data_format": "json"},
        {"name": "portail-d", "collection_method": "scraping"},
    ]


@pytest.fixture
def observateur(monkeypatch):
    """Enregistre l'ordre de passage et le parallélisme réel de chaque source."""
    trace = {"ordre": [], "en_cours": 0, "pic_html": 0}

    async def _collect_one(source, logger):
        nom = source["name"]
        html = nom.startswith("portail")
        trace["ordre"].append(nom)
        if html:
            trace["en_cours"] += 1
            trace["pic_html"] = max(trace["pic_html"], trace["en_cours"])
        await asyncio.sleep(0.01)          # laisse l'ordonnanceur entrelacer les tâches
        if html:
            trace["en_cours"] -= 1
        return {"ok": True, "status": "success", "key": "html" if html else "json",
                "records": [{"cve_id": f"CVE-2026-{nom}"}], "detected": 1, "error": None}

    monkeypatch.setattr(P, "_collect_one", _collect_one)
    return trace


def test_les_api_passent_avant_les_portails_html(observateur):
    """Une API ne doit JAMAIS attendre qu'un navigateur ait fini de parcourir un portail."""
    sources = _sources()
    asyncio.run(P._collecter_par_vagues(sources, _JournalMuet()))

    legeres = {"nvd", "msrc", "flux"}
    rangs_legers = [i for i, n in enumerate(observateur["ordre"]) if n in legeres]
    rangs_lourds = [i for i, n in enumerate(observateur["ordre"]) if n not in legeres]
    assert max(rangs_legers) < min(rangs_lourds), (
        "une source d'API a été lancée après un portail HTML : "
        f"ordre observé = {observateur['ordre']}")


def test_les_portails_html_sont_plafonnes(observateur):
    """Le parallélisme des portails est borné : c'est lui qui saturait la machine."""
    asyncio.run(P._collecter_par_vagues(_sources(), _JournalMuet()))
    assert observateur["pic_html"] <= P.SOURCES_HTML_SIMULTANEES


def test_les_resultats_restent_apparies_a_leur_source(observateur):
    """L'appelant apparie `sources[i]` et `results[i]` : un décalage mélangerait les CVE.

    C'est la propriété la plus dangereuse à casser — elle ne provoque aucune erreur, elle
    attribue silencieusement les vulnérabilités d'une source à une autre, et fait avancer
    `last_sync_at` sur la mauvaise.
    """
    sources = _sources()
    resultats = asyncio.run(P._collecter_par_vagues(sources, _JournalMuet()))

    assert len(resultats) == len(sources)
    assert all(r is not None for r in resultats), "une source n'a pas produit de résultat"
    for source, resultat in zip(sources, resultats):
        assert resultat["records"][0]["cve_id"] == f"CVE-2026-{source['name']}"


def test_toutes_les_sources_sont_collectees(observateur):
    asyncio.run(P._collecter_par_vagues(_sources(), _JournalMuet()))
    assert sorted(observateur["ordre"]) == sorted(s["name"] for s in _sources())


def test_une_seule_nature_de_source_ne_bloque_rien(observateur):
    """Un parc composé uniquement d'API — ou uniquement de portails — doit fonctionner."""
    api_seules = [{"name": "nvd", "collection_method": "api_public", "data_format": "json"}]
    assert len(asyncio.run(P._collecter_par_vagues(api_seules, _JournalMuet()))) == 1

    html_seuls = [{"name": "portail-a", "collection_method": "scraping"},
                  {"name": "portail-b", "collection_method": "scraping"}]
    assert len(asyncio.run(P._collecter_par_vagues(html_seuls, _JournalMuet()))) == 2


# ---------------------------------------------------------------------------------------
# Classement des méthodes : c'est lui qui décide de la vague
# ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("source, sans_navigateur", [
    ({"collection_method": "api_public", "data_format": "json"}, True),
    ({"collection_method": "api_protected", "data_format": "json"}, True),
    ({"collection_method": "rss"}, True),
    ({"data_format": "xml"}, True),
    ({"url": "https://exemple.fr/sitemap.xml"}, True),
    ({"collection_method": "scraping"}, False),
    ({}, False),                       # défaut : scraping HTML
])
def test_classement_des_methodes(source, sans_navigateur):
    _, cle = collectors.resolve(source)
    assert (cle in P.METHODES_SANS_NAVIGATEUR) is sans_navigateur


# ---------------------------------------------------------------------------------------
# Compte des publications du jour — ce qui rend un résultat vide interprétable
# ---------------------------------------------------------------------------------------

def test_compte_des_publications_du_jour():
    """« 36 parues aujourd'hui, 0 sur vos produits » est une réponse ; « 0 » n'en est pas une."""
    from datetime import datetime, timedelta

    debut, _ = P._bornes_du_jour()
    aujourd_hui = debut + timedelta(hours=3)
    records = [
        {"cve_id": "CVE-2026-1", "published_at": aujourd_hui},
        {"cve_id": "CVE-2026-2", "published_at": aujourd_hui},
        {"cve_id": "CVE-2026-3", "published_at": debut - timedelta(days=5)},   # ancienne
        {"cve_id": "CVE-2026-4"},                                             # sans date
        {"cve_id": "CVE-2026-5", "published_at": "2026-08-23"},               # date non typée
    ]
    assert P._compter_publiees_du_jour(records) == 2
    assert P._compter_publiees_du_jour([]) == 0
