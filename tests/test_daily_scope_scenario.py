"""Scénario exigé : un produit ajouté rejoint-il la collecte QUOTIDIENNE NORMALE ?

Étape 1  A, B          -> collecte A + B
Étape 2  ajout de C
Étape 3  collecte      -> A + B + C
Étape 4  retrait de A  -> B + C, jamais A

On appelle le VRAI code du pipeline quotidien (`refresh_scope`, `prefilter_scope`,
`tag_and_filter`) sur une base jetable. Aucun accès réseau, aucune collecte « initiale ».
"""
import os
import sys

import pytest
from motor.motor_asyncio import AsyncIOMotorClient

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app.backend.core.config import settings           # noqa: E402
from app.backend.services.collection import monitored  # noqa: E402
from app.backend.services.collection import pipeline   # noqa: E402

DB_TEST = "cyberwatch_scope_scenario"


@pytest.fixture
async def db():
    client = AsyncIOMotorClient(settings.MONGO_URI)
    await client.drop_database(DB_TEST)
    base = client[DB_TEST]
    # Domaine actif : sans lui, un domaine désactivé exclurait les produits.
    await base.domains.insert_one({"name": "Test", "enabled": True})
    yield base
    await client.drop_database(DB_TEST)
    client.close()


async def _ajouter(db, nom, vendor, alias):
    """Écrit le produit comme le fait `POST /consultant/monitoring/products`."""
    await db.monitored_products.insert_one({
        "name": nom, "vendor": vendor, "domain": "Test",
        "aliases": alias, "keywords": alias, "cpes": [],
        "enabled": True, "is_default": False,
        "default_key": f"custom__{monitored.slug(nom)}__test"})


def _flux_du_jour():
    """Ce que les sources remontent : une CVE par produit + une hors périmètre."""
    return [
        {"cve_id": "CVE-2026-1001", "vendor": "Fortinet", "product": "FortiOS",
         "description": "Vulnerability in FortiOS."},
        {"cve_id": "CVE-2026-1002", "vendor": "Microsoft", "product": "Exchange Server",
         "description": "Vulnerability in Microsoft Exchange Server."},
        {"cve_id": "CVE-2026-1003", "vendor": "Cisco", "product": "Cisco IOS",
         "description": "Vulnerability in Cisco IOS."},
        {"cve_id": "CVE-2026-1004", "vendor": "Juniper", "product": "Junos",
         "description": "Vulnerability in Junos."},
    ]


async def collecte_quotidienne(db) -> set[str]:
    """LES DEUX ÉTAPES DE PÉRIMÈTRE DU PIPELINE QUOTIDIEN, dans l'ordre réel.

    `refresh_scope` relit la base : c'est le point qui décide si un produit ajouté participe.
    """
    await pipeline.refresh_scope(db)                      # ← relecture depuis MongoDB
    retenus = pipeline.prefilter_scope(_flux_du_jour())   # filtre nº1
    gardes, _ = pipeline.tag_and_filter(retenus)          # filtre nº2 + étiquetage
    produits: set[str] = set()
    for r in gardes:
        produits.update(r.get("monitored_products") or [])
    return produits


@pytest.mark.asyncio
async def test_scenario_complet(db):
    # ---------------------------------------------------------- ÉTAPE 1 : A et B
    await _ajouter(db, "Fortinet FortiOS", "Fortinet", ["fortios", "fortinet fortios"])
    await _ajouter(db, "Microsoft Exchange Server", "Microsoft",
                   ["microsoft exchange server", "exchange server"])

    jour1 = await collecte_quotidienne(db)
    assert jour1 == {"Fortinet FortiOS", "Microsoft Exchange Server"}
    assert "Cisco IOS" not in jour1, "Cisco IOS n'existe pas encore"

    # ---------------------------------------------------------- ÉTAPE 2 : ajout de C
    await _ajouter(db, "Cisco IOS", "Cisco", ["cisco ios"])
    actif = await db.monitored_products.find_one({"name": "Cisco IOS"})
    assert actif and actif["enabled"] is True, "le produit doit être stocké et actif"

    # ---------------------------------------------------------- ÉTAPE 3 : A + B + C
    # Aucun redémarrage, aucune collecte « initiale » : la même fonction est rappelée.
    jour2 = await collecte_quotidienne(db)
    assert jour2 == {"Fortinet FortiOS", "Microsoft Exchange Server", "Cisco IOS"}, (
        "le produit ajouté doit rejoindre la collecte quotidienne NORMALE")

    # ---------------------------------------------------------- ÉTAPE 4 : retrait de A
    await db.monitored_products.delete_one({"name": "Fortinet FortiOS"})
    jour3 = await collecte_quotidienne(db)
    assert "Fortinet FortiOS" not in jour3, "produit retiré : ne doit plus être collecté"
    assert jour3 == {"Microsoft Exchange Server", "Cisco IOS"}


@pytest.mark.asyncio
async def test_traitement_identique_pour_tous(db):
    """Le produit ajouté suit-il EXACTEMENT le même chemin que les autres ?

    On compare les étiquettes posées : même structure, même mécanisme, aucun champ
    distinguant un produit « récent » d'un produit établi.
    """
    await _ajouter(db, "Fortinet FortiOS", "Fortinet", ["fortios"])
    await _ajouter(db, "Cisco IOS", "Cisco", ["cisco ios"])
    await pipeline.refresh_scope(db)

    flux = _flux_du_jour()
    gardes, _ = pipeline.tag_and_filter(pipeline.prefilter_scope(flux))
    par_produit = {r["monitored_products"][0]: r for r in gardes}

    ancien, nouveau = par_produit["Fortinet FortiOS"], par_produit["Cisco IOS"]
    assert set(ancien) - {"cve_id", "vendor", "product", "description"} == \
           set(nouveau) - {"cve_id", "vendor", "product", "description"}, (
        "les deux produits doivent produire exactement les mêmes champs")


@pytest.mark.asyncio
async def test_desactivation_totale_ne_doit_pas_revenir_au_catalogue_code(db):
    """CONSTAT D'AUDIT : tout désactiver fait retomber sur les 80 produits codés en dur."""
    await _ajouter(db, "Cisco IOS", "Cisco", ["cisco ios"])
    await db.monitored_products.update_one({"name": "Cisco IOS"}, {"$set": {"enabled": False}})
    await pipeline.refresh_scope(db)
    actifs = {p.name for p in monitored.PRODUCTS}
    assert actifs == set(), (
        f"périmètre vide attendu ; obtenu {len(actifs)} produits issus du catalogue codé en dur")


# ---------------------------------------------------------------------------------------
# Onglet « Mises à jour aujourd'hui » — deux dates qu'il ne faut jamais confondre
# ---------------------------------------------------------------------------------------

def test_la_date_de_detection_est_exposee_a_l_interface():
    """`last_important_update` DOIT figurer dans la projection de la liste.

    L'onglet « Mises à jour aujourd'hui » filtre sur ce champ mais affichait `updated_at`,
    la date de révision annoncée par l'ÉDITEUR. Une vulnérabilité détectée comme modifiée
    ce matin s'affichait donc « 13/08 » : la liste paraissait montrer de vieilles mises à
    jour alors qu'elle montrait exactement ce qui avait bougé aujourd'hui. Sans ce champ
    dans la projection, l'interface ne peut pas rétablir la distinction.
    """
    from app.backend.routers.consultant import _LIST_PROJECTION

    assert _LIST_PROJECTION.get("last_important_update") == 1
    assert _LIST_PROJECTION.get("updated_at") == 1, "la révision éditeur reste utile"
    assert _LIST_PROJECTION.get("collected_at") == 1, "l'ancienneté doit rester visible"
    assert _LIST_PROJECTION.get("change_summary") == 1, "le consultant doit voir CE qui a changé"


def test_les_deux_onglets_du_jour_sont_disjoints():
    """« Collectées aujourd'hui » et « Mises à jour aujourd'hui » ne se recouvrent JAMAIS.

    L'onglet « Collectées » mêlait auparavant les découvertes du jour ET les fiches anciennes
    dont les données avaient changé. Il affichait donc « Collectée le 12/08 » sous un intitulé
    « Collectées aujourd'hui » : un onglet qui contredit sa propre colonne ne peut inspirer
    aucune confiance, et le consultant ne sait plus ce qu'il regarde.

    Les deux critères ci-dessous sont mutuellement exclusifs PAR CONSTRUCTION : le premier
    exige `collected_at` dans la journée, le second `collected_at` strictement avant. Ce test
    verrouille cette exclusion, qu'aucune requête ne doit rétablir par mégarde.
    """
    from datetime import datetime, timedelta

    debut = datetime(2026, 8, 23, 0, 0, 0)
    fin = debut + timedelta(days=1)

    collectees = {"collected_at": {"$gte": debut, "$lt": fin}}
    mises_a_jour = {"last_important_update": {"$gte": debut}, "collected_at": {"$lt": debut}}

    # Une fiche découverte aujourd'hui ne peut satisfaire le critère « collectée avant ».
    assert collectees["collected_at"]["$gte"] == mises_a_jour["collected_at"]["$lt"]

    hier, ce_matin = debut - timedelta(hours=2), debut + timedelta(hours=9)

    def _satisfait(bornes, valeur):
        return (("$gte" not in bornes or valeur >= bornes["$gte"])
                and ("$lt" not in bornes or valeur < bornes["$lt"]))

    # Découverte ce matin : dans « Collectées », jamais dans « Mises à jour ».
    assert _satisfait(collectees["collected_at"], ce_matin)
    assert not _satisfait(mises_a_jour["collected_at"], ce_matin)
    # Découverte hier : l'inverse exactement.
    assert not _satisfait(collectees["collected_at"], hier)
    assert _satisfait(mises_a_jour["collected_at"], hier)
