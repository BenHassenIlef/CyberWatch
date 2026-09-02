"""AUDIT — le catalogue de collecte suit-il RÉELLEMENT l'état courant de la base ?

Scénario obligatoire :
    Jour 1 : produits A, B          -> collecte A + B
    Entre les deux : + C, - A
    Jour 2 :                        -> collecte B + C, JAMAIS A

Ces tests s'exécutent sur une base MongoDB JETABLE et appellent le VRAI code
(`monitored.refresh_catalog`, `pipeline.prefilter_scope`, `pipeline.tag_and_filter`).
Aucun accès réseau : on injecte des enregistrements CVE fabriqués.
"""
import os
import sys

import pytest
from motor.motor_asyncio import AsyncIOMotorClient

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app.backend.core.config import settings          # noqa: E402
from app.backend.services.collection import monitored  # noqa: E402
from app.backend.services.collection import pipeline   # noqa: E402

DB_TEST = "cyberwatch_audit_test"


@pytest.fixture
async def db():
    client = AsyncIOMotorClient(settings.MONGO_URI)
    await client.drop_database(DB_TEST)
    base = client[DB_TEST]
    yield base
    await client.drop_database(DB_TEST)
    client.close()


async def _ajouter_produit(db, nom: str, vendor: str, alias: list[str]):
    """Ajoute un produit surveillé comme le fait le routeur `monitoring.create_product`."""
    await db.monitored_products.insert_one({
        "name": nom, "vendor": vendor, "domain": "Test",
        "aliases": alias, "keywords": alias, "cpes": [],
        "enabled": True, "is_default": False,
        "default_key": f"custom__{monitored.slug(nom)}__test",
    })


def _cve(cve_id: str, vendor: str, produit: str) -> dict:
    """Enregistrement CVE tel que produit par un collecteur (champs structurés)."""
    return {"cve_id": cve_id, "vendor": vendor, "product": produit,
            "description": f"Vulnerability in {produit}."}


async def _catalogue_actif(db) -> set[str]:
    """Produits que la collecte utiliserait MAINTENANT (relecture depuis la base)."""
    await monitored.refresh_catalog(db)
    return {p.name for p in monitored.PRODUCTS}


async def _collecte_simulee(db, records: list[dict]) -> set[str]:
    """Rejoue les 2 étapes de périmètre du vrai pipeline et renvoie les produits retenus."""
    await monitored.refresh_catalog(db)
    retenus = pipeline.prefilter_scope(records)
    gardes, _ecartes = pipeline.tag_and_filter(retenus)
    out: set[str] = set()
    for r in gardes:
        out.update(r.get("monitored_products") or [])
    return out


# =======================================================================================
# LE SCÉNARIO OBLIGATOIRE
# =======================================================================================

@pytest.mark.asyncio
async def test_jour1_puis_ajout_et_suppression_puis_jour2(db):
    # ---------------------------------------------------------------- JOUR 1 : A et B
    await _ajouter_produit(db, "Fortinet FortiOS", "Fortinet", ["fortios", "fortinet fortios"])
    await _ajouter_produit(db, "Cisco ASA", "Cisco", ["cisco asa", "adaptive security appliance"])

    flux = [
        _cve("CVE-2026-1001", "Fortinet", "FortiOS"),
        _cve("CVE-2026-1002", "Cisco", "Cisco ASA"),
        _cve("CVE-2026-1003", "Juniper", "Junos"),      # hors périmètre : jamais retenu
    ]
    jour1 = await _collecte_simulee(db, [dict(r) for r in flux])
    assert jour1 == {"Fortinet FortiOS", "Cisco ASA"}, "Jour 1 doit collecter A et B"

    # ------------------------------------------- ENTRE LES DEUX : le consultant modifie
    await _ajouter_produit(db, "Microsoft Exchange Server", "Microsoft",
                           ["microsoft exchange server", "exchange server"])
    await db.monitored_products.delete_one({"name": "Fortinet FortiOS"})

    # ---------------------------------------------------------------- JOUR 2 : B et C
    flux2 = [
        _cve("CVE-2026-2001", "Fortinet", "FortiOS"),            # A supprimé -> exclu
        _cve("CVE-2026-2002", "Cisco", "Cisco ASA"),             # B conservé
        _cve("CVE-2026-2003", "Microsoft", "Exchange Server"),   # C ajouté
    ]
    jour2 = await _collecte_simulee(db, [dict(r) for r in flux2])

    assert "Fortinet FortiOS" not in jour2, "PRODUIT SUPPRIMÉ : ne doit plus être collecté"
    assert "Cisco ASA" in jour2, "produit conservé"
    assert "Microsoft Exchange Server" in jour2, "PRODUIT AJOUTÉ : inclus sans redémarrage"


@pytest.mark.asyncio
async def test_produit_desactive_exclu(db):
    """Désactiver (sans supprimer) doit suffire à sortir le produit du périmètre."""
    await _ajouter_produit(db, "Cisco IOS", "Cisco", ["cisco ios"])
    assert "Cisco IOS" in await _catalogue_actif(db)

    await db.monitored_products.update_one({"name": "Cisco IOS"}, {"$set": {"enabled": False}})
    assert "Cisco IOS" not in await _catalogue_actif(db)


@pytest.mark.asyncio
async def test_domaine_desactive_exclut_ses_produits(db):
    await _ajouter_produit(db, "Cisco IOS", "Cisco", ["cisco ios"])
    await db.domains.insert_one({"name": "Test", "enabled": False})
    assert "Cisco IOS" not in await _catalogue_actif(db)


@pytest.mark.asyncio
async def test_aucun_redemarrage_necessaire(db):
    """Le catalogue est relu à CHAQUE collecte : un ajout est visible dans le même processus."""
    await _ajouter_produit(db, "Cisco ASA", "Cisco", ["cisco asa"])
    avant = await _catalogue_actif(db)

    await _ajouter_produit(db, "Apache Tomcat", "Apache", ["apache tomcat", "tomcat"])
    apres = await _catalogue_actif(db)          # aucun redémarrage entre les deux

    assert "Apache Tomcat" not in avant
    assert "Apache Tomcat" in apres


# =======================================================================================
# FAUX POSITIFS (lot B — non implémenté : ces tests DOIVENT échouer aujourd'hui)
# =======================================================================================

@pytest.mark.asyncio
async def test_faux_positif_alias_editeur_seul(db):
    """Un produit créé via l'interface hérite d'un alias réduit à l'ÉDITEUR.

    Conséquence : « Windows Server 2022 » capte toute CVE Microsoft. C'est exactement le
    faux positif que le lot B doit supprimer.
    """
    alias, mots = monitored._auto_aliases("Windows Server 2022", "Microsoft")
    await _ajouter_produit(db, "Windows Server 2022", "Microsoft", alias)
    # `_auto_aliases` place l'éditeur nu dans les alias larges.
    assert "microsoft" in alias, "constat d'audit : l'éditeur seul sert d'alias"

    hors_sujet = [
        _cve("CVE-2026-9001", "Microsoft", "Excel"),
        _cve("CVE-2026-9002", "Microsoft", "Xbox Gaming Services"),
    ]
    retenus = await _collecte_simulee(db, [dict(r) for r in hors_sujet])
    assert "Windows Server 2022" not in retenus, (
        "FAUX POSITIF : Excel et Xbox ne concernent pas Windows Server 2022")


@pytest.mark.asyncio
async def test_niveaux_de_confiance_presents(db):
    """Le lot B exige confirmed / high_confidence / possible / rejected."""
    await _ajouter_produit(db, "Cisco ASA", "Cisco", ["cisco asa"])
    await monitored.refresh_catalog(db)
    rec = _cve("CVE-2026-3001", "Cisco", "Cisco ASA")
    _gardes, _ = pipeline.tag_and_filter([rec])
    assert "match_confidence" in rec, "aucun niveau de confiance n'est stocké"
    assert "match_evidence" in rec, "aucune preuve d'appariement n'est stockée"
