"""Configuration de surveillance (CONSULTANT) : domaines + produits surveillés, pilotés par la BASE.

Ces objets alimentent DYNAMIQUEMENT la collecte : ajouter/activer un produit ici suffit pour qu'il
soit pris en compte à la prochaine collecte — aucune modification de code. Après chaque écriture, on
rafraîchit le catalogue actif en mémoire (`monitored.refresh_catalog`).

Option de collecte HISTORIQUE à la création d'un produit (`history_days` : 0/7/30/90) : lance en
arrière-plan une collecte NVD ciblée du produit (sans relancer toutes les sources).
"""
from bson import ObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status

from app.backend.db.mongodb import get_database
from app.backend.dependencies.auth import require_role
from app.backend.schemas.monitoring import (DomainCreate, DomainUpdate, ProductCreate, ProductUpdate)
from app.backend.services.audit import log_action
from app.backend.services.collection import monitored, product_history
from app.backend.utils import serialize_doc, utcnow

router = APIRouter(prefix="/consultant/monitoring", tags=["monitoring"],
                   dependencies=[Depends(require_role("consultant"))])


def _oid(raw: str) -> ObjectId:
    try:
        return ObjectId(raw)
    except InvalidId:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Identifiant invalide.")


async def _refresh():
    """Recharge le catalogue actif après toute modification (effet immédiat sur la classification)."""
    await monitored.refresh_catalog(get_database())


# --------------------------------------------------------------------------------- Domaines
@router.get("/domains")
async def list_domains():
    db = get_database()
    await monitored.seed_catalog(db)
    docs = await db.domains.find().sort("name", 1).to_list(300)
    # Nb de produits par domaine (aide l'UI).
    counts = {d["_id"]: d["n"] async for d in db.monitored_products.aggregate(
        [{"$group": {"_id": "$domain", "n": {"$sum": 1}}}])}
    out = []
    for d in docs:
        doc = serialize_doc(d)
        doc["product_count"] = counts.get(d["name"], 0)
        out.append(doc)
    return out


@router.post("/domains", status_code=status.HTTP_201_CREATED)
async def create_domain(payload: DomainCreate, user: dict = Depends(require_role("consultant"))):
    db = get_database()
    name = payload.name.strip()
    if await db.domains.find_one({"name": name}):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Ce domaine existe déjà.")
    now = utcnow()
    doc = {"name": name, "description": payload.description or "", "enabled": payload.enabled,
           "deletable": True, "created_at": now, "updated_at": now}
    res = await db.domains.insert_one(doc)
    await log_action(str(user["_id"]), "consultant", "monitoring.domain.create", {"name": name})
    await _refresh()
    return serialize_doc({**doc, "_id": res.inserted_id})


@router.put("/domains/{domain_id}")
async def update_domain(domain_id: str, payload: DomainUpdate, user: dict = Depends(require_role("consultant"))):
    db = get_database()
    existing = await db.domains.find_one({"_id": _oid(domain_id)})
    if not existing:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Domaine introuvable.")
    updates = {k: v for k, v in payload.model_dump(exclude_none=True).items()}
    if not updates:
        return serialize_doc(existing)
    updates["updated_at"] = utcnow()
    # Renommage : on répercute sur les produits pour garder la cohérence des filtres.
    if "name" in updates and updates["name"].strip() != existing["name"]:
        updates["name"] = updates["name"].strip()
        await db.monitored_products.update_many({"domain": existing["name"]},
                                                {"$set": {"domain": updates["name"]}})
    await db.domains.update_one({"_id": existing["_id"]}, {"$set": updates})
    await log_action(str(user["_id"]), "consultant", "monitoring.domain.update", {"id": domain_id})
    await _refresh()
    return serialize_doc({**existing, **updates})


@router.delete("/domains/{domain_id}")
async def delete_domain(domain_id: str, user: dict = Depends(require_role("consultant"))):
    db = get_database()
    existing = await db.domains.find_one({"_id": _oid(domain_id)})
    if not existing:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Domaine introuvable.")
    if existing.get("deletable") is False:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Ce domaine ne peut pas être supprimé.")
    n = await db.monitored_products.count_documents({"domain": existing["name"]})
    if n:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            f"Supprimez ou déplacez d'abord les {n} produit(s) de ce domaine.")
    await db.domains.delete_one({"_id": existing["_id"]})
    await log_action(str(user["_id"]), "consultant", "monitoring.domain.delete", {"name": existing["name"]})
    await _refresh()
    return {"deleted": True}


# --------------------------------------------------------------------------------- Produits
@router.get("/products")
async def list_products(domain: str | None = None, vendor: str | None = None,
                        q: str | None = None, enabled: bool | None = None):
    db = get_database()
    await monitored.seed_catalog(db)
    query: dict = {}
    if domain:
        query["domain"] = domain
    if vendor:
        query["vendor"] = vendor
    if enabled is not None:
        query["enabled"] = enabled
    if q:
        rx = {"$regex": q.strip(), "$options": "i"}
        query["$or"] = [{"name": rx}, {"vendor": rx}, {"aliases": rx}, {"keywords": rx}]
    docs = await db.monitored_products.find(query).sort([("domain", 1), ("name", 1)]).to_list(2000)
    return [serialize_doc(d) for d in docs]


def _clean_list(items: list[str] | None) -> list[str]:
    return list(dict.fromkeys([s.strip() for s in (items or []) if s and s.strip()]))


@router.post("/products", status_code=status.HTTP_201_CREATED)
async def create_product(payload: ProductCreate, background: BackgroundTasks,
                         user: dict = Depends(require_role("consultant"))):
    db = get_database()
    name = payload.name.strip()
    domain = payload.domain.strip()
    if await db.monitored_products.find_one({"name": name, "domain": domain}):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Un produit portant ce nom existe déjà dans ce domaine.")
    # Crée le domaine à la volée s'il n'existe pas encore (jamais bloquant).
    if not await db.domains.find_one({"name": domain}):
        now0 = utcnow()
        await db.domains.insert_one({"name": domain, "description": "", "enabled": True,
                                     "deletable": True, "is_default": False, "created_at": now0, "updated_at": now0})
    # Alias/mots-clés GÉNÉRÉS EN INTERNE à partir du nom + éditeur (l'admin ne saisit rien de technique).
    aliases, keywords = _clean_list(payload.aliases), _clean_list(payload.keywords)
    if not aliases and not keywords:
        aliases, keywords = monitored._auto_aliases(name, payload.vendor)
    now = utcnow()
    doc = {"name": name, "vendor": (payload.vendor or "").strip(), "domain": domain,
           "aliases": aliases, "keywords": keywords, "cpes": _clean_list(payload.cpes),
           "enabled": payload.enabled, "is_default": False,       # produit PERSONNALISÉ (jamais élagué)
           "default_key": f"custom__{monitored.slug(name)}__{monitored.slug(domain)}",
           "created_at": now, "updated_at": now, "last_collection_at": None,
           "cve_count": 0, "new_count": 0}
    res = await db.monitored_products.insert_one(doc)
    await log_action(str(user["_id"]), "consultant", "monitoring.product.create",
                     {"name": name, "domain": doc["domain"], "history_days": payload.history_days})
    await _refresh()   # dès maintenant, la classification connaît ce produit

    saved = serialize_doc({**doc, "_id": res.inserted_id})
    # Collecte HISTORIQUE ciblée (optionnelle) en arrière-plan — n'impacte pas la collecte planifiée.
    if payload.enabled and payload.history_days:
        background.add_task(product_history.collect_product_history, db, dict(doc), int(payload.history_days))
        saved["history_started"] = True
    return saved


@router.put("/products/{product_id}")
async def update_product(product_id: str, payload: ProductUpdate,
                         user: dict = Depends(require_role("consultant"))):
    db = get_database()
    existing = await db.monitored_products.find_one({"_id": _oid(product_id)})
    if not existing:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Produit introuvable.")
    data = payload.model_dump(exclude_none=True)
    for key in ("aliases", "keywords", "cpes"):
        if key in data:
            data[key] = _clean_list(data[key])
    for key in ("name", "vendor", "domain"):
        if key in data and isinstance(data[key], str):
            data[key] = data[key].strip()
    if not data:
        return serialize_doc(existing)
    data["updated_at"] = utcnow()
    await db.monitored_products.update_one({"_id": existing["_id"]}, {"$set": data})
    await log_action(str(user["_id"]), "consultant", "monitoring.product.update", {"id": product_id})
    await _refresh()
    return serialize_doc({**existing, **data})


@router.post("/products/{product_id}/toggle")
async def toggle_product(product_id: str, user: dict = Depends(require_role("consultant"))):
    db = get_database()
    existing = await db.monitored_products.find_one({"_id": _oid(product_id)})
    if not existing:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Produit introuvable.")
    new_state = not existing.get("enabled", True)
    await db.monitored_products.update_one({"_id": existing["_id"]},
                                           {"$set": {"enabled": new_state, "updated_at": utcnow()}})
    await log_action(str(user["_id"]), "consultant", "monitoring.product.toggle",
                     {"id": product_id, "enabled": new_state})
    await _refresh()
    return {"id": product_id, "enabled": new_state}


@router.delete("/products/{product_id}")
async def delete_product(product_id: str, user: dict = Depends(require_role("consultant"))):
    db = get_database()
    existing = await db.monitored_products.find_one({"_id": _oid(product_id)})
    if not existing:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Produit introuvable.")
    await db.monitored_products.delete_one({"_id": existing["_id"]})
    await log_action(str(user["_id"]), "consultant", "monitoring.product.delete", {"name": existing["name"]})
    await _refresh()
    # NON DESTRUCTIF côté CVE : on ne supprime aucune CVE déjà collectée (le tag reste, informatif).
    return {"deleted": True}
