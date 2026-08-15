from bson import ObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status

from app.backend.db.mongodb import get_database
from app.backend.dependencies.auth import require_role
from app.backend.schemas.source import CredentialCreate, SourceCreate, SourceUpdate
from app.backend.services import credentials as credentials_service
from app.backend.services import verification as verification_agent
from app.backend.services.audit import log_action
from app.backend.services.collection import pipeline, scheduler
from app.backend.services.verification.detection import detect_collection_method
from app.backend.utils import serialize_doc, utcnow

# Champs sensibles jamais renvoyés au frontend.
_SENSITIVE_SOURCE_FIELDS = ("api_key", "endpoint", "headers")


def _public_source(doc: dict) -> dict:
    """Sérialise une source en retirant tout champ sensible (jamais de secret exposé)."""
    out = serialize_doc(doc)
    for field in _SENSITIVE_SOURCE_FIELDS:
        out.pop(field, None)
    return out


def _auth_status(authentication_required: bool, has_credential: bool) -> str:
    if not authentication_required:
        return "not_required"
    return "configured" if has_credential else "missing"


def _detection_fields(det: dict, has_cred: bool) -> dict:
    """Champs de méthode de collecte persistés sur la source (rapport + collecteur)."""
    return {
        "collection_method": det["collection_method"],
        "method_family": det.get("method_family"),
        "api_endpoint": det.get("api_endpoint") or det.get("detected_api_endpoint"),
        "detected_api_endpoint": det.get("detected_api_endpoint") or det.get("api_endpoint"),
        "backup_method": det.get("backup_method") or det.get("fallback_method"),
        "fallback_method": det.get("fallback_method") or det.get("backup_method"),
        "data_format": det.get("data_format"),
        "authentication_required": det["authentication_required"],
        "authentication_type": det["authentication_type"],
        "authentication_status": _auth_status(det["authentication_required"], has_cred),
        "detection_reason": det.get("validation_reason") or det.get("reason"),
        "detection_alternatives": det.get("alternatives") or [],
        "rss_url": det.get("rss_url"),
        "detected_rss_url": det.get("detected_rss_url") or det.get("rss_url"),
        # Validation de pertinence (présence réelle de CVE).
        "contains_cve": det.get("contains_cve"),
        "cve_count": det.get("cve_count"),
        "validation_score": det.get("validation_score"),
        "validation_reason": det.get("validation_reason") or det.get("reason"),
        "detection_candidates": det.get("candidates") or [],
        "render_required": det.get("render_required", False),
        "last_method_check": utcnow(),
    }

router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(require_role("admin"))])


def _object_id(raw_id: str) -> ObjectId:
    try:
        return ObjectId(raw_id)
    except InvalidId:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Identifiant invalide.")


# ---------- Sources ----------

@router.get("/sources/stats")
async def sources_stats():
    db = get_database()
    total = await db.sources.count_documents({})
    validated = await db.sources.count_documents({"status": "validated"})
    pending = await db.sources.count_documents({"status": "pending"})
    rejected = await db.sources.count_documents({"status": "rejected"})
    return {"total": total, "validated": validated, "pending": pending, "rejected": rejected}


@router.get("/sources")
async def list_sources():
    db = get_database()
    sources = await db.sources.find().sort("created_at", -1).to_list(500)
    out = []
    for s in sources:
        doc = _public_source(s)
        doc["confidence_score"] = (s.get("verification") or {}).get("confidence_score")
        out.append(doc)
    return out


def _normalize_url(url: str | None) -> str:
    return (url or "").strip().rstrip("/").lower()


@router.post("/sources", status_code=status.HTTP_201_CREATED)
async def create_source(payload: SourceCreate, admin: dict = Depends(require_role("admin"))):
    db = get_database()

    # Anti-doublon : une même URL ne peut être enregistrée qu'une seule fois.
    normalized = _normalize_url(payload.url)
    existing = await db.sources.find({}, {"url": 1}).to_list(1000)
    if normalized and any(_normalize_url(s.get("url")) == normalized for s in existing):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Cette source existe déjà. Veuillez utiliser une autre URL ou modifier la source existante.",
        )

    # Détection automatique de la méthode de collecte (priorité API → RSS → Scraping).
    detection = await detect_collection_method(payload.url)

    doc = payload.model_dump()
    doc["created_by"] = str(admin["_id"])
    doc["created_at"] = utcnow()
    doc["last_sync_at"] = None
    doc["status"] = "pending"
    doc["verification"] = None
    doc["api_key_configured"] = False
    doc.update(_detection_fields(detection.as_dict(), has_cred=False))
    result = await db.sources.insert_one(doc)

    await log_action(str(admin["_id"]), "admin", "create_source", {"source_id": str(result.inserted_id)})
    return {"id": str(result.inserted_id), "detection": detection.as_dict()}


@router.get("/sources/{source_id}")
async def get_source(source_id: str):
    db = get_database()
    source = await db.sources.find_one({"_id": _object_id(source_id)})
    if source is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Source introuvable.")
    return _public_source(source)


@router.put("/sources/{source_id}")
async def update_source(source_id: str, payload: SourceUpdate, admin: dict = Depends(require_role("admin"))):
    db = get_database()
    update = {k: v for k, v in payload.model_dump().items() if v is not None}
    if update:
        await db.sources.update_one({"_id": _object_id(source_id)}, {"$set": update})

    await log_action(str(admin["_id"]), "admin", "update_source", {"source_id": source_id, **update})
    return {"ok": True}


@router.delete("/sources/{source_id}")
async def delete_source(source_id: str, admin: dict = Depends(require_role("admin"))):
    db = get_database()
    source_oid = _object_id(source_id)

    # Cascade : supprimer la source, son secret d'auth et son historique de collecte.
    # Les CVE déjà collectées sont conservées (données consommées par le consultant).
    await db.sources.delete_one({"_id": source_oid})
    await db.source_credentials.delete_one({"source_id": source_oid})
    await db.source_history.delete_many({"source_id": source_oid})

    await log_action(str(admin["_id"]), "admin", "delete_source", {"source_id": source_id})
    return {"ok": True}


def _looks_like_url(value: str | None) -> bool:
    return bool(value) and value.startswith(("http://", "https://"))


@router.post("/sources/{source_id}/verify")
async def verify_source(source_id: str, admin: dict = Depends(require_role("admin"))):
    db = get_database()
    source_oid = _object_id(source_id)
    source = await db.sources.find_one({"_id": source_oid})
    if source is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Source introuvable.")

    # Corroborateur : combien d'AUTRES sources ont déjà collecté ces CVE ?
    async def corroborator(cve_ids: list[str]) -> int:
        return await db.cves.count_documents({"cve_id": {"$in": cve_ids}, "source_id": {"$ne": source_oid}})

    verification = await verification_agent.verify_source(source, corroborator=corroborator)

    # La vérification ré-exécute la détection : on met à jour la méthode/auth de la source.
    update = {"verification": verification}
    det = verification.get("detection")
    if det:
        has_cred = await credentials_service.has_credential(source_oid)
        update.update(_detection_fields(det, has_cred))
    await db.sources.update_one({"_id": source_oid}, {"$set": update})

    await log_action(
        str(admin["_id"]), "admin", "verify_source",
        {"source_id": source_id, "overall_score": verification["overall_score"]},
    )
    return verification


@router.post("/sources/{source_id}/test-connection")
async def test_connection(source_id: str, admin: dict = Depends(require_role("admin"))):
    db = get_database()
    source = await db.sources.find_one({"_id": _object_id(source_id)})
    if source is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Source introuvable.")

    result = await verification_agent.test_connection(source)

    await log_action(str(admin["_id"]), "admin", "test_connection", {"source_id": source_id, **result})
    return result


# ---------- Credentials d'authentification (secrets chiffrés) ----------

@router.put("/sources/{source_id}/credentials")
async def set_credentials(source_id: str, payload: CredentialCreate, admin: dict = Depends(require_role("admin"))):
    db = get_database()
    source_oid = _object_id(source_id)
    source = await db.sources.find_one({"_id": source_oid})
    if source is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Source introuvable.")

    await credentials_service.store_credential(source_oid, payload)
    await db.sources.update_one(
        {"_id": source_oid},
        {"$set": {"api_key_configured": True, "authentication_required": True, "authentication_status": "configured"}},
    )

    # Journalisation SANS le secret (uniquement le type d'authentification).
    await log_action(str(admin["_id"]), "admin", "set_credentials", {"source_id": source_id, "auth_type": payload.auth_type})
    return {"ok": True, "api_key_configured": True, "authentication_status": "configured"}


@router.delete("/sources/{source_id}/credentials")
async def remove_credentials(source_id: str, admin: dict = Depends(require_role("admin"))):
    db = get_database()
    source_oid = _object_id(source_id)
    source = await db.sources.find_one({"_id": source_oid})
    if source is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Source introuvable.")

    await credentials_service.delete_credential(source_oid)
    new_status = _auth_status(source.get("authentication_required", False), has_credential=False)
    await db.sources.update_one(
        {"_id": source_oid},
        {"$set": {"api_key_configured": False, "authentication_status": new_status}},
    )

    await log_action(str(admin["_id"]), "admin", "delete_credentials", {"source_id": source_id})
    return {"ok": True, "api_key_configured": False, "authentication_status": new_status}


@router.post("/sources/{source_id}/trigger-collection")
async def trigger_collection(source_id: str, admin: dict = Depends(require_role("admin"))):
    db = get_database()
    source_oid = _object_id(source_id)
    source = await db.sources.find_one({"_id": source_oid})
    if source is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Source introuvable.")

    now = utcnow()

    # Gating d'authentification : une API protégée sans credential ne peut pas être collectée.
    if source.get("authentication_required") and not await credentials_service.has_credential(source_oid):
        run = {
            "source_id": source_oid,
            "triggered_at": now,
            "status": "failed",
            "items_collected": 0,
            "duration_ms": 0,
            "message": "Collection impossible : API Key manquante.",
        }
        await db.source_history.insert_one(run)
        await log_action(
            str(admin["_id"]), "admin", "trigger_collection",
            {"source_id": source_id, "status": "failed", "reason": "missing_auth"},
        )
        return {"ok": False, "message": "Collection impossible : API Key manquante.", **serialize_doc(run)}

    await db.sources.update_one({"_id": source_oid}, {"$set": {"last_sync_at": now}})

    # Pour une API protégée configurée, le secret est récupéré côté serveur uniquement.
    if source.get("authentication_required"):
        _credential = await credentials_service.get_credential(source_oid)  # noqa: F841 (usage interne)

    # Agent de collecte : même pipeline générique, appliqué à cette seule source.
    result = await pipeline.collect_single(db, source)

    ok = result["ok"]
    run = {
        "source_id": source_oid,
        "triggered_at": now,
        "status": "success" if ok else "failed",
        "items_collected": result["new_saved"],
        "duration_ms": result["duration_ms"],
        "method_used": result["method_used"],
        "detected_count": result["detected_count"],
        "collected_count": result["collected_count"],
        "already_known": result["already_known"],
        "duplicates_ignored": result["duplicates_ignored"],
        "message": (f"{result['detected_count']} CVE détectées, {result['new_saved']} nouvelle(s) "
                    f"enregistrée(s), {result['duplicates_ignored']} doublon(s) ignoré(s)."
                    + (f" Erreur : {result['error']}" if result["error"] else "")),
    }
    await db.source_history.insert_one(run)

    await log_action(
        str(admin["_id"]), "admin", "trigger_collection",
        {"source_id": source_id, "status": run["status"], "method_used": result["method_used"],
         "detected": result["detected_count"], "inserted": result["new_saved"]},
    )
    return {"ok": ok, **serialize_doc(run)}


@router.post("/collect")
async def collect_all(background: BackgroundTasks, admin: dict = Depends(require_role("admin"))):
    """Lance la collecte sur TOUTES les sources validées (parcours parallèle, tolérant aux pannes).

    La collecte s'exécute en ARRIÈRE-PLAN (elle peut être longue). Le rapport final est
    consultable via GET /admin/collect/runs.
    """
    db = get_database()
    background.add_task(pipeline.run_collection_safe, db)
    await log_action(str(admin["_id"]), "admin", "collect_all_start", {})
    return {"status": "started", "message": "Collecte lancée en arrière-plan sur toutes les sources validées."}


@router.get("/collect/runs")
async def collection_runs(limit: int = 10):
    """Rapports des dernières collectes globales (sources parcourues, réussies, en erreur,
    CVE détectées, nouvelles enregistrées, doublons ignorés)."""
    db = get_database()
    runs = await db.collection_runs.find().sort("finished_at", -1).to_list(limit)
    return [serialize_doc(r) for r in runs]


@router.get("/collect/logs")
async def collection_logs(limit: int = 100):
    """Journaux de collecte (erreurs de sources, avertissements…)."""
    db = get_database()
    entries = await db.collection_logs.find().sort("ts", -1).to_list(limit)
    return [serialize_doc(e) for e in entries]


@router.get("/collection/health")
async def collection_health():
    """Santé de la collecte : état INDÉPENDANT de chaque source + santé du scheduler + alertes."""
    db = get_database()
    sources = []
    async for s in db.sources.find(
        {"status": "validated"},
        {"name": 1, "url": 1, "collection_method": 1, "sync_state": 1, "last_sync_at": 1},
    ):
        sources.append(serialize_doc(s))
    state = serialize_doc(await db.scheduler_state.find_one({"_id": "global"}) or {})
    active_alerts = await db.alerts.count_documents({"active": True})
    latest_consistency = await db.consistency_reports.find_one({}, sort=[("created_at", -1)])
    return {
        "scheduler": state,
        "sources": sources,
        "active_alerts": active_alerts,
        "last_consistency": serialize_doc(latest_consistency) if latest_consistency else None,
    }


@router.get("/collection/alerts")
async def collection_alerts(active_only: bool = True):
    """Alertes de supervision (source périmée >24 h, échecs répétés, retard scheduler, vides répétées)."""
    db = get_database()
    query = {"active": True} if active_only else {}
    docs = await db.alerts.find(query).sort("updated_at", -1).to_list(200)
    items = [serialize_doc(a) for a in docs]
    return {"total": len(items), "items": items}


@router.get("/scheduler/status")
async def scheduler_status():
    """État du scheduler : fréquence, dernière exécution, prochaine échéance (heure UTC)."""
    db = get_database()
    return serialize_doc(await scheduler.status(db))


@router.post("/scheduler/run")
async def scheduler_run_now(background: BackgroundTasks, admin: dict = Depends(require_role("admin"))):
    """Force une exécution immédiate de la collecte planifiée (arrière-plan)."""
    db = get_database()
    background.add_task(pipeline.run_collection_safe, db, "manual")
    await log_action(str(admin["_id"]), "admin", "scheduler_run_now", {})
    return {"status": "started", "message": "Collecte planifiée lancée immédiatement (arrière-plan)."}


@router.get("/sources/{source_id}/history")
async def source_history(source_id: str):
    db = get_database()
    runs = await db.source_history.find({"source_id": _object_id(source_id)}).sort("triggered_at", -1).to_list(100)
    return [serialize_doc(r) for r in runs]
