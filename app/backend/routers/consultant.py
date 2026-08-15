from datetime import datetime, timedelta, timezone

from bson import ObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from app.backend.db.mongodb import get_database
from app.backend.dependencies.auth import require_role
from app.backend.schemas.schedule import CollectionScheduleUpdate
from app.backend.services.audit import log_action
from app.backend.services.collection import (advisory_bulletin, bulletin_pdf, enrichment,
                                             product_bulletin, translation)
from app.backend.services.collection.schema import CANONICAL_KEYS, CVE_RE, LIST_FIELDS
from app.backend.utils import serialize_doc, utcnow

router = APIRouter(prefix="/consultant", tags=["consultant"], dependencies=[Depends(require_role("consultant"))])

DEFAULT_SCHEDULE = {"frequency": "daily", "hour": 8, "minute": 0}


async def _monitored_names(db) -> list[str]:
    """Noms des produits ACTUELLEMENT surveillés (activés, dans un domaine activé). Sert à ne
    proposer que les produits EXISTANTS — un produit supprimé, désactivé ou renommé disparaît du
    filtre même si d'anciennes CVE portent encore son étiquette."""
    disabled_domains = [d["name"] async for d in db.domains.find({"enabled": False}, {"name": 1})]
    q: dict = {"enabled": {"$ne": False}}
    if disabled_domains:
        q["domain"] = {"$nin": disabled_domains}
    names = {d["name"] async for d in db.monitored_products.find(q, {"name": 1}) if d.get("name")}
    return sorted(names)


def _object_id(raw_id: str) -> ObjectId:
    try:
        return ObjectId(raw_id)
    except InvalidId:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Identifiant invalide.")


def _cve_out(cve: dict, sources: dict) -> dict:
    # LOCALISATION : point de passage UNIQUE des CVE vers l'interface (liste et détail). Les
    # champs traduits par l'agent remplacent l'original ; l'original reste exposé sous
    # `*_original`. Sans traduction disponible, le texte d'origine est servi tel quel — un
    # champ n'est donc jamais vide à cause d'un échec de traduction.
    doc = serialize_doc(translation.apply_localization(cve))
    source = sources.get(cve.get("source_id"))
    doc["source"] = source["name"] if source else (doc.get("source_name") or "—")
    # Rendre la liste multi-sources sérialisable (ObjectId -> str) — points 7 & 8.
    doc["sources"] = [
        {"name": s.get("name"), "url": s.get("url"), "source_id": str(s.get("source_id"))}
        for s in (cve.get("sources") or [])
    ]
    return doc


# Projection LISTE : uniquement les champs affichés dans le tableau (documents réduits = rapide).
_LIST_PROJECTION = {
    "cve_id": 1, "title": 1, "product": 1, "affected_products": 1, "vuln_type": 1, "category": 1,
    "cvss_score": 1, "severity": 1, "published_at": 1, "updated_at": 1, "collected_at": 1,
    "is_new": 1, "source_id": 1, "source_name": 1, "sources": 1,
    # Titre traduit (affiché à la place de l'original quand il existe) + état de traduction.
    "title_fr": 1, "translation_status": 1,
    # Synchronisation incrémentale (badge « Mise à jour », complétude, temps relatif).
    "is_updated": 1, "update_unread": 1, "information_completeness": 1, "first_published": 1,
    "sync_status": 1, "change_summary": 1,
}


def _parse_day(s: str | None, end: bool = False):
    """« YYYY-MM-DD » -> datetime (début, ou fin de journée). None si absent/invalide."""
    if not s:
        return None
    try:
        d = datetime.strptime(s[:10], "%Y-%m-%d")
        return d.replace(hour=23, minute=59, second=59) if end else d
    except ValueError:
        return None


@router.get("/cves")
async def list_cves(
    q: str | None = Query(None),
    severity: str | None = Query(None),
    product: str | None = Query(None),
    category: str | None = Query(None),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    only_new: bool = Query(False),
    collected_today: bool = Query(False),  # vue « Collectées aujourd'hui » (date de collecte)
    published_today: bool = Query(False),  # vue « Publiées aujourd'hui » (date OFFICIELLE)
    sort_by: str = Query("date"),  # "date" | "cvss" | "collected"
    order: str = Query("desc"),    # "desc" | "asc"
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
):
    db = get_database()
    query: dict = {}
    if severity:
        query["severity"] = severity
    if product:
        # Le menu propose des PRODUITS SURVEILLÉS ; on accepte aussi l'ancien champ `affected_products`
        # pour rester correct sur les CVE collectées avant la mise en place du périmètre.
        # `$and` (et non `$or` à la racine) : le champ `$or` est déjà pris par la recherche `q`.
        query["$and"] = [{"$or": [{"monitored_products": product}, {"affected_products": product}]}]
    if category:
        query["category"] = category
    if only_new:
        query["is_new"] = True
    if collected_today:
        # Vue « activité de collecte du jour » : filtrée sur la date de COLLECTE, triée par collecte.
        query["collected_at"] = {"$gte": _start_of_today_utc()}
        sort_by = "collected"
    if published_today:
        # Vue « CVE PUBLIÉES aujourd'hui » : date OFFICIELLE de publication de la CVE, jamais la
        # date de collecte ni de mise à jour. Filtrage poussé côté MongoDB (index published_at).
        query.update(published_today_filter())
        sort_by = "date"
    # Filtre de date (published_at) poussé CÔTÉ MONGODB.
    if date_from or date_to:
        rng = {}
        if (d := _parse_day(date_from)) is not None:
            rng["$gte"] = d
        if (d := _parse_day(date_to, end=True)) is not None:
            rng["$lte"] = d
        if rng:
            query["published_at"] = rng
    if q:
        query["$or"] = [
            {"cve_id": {"$regex": q, "$options": "i"}},
            {"title": {"$regex": q, "$options": "i"}},
            {"product": {"$regex": q, "$options": "i"}},
            {"affected_products": {"$regex": q, "$options": "i"}},
        ]

    # PAGINATION CÔTÉ MONGODB : tri + skip + limit + projection. On ne charge QUE la page demandée
    # (~20 documents réduits), plus toute la collection -> affichage quasi instantané.
    sort_field = {"cvss": "cvss_score", "collected": "collected_at"}.get(sort_by, "published_at")
    direction = 1 if order == "asc" else -1
    total = await db.cves.count_documents(query)
    page = await (
        db.cves.find(query, _LIST_PROJECTION)
        .sort(sort_field, direction).skip(skip).limit(limit).to_list(limit)
    )

    source_ids = [c["source_id"] for c in page if c.get("source_id")]
    sources = {s["_id"]: s async for s in db.sources.find({"_id": {"$in": source_ids}})}
    return {"total": total, "items": [_cve_out(c, sources) for c in page]}


def _day_bounds(offset_days: int = 0) -> tuple[datetime, datetime]:
    """Bornes [minuit, minuit+24 h[ d'une journée, en UTC NAÏF — le format stocké en base.

    « Aujourd'hui » se définit dans le fuseau de l'APPLICATION (`SCHEDULER_TIMEZONE`, sinon
    fuseau local du serveur), et non en UTC : à UTC+1, la journée du 14/08 commence le 13/08
    à 23:00 UTC. Comparer bêtement des dates UTC décalerait la frontière d'une heure et
    ferait basculer les CVE publiées en fin de soirée dans le mauvais jour.

    Le même fuseau que le planificateur est utilisé, pour que « aujourd'hui » désigne la même
    journée partout dans l'application.
    """
    from app.backend.services.collection.scheduler import _tz

    midnight = (datetime.now(_tz()).replace(hour=0, minute=0, second=0, microsecond=0)
                + timedelta(days=offset_days))
    start = midnight.astimezone(timezone.utc).replace(tzinfo=None)
    return start, start + timedelta(days=1)


def _start_of_today_utc() -> datetime:
    """Début de la journée courante en UTC naïf (compat. — voir `_day_bounds`)."""
    return _day_bounds()[0]


def published_today_filter() -> dict:
    """Critère MongoDB « CVE PUBLIÉE aujourd'hui », sur la date OFFICIELLE de publication.

    Volontairement basé sur `published_at` (date de publication de la CVE par sa source), et
    JAMAIS sur `collected_at` / `updated_at` / `last_collected`, qui décrivent l'activité de
    CyberWatch AI. Une CVE publiée hier et mise à jour aujourd'hui n'est donc PAS retenue.

    Les CVE sans date de publication (578 en base) sont exclues : on ne peut pas affirmer
    qu'elles ont été publiées aujourd'hui.
    """
    start, end = _day_bounds()
    return {"published_at": {"$gte": start, "$lt": end}}


@router.get("/cve-stats")
async def cve_stats():
    """Compteurs pour les cartes de synthèse du consultant.

    Deux notions distinctes (non ambiguës) :
      - `new` / `published_recent` : CVE réellement PUBLIÉES récemment (date officielle).
      - `collected_today` : CVE COLLECTÉES aujourd'hui (activité de collecte du jour), même si
        leur date de publication est ancienne.
    """
    db = get_database()
    total = await db.cves.count_documents({})
    new = await db.cves.count_documents({"is_new": True})
    today = _start_of_today_utc()
    collected_today = await db.cves.count_documents({"collected_at": {"$gte": today}})
    # Compteur BORNÉ à la journée : sans borne haute, une CVE datée du futur (erreur de source)
    # serait comptée comme « publiée aujourd'hui ».
    published_today = await db.cves.count_documents(published_today_filter())
    by_severity = {}
    for level in ("critical", "high", "medium", "low"):
        by_severity[level] = await db.cves.count_documents({"severity": level})
    return {"total": total, "new": new, "collected_today": collected_today,
            "published_today": published_today, **by_severity}


@router.get("/cve-facets")
async def cve_facets():
    """Facettes de filtrage de la page CVE. Le menu « produit » liste TOUS les produits SURVEILLÉS
    existants (activés, dans un domaine activé) — jamais la liste brute des produits affectés
    remontés par les sources.

    On n'exige PAS qu'un produit ait déjà des CVE : un produit qui vient d'être ajouté est
    filtrable IMMÉDIATEMENT, sans attendre la collecte qui lui rattachera ses premières CVE. Le
    filtre renvoie alors 0 résultat, ce qui est l'information juste (« rien de connu à ce jour »).
    """
    db = get_database()
    categories = await db.cves.distinct("category")
    return {
        "products": await _monitored_names(db),
        "categories": sorted(c for c in categories if c),
    }


def _is_incomplete(cve: dict) -> bool:
    """La fiche manque-t-elle d'informations importantes (à agréger depuis d'autres sources) ?"""
    return (
        cve.get("cvss_score") is None
        or not cve.get("description")
        or not cve.get("published_at")
        or not cve.get("cwe")
        or len(cve.get("references") or []) < 2
    )


async def _aggregate_on_demand(db, oid, cve: dict) -> dict:
    """Agrégation multi-sources à l'ouverture d'une CVE : si la fiche est incomplète, on
    interroge toutes les sources officielles (NVD, MSRC, MITRE, Red Hat, OSV, GitHub) avec
    l'identifiant CVE comme clé, on fusionne par priorité et on complète la base."""
    # Les entrées « avis CERT seul » (identifiant non-CVE) ne sont pas interrogeables sur NVD/MITRE.
    if not CVE_RE.fullmatch(cve.get("cve_id", "")):
        return cve
    last = cve.get("enriched_at")
    recent = isinstance(last, datetime) and (utcnow().replace(tzinfo=None) - last.replace(tzinfo=None)).days < 1
    # On (ré)interroge les sources officielles pour COMPLÉTER la fiche ET pour LISTER toutes les
    # sources qui confirment la CVE (NVD, MITRE, CISA, GitHub, OSV, Red Hat…). On ne saute que si
    # c'est déjà fait récemment ET que la confirmation croisée est déjà renseignée.
    if recent and cve.get("confirmed_sources"):
        return cve
    if not _is_incomplete(cve) and cve.get("confirmed_sources"):
        return cve

    merged, confirmed = await enrichment.enrich(cve["cve_id"], seed=cve, use_nvd=True)

    set_fields: dict = {"enriched_at": utcnow()}
    for key in CANONICAL_KEYS:
        if key == "detail_url":
            continue
        if key in LIST_FIELDS:
            union = list(dict.fromkeys((cve.get(key) or []) + (merged.get(key) or [])))
            if len(union) != len(cve.get(key) or []):
                set_fields[key] = union
        elif not cve.get(key) and merged.get(key):  # on complète seulement les champs vides
            set_fields[key] = merged[key]
    if confirmed:
        conf = list(dict.fromkeys((cve.get("confirmed_sources") or []) + confirmed))
        set_fields["confirmed_sources"] = conf

    await db.cves.update_one({"_id": oid}, {"$set": set_fields})
    cve.update(set_fields)
    return cve


@router.get("/cves/{cve_id}")
async def get_cve(cve_id: str):
    db = get_database()
    oid = _object_id(cve_id)
    cve = await db.cves.find_one({"_id": oid})
    if cve is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "CVE introuvable.")

    # Agrégation multi-sources à la demande (complète les champs manquants).
    try:
        cve = await _aggregate_on_demand(db, oid, cve)
    except Exception:  # noqa: BLE001 - l'agrégation ne doit jamais casser l'affichage
        pass

    # Consulter une CVE la marque comme « lue » : ni « Nouvelle » ni « Mise à jour ».
    if cve.get("is_new") or cve.get("update_unread"):
        await db.cves.update_one({"_id": oid}, {"$set": {"is_new": False, "update_unread": False}})
        cve["is_new"] = False
        cve["update_unread"] = False

    source = await db.sources.find_one({"_id": cve.get("source_id")}) if cve.get("source_id") else None
    sources = {source["_id"]: source} if source else {}
    return _cve_out(cve, sources)


# ---------- Bulletin de sécurité normalisé (moteur générique multi-sources) ----------

_BULLETIN_TTL_HOURS = 24


async def _cached_bulletin(db, url: str, seed: dict | None, refresh: bool) -> dict:
    """Construit le bulletin (Phases 1→4) avec cache 24 h dans `bulletins`.

    Un bulletin mis en cache AVANT un changement de modèle est reconstruit d'office : sans ce
    contrôle de version, les anciens documents continueraient d'exposer les champs retirés et
    une « source officielle » calculée selon l'ancienne règle.
    """
    cached = await db.bulletins.find_one({"_id": url})
    if cached and not refresh:
        built = cached.get("built_at")
        fresh = isinstance(built, datetime) and \
            (utcnow().replace(tzinfo=None) - built.replace(tzinfo=None)).total_seconds() < _BULLETIN_TTL_HOURS * 3600
        current = cached.get("schema_version") == advisory_bulletin.BULLETIN_SCHEMA_VERSION
        if fresh and current:
            return serialize_doc(cached)
    bulletin = await advisory_bulletin.build_bulletin(url, seed=seed, db=db)
    # REMPLACEMENT complet (et non « $set ») : un « $set » conserverait les clés d'un modèle
    # antérieur — les champs retirés du bulletin réapparaîtraient depuis le cache.
    await db.bulletins.replace_one({"_id": url}, {**bulletin, "_id": url}, upsert=True)
    return serialize_doc({**bulletin, "_id": url})


@router.get("/bulletin")
async def bulletin_from_url(url: str = Query(..., description="URL de la page d'avis"),
                            refresh: bool = Query(False)):
    """Génère un bulletin normalisé depuis N'IMPORTE QUELLE page d'avis (moteur générique)."""
    db = get_database()
    return await _cached_bulletin(db, url, seed=None, refresh=refresh)


@router.get("/cves/{cve_id}/bulletin")
async def bulletin_from_cve(cve_id: str, refresh: bool = Query(False)):
    """Bulletin normalisé construit à partir de la page d'avis où la CVE a été COLLECTÉE.

    Cette page est la source de COLLECTE ; la source officielle est déterminée séparément,
    à partir des références de l'éditeur (voir `advisory_bulletin.official_source`).
    """
    db = get_database()
    oid = _object_id(cve_id)
    cve = await db.cves.find_one({"_id": oid})
    if cve is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "CVE introuvable.")
    url = cve.get("detail_url")
    if not url:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Cette CVE n'a pas de page d'avis d'origine.")
    return await _cached_bulletin(db, url, seed=cve, refresh=refresh)


def _pdf_response(pdf: bytes | None, filename: str) -> Response:
    """Réponse de TÉLÉCHARGEMENT d'un PDF (`attachment` -> enregistrement direct, jamais
    d'ouverture dans une visionneuse ni de boîte d'impression)."""
    if not pdf:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Génération du PDF indisponible : le moteur de rendu (Chromium/Playwright) n'a pas "
            "pu être démarré. Exécutez « python -m playwright install chromium ».")
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.get("/cves/{cve_id}/bulletin.pdf")
async def bulletin_pdf_from_cve(cve_id: str, refresh: bool = Query(False)):
    """Export PDF RÉEL du bulletin d'une CVE (aucune boîte d'impression navigateur)."""
    bulletin = await bulletin_from_cve(cve_id, refresh=refresh)
    return _pdf_response(await bulletin_pdf.build_pdf(bulletin),
                         bulletin_pdf.filename_for(bulletin))


# ---------- Tableau de bord de SYNCHRONISATION (moteur type OpenCVE) ----------

@router.get("/sync-stats")
async def sync_stats():
    """Statistiques du moteur de synchro : nouvelles / mises à jour / enrichies / inchangées,
    complétude moyenne, échecs, dernière & prochaine synchro, durée."""
    db = get_database()
    by_status = {}
    for st in ("new", "enriched", "updated", "unchanged"):
        by_status[st] = await db.cves.count_documents({"sync_status": st})
    agg = [a async for a in db.cves.aggregate(
        [{"$group": {"_id": None, "avg": {"$avg": "$information_completeness"}}}])]
    avg_completeness = round(agg[0]["avg"]) if agg and agg[0].get("avg") is not None else 0
    failed = await db.sources.count_documents(
        {"sync_state.status": {"$in": ["failed", "timeout", "parse_error"]}})
    from app.backend.services.collection import scheduler
    sched = await scheduler.status(db)
    last_run = await db.collection_runs.find_one({"status": "completed"}, sort=[("finished_at", -1)])
    return {
        "by_status": by_status,
        "avg_completeness": avg_completeness,
        "failed_syncs": failed,
        "last_sync": serialize_doc({"v": sched.get("last_run")})["v"] if sched.get("last_run") else None,
        "next_sync": sched.get("next_run"),
        "collecting": sched.get("collecting"),
        "last_run": {
            "finished_at": serialize_doc({"v": (last_run or {}).get("finished_at")})["v"],
            "duration_ms": (last_run or {}).get("duration_ms"),
            "new_saved": (last_run or {}).get("new_saved"),
            "updated": (last_run or {}).get("updated"),
            "notifications_created": (last_run or {}).get("notifications_created"),
        } if last_run else None,
    }


# ---------- Bulletins GROUPÉS PAR PRODUIT / ÉDITEUR (vue CERT) ----------

@router.get("/product-bulletins")
async def product_bulletins(days: int = Query(45, ge=1, le=365), severity: str | None = Query(None),
                            q: str | None = Query(None), skip: int = Query(0, ge=0),
                            limit: int = Query(24, ge=1, le=100)):
    """Liste des bulletins groupés par éditeur (cartes : produit, nb de CVE, sévérité max)."""
    db = get_database()
    return await product_bulletin.list_product_bulletins(db, days=days, severity=severity,
                                                         q=q, skip=skip, limit=limit)


@router.get("/product-bulletins/{vendor_key}")
async def product_bulletin_detail(vendor_key: str, days: int = Query(45, ge=1, le=365)):
    """Bulletin complet d'un éditeur : toutes ses CVE récentes regroupées (structure SecurityBulletin)."""
    db = get_database()
    bulletin = await product_bulletin.build_product_bulletin(db, vendor_key, days=days)
    if not bulletin:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Aucune vulnérabilité récente pour cet éditeur.")
    return serialize_doc(bulletin)


@router.get("/product-bulletins/{vendor_key}/bulletin.pdf")
async def product_bulletin_pdf(vendor_key: str, days: int = Query(45, ge=1, le=365)):
    """Export PDF RÉEL du bulletin groupé d'un éditeur (plusieurs CVE dans un seul document)."""
    bulletin = await product_bulletin_detail(vendor_key, days=days)
    return _pdf_response(await bulletin_pdf.build_pdf(bulletin),
                         bulletin_pdf.filename_for(bulletin))


# ---------- Notifications (nouvelles CVE détectées par la collecte) ----------

_UNREAD_FILTER = {"$or": [{"is_new": True}, {"update_unread": True}]}


@router.get("/notifications")
async def list_notifications(limit: int = Query(40, ge=1, le=100)):
    """Nouvelles CVE ET CVE ayant reçu une mise à jour importante, non encore consultées."""
    db = get_database()
    news = await db.cves.find(_UNREAD_FILTER).sort("collected_at", -1).to_list(limit)
    source_ids = [c["source_id"] for c in news if c.get("source_id")]
    sources = {s["_id"]: s async for s in db.sources.find({"_id": {"$in": source_ids}})}
    items = []
    for c in news:
        doc = _cve_out(c, sources)
        items.append({
            "id": doc["id"],
            "cve_id": doc.get("cve_id"),
            "product": doc.get("product") or (doc.get("affected_products") or ["—"])[0],
            "severity": doc.get("severity"),
            "cvss_score": doc.get("cvss_score"),
            "source": doc.get("source"),
            "type": "update" if (c.get("update_unread") and not c.get("is_new")) else "new",
            # Vraie date de publication de la CVE (source officielle).
            "published_at": doc.get("published_at"),
            # Date à laquelle notre agent l'a détectée (technique).
            "collected_at": doc.get("last_important_update") or doc.get("collected_at"),
        })
    return {"total": len(items), "items": items}


@router.get("/notifications/count")
async def notifications_count():
    """Nombre de CVE nouvelles ou mises à jour non consultées (badge)."""
    db = get_database()
    return {"count": await db.cves.count_documents(_UNREAD_FILTER)}


@router.post("/notifications/read")
async def mark_notifications_read(user: dict = Depends(require_role("consultant"))):
    """Marque toutes les notifications comme consultées (vide le badge)."""
    db = get_database()
    result = await db.cves.update_many(_UNREAD_FILTER, {"$set": {"is_new": False, "update_unread": False}})
    await log_action(str(user["_id"]), "consultant", "read_notifications", {"count": result.modified_count})
    return {"ok": True, "marked": result.modified_count}


# ---------- Planification de la collecte (config globale, gérée par le consultant) ----------

@router.get("/collection-schedule")
async def get_collection_schedule():
    db = get_database()
    doc = await db.collection_schedule.find_one({"_id": "global"})
    if doc is None:
        return DEFAULT_SCHEDULE
    doc.pop("_id", None)
    return {**DEFAULT_SCHEDULE, **doc}


@router.put("/collection-schedule")
async def update_collection_schedule(payload: CollectionScheduleUpdate, user: dict = Depends(require_role("consultant"))):
    db = get_database()
    data = payload.model_dump()
    await db.collection_schedule.update_one({"_id": "global"}, {"$set": data}, upsert=True)

    await log_action(str(user["_id"]), "consultant", "update_collection_schedule", data)
    return data
