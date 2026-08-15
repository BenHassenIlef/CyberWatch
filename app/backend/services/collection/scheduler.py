"""Scheduler de collecte automatique — prêt pour la production.

Lit la planification (collection_schedule) et déclenche `pipeline.run_collection` à
l'échéance (horaire / toutes les 6 h / quotidien / hebdomadaire).

Points clés :
- L'heure configurée (ex. 08:00) est interprétée dans le FUSEAU LOCAL du serveur (ou
  `settings.SCHEDULER_TIMEZONE` si défini) — PAS en UTC. C'était la cause du non-déclenchement.
- Tourne en tâche de fond démarrée au lancement de l'application, vérifie l'échéance chaque
  minute, et « rattrape » une échéance manquée (redémarrage, serveur éteint à l'heure prévue).
- État persistant en base (`scheduler_state`) : rechargé automatiquement au redémarrage.
- Un changement de planification remplace l'échéance (pas de doublon d'exécution).
- Une collecte qui échoue n'arrête jamais le scheduler ; il continue le lendemain.
- Journalisation détaillée à chaque étape (démarrage, chargement, prochaine exécution, début
  et fin de collecte, erreurs).
"""
import asyncio
import logging
import os
import socket
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from app.backend.core.config import settings
from app.backend.db.mongodb import get_database
from app.backend.services.collection import pipeline, source_state
from app.backend.services.collection.source_manager import get_active_sources

logger = logging.getLogger("cyberwatch.scheduler")

DEFAULT_SCHEDULE = {"frequency": "daily", "hour": 8, "minute": 0}
_CHECK_INTERVAL = 30          # vérification de l'échéance toutes les 30 s
_HEARTBEAT_EVERY = 20         # log « je suis vivant » tous les ~10 min (20 × 30 s)
_RETRY_BACKOFF = timedelta(minutes=10)  # attente avant de ré-essayer une échéance qui a ÉCHOUÉ
_LOCK_TTL = timedelta(minutes=60)       # durée de vie du VERROU de collecte (auto-expiration si crash)
_task: asyncio.Task | None = None
_running = False              # verrou en-processus : une seule collecte planifiée à la fois

# Statuts d'une ÉCHÉANCE quotidienne (distincts du statut par-source et du statut du run).
#   completed        : toutes les sources honorées, des CVE collectées, à l'heure.
#   completed_late   : idem mais exécutée en retard (PC éteint à l'heure prévue, rattrapage).
#   degraded         : échéance validée alors que des sources échouent de façon PERSISTANTE.
#   partial          : des sources restent à ré-essayer -> échéance NON validée (reprise à venir).
#   suspicious_empty : sources joignables MAIS 0 CVE au total -> anomalie, échéance NON validée.
#   interrupted      : process arrêté en pleine collecte -> échéance NON validée.
#   failed           : exception globale -> échéance NON validée.
DAILY_HONORED = {"completed", "completed_late", "degraded"}  # avancent last_completed_due


# --------------------------------------------------------------------------------------
# Fuseau horaire
# --------------------------------------------------------------------------------------

def _tz():
    """Fuseau de planification : `settings.SCHEDULER_TIMEZONE` sinon le fuseau LOCAL du serveur."""
    name = (settings.SCHEDULER_TIMEZONE or "").strip()
    if name:
        try:
            return ZoneInfo(name)
        except Exception:  # noqa: BLE001
            logger.warning("Scheduler : fuseau '%s' inconnu, utilisation du fuseau local.", name)
    return datetime.now().astimezone().tzinfo  # fuseau local du serveur


def _now():
    return datetime.now(_tz())


def _as_aware(dt: datetime | None):
    """Un datetime lu depuis Mongo est naïf en UTC : on le rend « aware » pour comparer."""
    if not isinstance(dt, datetime):
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _sig(freq: str, hour: int, minute: int) -> str:
    return f"{freq}:{hour:02d}:{minute:02d}"


# --------------------------------------------------------------------------------------
# Calcul des échéances (dans le fuseau de planification)
# --------------------------------------------------------------------------------------

def _last_due(freq: str, hour: int, minute: int, now: datetime) -> datetime:
    """Dernière échéance théorique <= now (aware, dans le fuseau de `now`)."""
    if freq == "hourly":
        return now.replace(minute=minute, second=0, microsecond=0)
    if freq == "every_6h":
        return now.replace(hour=(now.hour // 6) * 6, minute=minute, second=0, microsecond=0)
    if freq == "weekly":
        return (now - timedelta(days=now.weekday())).replace(hour=hour, minute=minute, second=0, microsecond=0)
    return now.replace(hour=hour, minute=minute, second=0, microsecond=0)  # daily


def next_run(freq: str, hour: int, minute: int, now: datetime) -> datetime:
    """Prochaine échéance strictement après `now` (pour l'affichage du statut)."""
    if freq == "hourly":
        cand = now.replace(minute=minute, second=0, microsecond=0)
        return cand if cand > now else cand + timedelta(hours=1)
    if freq == "every_6h":
        cand = now.replace(hour=(now.hour // 6) * 6, minute=minute, second=0, microsecond=0)
        return cand if cand > now else cand + timedelta(hours=6)
    if freq == "weekly":
        cand = (now - timedelta(days=now.weekday())).replace(hour=hour, minute=minute, second=0, microsecond=0)
        return cand if cand > now else cand + timedelta(days=7)
    cand = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    return cand if cand > now else cand + timedelta(days=1)


async def _read_schedule(db) -> tuple[str, int, int]:
    sched = await db.collection_schedule.find_one({"_id": "global"}) or {}
    return (
        sched.get("frequency", DEFAULT_SCHEDULE["frequency"]),
        int(sched.get("hour", DEFAULT_SCHEDULE["hour"])),
        int(sched.get("minute", DEFAULT_SCHEDULE["minute"])),
    )


async def status(db) -> dict:
    """État du scheduler : planning, dernière exécution, prochaine échéance, fuseau."""
    freq, hour, minute = await _read_schedule(db)
    state = await db.scheduler_state.find_one({"_id": "global"}) or {}
    now = _now()
    due = _last_due(freq, hour, minute, now)
    completed_due = _as_aware(state.get("last_completed_due"))
    pending = now >= due and (completed_due is None or completed_due < due)
    return {
        "running": _task is not None and not _task.done(),
        "collecting": _running,                       # une collecte est-elle en cours ?
        "pending_catch_up": pending and not _running,  # échéance en attente (à rattraper) ?
        "timezone": str(_tz()),
        "frequency": freq, "hour": hour, "minute": minute,
        "server_time_local": now.isoformat(),
        "last_run": _as_aware(state.get("last_run")),
        "last_completed_due": completed_due,
        "last_report": state.get("last_report"),
        "next_run": next_run(freq, hour, minute, now).isoformat(),
    }


# --------------------------------------------------------------------------------------
# Boucle d'exécution
# --------------------------------------------------------------------------------------

# --------------------------------------------------------------------------------------
# Verrou de collecte PARTAGÉ entre processus (FastAPI scheduler ↔ collect_once.py / Tâche Windows)
# --------------------------------------------------------------------------------------

def _owner_id(trigger: str) -> str:
    return f"{socket.gethostname()}:{os.getpid()}:{trigger}"


async def _acquire_lock(db, owner: str, trigger: str) -> bool:
    """Verrou d'exclusion mutuelle inter-processus : au plus UNE collecte à la fois.

    Empêche que le scheduler interne ET la Tâche Windows ne collectent en même temps. Le verrou
    s'auto-expire (`_LOCK_TTL`) pour ne jamais rester bloqué si un process meurt en le détenant.
    """
    now = utcnow_naive()
    expires = now + _LOCK_TTL
    # 1) Reprend un verrou LIBRE ou EXPIRÉ (upsert non nécessaire : le doc peut ne pas exister).
    res = await db.scheduler_state.update_one(
        {"_id": "lock", "$or": [{"expires_at": {"$lte": now}}, {"expires_at": None}]},
        {"$set": {"owner": owner, "trigger": trigger, "acquired_at": now, "expires_at": expires}},
    )
    if res.modified_count:
        return True
    # 2) Aucun doc existant -> tente de le CRÉER atomiquement (échoue si un autre l'a créé entre-temps).
    try:
        await db.scheduler_state.insert_one(
            {"_id": "lock", "owner": owner, "trigger": trigger, "acquired_at": now, "expires_at": expires})
        return True
    except Exception:  # noqa: BLE001 - DuplicateKey : un verrou VALIDE est déjà détenu ailleurs.
        return False


async def _release_lock(db, owner: str) -> None:
    await db.scheduler_state.update_one(
        {"_id": "lock", "owner": owner}, {"$set": {"expires_at": utcnow_naive(), "owner": None}})


def utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# --------------------------------------------------------------------------------------
# Évaluation d'une échéance : classification (completed/late/degraded/partial/suspicious_empty)
# --------------------------------------------------------------------------------------

def _classify_due(still_failing: list, detected_total: int, delay_min: float) -> str:
    """Statut QUOTIDIEN de l'échéance à partir du résultat de collecte (voir DAILY_HONORED)."""
    if not still_failing:
        if detected_total <= 0:
            return "suspicious_empty"  # joignable mais 0 CVE partout -> anomalie, on NE valide PAS
        return "completed_late" if delay_min > source_state.MAX_DELAY_MIN else "completed"
    if all(source_state.retries_exhausted(s) for s in still_failing):
        return "degraded"
    return "partial"


def _source_breakdown(report: dict) -> dict:
    per = report.get("per_source", [])
    return {
        "successful_sources": [p["source"] for p in per if p.get("ok")],
        "failed_sources": [p["source"] for p in per if p.get("status") in ("failed", "parse_error")],
        "timeout_sources": [p["source"] for p in per if p.get("status") == "timeout"],
    }


# --------------------------------------------------------------------------------------
# Exécuteur PARTAGÉ d'une échéance — utilisé par le scheduler interne ET par collect_once.py
# --------------------------------------------------------------------------------------

async def execute_due(db, due: datetime, sig: str, trigger: str, now: datetime,
                      delay_min: float) -> dict:
    """Collecte + évaluation + persistance d'état pour UNE échéance. Point d'entrée UNIQUE
    partagé (scheduler interne et Tâche Windows) — garantit une logique de collecte identique.

    Protégé par un VERROU en base (anti-double-collecte). `last_completed_due` n'avance QUE pour
    les statuts DAILY_HONORED (jamais pour partial/suspicious_empty/interrupted/failed).
    Renvoie un résumé structuré ({status, detected, new, sources...}).
    """
    owner = _owner_id(trigger)
    if not await _acquire_lock(db, owner, trigger):
        logger.info("Collecte NON lancée (%s) : un verrou est déjà détenu — anti-doublon.", trigger)
        return {"status": "skipped_locked", "trigger": trigger}

    now_utc = now.astimezone(timezone.utc)
    due_utc = due.astimezone(timezone.utc)
    due_naive = due_utc.replace(tzinfo=None)
    started = _now()
    await db.scheduler_state.update_one(
        {"_id": "global"},
        {"$set": {"sig": sig, "last_due": due_utc, "running": True, "running_since": now_utc,
                  "current_trigger": trigger}},
        upsert=True)
    try:
        # RECOUVREMENT PARTIEL : ne (re)collecte QUE les sources pas encore honorées pour l'échéance.
        sources = await get_active_sources(db)
        pending = [s for s in sources if not source_state.source_done_for_due(s, due_naive)]
        logger.info("[%s] Échéance %s : %d source(s) à collecter (%d déjà à jour).",
                    trigger, due.strftime("%Y-%m-%d %H:%M"), len(pending), len(sources) - len(pending))

        report = await pipeline.run_collection(
            db, scope=trigger, source_ids=[s["_id"] for s in pending] if pending else None, due=due_naive)
        finished = _now()

        refreshed = {s["_id"]: s for s in await get_active_sources(db)}
        still_failing = [refreshed[s["_id"]] for s in pending
                         if s["_id"] in refreshed and not source_state.source_done_for_due(refreshed[s["_id"]], due_naive)]
        detected_total = report.get("cve_detected", 0)
        daily_status = _classify_due(still_failing, detected_total, delay_min)
        breakdown = _source_breakdown(report)

        last_report = {
            "run_id": report.get("run_id"), "trigger": trigger,
            "due_date": due.strftime("%Y-%m-%d"), "scheduled_time": sig.split(":", 1)[1],
            "actual_start": started.astimezone(timezone.utc).replace(tzinfo=None),
            "actual_end": finished.astimezone(timezone.utc).replace(tzinfo=None),
            "duration_ms": report.get("duration_ms"),
            "status": daily_status, "execution_delay_min": round(delay_min, 1),
            "detected": detected_total, "new": report.get("new_saved", 0),
            "updated": report.get("updated", 0),
            "source_count": report.get("sources_total", 0),
            "successful_sources": breakdown["successful_sources"],
            "failed_sources": breakdown["failed_sources"],
            "timeout_sources": breakdown["timeout_sources"],
            "status_counts": report.get("status_counts", {}),
            "notifications_created": report.get("notifications_created", 0),
            "degraded": daily_status == "degraded",
            "suspicious_empty": daily_status == "suspicious_empty",
            "errors": report.get("errors", []),
        }

        state_set = {"last_run": now_utc, "running": False, "running_since": None,
                     "current_trigger": None, "last_report": last_report}
        if daily_status in DAILY_HONORED:
            state_set["last_completed_due"] = due_utc
            state_set["degraded"] = (daily_status == "degraded")
            if daily_status in ("completed", "completed_late"):
                state_set["last_successful_collection"] = now_utc
        await db.scheduler_state.update_one({"_id": "global"}, {"$set": state_set}, upsert=True)

        # Estampille le run avec la sémantique QUOTIDIENNE (traçabilité échéance ↔ exécution réelle).
        if report.get("run_id"):
            try:
                from bson import ObjectId
                await db.collection_runs.update_one(
                    {"_id": ObjectId(report["run_id"])},
                    {"$set": {"due_date": due.strftime("%Y-%m-%d"), "scheduled_time": sig.split(":", 1)[1],
                              "trigger": trigger, "daily_status": daily_status,
                              "execution_delay_min": round(delay_min, 1)}})
            except Exception:  # noqa: BLE001
                pass

        _log_summary(last_report, due, daily_status)
        return {"status": daily_status, **{k: last_report[k] for k in
                ("detected", "new", "updated", "source_count", "successful_sources",
                 "failed_sources", "timeout_sources")}}

    except Exception as exc:  # noqa: BLE001 - ne laisse jamais d'état incohérent ; échéance NON validée.
        logger.exception("[%s] ÉCHEC de la collecte : %s — échéance NON validée.", trigger, exc)
        await db.scheduler_state.update_one({"_id": "global"}, {"$set": {
            "running": False, "running_since": None, "current_trigger": None,
            "last_report": {"trigger": trigger, "due_date": due.strftime("%Y-%m-%d"),
                            "status": "failed", "error": str(exc)[:300]}}})
        return {"status": "failed", "trigger": trigger, "error": str(exc)[:300]}
    finally:
        await _release_lock(db, owner)


def _log_summary(rep: dict, due: datetime, status: str) -> None:
    honored = "OUI" if status in DAILY_HONORED else "NON (à re-tenter)"
    logger.info(
        "COLLECTE QUOTIDIENNE | échéance=%s %s | déclencheur=%s | statut=%s | échéance_honorée=%s | "
        "retard=%.0f min | détectées=%s | nouvelles=%s | MAJ=%s | sources=%s (ok=%d, timeout=%s, échec=%s) | "
        "durée=%sms | notif=%s",
        rep["due_date"], rep["scheduled_time"], rep["trigger"], status, honored,
        rep.get("execution_delay_min", 0), rep.get("detected"), rep.get("new"), rep.get("updated"),
        rep.get("source_count"), len(rep.get("successful_sources", [])),
        rep.get("timeout_sources"), rep.get("failed_sources"),
        rep.get("duration_ms"), rep.get("notifications_created"))


async def run_scheduled_collection(db, trigger: str, force: bool = False) -> dict:
    """Lance la collecte pour l'ÉCHÉANCE COURANTE si elle n'est pas déjà honorée. Point d'entrée
    de collect_once.py (Tâche Windows) ET du rattrapage du scheduler. Idempotent : si l'échéance du
    jour est déjà validée, ne fait rien (sauf `force`)."""
    freq, hour, minute = await _read_schedule(db)
    now = _now()
    due = _last_due(freq, hour, minute, now)
    sig = _sig(freq, hour, minute)
    delay_min = max(0.0, (now - due).total_seconds() / 60)

    state = await db.scheduler_state.find_one({"_id": "global"}) or {}
    completed_due = _as_aware(state.get("last_completed_due"))
    if not force and completed_due is not None and completed_due >= due:
        logger.info("[%s] Échéance %s DÉJÀ honorée (dernière=%s) — rien à faire.", trigger,
                    due.strftime("%Y-%m-%d %H:%M"),
                    completed_due.astimezone(_tz()).strftime("%Y-%m-%d %H:%M"))
        return {"status": "already_completed", "due": due.isoformat(), "trigger": trigger}

    if delay_min > source_state.MAX_DELAY_MIN:
        logger.info("[%s] Échéance %s en RETARD de %.0f min (PC éteint / rattrapage) — exécution.",
                    trigger, due.strftime("%Y-%m-%d %H:%M"), delay_min)
    return await execute_due(db, due, sig, trigger, now, delay_min)


async def _maybe_run(heartbeat: bool) -> None:
    """Boucle interne du scheduler FastAPI : vérifie l'échéance et délègue à `execute_due`
    (mêmes règles que la Tâche Windows). N'agit QUE si `COLLECTION_TRIGGER=internal`."""
    global _running
    db = get_database()
    freq, hour, minute = await _read_schedule(db)
    now = _now()
    due = _last_due(freq, hour, minute, now)
    sig = _sig(freq, hour, minute)

    state = await db.scheduler_state.find_one({"_id": "global"}) or {}
    completed_due = _as_aware(state.get("last_completed_due"))
    if state.get("sig") and state["sig"] != sig:
        logger.info("Scheduler : planification modifiée (%s -> %s) — nouvelle échéance prise en compte.",
                    state["sig"], sig)
        completed_due = None

    if heartbeat:
        logger.info("Scheduler ACTIF | fuseau=%s | planning=%s | maintenant=%s | prochaine=%s | "
                    "dernière_terminée=%s | en_cours=%s",
                    _tz(), sig, now.strftime("%Y-%m-%d %H:%M"),
                    next_run(freq, hour, minute, now).strftime("%Y-%m-%d %H:%M"),
                    completed_due.astimezone(_tz()).strftime("%Y-%m-%d %H:%M") if completed_due else "jamais",
                    _running)

    if now < due:
        return
    if completed_due is not None and completed_due >= due:
        return
    if _running:
        return

    # Backoff : si CETTE échéance a déjà échoué récemment, on patiente avant de re-tenter.
    attempt_due = _as_aware(state.get("last_attempt_due"))
    attempt_at = _as_aware(state.get("last_attempt_at"))
    now_utc = now.astimezone(timezone.utc)
    if attempt_due == due and attempt_at and (now_utc - attempt_at) < _RETRY_BACKOFF:
        return

    delay_min = max(0.0, (now - due).total_seconds() / 60)
    if delay_min * 60 > 90:
        logger.info("Scheduler : échéance %s MANQUÉE (retard %.0f min) — RATTRAPAGE immédiat.",
                    due.strftime("%Y-%m-%d %H:%M"), delay_min)
    _running = True
    await db.scheduler_state.update_one(
        {"_id": "global"},
        {"$set": {"last_attempt_due": due.astimezone(timezone.utc), "last_attempt_at": now_utc}},
        upsert=True)
    try:
        await execute_due(db, due, sig, "internal_scheduler", now, delay_min)
    finally:
        _running = False


async def _loop() -> None:
    global _running
    db = get_database()
    # Démarrage propre : clôturer les exécutions orphelines et réarmer le rattrapage immédiat.
    try:
        await pipeline.mark_interrupted_runs(db)
        await db.scheduler_state.update_one(
            {"_id": "global"},
            {"$set": {"running": False}, "$unset": {"last_attempt_at": "", "last_attempt_due": ""}},
            upsert=True,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Scheduler : nettoyage de démarrage impossible : %s", exc)
    _running = False

    freq, hour, minute = await _read_schedule(db)
    now = _now()
    due = _last_due(freq, hour, minute, now)
    state = await db.scheduler_state.find_one({"_id": "global"}) or {}
    completed_due = _as_aware(state.get("last_completed_due"))
    catch_up = now >= due and (completed_due is None or completed_due < due)
    logger.info("Scheduler DÉMARRÉ | fuseau=%s | heure serveur=%s | planning=%s | prochaine=%s | "
                "rattrapage_au_démarrage=%s",
                _tz(), now.strftime("%Y-%m-%d %H:%M:%S"), _sig(freq, hour, minute),
                next_run(freq, hour, minute, now).strftime("%Y-%m-%d %H:%M"), catch_up)
    tick = 0
    while True:
        try:
            await _maybe_run(heartbeat=(tick % _HEARTBEAT_EVERY == 0))
        except Exception as exc:  # noqa: BLE001
            logger.exception("Scheduler : erreur inattendue dans la boucle : %s", exc)
        tick += 1
        await asyncio.sleep(_CHECK_INTERVAL)


def start() -> None:
    """Démarre le scheduler en tâche de fond (idempotent)."""
    global _task
    if _task is not None and not _task.done():
        return
    _task = asyncio.create_task(_loop())


def stop() -> None:
    global _task
    if _task and not _task.done():
        _task.cancel()
    _task = None
