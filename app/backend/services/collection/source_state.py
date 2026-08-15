"""État de collecte PAR SOURCE, classification des résultats, santé et alertes.

Principes production :
- Chaque source est suivie INDÉPENDAMMENT (jamais un seul état global) : statut, dernière
  tentative, dernière réussite, dernière erreur, nb de tentatives, série de collectes vides,
  dernière échéance honorée.
- Le NOMBRE de CVE ne détermine JAMAIS le succès. Une source joignable et correctement analysée
  mais sans nouveauté du jour est un SUCCÈS (« EMPTY »). Seuls FAILED / TIMEOUT / PARSE_ERROR
  sont ré-essayés.
"""
import logging
from datetime import datetime, timedelta, timezone

from app.backend.utils import utcnow

logger = logging.getLogger("cyberwatch.collection.state")

# Statuts de collecte d'UNE source.
SUCCESS = "success"        # joignable + analysé + au moins 1 CVE
EMPTY = "empty"            # joignable + analysé + 0 nouveauté (SUCCÈS, pas d'erreur)
FAILED = "failed"          # injoignable / erreur réseau
TIMEOUT = "timeout"        # délai dépassé
PARSE_ERROR = "parse_error"  # contenu récupéré mais non analysable

GOOD = {SUCCESS, EMPTY}              # échéance honorée pour la source
RETRYABLE = {FAILED, TIMEOUT, PARSE_ERROR}  # à ré-essayer

# Seuils d'alerte.
STALE_HOURS = 24            # source sans succès depuis > 24 h
MAX_DELAY_MIN = 15         # exécution planifiée en retard de > 15 min
RETRY_ALERT_THRESHOLD = 3  # trop de tentatives consécutives en échec
EMPTY_STREAK_ALERT = 5     # source vide plusieurs jours d'affilée


def classify(ok: bool, detected: int, error: str | None) -> str:
    """Classe un résultat de collecteur (le collecteur signale l'injoignabilité via une exception,
    déjà transformée en `error` par le pipeline). Le compte de CVE ne sert QU'À distinguer
    SUCCESS/EMPTY, jamais succès/échec."""
    if error == "timeout":
        return TIMEOUT
    if error == "parse_error":
        return PARSE_ERROR
    if error:
        return FAILED
    return SUCCESS if detected > 0 else EMPTY


def _utc_naive(dt):
    if not isinstance(dt, datetime):
        return None
    return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt


async def record_result(db, source: dict, res: dict, due: datetime | None = None) -> str:
    """Met à jour l'état INDÉPENDANT de la source d'après le résultat de sa collecte."""
    st = source.get("sync_state") or {}
    status = res.get("status") or classify(res.get("ok", False), res.get("detected", 0), res.get("error"))
    now = utcnow()
    due_n = _utc_naive(due)
    upd = {
        "sync_state.status": status,
        "sync_state.last_attempt": now,
        "sync_state.detected": res.get("detected", 0),
        "sync_state.last_error": res.get("error") if status in RETRYABLE else None,
        "sync_state.last_due": due_n,
    }
    if status in GOOD:
        upd["sync_state.last_successful_collection"] = now
        upd["sync_state.retry_count"] = 0
        if due_n is not None:
            upd["sync_state.last_success_due"] = due_n
        upd["sync_state.empty_streak"] = (st.get("empty_streak") or 0) + 1 if status == EMPTY else 0
    else:
        upd["sync_state.retry_count"] = (st.get("retry_count") or 0) + 1
    await db.sources.update_one({"_id": source["_id"]}, {"$set": upd})
    logger.info("[state] Source « %s » → %s (retry=%s, détectées=%s).",
                source.get("name"), status, upd.get("sync_state.retry_count", 0), res.get("detected", 0))
    return status


def source_done_for_due(source: dict, due: datetime | None) -> bool:
    """La source a-t-elle DÉJÀ été collectée avec succès pour CETTE échéance ? (recouvrement partiel)."""
    if due is None:
        return False
    st = source.get("sync_state") or {}
    ls = _utc_naive(st.get("last_success_due"))
    return ls is not None and ls >= _utc_naive(due)


def retries_exhausted(source: dict) -> bool:
    """Trop de tentatives en échec : on cesse de bloquer l'échéance (mais on lève une alerte)."""
    st = source.get("sync_state") or {}
    return (st.get("retry_count") or 0) >= RETRY_ALERT_THRESHOLD


# --------------------------------------------------------------------------------------
# Santé & alertes
# --------------------------------------------------------------------------------------

async def compute_alerts(db, scheduler_delay_min: float | None = None) -> list[dict]:
    """Calcule les alertes de supervision (persistées dans `alerts`)."""
    now = _utc_naive(utcnow())  # comparaisons en UTC naïf (comme les dates relues depuis Mongo)
    alerts: list[dict] = []

    async for s in db.sources.find({"status": "validated"}):
        st = s.get("sync_state") or {}
        name = s.get("name")
        # Repli sur last_sync_at pour les sources collectées avant l'introduction de sync_state.
        last_ok = _utc_naive(st.get("last_successful_collection") or s.get("last_sync_at"))
        if last_ok is None or (now - last_ok) > timedelta(hours=STALE_HOURS):
            hrs = "jamais" if last_ok is None else f"{(now - last_ok).total_seconds() / 3600:.0f} h"
            alerts.append({"key": f"stale:{s['_id']}", "level": "critical", "type": "source_stale",
                           "source": name, "message": f"Aucune collecte réussie depuis {hrs}."})
        if (st.get("retry_count") or 0) >= RETRY_ALERT_THRESHOLD:
            alerts.append({"key": f"retries:{s['_id']}", "level": "warning", "type": "source_retries",
                           "source": name, "message": f"{st['retry_count']} échecs consécutifs "
                                                       f"(dernière erreur : {st.get('last_error')})."})
        if (st.get("empty_streak") or 0) >= EMPTY_STREAK_ALERT:
            alerts.append({"key": f"empty:{s['_id']}", "level": "info", "type": "source_empty_streak",
                           "source": name, "message": f"Vide depuis {st['empty_streak']} collectes consécutives "
                                                       f"(à vérifier : la source publie-t-elle encore ?)."})

    if scheduler_delay_min is not None and scheduler_delay_min > MAX_DELAY_MIN:
        alerts.append({"key": "scheduler:delay", "level": "warning", "type": "scheduler_delay",
                       "source": "scheduler", "message": f"Exécution planifiée en retard de "
                                                         f"{scheduler_delay_min:.0f} min."})

    # Persistance idempotente (une alerte par clé, horodatée).
    for a in alerts:
        await db.alerts.update_one({"_id": a["key"]},
                                   {"$set": {**a, "updated_at": now, "active": True},
                                    "$setOnInsert": {"created_at": now}}, upsert=True)
    active_keys = {a["key"] for a in alerts}
    await db.alerts.update_many({"_id": {"$nin": list(active_keys)}, "active": True},
                                {"$set": {"active": False, "resolved_at": now}})
    if alerts:
        logger.warning("[alerts] %d alerte(s) active(s) : %s", len(alerts),
                       ", ".join(f"{a['type']}({a['source']})" for a in alerts))
    return alerts
