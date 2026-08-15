"""Tests de la nouvelle architecture de planification (état quotidien + verrou anti-doublon).

Exécute la VRAIE logique `scheduler.execute_due` / `run_scheduled_collection` contre une base
MongoDB JETABLE, en remplaçant UNIQUEMENT `pipeline.run_collection` par un faux qui simule le
résultat des sources (aucun réseau). Vérifie les transitions d'état :

  TEST 1  completed        -> échéance honorée, last_completed_due avance
  TEST 2  completed_late   -> exécutée en retard, honorée
  TEST 3  degraded         -> sources en échec persistant, honorée + degraded
  TEST 4  partial          -> source en échec récupérable, NON honorée
  TEST 5  suspicious_empty -> sources OK mais 0 CVE, NON honorée
  TEST 6  interrupted      -> run tué -> 'interrupted', n'avance PAS l'échéance
  TEST 7  already_completed-> idempotent : ne relance pas une échéance déjà honorée
  TEST 8  lock/double-run  -> le verrou empêche une 2e collecte simultanée

Lancer :  python tests/test_scheduling.py
"""
import asyncio
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from motor.motor_asyncio import AsyncIOMotorClient  # noqa: E402

from app.backend.core.config import settings  # noqa: E402
from app.backend.services.collection import scheduler, source_state  # noqa: E402
from app.backend.services.collection import pipeline as pipeline_mod  # noqa: E402
from app.backend.utils import utcnow  # noqa: E402

TEST_DB = settings.DB_NAME + "_sched_test"
SOURCES = ["alpha", "beta", "gamma"]
_fails = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global _fails
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        _fails += 1


async def _seed(db):
    await db.sources.delete_many({})
    await db.scheduler_state.delete_many({})
    await db.collection_runs.delete_many({})
    await db.collection_schedule.delete_many({})
    await db.collection_schedule.insert_one({"_id": "global", "frequency": "daily", "hour": 8, "minute": 0})
    for n in SOURCES:
        await db.sources.insert_one({"name": n, "status": "validated", "url": f"https://{n}.example",
                                     "collection_method": "scraping", "sync_state": {}})


def make_fake(outcomes: dict, detected: int):
    """Faux run_collection : met à jour l'état des sources comme le vrai pipeline, sans réseau.
    outcomes[name] ∈ {"ok","exhausted","fail1"} ; `detected` = CVE par source OK."""
    async def fake(db, scope="collect-all", source_ids=None, due=None):
        from app.backend.services.collection.source_manager import get_active_sources
        run_id = (await db.collection_runs.insert_one(
            {"scope": scope, "status": "running", "started_at": utcnow()})).inserted_id
        srcs = await get_active_sources(db)
        if source_ids is not None:
            wanted = {str(x) for x in source_ids}
            srcs = [s for s in srcs if str(s["_id"]) in wanted]
        per_source, status_counts = [], {}
        for s in srcs:
            o = outcomes.get(s["name"], "ok")
            if o == "ok":
                st, ok = ("success" if detected > 0 else "empty"), True
                await db.sources.update_one({"_id": s["_id"]}, {"$set": {
                    "sync_state.last_success_due": due, "sync_state.retry_count": 0, "sync_state.status": st}})
            else:
                st, ok = "timeout", False
                rc = 5 if o == "exhausted" else 1
                await db.sources.update_one({"_id": s["_id"]}, {"$set": {
                    "sync_state.retry_count": rc, "sync_state.status": st, "sync_state.last_error": "timeout"}})
            status_counts[st] = status_counts.get(st, 0) + 1
            per_source.append({"source": s["name"], "method": "html", "ok": ok, "status": st,
                               "detected": (detected if ok else 0), "error": None if ok else "timeout"})
        report = {"run_id": str(run_id), "scope": scope, "status": "completed", "finished_at": utcnow(),
                  "duration_ms": 5, "sources_total": len(srcs), "status_counts": status_counts,
                  "cve_detected": sum(p["detected"] for p in per_source),
                  "new_saved": sum(p["detected"] for p in per_source), "updated": 0,
                  "notifications_created": 0, "per_source": per_source, "errors": []}
        await db.collection_runs.update_one({"_id": run_id}, {"$set": report})
        return report
    return fake


async def _due_now():
    now = scheduler._now()
    due = scheduler._last_due("daily", 8, 0, now)
    return now, due, scheduler._sig("daily", 8, 0)


async def _state(db):
    return await db.scheduler_state.find_one({"_id": "global"}) or {}


async def main():
    client = AsyncIOMotorClient(settings.MONGO_URI)
    db = client[TEST_DB]
    orig_run = pipeline_mod.run_collection
    try:
        now, due, sig = await _due_now()
        due_naive = due.astimezone(__import__("datetime").timezone.utc).replace(tzinfo=None)

        # ---- TEST 1 : completed ----
        print("TEST 1 — completed")
        await _seed(db)
        pipeline_mod.run_collection = make_fake({}, detected=10)
        r = await scheduler.execute_due(db, due, sig, "test", now, delay_min=0.0)
        st = await _state(db)
        check("statut completed", r["status"] == "completed", r["status"])
        check("last_completed_due avancé", st.get("last_completed_due") is not None)
        check("last_report.status", (st.get("last_report") or {}).get("status") == "completed")

        # ---- TEST 2 : completed_late ----
        print("TEST 2 — completed_late")
        await _seed(db)
        pipeline_mod.run_collection = make_fake({}, detected=10)
        r = await scheduler.execute_due(db, due, sig, "test", now, delay_min=120.0)
        st = await _state(db)
        check("statut completed_late", r["status"] == "completed_late", r["status"])
        check("échéance honorée (avance)", st.get("last_completed_due") is not None)

        # ---- TEST 3 : degraded ----
        print("TEST 3 — degraded")
        await _seed(db)
        pipeline_mod.run_collection = make_fake({"gamma": "exhausted"}, detected=10)
        r = await scheduler.execute_due(db, due, sig, "test", now, delay_min=0.0)
        st = await _state(db)
        check("statut degraded", r["status"] == "degraded", r["status"])
        check("degraded avance l'échéance", st.get("last_completed_due") is not None)
        check("flag degraded=True", st.get("degraded") is True)
        check("timeout_sources listées", "gamma" in (st.get("last_report") or {}).get("timeout_sources", []))

        # ---- TEST 4 : partial (NON honorée) ----
        print("TEST 4 — partial")
        await _seed(db)
        pipeline_mod.run_collection = make_fake({"beta": "fail1"}, detected=10)
        r = await scheduler.execute_due(db, due, sig, "test", now, delay_min=0.0)
        st = await _state(db)
        check("statut partial", r["status"] == "partial", r["status"])
        check("partial N'AVANCE PAS l'échéance", st.get("last_completed_due") is None)

        # ---- TEST 5 : suspicious_empty (NON honorée) ----
        print("TEST 5 — suspicious_empty")
        await _seed(db)
        pipeline_mod.run_collection = make_fake({}, detected=0)  # toutes OK mais 0 CVE
        r = await scheduler.execute_due(db, due, sig, "test", now, delay_min=0.0)
        st = await _state(db)
        check("statut suspicious_empty", r["status"] == "suspicious_empty", r["status"])
        check("suspicious N'AVANCE PAS l'échéance", st.get("last_completed_due") is None)

        # ---- TEST 6 : interrupted ----
        print("TEST 6 — interrupted")
        await _seed(db)
        await db.collection_runs.insert_one({"scope": "test", "status": "running", "started_at": utcnow()})
        n = await pipeline_mod.mark_interrupted_runs(db)
        run = await db.collection_runs.find_one({"scope": "test"})
        st = await _state(db)
        check("run marqué interrupted", run.get("status") == "interrupted", str(n))
        check("interrupted n'avance PAS l'échéance", st.get("last_completed_due") is None)

        # ---- TEST 7 : already_completed (idempotence) ----
        print("TEST 7 — already_completed")
        await _seed(db)
        pipeline_mod.run_collection = make_fake({}, detected=10)
        await scheduler.execute_due(db, due, sig, "test", now, delay_min=0.0)  # honore l'échéance
        called = {"n": 0}
        orig_fake = pipeline_mod.run_collection
        async def counting(*a, **k):
            called["n"] += 1
            return await orig_fake(*a, **k)
        pipeline_mod.run_collection = counting
        r = await scheduler.run_scheduled_collection(db, trigger="test")
        check("statut already_completed", r["status"] == "already_completed", r["status"])
        check("aucune collecte relancée", called["n"] == 0)

        # ---- TEST 8 : verrou anti-doublon ----
        print("TEST 8 — lock / double-run")
        await _seed(db)
        ok1 = await scheduler._acquire_lock(db, "ownerA", "windows_task")
        ok2 = await scheduler._acquire_lock(db, "ownerB", "internal_scheduler")
        check("1er verrou acquis", ok1 is True)
        check("2e verrou refusé (anti-doublon)", ok2 is False)
        # execute_due doit renvoyer skipped_locked tant que le verrou est détenu par A.
        pipeline_mod.run_collection = make_fake({}, detected=10)
        r = await scheduler.execute_due(db, due, sig, "internal_scheduler", now, 0.0)
        check("execute_due -> skipped_locked", r["status"] == "skipped_locked", r["status"])
        await scheduler._release_lock(db, "ownerA")
        ok3 = await scheduler._acquire_lock(db, "ownerC", "windows_task")
        check("verrou ré-acquis après libération", ok3 is True)
        await scheduler._release_lock(db, "ownerC")

    finally:
        pipeline_mod.run_collection = orig_run
        await client.drop_database(TEST_DB)
        client.close()

    print("\n" + ("TOUS LES TESTS PASSENT ✅" if _fails == 0 else f"{_fails} ASSERTION(S) EN ÉCHEC ❌"))
    return 1 if _fails else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
