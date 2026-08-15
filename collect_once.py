"""Collecte CVE « one-shot » — point d'entrée de la TÂCHE PLANIFIÉE WINDOWS.

But : réaliser UNE collecte quotidienne SANS dépendre d'une fenêtre Uvicorn ouverte. Ce script
RÉUTILISE exactement le même service de collecte que le scheduler interne (aucune duplication) :

    collect_once.py
        └─ scheduler.run_scheduled_collection(trigger="windows_task")
                └─ scheduler.execute_due()            (verrou anti-doublon + état quotidien)
                        └─ pipeline.run_collection()   (sources → dédup → enrichissement → Mongo)

Comportement : init logging (console + fichier) → connexion Mongo → clôture des collectes
orphelines → collecte de l'échéance courante si non déjà honorée → fermeture du navigateur
partagé → code de sortie selon le statut.

Utilisation :
    python collect_once.py            # collecte l'échéance du jour si pas déjà honorée
    python collect_once.py --force    # force une collecte même si l'échéance est déjà honorée

Codes de sortie : 0 = honorée / déjà faite / verrou (autre instance) ; 1 = échec / partiel /
suspicious_empty (échéance NON validée : à re-tenter).
"""
import argparse
import asyncio
import logging
import os
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler

# Racine du projet sur le sys.path (permet `import app...` quel que soit le CWD de la tâche).
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

LOG_DIR = os.path.join(ROOT, "logs")
LOG_FILE = os.path.join(LOG_DIR, "collect_once.log")

# Statuts d'échéance considérés comme un SUCCÈS opérationnel (code de sortie 0).
_OK_EXIT = {"completed", "completed_late", "degraded", "already_completed", "skipped_locked"}


def _setup_logging() -> None:
    os.makedirs(LOG_DIR, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    root.addHandler(console)
    fileh = RotatingFileHandler(LOG_FILE, maxBytes=2_000_000, backupCount=5, encoding="utf-8")
    fileh.setFormatter(fmt)
    root.addHandler(fileh)
    logging.getLogger("cyberwatch").setLevel(logging.INFO)


async def _print_schedule() -> int:
    """Affiche l'heure d'échéance CONFIGURÉE DANS L'APPLICATION, au format HH:MM.

    Sert à aligner la Tâche Windows sur l'application (`setup_scheduler.ps1` appelle ce mode).
    Sans cet alignement, la tâche peut se déclencher à 08:00 alors que l'échéance applicative
    est à 10:00 : `execute_due` constate qu'aucune échéance n'est due et ne collecte rien —
    la collecte automatique ne se produit alors JAMAIS, sans le moindre message d'erreur.
    """
    from app.backend.db.mongodb import get_database
    from app.backend.services.collection.scheduler import _read_schedule

    _freq, hour, minute = await _read_schedule(get_database())
    print(f"{hour:02d}:{minute:02d}")
    return 0


async def _record_outcome(status: str, exit_code: int, error: str | None = None) -> None:
    """Persiste le RÉSULTAT de l'exécution planifiée dans `scheduler_state`.

    Une tâche Windows qui échoue est invisible : elle n'écrit rien dans l'application et son
    code de retour se consulte dans le Planificateur de tâches. En consignant ici chaque
    exécution — réussie ou non — un échec répété devient constatable depuis CyberWatch AI.
    """
    try:
        from app.backend.db.mongodb import get_database
        from app.backend.utils import utcnow

        await get_database().scheduler_state.update_one(
            {"_id": "global"},
            {"$set": {"last_task_run": {
                "at": utcnow(), "status": status, "exit_code": exit_code,
                "ok": exit_code == 0, "error": error, "trigger": "windows_task",
                "script": os.path.abspath(__file__),
            }}},
            upsert=True)
    except Exception as exc:  # noqa: BLE001 - la trace ne doit jamais faire échouer la collecte
        logging.getLogger("cyberwatch.collect_once").warning(
            "Résultat non enregistré en base : %s", exc)


async def _run(force: bool) -> str:
    # Imports tardifs : après l'ajout de ROOT au sys.path.
    from app.backend.db.mongodb import create_indexes, get_database
    from app.backend.services.collection import pipeline, scheduler
    from app.backend.services.verification import browser_client

    log = logging.getLogger("cyberwatch.collect_once")
    db = get_database()
    try:
        await create_indexes()
    except Exception as exc:  # noqa: BLE001 - non bloquant (index déjà présents en général)
        log.warning("create_indexes : %s", exc)

    # Clôture des collectes restées « running » (process précédent tué en pleine collecte).
    await pipeline.mark_interrupted_runs(db)

    log.info("collect_once : démarrage (trigger=windows_task, force=%s).", force)
    try:
        result = await scheduler.run_scheduled_collection(db, trigger="windows_task", force=force)
    finally:
        # Ferme le navigateur Chromium partagé (process one-shot : on ne laisse rien traîner).
        await browser_client.close_shared()

    status = result.get("status", "unknown")
    log.info("collect_once : TERMINÉ — statut=%s | %s", status,
             {k: v for k, v in result.items() if k != "status"})
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description="Collecte CVE quotidienne (one-shot).")
    parser.add_argument("--force", action="store_true",
                        help="Forcer la collecte même si l'échéance du jour est déjà honorée.")
    parser.add_argument("--print-schedule", action="store_true",
                        help="Affiche l'heure d'échéance configurée dans l'application (HH:MM) "
                             "et quitte. Sert à aligner la Tâche Windows sur l'application.")
    args = parser.parse_args()

    # Mode « lecture de l'heure » : silencieux, pour être consommé par un script.
    if args.print_schedule:
        try:
            return asyncio.run(_print_schedule())
        except Exception as exc:  # noqa: BLE001
            print(f"ERREUR: {exc}", file=sys.stderr)
            return 1

    _setup_logging()
    log = logging.getLogger("cyberwatch.collect_once")
    log.info("================ COLLECT_ONCE %s ================", datetime.now().isoformat(timespec="seconds"))
    try:
        status = asyncio.run(_run(args.force))
    except KeyboardInterrupt:
        log.warning("collect_once : interrompu (Ctrl-C).")
        asyncio.run(_record_outcome("interrupted", 130, "Interrompu (Ctrl-C)."))
        return 130
    except Exception as exc:  # noqa: BLE001 - toute erreur -> code non nul (la tâche journalise l'échec)
        log.exception("collect_once : ÉCHEC inattendu : %s", exc)
        asyncio.run(_record_outcome("failed", 1, str(exc)[:300]))
        return 1

    code = 0 if status in _OK_EXIT else 1
    # ÉCHEC VISIBLE : niveau ERROR (et non INFO) pour qu'une exécution planifiée ratée
    # ressorte immédiatement dans logs/collect_once.log, sans lecture ligne à ligne.
    if code == 0:
        log.info("collect_once : code de sortie=0 (statut=%s).", status)
    else:
        log.error("collect_once : ÉCHEC — statut=%s, code de sortie=%d. "
                  "L'échéance N'EST PAS honorée ; elle sera retentée.", status, code)
    asyncio.run(_record_outcome(status, code))
    return code


if __name__ == "__main__":
    sys.exit(main())
