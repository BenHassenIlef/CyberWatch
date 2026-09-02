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


# ATTENTE DU RESEAU — controle fait ICI, et non delegue a Windows.
#
# Le planificateur Windows propose « n executer que si le reseau est disponible ». Sa detection
# (NLA) juge parfois indisponible un reseau parfaitement fonctionnel — VPN, connexion dite
# limitee, profil non identifie — et l execution est alors PUREMENT ET SIMPLEMENT sautee, sans
# trace exploitable. Constate en production : une journee entiere sans collecte.
#
# On lance donc toujours la tache, et c est le programme qui attend le reseau : l attente est
# bornee, journalisee, et son echec laisse une trace consultable.
SONDES_RESEAU = ("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1",
                 "https://api.stackexchange.com/2.3/info?site=security")
ATTENTES_RESEAU = (0, 30, 60, 120, 240)   # secondes avant chaque tentative


async def _attendre_le_reseau() -> bool:
    """True des qu une source repond. Attentes croissantes, bornees a ~7 minutes.

    Au reveil d une machine, la connectivite met souvent une a deux minutes a s etablir :
    partir immediatement faisait expirer les quatorze sources d un bloc et produisait une
    collecte vide en moins d une minute.
    """
    import httpx

    log = logging.getLogger("cyberwatch.collect_once")
    for i, attente in enumerate(ATTENTES_RESEAU, start=1):
        if attente:
            log.info("Reseau indisponible : nouvel essai dans %ds (%d/%d).",
                     attente, i, len(ATTENTES_RESEAU))
            await asyncio.sleep(attente)
        for url in SONDES_RESEAU:
            try:
                async with httpx.AsyncClient(timeout=15) as c:
                    if (await c.get(url)).status_code < 500:
                        if i > 1:
                            log.info("Reseau retabli apres %d tentative(s).", i)
                        return True
            except Exception:  # noqa: BLE001 - sonde en echec : on retente plus tard
                continue
    log.error("Aucune source joignable apres %d tentatives : collecte ABANDONNEE. "
              "L echeance n est pas honoree et sera retentee.", len(ATTENTES_RESEAU))
    return False


async def _run_and_record(force: bool) -> int:
    """Exécute la collecte ET consigne son résultat DANS LA MÊME BOUCLE D'ÉVÉNEMENTS.

    Le client MongoDB (Motor) est lié à la boucle qui l'a créé : appeler `asyncio.run()` une
    seconde fois pour enregistrer le résultat échouait avec « Event loop is closed », et la
    trace était silencieusement perdue — précisément ce que cette trace doit éviter.
    """
    log = logging.getLogger("cyberwatch.collect_once")

    # Sans reseau, une collecte ne rapporte rien mais MARQUE l echeance comme traitee : la
    # veille du jour serait perdue jusqu au lendemain. On prefere echouer explicitement.
    if not await _attendre_le_reseau():
        await _record_outcome("failed", 1, "reseau indisponible")
        return 1

    try:
        status = await _run(force)
    except Exception as exc:  # noqa: BLE001 - toute erreur -> code non nul, mais TRACÉE
        log.exception("collect_once : ÉCHEC inattendu : %s", exc)
        await _record_outcome("failed", 1, str(exc)[:300])
        return 1

    code = 0 if status in _OK_EXIT else 1
    # ÉCHEC VISIBLE : niveau ERROR (et non INFO) pour qu'une exécution planifiée ratée
    # ressorte immédiatement dans logs/collect_once.log, sans lecture ligne à ligne.
    if code == 0:
        log.info("collect_once : code de sortie=0 (statut=%s).", status)
    else:
        log.error("collect_once : ÉCHEC — statut=%s, code de sortie=%d. "
                  "L'échéance N'EST PAS honorée ; elle sera retentée.", status, code)
    await _record_outcome(status, code)
    return code


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
        return asyncio.run(_run_and_record(args.force))
    except KeyboardInterrupt:
        log.warning("collect_once : interrompu (Ctrl-C).")
        return 130


if __name__ == "__main__":
    sys.exit(main())
