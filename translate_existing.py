"""Traduction des CVE DÉJÀ stockées en base — traitement par lots, REPRENABLE.

La base contient ~10 000 CVE collectées avant l'agent de traduction. Ce script les rattrape
progressivement, sans jamais charger l'ensemble en mémoire :

    MongoDB → recherche des CVE non traduites → lot de N → Agent de traduction
            → écriture des champs français → lot suivant

REPRENABLE : la sélection porte sur les CVE dont `translation_status` est absent ou vaut
« failed ». Interrompre le script (Ctrl-C) puis le relancer reprend là où il s'était arrêté —
les CVE déjà traitées ne sont jamais retraduites.

NON DESTRUCTIF : seuls les champs `*_fr` et les métadonnées de traduction sont écrits. Le
contenu d'origine n'est jamais modifié.

Utilisation :
    python translate_existing.py                      # tout le reliquat, lots de 50
    python translate_existing.py --batch-size 100     # lots plus gros
    python translate_existing.py --limit 200          # s'arrête après 200 CVE (essai)
    python translate_existing.py --retry-failed       # rejoue aussi les échecs précédents
    python translate_existing.py --dry-run            # compte seulement, aucun appel LLM
"""
import argparse
import asyncio
import logging
import os
import sys
from datetime import datetime

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

LOG_FILE = os.path.join(ROOT, "logs", "translate_existing.log")

# Champs nécessaires à la traduction (projection réduite = mémoire maîtrisée).
_PROJECTION = {"cve_id": 1, "title": 1, "description": 1, "impact": 1, "solution": 1,
               "translation_status": 1, "title_fr": 1, "description_fr": 1,
               "impact_fr": 1, "solution_fr": 1}


def _setup_logging() -> logging.Logger:
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    root.addHandler(console)
    fileh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fileh.setFormatter(fmt)
    root.addHandler(fileh)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    return logging.getLogger("cyberwatch.translate")


def _query(retry_failed: bool) -> dict:
    """CVE restant à traiter. « completed » et « not_required » sont toujours exclus."""
    states = [{"translation_status": {"$exists": False}}, {"translation_status": None}]
    if retry_failed:
        states.append({"translation_status": "failed"})
    return {"$or": states}


async def _run(batch_size: int, limit: int | None, retry_failed: bool, dry_run: bool,
               concurrency: int, delay: float) -> int:
    from app.backend.db.mongodb import get_database
    from app.backend.services.assistant import llm
    from app.backend.services.collection import translation

    log = _setup_logging()
    db = get_database()
    query = _query(retry_failed)

    total_db = await db.cves.count_documents({})
    remaining = await db.cves.count_documents(query)
    done = await db.cves.count_documents({"translation_status": "completed"})
    skipped_fr = await db.cves.count_documents({"translation_status": "not_required"})
    log.info("Base : %d CVE | déjà traduites : %d | déjà en français : %d | à traiter : %d",
             total_db, done, skipped_fr, remaining)

    if dry_run:
        log.info("--dry-run : aucun appel au modèle, aucune écriture.")
        return 0
    if not remaining:
        log.info("Rien à faire.")
        return 0
    if not llm.available():
        log.error("Aucun modèle LLM configuré (LLM_PROVIDER / LLM_API_KEY) — abandon.")
        return 1

    stats = {"translated": 0, "not_required": 0, "failed": 0, "skipped": 0}
    processed = 0
    started = datetime.now()

    while True:
        if limit is not None and processed >= limit:
            log.info("Limite de %d CVE atteinte — arrêt volontaire.", limit)
            break
        taille = batch_size if limit is None else min(batch_size, limit - processed)
        # On relit la requête à CHAQUE lot : les CVE traitées en sortent d'elles-mêmes, donc
        # pas de pagination à maintenir — et une interruption ne perd aucun avancement.
        lot = await db.cves.find(query, _PROJECTION).limit(taille).to_list(taille)
        if not lot:
            break

        res = await translation.translate_batch(lot, concurrency=concurrency)
        for k in stats:
            stats[k] += res.get(k, 0)

        for rec in lot:
            updates = {k: rec[k] for k in
                       ("title_fr", "description_fr", "impact_fr", "solution_fr",
                        "translation_status", "translated_fields", "translation_error",
                        "translation_warning") if rec.get(k) is not None}
            if updates:
                await db.cves.update_one({"_id": rec["_id"]}, {"$set": updates})

        processed += len(lot)
        reste = await db.cves.count_documents(query)
        vitesse = processed / max(1, (datetime.now() - started).total_seconds()) * 60
        log.info("Lot de %d traité — cumul %d (traduites %d, déjà FR %d, échecs %d) | "
                 "reste %d | %.0f CVE/min", len(lot), processed, stats["translated"],
                 stats["not_required"], stats["failed"], reste, vitesse)

        # Respiration entre deux lots : les fournisseurs plafonnent le débit (Groq renvoie
        # HTTP 429). Sans cette pause, une partie des traductions échoue pour rien.
        if delay > 0:
            await asyncio.sleep(delay)

    duree = (datetime.now() - started).total_seconds()
    log.info("TERMINÉ en %.0f s — %d CVE traitées : %d traduites, %d déjà en français, %d échecs.",
             duree, processed, stats["translated"], stats["not_required"], stats["failed"])
    if stats["failed"]:
        log.info("Les échecs sont rejouables : relancez avec --retry-failed.")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Traduction par lots des CVE déjà en base.")
    p.add_argument("--batch-size", type=int, default=50, help="CVE par lot (défaut : 50).")
    p.add_argument("--limit", type=int, default=None, help="Nombre max de CVE à traiter.")
    p.add_argument("--retry-failed", action="store_true",
                   help="Rejouer aussi les CVE en échec de traduction.")
    p.add_argument("--dry-run", action="store_true", help="Compter seulement, sans traduire.")
    p.add_argument("--concurrency", type=int, default=2,
                   help="Traductions simultanées (défaut : 2). Au-delà, risque de HTTP 429.")
    p.add_argument("--delay", type=float, default=2.0,
                   help="Pause en secondes entre deux lots (défaut : 2).")
    args = p.parse_args()
    try:
        return asyncio.run(_run(args.batch_size, args.limit, args.retry_failed, args.dry_run,
                                args.concurrency, args.delay))
    except KeyboardInterrupt:
        print("\nInterrompu. Relancez la commande pour reprendre où vous en étiez.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
