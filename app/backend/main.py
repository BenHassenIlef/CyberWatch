import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.backend.core import config
from app.backend.core.config import settings
from app.backend.db.mongodb import create_indexes, get_database
from app.backend.routers import admin, assistant, auth, chat, consultant, monitoring
from app.backend.services.collection import pipeline, scheduler

logger = logging.getLogger("cyberwatch.startup")


def _configure_logging() -> None:
    """Rend visibles les logs applicatifs (scheduler, collecte, vérification) dans la console."""
    root = logging.getLogger()
    if not any(getattr(h, "_cyberwatch", False) for h in root.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
        handler._cyberwatch = True  # évite les doublons de handler au reload
        root.addHandler(handler)
    logging.getLogger("cyberwatch").setLevel(logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    _configure_logging()
    # Quel fichier de configuration a RÉELLEMENT été lu, et lesquels sont ignorés. Une valeur
    # saisie dans un fichier que personne ne charge est indétectable autrement : on constate
    # seulement que le réglage « ne marche pas », sans jamais soupçonner le bon coupable.
    config.tracer_chargement()
    await create_indexes()
    # Hygiène : au démarrage, clôturer toute collecte orpheline restée « running » (process tué).
    try:
        await pipeline.mark_interrupted_runs(get_database())
    except Exception as exc:  # noqa: BLE001
        logger.warning("Nettoyage des exécutions interrompues impossible : %s", exc)
    # Déclencheur de la collecte quotidienne. En mode « external » (défaut), la collecte est
    # pilotée par la Tâche planifiée Windows (collect_once.py) et NE dépend PAS d'Uvicorn :
    # FastAPI ne sert alors que l'API/UI. Voir docs/SCHEDULING.md.
    if settings.internal_scheduler_enabled:
        logger.info("COLLECTION_TRIGGER=internal → scheduler interne ACTIVÉ (collecte liée à Uvicorn).")
        scheduler.start()
    else:
        logger.info("COLLECTION_TRIGGER=external → collecte quotidienne déléguée à la Tâche Windows "
                    "(collect_once.py) ; scheduler interne DÉSACTIVÉ (pas de double déclenchement).")
    yield
    scheduler.stop()


app = FastAPI(title="CyberWatch AI API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    # En dev, Vite peut basculer de port (5173 occupé -> 5174…) et l'app peut être ouverte via
    # « localhost » OU « 127.0.0.1 » : on autorise tout origine locale (n'importe quel port) pour
    # éviter les blocages CORS. Les origines de PRODUCTION restent listées via CORS_ORIGINS.
    allow_origin_regex=r"^http://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(consultant.router)
app.include_router(monitoring.router)
app.include_router(chat.router)
app.include_router(assistant.router)


@app.get("/health")
async def health():
    return {"status": "ok"}
