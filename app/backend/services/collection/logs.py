"""Journalisation de la collecte : logs Python + persistance en base (collection_logs)."""
import logging

from app.backend.utils import utcnow

logger = logging.getLogger("cyberwatch.collection")


class RunLogger:
    """Accumule les entrées d'une exécution de collecte et les persiste."""

    def __init__(self, db, scope: str = "collect"):
        self.db = db
        self.scope = scope
        self.entries: list[dict] = []

    def _add(self, level: str, message: str, source_name: str | None = None, source_id=None):
        entry = {
            "scope": self.scope, "level": level, "message": message,
            "source_name": source_name, "source_id": source_id, "ts": utcnow(),
        }
        self.entries.append(entry)
        getattr(logger, level if level in ("info", "warning", "error") else "info")(
            f"[{source_name or '-'}] {message}"
        )

    def info(self, message, source=None):
        self._add("info", message, _name(source), _id(source))

    def warning(self, message, source=None):
        self._add("warning", message, _name(source), _id(source))

    def error(self, message, source=None):
        self._add("error", message, _name(source), _id(source))

    async def flush(self):
        if self.entries:
            await self.db.collection_logs.insert_many(self.entries)


def _name(source):
    return source.get("name") if isinstance(source, dict) else source


def _id(source):
    return source.get("_id") if isinstance(source, dict) else None
