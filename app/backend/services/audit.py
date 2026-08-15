from app.backend.db.mongodb import get_database
from app.backend.utils import utcnow


async def log_action(actor_id: str, actor_role: str, action: str, meta: dict | None = None) -> None:
    db = get_database()
    await db.logs.insert_one(
        {
            "actor_id": actor_id,
            "actor_role": actor_role,
            "action": action,
            "meta": meta or {},
            "created_at": utcnow(),
        }
    )
