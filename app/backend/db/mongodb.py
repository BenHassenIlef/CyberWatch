from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from app.backend.core.config import settings

_client: AsyncIOMotorClient | None = None


def get_client() -> AsyncIOMotorClient:
    global _client
    if _client is None:
        _client = AsyncIOMotorClient(settings.MONGO_URI)
    return _client


def get_database() -> AsyncIOMotorDatabase:
    return get_client()[settings.DB_NAME]


async def create_indexes() -> None:
    db = get_database()
    await db.users.create_index("email", unique=True)
    await db.logs.create_index("created_at")
    await db.cves.create_index("status")
    await db.cves.create_index("source_id")
    await db.source_history.create_index("source_id")
    await db.source_credentials.create_index("source_id", unique=True)
    # Index de LISTE des CVE : tri/pagination côté MongoDB rapides (page ~20 docs, pas de scan complet).
    await db.cves.create_index("cve_id")
    await db.cves.create_index([("published_at", -1)])
    await db.cves.create_index([("collected_at", -1)])
    await db.cves.create_index([("cvss_score", -1)])
    await db.cves.create_index("severity")
    await db.cves.create_index("is_new")
    await db.cves.create_index("affected_products")
    # PÉRIMÈTRE DE SURVEILLANCE — étiquettes posées sur les CVE par la collecte (produit primaire +
    # tableau multi-produits : une CVE peut affecter plusieurs produits suivis).
    await db.cves.create_index("monitored_product")
    await db.cves.create_index("monitored_products")
    # Catalogue piloté par la base : domaines + produits surveillés (page « Produits surveillés »).
    # `default_key` est l'ancre d'idempotence du seed ; sparse car absente des produits personnalisés
    # hérités. Un même nom peut exister dans PLUSIEURS domaines -> pas d'unicité sur `name` seul.
    await db.monitored_products.create_index("default_key", unique=True, sparse=True)
    await db.monitored_products.create_index("name")
    await db.monitored_products.create_index("domain")
    await db.monitored_products.create_index("enabled")
    await db.domains.create_index("name", unique=True)
    # Messagerie interne (chat Admin ⇄ Consultant).
    await db.chat_conversations.create_index("consultant_id")
    await db.chat_conversations.create_index([("updated_at", -1)])
    await db.chat_messages.create_index([("conversation_id", 1), ("created_at", 1)])
    await db.chat_messages.create_index([("sender_role", 1), ("read", 1)])

