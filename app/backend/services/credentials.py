"""Stockage sécurisé des secrets d'authentification des sources.

Les secrets (API Key, Bearer, Basic, OAuth) sont chiffrés au repos (voir `core/crypto.py`)
dans la collection dédiée `source_credentials`. Ils ne sont **jamais** renvoyés au frontend
ni journalisés — seul l'état `api_key_configured` est exposé. Le déchiffrement n'a lieu que
côté serveur, au moment de la collecte.

Architecture remplaçable par un coffre de secrets externe (Vault, AWS Secrets Manager…) :
il suffit de réimplémenter `store_credential` / `get_credential`.
"""
from bson import ObjectId

from app.backend.core.crypto import decrypt, encrypt
from app.backend.db.mongodb import get_database
from app.backend.schemas.source import CredentialCreate
from app.backend.utils import utcnow


async def store_credential(source_id: ObjectId, cred: CredentialCreate) -> None:
    """Chiffre et enregistre (ou remplace) le secret d'une source."""
    db = get_database()
    await db.source_credentials.update_one(
        {"source_id": source_id},
        {
            "$set": {
                "source_id": source_id,
                "auth_type": cred.auth_type,
                "username": cred.username,
                "secret_encrypted": encrypt(cred.secret),
                "updated_at": utcnow(),
            }
        },
        upsert=True,
    )


async def has_credential(source_id: ObjectId) -> bool:
    db = get_database()
    return await db.source_credentials.count_documents({"source_id": source_id}) > 0


async def get_credential(source_id: ObjectId) -> dict | None:
    """Déchiffre et renvoie le secret — USAGE SERVEUR UNIQUEMENT (collecte)."""
    db = get_database()
    doc = await db.source_credentials.find_one({"source_id": source_id})
    if doc is None:
        return None
    return {
        "auth_type": doc["auth_type"],
        "username": doc.get("username"),
        "secret": decrypt(doc["secret_encrypted"]),
    }


async def delete_credential(source_id: ObjectId) -> None:
    db = get_database()
    await db.source_credentials.delete_one({"source_id": source_id})
