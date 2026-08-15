from bson import ObjectId
from bson.errors import InvalidId
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.backend.core.security import decode_access_token
from app.backend.db.mongodb import get_database

bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> dict:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentification requise.")

    payload = decode_access_token(credentials.credentials)
    if payload is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            "Session expirée ou jeton invalide. Reconnectez-vous.")

    try:
        user_id = ObjectId(payload["sub"])
    except (InvalidId, KeyError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Jeton d'authentification invalide.")

    db = get_database()
    user = await db.users.find_one({"_id": user_id})
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Ce compte utilisateur n'existe plus.")

    return user


def require_role(role: str):
    async def dependency(user: dict = Depends(get_current_user)) -> dict:
        if user["role"] != role:
            libelle = {"admin": "administrateur", "consultant": "consultant"}.get(role, role)
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                f"Accès réservé au rôle {libelle}.")
        return user

    return dependency
