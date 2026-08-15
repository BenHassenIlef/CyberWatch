from fastapi import APIRouter, Depends, HTTPException, status
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from app.backend.core.security import create_access_token, hash_password, verify_password
from app.backend.db.mongodb import get_database
from app.backend.dependencies.auth import get_current_user
from app.backend.schemas.auth import (
    ProfileUpdateRequest,
    SignInRequest,
    SignUpRequest,
    TokenResponse,
    UserOut,
)
from app.backend.services.audit import log_action
from app.backend.utils import utcnow

router = APIRouter(prefix="/auth", tags=["auth"])


def _to_user_out(user: dict) -> UserOut:
    return UserOut(
        id=str(user["_id"]),
        full_name=user["full_name"],
        email=user["email"],
        role=user["role"],
        avatar_url=user.get("avatar_url"),
    )


@router.post("/signup", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def signup(payload: SignUpRequest):
    db = get_database()

    user_doc = {
        "full_name": payload.full_name,
        "email": payload.email.lower(),
        "hashed_password": hash_password(payload.password),
        "role": payload.role,
        "created_at": utcnow(),
    }

    try:
        result = await db.users.insert_one(user_doc)
    except DuplicateKeyError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "Un compte existe déjà avec cette adresse e-mail.")

    user_doc["_id"] = result.inserted_id

    await log_action(str(result.inserted_id), payload.role, "signup", {"email": payload.email})

    token = create_access_token(str(result.inserted_id), payload.role)
    return TokenResponse(access_token=token, user=_to_user_out(user_doc))


@router.post("/login", response_model=TokenResponse)
async def login(payload: SignInRequest):
    db = get_database()
    user = await db.users.find_one({"email": payload.email.lower(), "role": payload.role})

    if user is None or not verify_password(payload.password, user["hashed_password"]):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            "Adresse e-mail ou mot de passe incorrect.")

    await log_action(str(user["_id"]), user["role"], "login")

    token = create_access_token(str(user["_id"]), user["role"])
    return TokenResponse(access_token=token, user=_to_user_out(user))


@router.get("/me", response_model=UserOut)
async def me(user: dict = Depends(get_current_user)):
    return _to_user_out(user)


@router.patch("/me", response_model=UserOut)
async def update_me(payload: ProfileUpdateRequest, user: dict = Depends(get_current_user)):
    """Met à jour le nom et/ou la photo de l'utilisateur connecté (admin comme consultant)."""
    # exclude_unset : seuls les champs réellement envoyés sont pris en compte, ce qui permet de
    # distinguer « champ non fourni » (inchangé) de « avatar_url: null » (photo supprimée).
    updates = payload.model_dump(exclude_unset=True)

    to_set: dict = {}
    to_unset: dict = {}

    if "full_name" in updates:
        to_set["full_name"] = updates["full_name"]
    if "avatar_url" in updates:
        if updates["avatar_url"]:
            to_set["avatar_url"] = updates["avatar_url"]
        else:
            to_unset["avatar_url"] = ""

    if not to_set and not to_unset:
        return _to_user_out(user)

    operations: dict = {"$set": {**to_set, "updated_at": utcnow()}}
    if to_unset:
        operations["$unset"] = to_unset

    db = get_database()
    updated = await db.users.find_one_and_update(
        {"_id": user["_id"]}, operations, return_document=ReturnDocument.AFTER
    )
    if updated is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Ce compte utilisateur n'existe plus.")

    # On journalise les champs touchés, jamais le contenu de l'image (base64 volumineux).
    await log_action(str(user["_id"]), user["role"], "profile_update", {"fields": sorted(updates)})

    return _to_user_out(updated)
