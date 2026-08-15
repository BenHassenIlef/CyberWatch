import re
from typing import Literal

from pydantic import BaseModel, EmailStr, Field, field_validator

Role = Literal["admin", "consultant"]

# La photo de profil est stockée en « data URI » base64 directement dans le document utilisateur :
# pas de stockage fichier ni de route statique à configurer. Le front redimensionne l'image à
# 256 px avant l'envoi (~20-40 Ko), la limite ci-dessous n'est qu'un garde-fou.
AVATAR_DATA_URI_RE = re.compile(r"^data:image/(png|jpeg|jpg|webp);base64,[A-Za-z0-9+/=]+$")
MAX_AVATAR_CHARS = 1_500_000


class SignUpRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    password: str = Field(min_length=6, max_length=128)
    role: Role = "admin"


class SignInRequest(BaseModel):
    email: EmailStr
    password: str
    role: Role = "admin"


class ProfileUpdateRequest(BaseModel):
    """Modification du profil par l'utilisateur connecté (admin ou consultant).

    Champ absent = inchangé. `avatar_url` à null ou "" = suppression de la photo.
    L'e-mail et le rôle ne sont pas modifiables ici (identifiant de connexion / habilitation).
    """

    full_name: str | None = Field(default=None, min_length=2, max_length=120)
    avatar_url: str | None = None

    @field_validator("full_name")
    @classmethod
    def _clean_full_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = " ".join(value.split())
        if len(cleaned) < 2:
            raise ValueError("Le nom doit contenir au moins 2 caractères")
        return cleaned

    @field_validator("avatar_url")
    @classmethod
    def _check_avatar(cls, value: str | None) -> str | None:
        if not value:  # None ou "" -> suppression de la photo
            return None
        if len(value) > MAX_AVATAR_CHARS:
            raise ValueError("Image trop volumineuse (max ~1 Mo après encodage)")
        if not AVATAR_DATA_URI_RE.match(value):
            raise ValueError("Format d'image invalide (attendu : data URI PNG, JPEG ou WebP)")
        return value


class UserOut(BaseModel):
    id: str
    full_name: str
    email: EmailStr
    role: Role
    avatar_url: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut
