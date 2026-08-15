"""Chiffrement symétrique des secrets (API Key, Bearer, OAuth…).

Utilise Fernet (AES-128 en CBC + HMAC). La clé maître provient de `settings.credentials_key`
— jamais écrite dans le code source. Les secrets sont chiffrés au repos dans MongoDB et ne
sont déchiffrés que côté serveur, au moment de la collecte.
"""
from cryptography.fernet import Fernet, InvalidToken

from app.backend.core.config import settings

_fernet = Fernet(settings.credentials_key)


def encrypt(value: str) -> str:
    """Chiffre une chaîne en clair et renvoie un token texte (base64 urlsafe)."""
    return _fernet.encrypt(value.encode()).decode()


def decrypt(token: str) -> str | None:
    """Déchiffre un token. Renvoie None si le token est invalide/corrompu."""
    try:
        return _fernet.decrypt(token.encode()).decode()
    except (InvalidToken, ValueError):
        return None
