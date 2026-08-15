from typing import Literal

from pydantic import BaseModel, Field

# Méthode de collecte — détectée automatiquement, jamais choisie par l'admin.
CollectionMethod = Literal["api_public", "api_protected", "rss", "scraping"]
AuthenticationType = Literal["api_key", "bearer", "basic", "oauth"]
AuthenticationStatus = Literal["not_required", "configured", "missing"]
SourceStatus = Literal["pending", "validated", "rejected", "disabled"]
SyncFrequency = Literal["15min", "1h", "6h", "24h"]


class SourceCreate(BaseModel):
    """L'admin ne fournit que l'essentiel — la méthode et l'auth sont auto-détectées."""

    name: str = Field(min_length=2, max_length=160)
    url: str = Field(min_length=4, max_length=500)
    description: str | None = Field(default=None, max_length=1000)
    sync_frequency: SyncFrequency = "1h"


class SourceUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    url: str | None = None
    sync_frequency: SyncFrequency | None = None
    status: SourceStatus | None = None


class CredentialCreate(BaseModel):
    """Secret d'authentification saisi par l'admin — chiffré au repos, jamais renvoyé."""

    auth_type: AuthenticationType
    secret: str = Field(min_length=1, max_length=4096)
    username: str | None = Field(default=None, max_length=200)  # pour Basic Auth
