"""Schémas de la CONFIGURATION DE SURVEILLANCE (domaines + produits surveillés).

L'admin gère ces objets ; la collecte les charge dynamiquement (aucun code à modifier pour
ajouter un produit). Le champ `history_days` (à la création) déclenche une collecte HISTORIQUE
ciblée du produit (0 = à partir de maintenant)."""
from typing import Literal

from pydantic import BaseModel, Field

HistoryWindow = Literal[0, 7, 30, 90]


class DomainCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    description: str | None = Field(default=None, max_length=500)
    enabled: bool = True


class DomainUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    description: str | None = Field(default=None, max_length=500)
    enabled: bool | None = None


class ProductCreate(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    vendor: str | None = Field(default=None, max_length=160)
    domain: str = Field(min_length=2, max_length=120)
    aliases: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)
    cpes: list[str] = Field(default_factory=list)
    enabled: bool = True
    history_days: HistoryWindow = 0   # 0 = surveiller à partir de maintenant


class ProductUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=160)
    vendor: str | None = Field(default=None, max_length=160)
    domain: str | None = Field(default=None, min_length=2, max_length=120)
    aliases: list[str] | None = None
    keywords: list[str] | None = None
    cpes: list[str] | None = None
    enabled: bool | None = None
