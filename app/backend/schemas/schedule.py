from typing import Literal

from pydantic import BaseModel, Field

CollectionFrequency = Literal["hourly", "every_6h", "daily", "weekly"]


class CollectionScheduleUpdate(BaseModel):
    """Planification globale de la collecte, configurée par le Consultant."""

    frequency: CollectionFrequency = "daily"
    hour: int = Field(default=8, ge=0, le=23)
    minute: int = Field(default=0, ge=0, le=59)
