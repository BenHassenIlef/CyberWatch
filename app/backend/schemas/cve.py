from typing import Literal

from pydantic import BaseModel

Severity = Literal["low", "medium", "high", "critical"]
CveStatus = Literal["pending", "validated", "rejected"]


class ValidateCveRequest(BaseModel):
    status: Literal["validated", "rejected"]
