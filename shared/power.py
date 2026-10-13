from typing import Literal
from pydantic import Field
from shared.models import StrictModel


class PowerRequest(StrictModel):
    action: Literal['suspend', 'shutdown']
    operation_id: str = Field(pattern=r'^[a-f0-9]{32}$')
    fingerprint: str = Field(pattern=r'^[a-f0-9]{64}$')
    confirmed: bool = False


class PowerReview(StrictModel):
    action: Literal['suspend', 'shutdown']
    fingerprint: str = Field(pattern=r'^[a-f0-9]{64}$')
    confirmed: bool = False


class PowerAcknowledge(StrictModel):
    operation_id: str = Field(pattern=r'^[a-f0-9]{32}$')
    confirmed: bool = False
