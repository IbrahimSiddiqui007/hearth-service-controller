from typing import Literal
from pydantic import Field
from shared.models import StrictModel, Runtime


class BootTarget(StrictModel):
    runtime: Runtime
    handle: dict[str, str] = Field(max_length=8)


class BootChange(BootTarget):
    operation_id: str = Field(pattern=r'^[a-f0-9]{32}$')
    fingerprint: str = Field(pattern=r'^[a-f0-9]{64}$')
    policy: Literal['enabled', 'disabled', 'always', 'unless-stopped', 'on-failure', 'no']
    confirmed: bool = False


class BootReview(StrictModel):
    policy: Literal['enabled', 'disabled', 'always', 'unless-stopped', 'on-failure', 'no']
    fingerprint: str = Field(pattern=r'^[a-f0-9]{64}$')
    confirmed: bool = False


class BootInspection(StrictModel):
    operation_id: str = Field(pattern=r'^[a-f0-9]{32}$')
    confirmed: bool = False
