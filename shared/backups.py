from typing import Literal
from pydantic import Field, model_validator
from shared.models import StrictModel


class BackupPolicy(StrictModel):
    profile: str = Field(default='',max_length=80,pattern=r'^[a-zA-Z0-9_.-]*$')
    mode: Literal['live','stop-copy-start'] = 'live'
    schedule: Literal['manual','daily','weekly'] = 'manual'
    hour_utc: int = Field(default=3,ge=0,le=23)
    weekday: int = Field(default=6,ge=0,le=6)
    keep_daily: int = Field(default=7,ge=1,le=90)
    keep_weekly: int = Field(default=4,ge=0,le=52)
    enabled: bool = False

    @model_validator(mode='after')
    def configured(self):
        if self.enabled and not self.profile:
            raise ValueError('Enabled backups require an agent-approved profile')
        return self


class BackupPolicyEdit(StrictModel):
    revision: int = Field(ge=1)
    policy: BackupPolicy


class BackupAction(StrictModel):
    action: Literal['backup','restore','retention'] = 'backup'
    fingerprint: str = Field(pattern=r'^[a-f0-9]{64}$')
    snapshot: str = Field(default='',pattern=r'^(?:[a-f0-9]{64})?$')
    confirmed: bool = False


class AgentBackupRequest(StrictModel):
    profile: str = Field(min_length=1,max_length=80,pattern=r'^[a-zA-Z0-9_.-]+$')
    operation_id: str = Field(pattern=r'^[a-f0-9]{32}$')
    action: Literal['backup','restore','retention']
    fingerprint: str = Field(pattern=r'^[a-f0-9]{64}$')
    snapshot: str = Field(default='',pattern=r'^(?:[a-f0-9]{64})?$')
    documentation: str = Field(default='',max_length=100000)
    keep_daily: int = Field(default=7,ge=1,le=90)
    keep_weekly: int = Field(default=4,ge=0,le=52)
    confirmed: bool = False
    mode: Literal['live','stop-copy-start'] = 'live'
    retention_fingerprint: str = Field(default='',pattern=r'^(?:[a-f0-9]{64})?$')


class BackupInspection(StrictModel):
    operation_id: str = Field(pattern=r'^[a-f0-9]{32}$')
    confirmed: bool = False
