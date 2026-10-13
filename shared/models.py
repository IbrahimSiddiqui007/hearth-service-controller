from __future__ import annotations

import re
import math
from collections import Counter
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

IDENTIFIER = r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$"
Runtime = Literal["docker", "compose", "systemd", "pm2", "process", "windows", "launchd"]
ServiceIcon = Literal["auto", "server", "game", "ai", "security", "monitoring", "network", "documents", "box"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class HealthCheck(StrictModel):
    enabled: bool = False
    type: Literal["http", "tcp", "icmp", "command"] = "http"
    target: str = Field(default="", max_length=1000)
    port: int | None = Field(default=None, ge=1, le=65535)
    interval_s: int = Field(default=60, ge=30, le=86400)
    timeout_s: int = Field(default=5, ge=1, le=15)

    @model_validator(mode="after")
    def valid_target(self):
        if not self.enabled:
            return self
        if not self.target:
            raise ValueError("An enabled check needs a target")
        if self.type == "http":
            parsed = urlsplit(self.target)
            if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
                raise ValueError("HTTP health targets must be HTTP(S) URLs without embedded credentials")
        elif self.type == "command":
            if not re.fullmatch(IDENTIFIER, self.target):
                raise ValueError("Custom checks select an agent profile ID, never a command string")
        elif self.type == "icmp":
            if not re.fullmatch(r"[a-zA-Z0-9:][a-zA-Z0-9.:-]{0,254}", self.target):
                raise ValueError("ICMP checks need a hostname or IP address")
        elif not self.port or any(c in self.target for c in ("/", "\\", " ", "\x00", "@")):
            raise ValueError("TCP checks need a hostname/IP and a port")
        return self


class CredentialPointer(StrictModel):
    label: str = Field(min_length=1, max_length=100)
    username: str = Field(default="", max_length=200)
    vault_ref: str = Field(default="", max_length=1000)
    hint: str = Field(default="", max_length=1000)

    @model_validator(mode="after")
    def no_literal_secrets(self):
        if any(redact(value) != value for value in (self.label, self.username, self.vault_ref, self.hint)):
            raise ValueError("Use vault references and location hints, not secret assignments")
        return self

    @field_validator("vault_ref")
    @classmethod
    def safe_reference(cls, value):
        if value and not re.fullmatch(r"[a-zA-Z0-9_-]{1,100}", value):
            parsed = urlsplit(value)
            if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
                raise ValueError("Use a vault item ID or an HTTP(S) vault link without credentials")
        return value


class FileLocations(StrictModel):
    working_directory: str = Field(default="", max_length=1024)
    configuration: list[str] = Field(default_factory=list, max_length=30)
    data: list[str] = Field(default_factory=list, max_length=30)
    volumes: list[str] = Field(default_factory=list, max_length=50)
    logs: list[str] = Field(default_factory=list, max_length=30)

    @field_validator("working_directory")
    @classmethod
    def safe_working_directory(cls, value):
        if "\x00" in value:
            raise ValueError("Working directory cannot contain NUL bytes")
        return value

    @field_validator("configuration", "data", "volumes", "logs")
    @classmethod
    def safe_paths(cls, value):
        if any(not item or len(item) > 1024 or "\x00" in item for item in value):
            raise ValueError("Locations must be nonempty paths under 1024 characters")
        return list(dict.fromkeys(value))


class IdlePolicy(StrictModel):
    enabled: bool = False
    profile: str = Field(default='', max_length=80, pattern=r'^[a-zA-Z0-9_.-]*$')
    minutes: int = Field(default=30, ge=5, le=1440)
    component_profiles: dict[str, str] = Field(default_factory=dict, max_length=8)

    @field_validator('component_profiles')
    @classmethod
    def fixed_component_profiles(cls, value):
        if any(not re.fullmatch(IDENTIFIER, key) or not re.fullmatch(IDENTIFIER, profile) for key, profile in value.items()):
            raise ValueError('Component activity checks select service IDs and agent profile IDs')
        return value

    @model_validator(mode='after')
    def configured_profile(self):
        if self.enabled and not self.profile:
            raise ValueError('Auto-stop needs an explicit agent activity-check profile')
        return self


class ServiceDocumentation(StrictModel):
    installation: str = Field(default='', max_length=15000)
    backup_plan: str = Field(default='', max_length=15000)
    recovery: str = Field(default='', max_length=15000)

    @model_validator(mode='after')
    def prose_only(self):
        for value in (self.installation, self.backup_plan, self.recovery):
            if redact(value) != value or '<!-- psc:notes:' in value:
                raise ValueError('Use documentation and vault references, not secret values or reserved sync markers')
        return self


class ScheduleRule(StrictModel):
    action: Literal['start', 'stop']
    cron: str = Field(min_length=9, max_length=100)

    @field_validator('cron')
    @classmethod
    def supported_cron(cls, value):
        from shared.schedules import parse
        parse(value)
        return ' '.join(value.split())


class SchedulePolicy(StrictModel):
    enabled: bool = False
    timezone: str = Field(default='UTC', min_length=1, max_length=100)
    acknowledge_components: bool = False
    rules: list[ScheduleRule] = Field(default_factory=list, max_length=8)

    @field_validator('timezone')
    @classmethod
    def known_timezone(cls, value):
        from shared.schedules import zone
        zone(value)
        return value

    @model_validator(mode='after')
    def configured(self):
        if self.enabled and not self.rules:
            raise ValueError('Enable schedules only with explicit start/stop rules')
        if len({row.cron for row in self.rules}) != len(self.rules):
            raise ValueError('Duplicate cron expressions are ambiguous')
        return self


class ScheduleEdit(StrictModel):
    revision: int = Field(ge=1)
    policy: SchedulePolicy


class ServiceDefinition(StrictModel):
    schedule_policy: SchedulePolicy = Field(default_factory=SchedulePolicy)
    documentation: ServiceDocumentation = Field(default_factory=ServiceDocumentation)
    idle_policy: IdlePolicy = Field(default_factory=IdlePolicy)
    component_ids: list[str] = Field(default_factory=list, max_length=30)
    id: str = Field(pattern=IDENTIFIER)
    host_id: str = Field(pattern=IDENTIFIER)
    name: str = Field(min_length=1, max_length=100)
    runtime: Runtime
    icon: ServiceIcon = "auto"
    description: str = Field(default="", max_length=2000)
    tags: list[str] = Field(default_factory=list, max_length=20)
    ports: list[str] = Field(default_factory=list, max_length=30)
    urls: list[str] = Field(default_factory=list, max_length=10)
    paths: list[str] = Field(default_factory=list, max_length=30)
    locations: FileLocations = Field(default_factory=FileLocations)
    track_configuration: bool = False
    config_capture_interval_s: int = Field(default=300, ge=60, le=86400)
    dependencies: list[str] = Field(default_factory=list, max_length=30)
    control_handle: dict[str, str] = Field(default_factory=dict)
    notes: str = Field(default="", max_length=100_000)
    health_check: HealthCheck | None = None
    credentials: list[CredentialPointer] = Field(default_factory=list, max_length=30)

    @field_validator("notes")
    @classmethod
    def safe_note_markers(cls, value):
        if "<!-- psc:notes:start -->" in value or "<!-- psc:notes:end -->" in value:
            raise ValueError("Owner notes cannot contain reserved Obsidian sync markers")
        return value

    @field_validator("urls")
    @classmethod
    def safe_urls(cls, value):
        for url in value:
            parsed = urlsplit(url)
            if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
                raise ValueError("Service URLs must be HTTP(S), without credentials")
        return value

    @field_validator("tags", "ports", "paths", "dependencies", "component_ids")
    @classmethod
    def bounded_strings(cls, value):
        if any(len(item) > 1024 or "\x00" in item for item in value):
            raise ValueError("List entries must be under 1024 characters and contain no NUL bytes")
        return list(dict.fromkeys(value))

    @field_validator("control_handle")
    @classmethod
    def handle_fields(cls, value):
        allowed = {"container", "project", "path", "unit", "name", "agent_ref", "pm_id", "domain", "plist_hash"}
        if set(value) - allowed or any(len(v) > 1024 or "\x00" in v for v in value.values()):
            raise ValueError("Unsupported control handle; arbitrary commands and credentials are not allowed")
        return value


class HostDefinition(StrictModel):
    signing_env: str = Field(default="", max_length=100)
    physical_host_id: str = Field(default="", max_length=80, pattern=r"^[a-zA-Z0-9_.-]*$")
    monitoring_urls: list[str] = Field(default_factory=list, max_length=10)
    @field_validator("monitoring_urls")
    @classmethod
    def monitoring_links(cls, value):
        ServiceDefinition.safe_urls(value)
        if any(redact(url) != url for url in value):
            raise ValueError("Monitoring links must not embed secret values")
        return value

    id: str = Field(pattern=IDENTIFIER)
    name: str = Field(min_length=1, max_length=100)
    address: str = Field(default="", max_length=255)
    os: str = Field(default="Linux", max_length=80)
    architecture: str = Field(default="", max_length=40)
    agent_url: str = Field(default="", max_length=500)
    token_env: str = Field(default="", max_length=100)

    @field_validator("agent_url")
    @classmethod
    def safe_agent_url(cls, value):
        if value:
            parsed = urlsplit(value)
            if (parsed.scheme not in ("http", "https") or not parsed.hostname or
                    parsed.username or parsed.password or parsed.query or parsed.fragment or
                    parsed.path not in ("", "/")):
                raise ValueError("Agent URL must be an HTTP(S) origin without credentials, path, query, or fragment")
        return value.rstrip("/")

    @field_validator("token_env", "signing_env")
    @classmethod
    def env_name(cls, value):
        if value and not re.fullmatch(r"PSC_AGENT_[A-Z0-9_]+", value):
            raise ValueError("Token references must be environment variable names starting PSC_AGENT_")
        return value


class Manifest(StrictModel):
    version: Literal[1] = 1
    hosts: list[HostDefinition] = Field(default_factory=list, max_length=100)
    services: list[ServiceDefinition] = Field(default_factory=list, max_length=1000)

    @model_validator(mode="after")
    def unique_ids(self):
        for records in (self.hosts, self.services):
            ids = [row.id.casefold() for row in records]
            if len(ids) != len(set(ids)):
                raise ValueError("Duplicate IDs in manifest")
        return self


class ManifestInput(StrictModel):
    content: str = Field(min_length=1, max_length=1_000_000)


class ServiceEdit(StrictModel):
    documentation: ServiceDocumentation | None = None
    idle_policy: IdlePolicy | None = None
    component_ids: list[str] | None = Field(default=None, max_length=30)
    locations: FileLocations | None = None
    track_configuration: bool | None = None
    config_capture_interval_s: int | None = Field(default=None, ge=60, le=86400)
    name: str | None = Field(default=None, min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=2000)
    tags: list[str] | None = Field(default=None, max_length=20)
    notes: str | None = Field(default=None, max_length=100_000)
    icon: ServiceIcon | None = None
    host_id: str | None = Field(default=None, pattern=IDENTIFIER)
    dependencies: list[str] | None = Field(default=None, max_length=30)
    revision: int = Field(ge=1)

    @field_validator("tags", "dependencies", "component_ids")
    @classmethod
    def bounded_entries(cls, value):
        if value is not None and any(not item or len(item) > 100 or "\x00" in item for item in value):
            raise ValueError("Entries must contain 1–100 characters and no NUL bytes")
        return list(dict.fromkeys(value)) if value is not None else None


class ScanOptions(StrictModel):
    include_system: bool = False


class InstallationSnapshot(StrictModel):
    ref: str = Field(min_length=1, max_length=255)


class CheckRequest(StrictModel):
    profile: str = Field(pattern=IDENTIFIER)
    timeout_s: int = Field(default=5, ge=1, le=15)


class TerminalInput(StrictModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=False)
    data: str = Field(default='', max_length=8192)
    rows: int | None = Field(default=None, ge=5, le=100)
    cols: int | None = Field(default=None, ge=20, le=240)


class IncidentNote(StrictModel):
    note: str = Field(min_length=1, max_length=30_000)
    incident_id: int | None = Field(default=None, ge=1)
    source: Literal["owner", "ai"] = "owner"
    model: str = Field(default="", max_length=100)


class IncidentEdit(StrictModel):
    cause: str = Field(max_length=2000)


class LogsRequest(StrictModel):
    runtime: Runtime
    handle: dict[str, str]
    action: Literal["start", "stop", "restart"] = "start"
    lines: int = Field(default=300, ge=1, le=5000)


class AISettings(StrictModel):
    enabled: bool = True
    endpoint: str = Field(default="", max_length=500)
    model: str = Field(default="", max_length=100)
    timeout_s: int = Field(default=60, ge=5, le=180)
    context_lines: int = Field(default=200, ge=10, le=1000)

    @field_validator("endpoint")
    @classmethod
    def safe_endpoint(cls, value):
        if value:
            parsed = urlsplit(value)
            if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
                raise ValueError("Use an HTTP(S) origin without credentials, paths, or query parameters")
        return value.rstrip("/")


class HealthEdit(StrictModel):
    check: HealthCheck
    revision: int = Field(ge=1)


class CredentialEdit(StrictModel):
    credentials: list[CredentialPointer] = Field(max_length=30)
    revision: int = Field(ge=1)


class SecretFindingReview(StrictModel):
    revision: int = Field(ge=1)
    pointer: CredentialPointer


class ControlRequest(StrictModel):
    runtime: Runtime
    handle: dict[str, str]
    action: Literal["start", "stop", "restart"]


class FileWrite(StrictModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)
    content: str = Field(max_length=2_000_000)
    etag: str = Field(min_length=1, max_length=100)
    validate_runtime: bool = False


SECRET_PATTERN = re.compile(
    r"(?im)((?:[\w.-]*(?:password|passwd|token|secret|api[_-]?key)[\w.-]*)\s*[:=]\s*)([^\r\n]+)"
)


def redact(text: str) -> str:
    """Best-effort display redaction, not a guarantee of complete secret detection."""
    def assignment(match):
        value = match.group(2).strip()
        if re.fullmatch(r"[\"']?\$\{[A-Z_][A-Z0-9_]*\}[\"']?", value):
            return match.group(0)
        return match.group(1) + "[REDACTED]"
    text = SECRET_PATTERN.sub(assignment, text)
    text = re.sub(r'-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z ]+ )?PRIVATE KEY-----|\Z)', '[REDACTED private key material]', text)
    text = re.sub(r'\b(?:ghp_|github_pat_|sk-proj-)[a-zA-Z0-9_-]{16,}', '[REDACTED credential token]', text)
    def entropy_candidate(match):
        value = match.group(0)
        if re.fullmatch(r'[a-fA-F0-9]+', value) or not (any(c.isupper() for c in value) and any(c.islower() for c in value) and any(c.isdigit() for c in value)):
            return value
        entropy = -sum(count / len(value) * math.log2(count / len(value)) for count in Counter(value).values())
        return '[REDACTED possible credential]' if entropy >= 4.6 else value
    text = re.sub(r'(?<![\w/-])[a-zA-Z0-9+/=_-]{40,}(?![\w/-])', entropy_candidate, text)
    text = re.sub(r"(?i)(authorization\s*:\s*)([^\r\n]+)", r"\1[REDACTED]", text)
    return re.sub(r"(?i)(https?://)[^\s/@:]+:[^\s/@]+@", r"\1[REDACTED]@", text)


def mask_metadata(value, depth=0):
    """Mask observed prose before persistence; callers separately validate identity."""
    if depth > 20:
        return '[OMITTED deeply nested metadata]'
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [mask_metadata(item, depth + 1) for item in value]
    if isinstance(value, dict):
        return {key: '[REDACTED]' if re.fullmatch(r'(?i)(password|passwd|secret|token|api[_-]?key|authorization)', str(key)) else mask_metadata(item, depth + 1) for key, item in value.items()}
    return value


class ConfigEdit(FileWrite):
    path: str = Field(min_length=1, max_length=1024)
    root_index: int = Field(default=0, ge=0, le=99)
    message: str = Field(default="Configuration edited", min_length=1, max_length=500)


class ConfigRestore(StrictModel):
    version_id: int = Field(ge=1)
    path: str = Field(min_length=1, max_length=1024)
    root_index: int = Field(default=0, ge=0, le=99)
    etag: str = Field(min_length=1, max_length=100)
    validate_runtime: bool = False


class NotificationSettings(StrictModel):
    enabled: bool = False
    channel: Literal["ntfy", "telegram"] = "ntfy"
    endpoint: str = Field(default="", max_length=500)
    topic: str = Field(default="", max_length=120, pattern=r"^[a-zA-Z0-9_-]*$")
    token_env: str = Field(default="", max_length=100, pattern=r"^(PSC_NOTIFY_[A-Z0-9_]+)?$")
    chat_id: str = Field(default="", max_length=100, pattern=r"^(-?[0-9]+|@[a-zA-Z0-9_]+)?$")
    restart_threshold: int = Field(default=3, ge=2, le=20)
    restart_window_s: int = Field(default=300, ge=60, le=3600)
    endpoint_validator = field_validator("endpoint")(classmethod(AISettings.safe_endpoint.__func__))


class TelemetryPolicy(StrictModel):
    enabled: bool = False
    cpu_percent: float = Field(default=90, ge=1, le=100)
    memory_percent: float = Field(default=90, ge=1, le=100)
    disk_percent: float = Field(default=90, ge=1, le=100)
    temperature_c: float = Field(default=80, ge=1, le=150)
    sustained_samples: int = Field(default=3, ge=1, le=10)
