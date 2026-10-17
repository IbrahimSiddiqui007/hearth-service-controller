from __future__ import annotations

import hashlib
import asyncio
import base64
import codecs
import hmac
import json
import os
import platform
import re
import subprocess
import time
from pathlib import Path
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from agent.config_files import atomic_edit, editable
from agent.installation import inventory as installation_inventory
from agent.installation import docker_resources as installation_docker_resources
from shared.models import InstallationSnapshot
from agent.windows_observability import snapshot as windows_snapshot
from agent.software_inventory import snapshot as software_snapshot
from agent.macos import launchd_inventory, launchd_control
from agent.terminal import TerminalManager, TerminalOpen, TerminalInput
from agent.extra_runtimes import file_log, pm2_args, pm2_inventory, process_control, process_inventory
from agent.replay import ReplayGuard
from agent.log_stream import command_lines, file_lines
from shared.signatures import valid as valid_signature
from shared.binding import verified_listener
from agent.persistence import snapshot as persistence_snapshot
from agent.heartbeat import run as heartbeat_run, target as heartbeat_target
from agent.idle_activity import check as activity_check
from shared.configuration import secret_filename, secret_reasons
from agent.secret_scan import scan as scan_secrets
from agent.power import Power
from agent.backups import Backups
from agent.boot import Boot
from agent.listeners import inventory as listener_inventory
from agent.vault import check as check_vault,VaultCheck
from shared.boot import BootTarget,BootChange,BootInspection
from agent.host_files import read as read_host_file
from shared.backups import AgentBackupRequest, BackupInspection
from shared.power import PowerRequest, PowerAcknowledge
from shared.secret_findings import categories as secret_categories

from agent.observability import counter_cpu, docker_samples, metadata_path, process_sample, systemd_details

import psutil
import yaml
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse

from shared.models import CheckRequest, ControlRequest, FileWrite, LogsRequest, ScanOptions, redact


def command(args: list[str], timeout=15, env=None) -> str:
    """Fixed argument vectors only. Never pass shell=True or accept command strings."""
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace", env=env)
    except FileNotFoundError as exc:
        raise HTTPException(503, f"{args[0]} is not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(504, "Host operation timed out; inspect runtime state before retrying") from exc
    if result.returncode:
        raise HTTPException(502, redact(result.stderr[-2000:] or "Runtime command failed"))
    return result.stdout


def fingerprint(value: str):
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def safe_path(root: Path, relative: str) -> Path:
    if "\x00" in relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise HTTPException(403, "Path must be relative to an approved root")
    if root.is_symlink():
        raise HTTPException(403, "Configured root cannot be a symlink")
    root = root.resolve(strict=True)
    target = (root / relative).resolve(strict=True)
    if not target.is_relative_to(root):
        raise HTTPException(403, "Path escapes the approved service root")
    return target


def telemetry():
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage(Path.cwd().anchor or "/")
    network = psutil.net_io_counters()
    io = psutil.disk_io_counters()
    temperature = None
    if hasattr(psutil, "sensors_temperatures"):
        try:
            sensors = psutil.sensors_temperatures()
            readings = [item.current for group in sensors.values() for item in group if item.current is not None]
            temperature = round(max(readings), 1) if readings else None
        except (OSError, AttributeError):
            pass
    volumes = []
    seen_mounts = set()
    for partition in psutil.disk_partitions(all=False)[:40]:
        if partition.mountpoint in seen_mounts or partition.fstype.lower() in ('nfs', 'nfs4', 'cifs', 'smbfs', 'sshfs') or partition.device.startswith('\\\\'):
            continue
        seen_mounts.add(partition.mountpoint)
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            volumes.append({"mount": partition.mountpoint, "device": partition.device, "filesystem": partition.fstype,
                            "total_bytes": usage.total, "used_bytes": usage.used, "free_bytes": usage.free, "percent": usage.percent})
        except (OSError, PermissionError):
            continue
    interfaces = {}
    for name, counter in list(psutil.net_io_counters(pernic=True).items())[:40]:
        interfaces[name] = {"sent_bytes": counter.bytes_sent, "received_bytes": counter.bytes_recv}
    return {"volumes": volumes, "interfaces": interfaces, "cpu_percent": psutil.cpu_percent(interval=0.1), "memory_percent": memory.percent,
            "memory_total_gb": round(memory.total / 1024 ** 3, 1), "disk_percent": disk.percent,
            "disk_total_gb": round(disk.total / 1024 ** 3, 1), "temperature_c": temperature,
            "network_sent_bytes": network.bytes_sent, "network_recv_bytes": network.bytes_recv,
            "disk_read_bytes": io.read_bytes if io else None, "disk_write_bytes": io.write_bytes if io else None,
            "boot_time": psutil.boot_time(), "os": platform.system(), "architecture": platform.machine()}


def docker_inventory(config):
    listed = command(["docker", "ps", "-a", "--format", "{{.ID}}"])
    ids = listed.split()
    if not ids:
        return [], []
    # Batched inspect never passes names supplied by an unauthenticated caller.
    objects = []
    for index in range(0, len(ids), 100):
        objects.extend(json.loads(command(["docker", "inspect", *ids[index:index + 100]])))
    services, containers, projects = [], [], {}
    samples = docker_samples(command) if config.get("resource_samples", True) else {}
    allowed = config.get("allow_containers", [])
    for item in objects:
        name = item["Name"].lstrip("/")
        labels = item.get("Config", {}).get("Labels") or {}
        project = labels.get("com.docker.compose.project")
        raw_state = item.get("State", {}).get("Status", "unknown")
        status = {"exited": "stopped", "created": "stopped", "dead": "failed"}.get(raw_state, raw_state)
        if status not in ("running", "stopped", "restarting", "failed"):
            status = "unknown"
        ports = [f"{binding['HostPort']}/{port.split('/')[-1]}" for port, bindings in
                 (item.get("NetworkSettings", {}).get("Ports") or {}).items() for binding in (bindings or [])]
        row = {"agent_ref": "docker-" + fingerprint(name), "name": name, "runtime": "docker", "status": status,
               "description": "Container: " + item.get("Config", {}).get("Image", ""), "tags": ["discovered"],
               "ports": sorted(set(ports)), "urls": [], "paths": [m["Source"] for m in item.get("Mounts", []) if m.get("Source")],
               "dependencies": [], "control_handle": {"container": name},
               "capabilities": {"control": name in allowed, "logs": name in allowed, "files": False},
               "image": item.get("Config", {}).get("Image", ""), "project": project}
        row["runtime_details"] = {"started_at": item.get("State", {}).get("StartedAt"), "restart_count": item.get("RestartCount", 0),
                                  "health": (item.get("State", {}).get("Health") or {}).get("Status"),
                                  "restart_policy": item.get("HostConfig", {}).get("RestartPolicy", {}).get("Name", "no"),
                                  "image": row["image"], "container_working_directory": item.get("Config", {}).get("WorkingDir", "")}
        row["metrics"] = samples.get(name, {"cpu_percent": None, "memory_mb": None, "scope": "container unavailable"})
        row['secret_categories'] = secret_categories(item.get('Config', {}).get('Env') or [])
        row["locations"] = {"working_directory": item.get("Config", {}).get("WorkingDir", ""),
                            "configuration": [m["Source"] for m in item.get("Mounts", []) if m.get("Source") and str(m.get("Destination", "")).endswith((".yaml", ".yml", ".json", ".conf", ".ini", ".toml"))],
                            "data": [], "volumes": row["paths"], "logs": [item["LogPath"]] if item.get("LogPath") else []}
        containers.append(row)
        if project:
            projects.setdefault(project, []).append((row, labels))
        else:
            services.append(row)
    for name, members in projects.items():
        root = members[0][1].get("com.docker.compose.project.working_dir", "")
        configured_root = config.get("allow_projects", {}).get(name)
        authorized = bool(configured_root and root and Path(configured_root).resolve() == Path(root).resolve())
        states = {x[0]["status"] for x in members}
        status = "running" if states == {"running"} else "stopped" if states == {"stopped"} else "failed" if "failed" in states else "unknown"
        services.append({"agent_ref": "compose-" + fingerprint(name), "name": name, "runtime": "compose", "status": status,
                         "description": f"Compose project · {len(members)} containers", "tags": ["discovered"],
                         "ports": sorted(set(p for row, _ in members for p in row["ports"])), "urls": [],
                         "paths": [root] if root else [], "dependencies": [], "control_handle": {"project": name, "path": root},
                         "capabilities": {"control": authorized, "logs": authorized, "files": False},
                         "components": [row["name"] for row, _ in members]})
        services[-1]["images"] = sorted({row["image"] for row, _ in members})
        services[-1]['secret_categories'] = sorted({category for row, _ in members for category in row.get('secret_categories', [])})
        metrics = [row["metrics"] for row, _ in members]
        services[-1]["metrics"] = {"cpu_percent": round(sum(m["cpu_percent"] for m in metrics), 2) if all(m.get("cpu_percent") is not None for m in metrics) else None,
                                   "memory_mb": round(sum(m["memory_mb"] for m in metrics), 2) if all(m.get("memory_mb") is not None for m in metrics) else None, "scope": "Compose containers combined"}
        config_files = members[0][1].get("com.docker.compose.project.config_files", "").split(',')
        services[-1]["locations"] = {"working_directory": root, "configuration": [metadata_path(root, path) for path in config_files if path],
                                     "data": [], "volumes": sorted({p for row, _ in members for p in row["paths"]}), "logs": sorted({p for row, _ in members for p in row["locations"]["logs"]})}
        starts = [row["runtime_details"].get("started_at") for row, _ in members]
        services[-1]["runtime_details"] = {"started_at": max(starts) if all(starts) else None, "restart_count": sum(row["runtime_details"].get("restart_count", 0) for row, _ in members),
                                          "restart_policies": {row["name"]: row["runtime_details"]["restart_policy"] for row, _ in members}, "configuration": services[-1]["locations"]["configuration"]}
    return services, containers


def systemd_inventory(config, include_system=False):
    units = json.loads(command(["systemctl", "list-units", "--type=service", "--all", "--output=json", "--no-pager"]))
    loaded = {unit["unit"]: unit for unit in units}
    enabled = {}
    for line in command(["systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager", "--plain"]).splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] in ("enabled", "enabled-runtime", "linked", "linked-runtime"):
            enabled[parts[0]] = parts[1]
    hidden = ("systemd-", "dbus", "getty@", "serial-getty@", "snapd", "user@", "NetworkManager")
    rows = []
    names = [name for name in sorted(set(loaded) | set(enabled)) if include_system or not name.startswith(hidden) or name in config.get("allow_units", [])]
    details = systemd_details(command, names)
    for name in names:
        unit = loaded.get(name, {"unit": name, "active": "inactive", "description": name})
        if name.startswith(hidden) and name not in config.get("allow_units", []) and not include_system:
            continue
        state = {"active": "running", "inactive": "stopped", "failed": "failed", "activating": "restarting"}.get(unit.get("active"), "unknown")
        permitted = name in config.get("allow_units", [])
        rows.append({"agent_ref": "systemd-" + fingerprint(name), "name": name.removesuffix(".service"), "runtime": "systemd",
                     "status": state, "description": unit.get("description", ""), "tags": ["discovered"], "ports": [], "urls": [],
                     "paths": [], "dependencies": [], "control_handle": {"unit": name},
                     "capabilities": {"control": permitted, "logs": permitted, "files": False},
                     "runtime_details": {"enabled_state": enabled.get(name, "not enabled"), "loaded": name in loaded},
                     "system_unit": name.startswith(hidden)})
        detail = details.get(name, {})
        enabled_sampling = config.get("resource_samples", True)
        sampled = process_sample(detail.get("MainPID")) if enabled_sampling and detail.get("MainPID") not in (None, "0") else {"metrics": {"cpu_percent": None, "memory_mb": None, "scope": "unit unavailable" if enabled_sampling else "sampling disabled"}}
        metric = sampled["metrics"]
        if enabled_sampling and detail.get("MemoryCurrent", "").isdigit():
            metric["memory_mb"] = round(int(detail["MemoryCurrent"]) / 1024 ** 2, 2)
            metric["scope"] = "CPU main process; memory cgroup"
        if enabled_sampling and detail.get("CPUUsageNSec", "").isdigit():
            metric["cpu_percent"] = counter_cpu(('systemd', name, detail.get("ActiveEnterTimestampMonotonic")), int(detail["CPUUsageNSec"]) / 1e9)
            metric["scope"] = "systemd cgroup" if detail.get("MemoryCurrent", "").isdigit() else "CPU cgroup; memory main process"
        rows[-1]["metrics"] = metric
        rows[-1]["locations"] = {"working_directory": detail.get("WorkingDirectory", ""), "configuration": [value for value in [detail.get("FragmentPath", "")] + detail.get("DropInPaths", "").split() if value],
                                 "data": [], "volumes": [], "logs": ["journalctl --unit " + name]}
        rows[-1]["paths"] = rows[-1]["locations"]["configuration"]
        rows[-1]["runtime_details"].update(restart_policy=detail.get("Restart"), restart_count=int(detail["NRestarts"]) if detail.get("NRestarts", "").isdigit() else None,
                                           started_at=sampled.get("started_at"), configuration=rows[-1]["locations"]["configuration"], log_output=detail.get("StandardOutput"))
    return rows


def windows_inventory(config=None):
    rows = []
    if not hasattr(psutil, "win_service_iter"):
        return rows
    for service in psutil.win_service_iter():
        try:
            item = service.as_dict()
            rows.append({"agent_ref": "windows-" + fingerprint(item["name"]), "name": item["display_name"], "runtime": "windows",
                         "status": "running" if item["status"] == "running" else "stopped" if item["status"] == "stopped" else "unknown",
                         "description": item.get("description", ""), "tags": ["windows", "discovered"], "ports": [], "urls": [],
                         "paths": [], "dependencies": [], "control_handle": {"name": item["name"]},
                         "capabilities": {"control": False, "logs": False, "files": False}})
            enabled_sampling = (config or {}).get("resource_samples", True)
            sampled = process_sample(item.get("pid")) if enabled_sampling and item.get("pid") else {"metrics": {"cpu_percent": None, "memory_mb": None, "scope": "Windows service process unavailable" if enabled_sampling else "sampling disabled"}}
            rows[-1]["metrics"] = sampled["metrics"]
            rows[-1]["runtime_details"] = {"started_at": sampled.get("started_at"), "restart_count": None, "enabled_state": item.get("start_type", "unknown")}
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
    return rows


def create_agent(config: dict | None = None, token: str | None = None):
    config = config or {}
    token = token if token is not None else os.environ.get("PSC_AGENT_TOKEN", "")
    heartbeat_target(config)  # Validate opt-in configuration before starting.
    terminals = TerminalManager(config)
    @asynccontextmanager
    async def lifespan(app):
        def collect(include_inventory):
            payload = {'metrics': metrics()}
            if include_inventory:
                payload['inventory'] = scan(ScanOptions(include_system=True))
            return payload
        task = asyncio.create_task(heartbeat_run(config, token, collect)) if config.get('heartbeat_controller') else None
        async def reap_terminals():
            while True:
                await asyncio.sleep(2)
                try:
                    await asyncio.to_thread(terminals.sweep)
                except OSError:
                    pass  # Keep retrying owned-session cleanup; do not lose the janitor.
        terminal_task = asyncio.create_task(reap_terminals())
        try:
            yield
        finally:
            terminal_task.cancel()
            await asyncio.gather(terminal_task, return_exceptions=True)
            if task:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            await asyncio.to_thread(terminals.close_all)
    app = FastAPI(title="PSC Host Agent", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    log_followers = set()
    app.state.terminals = terminals
    signing_env = config.get('signing_key_env', '')
    replay = ReplayGuard(config.get('state_dir', '')) if signing_env else None
    if signing_env and len(os.environ.get(signing_env, '').encode()) < 32:
        raise ValueError('Configured request signing key is missing or too short')
    power = Power(config, replay, command)
    backups = Backups(config,replay,observer=lambda:scan(ScanOptions(include_system=True)))
    app.state.backups = backups
    boot = Boot(config,replay,command)

    @app.get('/host-files/profiles')
    def host_file_profiles():
        if not replay:raise HTTPException(403,'Host browsing requires signed transport')
        roots=config.get('host_browse_roots',{})
        if not isinstance(roots,dict) or len(roots)>8 or any(not isinstance(k,str) or not re.fullmatch(r'[a-zA-Z0-9_.-]{1,80}',k) or not isinstance(v,str) for k,v in roots.items()):raise HTTPException(409,'Invalid local host browse profiles')
        return {'profiles':list(roots),'physical_host_id':config.get('physical_host_id',''),'os':platform.system()}

    @app.get('/host-files')
    def host_file(profile:str=Query(max_length=80),path:str=Query(default='',max_length=4096)):
        host_file_profiles()
        try:return read_host_file(config,profile,path,replay.path.parent)
        except (FileNotFoundError,NotADirectoryError):raise HTTPException(404,'Host path not found')

    @app.post('/boot/plan')
    def boot_plan(body:BootTarget):return boot.plan(body)

    @app.post('/boot')
    def boot_change(body:BootChange):return boot.change(body)

    @app.post('/boot/acknowledge')
    def boot_acknowledge(body:BootInspection):return boot.acknowledge(body)

    @app.post('/vault/check')
    def vault_check(body:VaultCheck):
        if not replay:raise HTTPException(403,'Vault checks require signed transport')
        return check_vault(config,body)

    @app.get('/backups/profile')
    def get_backup_profile(name: str,keep_daily: int=Query(default=7,ge=1,le=90),keep_weekly: int=Query(default=4,ge=0,le=52)):
        return backups.plan(name,keep_daily,keep_weekly)

    @app.get('/backups/preview')
    def get_backup_preview(name: str,snapshot: str):
        import re
        if not re.fullmatch(r'[a-f0-9]{64}',snapshot):
            raise HTTPException(422,'Choose a full immutable snapshot ID')
        return backups.preview(name,snapshot)

    @app.post('/backups')
    def run_backup(body: AgentBackupRequest):
        return backups.request(body)

    @app.post('/backups/acknowledge')
    def acknowledge_backup(body: BackupInspection):
        return backups.acknowledge(body)

    @app.get('/backups/inspection')
    def inspect_backup(operation_id: str=Query(pattern=r'^[a-f0-9]{32}$')):
        return backups.inspection(operation_id)

    @app.get('/power/profile')
    def power_profile():
        return power.plan()

    @app.post('/power')
    def power_request(body: PowerRequest):
        return power.request(body)

    @app.post('/power/acknowledge')
    def power_acknowledge(body: PowerAcknowledge):
        return power.acknowledge(body)


    def runtime_command(argv, **kwargs):
        if argv and argv[0] == "pm2":
            kwargs["env"] = {**os.environ, "PM2_HOME": config.get("pm2_home", "")}
        return command(argv, **kwargs)

    @app.middleware("http")
    async def authenticate(request: Request, call_next):
        supplied = request.headers.get("authorization", "").removeprefix("Bearer ")
        if not token or not hmac.compare_digest(supplied.encode(), token.encode()):
            return JSONResponse({"detail": "Agent authentication required"}, status_code=401)
        if request.method not in ("GET", "HEAD") and request.headers.get("origin"):
            return JSONResponse({"detail": "Browser requests must go through the controller"}, status_code=403)
        if replay:
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 4_200_000:
                    return JSONResponse({'detail': 'Signed request exceeds size limit'}, status_code=413)
            request._body = bytes(body)
            target = request.scope.get('raw_path', request.url.path.encode()).decode('ascii')
            if request.scope.get('query_string'):
                target += '?' + request.scope['query_string'].decode('ascii')
            key = os.environ.get(signing_env, '')
            if not valid_signature(key, request.method, target, bytes(body), request.headers) or not replay.claim(request.headers.get('x-psc-nonce', ''), request.headers.get('x-psc-time', '')):
                return JSONResponse({'detail': 'Request signature invalid, expired, or replayed'}, status_code=401)
        return await call_next(request)

    @app.get("/health")
    def health():
        return {"status": "ok", "version": "0.1.0", "os": platform.system(), "architecture": platform.machine()}

    @app.get('/terminal/profiles')
    def terminal_profiles(ref: str):
        return {'profiles': terminals.profiles(ref), 'physical_host_id': config.get('physical_host_id', ''), 'os': platform.system()}

    @app.post('/terminal/open')
    def terminal_open(body: TerminalOpen):
        if not replay:
            raise HTTPException(403, 'Interactive terminals require signed agent requests and private replay state')
        return terminals.open(body)

    @app.get('/terminal/{identifier}/output')
    def terminal_output(identifier: str):
        return terminals.read(identifier)

    @app.post('/terminal/{identifier}/input')
    def terminal_input(identifier: str, body: TerminalInput):
        return terminals.input(identifier, body)

    @app.post('/terminal/{identifier}/close')
    def terminal_close(identifier: str):
        return terminals.close(identifier)

    @app.get("/telemetry")
    def metrics():
        return telemetry() | {"physical_host_id": config.get("physical_host_id", "")}

    @app.get("/inventory/windows")
    def windows_details():
        return windows_snapshot(config, command)

    @app.get('/inventory/software')
    def software_details():
        return windows_snapshot(config, command) if platform.system() == 'Windows' else software_snapshot(config, command)

    @app.get('/inventory/persistence')
    def persistence_details():
        return persistence_snapshot(config)

    @app.post('/idle/check')
    def idle_check(body: CheckRequest):
        profile = config.get('idle_checks', {}).get(body.profile)
        idle = activity_check(profile, command, body.timeout_s)
        return {'idle': idle, 'detail': 'Explicit configured activity profile' if idle is not None else 'Activity signal unavailable; automatic stopping is inhibited'}

    @app.post("/scan")
    def scan(options: ScanOptions):
        services, containers, warnings = [], [], []
        completed = []
        defaults = {'Linux': ['docker', 'systemd'], 'Windows': ['windows'], 'Darwin': ['launchd']}
        for runtime in config.get("discover", defaults.get(platform.system(), [])):
            try:
                if runtime == "docker":
                    found, containers = docker_inventory(config)
                    services.extend(found)
                    completed.extend(["docker", "compose"])
                elif runtime == "systemd" and platform.system() == "Linux":
                    services.extend(systemd_inventory(config, options.include_system))
                    completed.append("systemd")
                elif runtime == 'launchd' and platform.system() == 'Darwin':
                    services.extend(launchd_inventory(config, command, options.include_system))
                    completed.append('launchd')
                elif runtime == "windows" and platform.system() == 'Windows':
                    services.extend(windows_inventory(config))
                    completed.append("windows")
                elif runtime == "pm2":
                    services.extend(pm2_inventory(config, runtime_command))
                    completed.append("pm2")
                elif runtime == "process" and platform.system() in ('Linux', 'Darwin'):
                    services.extend(process_inventory(config))
                    completed.append("process")
            except (HTTPException, OSError, ValueError) as exc:
                warnings.append({"runtime": runtime, "detail": str(exc.detail) if isinstance(exc, HTTPException) else "Runtime discovery failed"})
        if config.get('listener_suggestions') is True:
            # Bounded suggestions and per-process permission gaps never establish
            # a complete process inventory or prove a previous process vanished.
            completed=[runtime for runtime in completed if runtime!='process']
            try:
                services.extend(listener_inventory(services))
            except (psutil.Error,OSError):
                completed=[runtime for runtime in completed if runtime!='process']
                warnings.append({'runtime':'process','detail':'Listening-process inventory unavailable; disappearance is unverified'})
        for row in services:
            findings = scan_secrets(config, row['agent_ref'], safe_path)
            row['secret_categories'] = sorted(set(row.get('secret_categories', []) + findings['categories']))
            row['secret_scan_scope'] = findings['scope']
            row["capabilities"]["files"] = row["agent_ref"] in config.get("file_roots", {})
            if row["agent_ref"] in config.get("log_files", {}):
                row["capabilities"]["logs"] = True
        return {"services": services, "containers": containers, "warnings": warnings, "completed_runtimes": completed,
                "systemd_scope": "all" if options.include_system else "user", "launchd_scope": "all" if options.include_system else "user", "os": platform.system()}

    @app.post('/installation/snapshot')
    def installation_snapshot(body: InstallationSnapshot):
        if body.ref not in config.get('installation_snapshot_refs', []):
            raise HTTPException(403, 'Installation snapshots require local approval')
        runtime = scan(ScanOptions(include_system=True))
        software = windows_snapshot(config, command) if platform.system() == 'Windows' else software_snapshot(config, command)
        resources = installation_docker_resources(command) if 'docker' in runtime.get('completed_runtimes', []) else None
        return installation_inventory(config, body.ref, runtime, software, resources) | {'os': platform.system(), 'physical_host_id': config.get('physical_host_id', '')}

    def args_for(request: ControlRequest, logs=False, stream=False):
        line_count = str(getattr(request, "lines", 300))
        handle = request.handle
        if request.runtime == "docker":
            name = handle.get("container", "")
            if not name or name not in config.get("allow_containers", []) or name.startswith("-"):
                raise HTTPException(403, "Container is not allow-listed on this agent")
            return ["docker", "logs", *(["--follow"] if stream else []), "--tail", line_count, "--timestamps", name] if logs else ["docker", request.action, name]
        if request.runtime == "compose":
            name = handle.get("project", "")
            root = config.get("allow_projects", {}).get(name)
            if not root or Path(root).resolve() != Path(handle.get("path", "")).resolve() or name.startswith("-"):
                raise HTTPException(403, "Compose project is not allow-listed on this agent")
            base = ["docker", "compose", "--project-directory", str(Path(root).resolve()), "--project-name", name]
            # Starting existing containers is intentionally distinct from deploying config.
            return base + (["logs", *(["--follow"] if stream else []), "--no-color", "--tail", line_count, "--timestamps"] if logs else [request.action])
        if request.runtime == "systemd":
            name = handle.get("unit", "")
            if name not in config.get("allow_units", []) or not name.endswith(".service") or name.startswith("-"):
                raise HTTPException(403, "Unit is not allow-listed on this agent")
            return ["journalctl", *(["--follow"] if stream else []), "--unit", name, "--lines", line_count, "--no-pager", "--output", "short-iso"] if logs else ["systemctl", "--no-ask-password", request.action, name]
        if request.runtime == "pm2":
            return pm2_args(config, handle, request.action, runtime_command, lines=int(line_count) if logs else None, stream=stream)
        raise HTTPException(409, "This runtime currently supports inventory only")

    @app.post("/control")
    def control(request: ControlRequest):
        if request.runtime == 'launchd':
            return {'output': launchd_control(config, request.handle, request.action, command), 'accepted': True}
        if request.runtime == "process":
            if not request.handle.get("name"):
                raise HTTPException(409, "Choose a configured process profile")
            return {"output": process_control(config, request.handle["name"], request.action), "accepted": True}
        argv = args_for(request)
        return {"output": redact(runtime_command(argv, timeout=45))[-12000:] if argv else "Application instance is already running", "accepted": True}

    @app.post("/logs")
    def logs(request: LogsRequest):
        ref = request.handle.get("agent_ref", "")
        if ref in config.get("log_files", {}):
            return {"content": file_log(config, ref, request.lines, safe_path), "redaction": "best-effort", "mode": "file snapshot"}
        return {"content": redact(runtime_command(args_for(request, logs=True)))[-100_000:], "redaction": "best-effort", "mode": "snapshot"}

    @app.post('/logs/stream')
    async def stream_logs(body: LogsRequest):
        ref = body.handle.get('agent_ref', '')
        is_file = ref in config.get('log_files', {})
        if is_file:
            from agent.extra_runtimes import approved_log
            approved_log(config, ref, safe_path)
            argv = []
        else:
            argv = await asyncio.to_thread(args_for, body, True, True)
        if len(log_followers) >= 4:
            raise HTTPException(429, 'Agent log follower limit reached')
        async def generate():
            ticket = object()
            if len(log_followers) >= 4:
                yield '{"kind":"error","content":"Agent log follower limit reached"}\n'
                return
            log_followers.add(ticket)
            source = file_lines(config, ref, safe_path, body.lines) if is_file else command_lines(argv,
                env={**os.environ, 'PM2_HOME': config['pm2_home']} if body.runtime == 'pm2' else None)
            try:
                async for row in source:
                    yield row
            except (HTTPException, OSError):
                yield '{"kind":"error","content":"Approved log source became unavailable"}\n'
            finally:
                await source.aclose()
                log_followers.discard(ticket)
        return StreamingResponse(generate(), media_type='application/x-ndjson', headers={'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no'})

    @app.get("/files")
    def files(ref: str, path: str = "", root_index: int = Query(0, ge=0), download: bool = False):
        roots = config.get("file_roots", {}).get(ref, [])
        if not isinstance(roots, list) or root_index >= len(roots):
            raise HTTPException(403, "No approved file root for this service")
        try:
            target = safe_path(Path(roots[root_index]), path)
            if target.is_dir():
                if download:
                    raise HTTPException(400, "Choose a file to download")
                entries = []
                for item in sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
                    if len(entries) >= 500:
                        break
                    if item.is_symlink():
                        continue
                    entries.append({"name": item.name, "directory": item.is_dir(), "size": item.stat().st_size if item.is_file() else None})
                return {"kind": "directory", "path": path, "entries": entries, "roots": roots, "readonly": True}
            if not target.is_file():
                raise HTTPException(415, "Only regular files can be read")
            size = target.stat().st_size
            lowered = target.name.lower()
            if secret_filename(target):
                raise HTTPException(403, "Secret-bearing file access is disabled")
            if download and size > 2_000_000:
                raise HTTPException(413, "Downloads are limited to 2 MB; large files have a read-only prefix preview")
            with target.open("rb") as stream:
                raw = stream.read(2_000_001)
            truncated = len(raw) > 2_000_000
            if download and truncated:
                raise HTTPException(413, "File grew beyond the 2 MB download limit")
            raw = raw[:2_000_000]
            try:
                content = codecs.getincrementaldecoder("utf-8")().decode(raw, final=not truncated)
                binary = "\x00" in content
            except UnicodeError:
                content, binary = "", True
            if download:
                payload = raw if binary else redact(content).encode("utf-8")
                return {"kind": "download", "path": path, "name": target.name, "binary": binary,
                        "data": base64.b64encode(payload).decode("ascii"), "readonly": True}
            if binary:
                return {"kind": "binary", "path": path, "size": size, "downloadable": size <= 2_000_000, "readonly": True}
            content = content.replace("\r\n", "\n").replace("\r", "\n")
            can_edit = editable(config, ref, target, content, truncated, platform.system(), Path(roots[root_index]) / path)
            return {"kind": "file", "path": path, "size": size, "content": redact(content), "truncated": truncated,
                    "downloadable": size <= 2_000_000, "readonly": not can_edit,
                    "editable": can_edit, "secret_excluded": bool(secret_reasons(content)), "validator_available": ref in config.get("config_validators", {}), "etag": hashlib.sha256(raw).hexdigest(), "resolved_path": str(target)}
        except (FileNotFoundError, NotADirectoryError) as exc:
            raise HTTPException(404, "File not found") from exc
        except PermissionError as exc:
            raise HTTPException(403, "Agent cannot read this path") from exc
        except UnicodeError as exc:
            raise HTTPException(415, "Only UTF-8 text previews are supported") from exc

    @app.put("/files")
    def edit_file(body: FileWrite, ref: str, path: str, root_index: int = Query(0, ge=0)):
        return atomic_edit(config, ref, root_index, path, body, safe_path, platform.system(), command)

    @app.get("/documents")
    def runtime_document(ref: str, path: str):
        target = Path(path)
        if not target.is_absolute():
            raise HTTPException(403, "Runtime documents need an absolute path within an approved root")
        for index, root in enumerate(config.get("file_roots", {}).get(ref, [])):
            try:
                relative = target.relative_to(Path(root))
                result = files(ref, str(relative), index, False)
                if result["kind"] != "file":
                    raise HTTPException(415, "Runtime configuration must be a UTF-8 text file")
                result["root_index"] = index
                return result
            except ValueError:
                continue
        raise HTTPException(403, "This configuration file is outside the approved file roots")

    @app.get("/checks")
    def check_profiles():
        return [{"id": key, "label": value.get("label", key)} for key, value in config.get("health_commands", {}).items() if isinstance(value, dict)]

    @app.post("/checks/run")
    def custom_check(body: CheckRequest):
        profile = config.get("health_commands", {}).get(body.profile)
        if not isinstance(profile, dict):
            raise HTTPException(403, "This health-check profile is not allowed by the agent")
        argv = profile.get("argv")
        if not isinstance(argv, list) or not argv or len(argv) > 30 or any(not isinstance(arg, str) or len(arg) > 1024 or "\x00" in arg for arg in argv):
            raise HTTPException(409, "Agent health profile needs a fixed argument list")
        started = time.perf_counter()
        try:
            timeout = min(body.timeout_s, max(1, min(15, int(profile.get("timeout_s", 5)))))
        except (ValueError, TypeError):
            raise HTTPException(409, "Agent profile timeout must be a number")
        try:
            output = command(argv, timeout=timeout)
            ok, detail = True, "Custom check passed" + (": " + redact(output[:1500]) if output.strip() else "")
        except HTTPException as exc:
            ok, detail = False, "Custom check failed: " + redact(str(exc.detail))
        return {"ok": ok, "detail": detail, "latency_ms": round((time.perf_counter() - started) * 1000, 1)}

    return app


def main():
    import argparse
    import uvicorn
    parser = argparse.ArgumentParser(description="PSC opt-in host agent")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8788, type=int)
    args = parser.parse_args()
    if not verified_listener(args.host):
        parser.error('Bind to loopback or an explicit Tailscale IP; wildcard, LAN and public listeners are refused')
    if hasattr(os, "getuid") and os.getuid() == 0:
        parser.error("Run the agent as a dedicated non-root user; grant only the required runtime permissions")
    if not os.environ.get("PSC_AGENT_TOKEN") or len(os.environ["PSC_AGENT_TOKEN"]) < 24:
        parser.error("Set PSC_AGENT_TOKEN to a random secret of at least 24 characters")
    config = yaml.safe_load(args.config.read_text(encoding="utf-8")) or {}
    uvicorn.run(create_agent(config), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
