from __future__ import annotations

import asyncio
import base64
import hashlib
import difflib
import hmac
import json
import os
import re
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import Field

from controller.demo import illustrative_telemetry, seed
from controller.dependencies import startup_order, validate_dependencies
from controller.groups import component_suggestions, group_plan, validate_groups
from controller.login import COOKIE, OwnerLogin
from controller.terminals import Terminals
from controller.idle import observe as idle_observe
from controller.schedules import Scheduler, fingerprint as schedule_fingerprint, preflight as schedule_preflight
from shared.models import ScheduleEdit, SchedulePolicy
from shared.schedules import preview as schedule_preview
from controller.heartbeats import liveness as heartbeat_liveness
from controller.persistence import verified as verified_persistence, view as persistence_view, demo_snapshot as persistence_demo
from controller.discovery import due as discovery_due, get_scan, proposals, save_scan, snapshot
from controller.ai import availability as ai_availability, configuration as ai_configuration, explain as ai_explain
from controller.health import check_key, history as health_history, latest as latest_health, probe, record as record_health
from controller.manifests import apply_manifest, parse_manifest, plan_manifest
from controller.obsidian import export_zip, service_note, sync_vault
from controller.store import Store, now
from controller.audit import AuditJournal
from controller.config_history import capture_due, file_key, snapshot as config_snapshot, version as config_version
from shared.configuration import secret_filename, secret_reasons, validate_configuration
from shared.models import SecretFindingReview
from controller.secret_findings import record as record_secrets, listing as list_secrets
from controller.notifications import config_key as notification_key, enqueue as queue_notification, flush as flush_notifications, settings as notification_settings
from controller.telemetry import rates as telemetry_rates, thresholds as telemetry_thresholds
from controller.windows_inventory import demo_snapshot as windows_demo, verified as verify_windows
from shared.software_guides import guides as software_guides
from shared.signatures import headers as signed_headers, valid as valid_signature, frame_signature, WINDOW as SIGNATURE_WINDOW
from shared.streams import frame as log_frame
from shared.models import AISettings, ConfigEdit, ConfigRestore, IdlePolicy, NotificationSettings, TelemetryPolicy, CredentialEdit, HealthCheck, HealthEdit, HostDefinition, IncidentEdit, IncidentNote, ManifestInput, ScanOptions, ServiceDefinition, ServiceEdit, StrictModel, redact, mask_metadata

ROOT = Path(__file__).resolve().parents[1]


class ManifestApply(ManifestInput):
    fingerprint: str


class DiscoveryAccept(StrictModel):
    scan_id: str
    refs: list[str] = Field(max_length=1000)


class Action(StrictModel):
    action: str = Field(pattern="^(start|stop|restart)$")
    acknowledge_dependencies: bool = False
    start_dependencies: bool = False
    acknowledge_components: bool = False


class ExplainRequest(StrictModel):
    selected_logs: str = Field(default="", max_length=30_000)


class InventoryReview(StrictModel):
    fingerprint: str = Field(pattern=r'^[a-f0-9]{64}$')


def create_app(data_dir: Path | None = None, demo=False, token: str | None = None, background=True, port=8787):
    store = Store(data_dir or ROOT / "data" / ("demo" if demo else "live"))
    if demo:
        seed(store)
        illustrative_telemetry(store)
    token = os.environ.get("PSC_TOKEN", "") if token is None else token
    owner_login = OwnerLogin(store, enabled=not demo)
    terminal_coordinator = None
    lock = asyncio.Lock()
    config_lock = asyncio.Lock()
    config_capturing = set()
    health_running = set()
    inventory_running = set()
    log_followers = set()
    event_followers = set()
    state_followers = set()
    idle_running = set()
    heartbeat_channels = set()
    allowed_origins = {"http://localhost:8787", "http://127.0.0.1:8787", "http://localhost:5173", "http://127.0.0.1:5173"}
    allowed_origins.update((f"http://localhost:{port}", f"http://127.0.0.1:{port}", f"http://[::1]:{port}"))
    allowed_origins.update(x.strip() for x in os.environ.get("PSC_ORIGINS", "").split(",") if x.strip())
    allowed_hosts = {"localhost", "127.0.0.1", "::1", "testserver"}
    allowed_hosts.update(urlsplit(x).hostname for x in allowed_origins)

    async def agent_request(host, method, path, payload=None, timeout=12):
        if demo:
            raise HTTPException(409, "Demo workspace never connects to agents")
        if not host.get("agent_url"):
            raise HTTPException(409, "Configure this host's agent URL first")
        secret = os.environ.get(host.get("token_env", ""), "")
        if not secret:
            raise HTTPException(409, "Agent token environment variable is not configured")
        headers = {"Authorization": "Bearer " + secret}
        if host.get('signing_env'):
            prepared = httpx.Request(method, host['agent_url'] + path, json=payload)
            try:
                headers.update(signed_headers(os.environ.get(host['signing_env'], ''), method, prepared.url.raw_path.decode('ascii'), prepared.content))
            except ValueError as exc:
                raise HTTPException(409, 'Agent signing key environment variable is missing or too short') from exc
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, trust_env=False) as client:
                response = await client.request(method, host["agent_url"] + path, json=payload,
                                                headers=headers)
            if len(response.content) > 4_000_000:
                raise HTTPException(502, "Agent response exceeds the supported size limit")
            if response.status_code >= 400:
                try:
                    detail = response.json().get("detail", "Agent request failed")
                except ValueError:
                    detail = "Agent request failed"
                raise HTTPException(response.status_code, redact(str(detail)))
            if response.status_code >= 300:
                raise HTTPException(502, "Agent redirects are not accepted")
            return response.json()
        except httpx.TimeoutException as exc:
            raise HTTPException(504, "Agent timed out; operation outcome may be unknown") from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise HTTPException(503, "Agent unreachable or returned an invalid response") from exc

    def agent_headers(host, method, path, payload=None):
        secret = os.environ.get(host.get('token_env', ''), '')
        if not host.get('agent_url') or not secret:
            raise HTTPException(409, 'Configure the agent URL and token environment reference first')
        headers = {'Authorization': 'Bearer ' + secret}
        if host.get('signing_env'):
            prepared = httpx.Request(method, host['agent_url'] + path, json=payload)
            try:
                headers.update(signed_headers(os.environ.get(host['signing_env'], ''), method, prepared.url.raw_path.decode('ascii'), prepared.content))
            except ValueError as exc:
                raise HTTPException(409, 'Agent signing key environment variable is missing or too short') from exc
        return headers

    def record_host_metrics(hid, metrics, expected, transport="polling"):
        if not isinstance(metrics, dict) or metrics.get('os') is not None and (not isinstance(metrics['os'], str) or len(metrics['os']) > 80):
            raise HTTPException(502, 'Invalid host telemetry')
        if expected.get('physical_host_id') and metrics.get('physical_host_id') != expected['physical_host_id']:
            raise HTTPException(409, 'Agent physical-host identity does not match this registration')
        current_host = require("hosts", hid)
        if any(current_host.get(key) != expected.get(key) for key in ("agent_url", "token_env", "signing_env", "physical_host_id")):
            raise HTTPException(409, "Host connection changed during telemetry; refresh again")
        host = current_host
        previous = host.get("status")
        previous_os = host.get("active_os")
        host.update(status="online", last_seen=now(), transport=transport, error=None, active_os=metrics.get("os", host.get("os")))
        host["identity_verified"] = bool(host.get("physical_host_id") and metrics.get("physical_host_id") == host["physical_host_id"])
        if previous_os and previous_os != host["active_os"]:
            for item in store.all("services"):
                if item["host_id"] == hid:
                    item.update(status="unknown", capabilities={"control": False, "logs": False, "files": False})
                    store.put("services", item)
            host["os_history"] = (host.get("os_history", []) + [{"os": previous_os, "ended_at": now()}])[-10:]
            store.audit("host.os_changed", "success", "Observed active OS changed; previous runtime access cleared", host_id=hid)
        store.put("hosts", host)
        with store.connection() as db:
            timestamp = now()
            previous_sample = db.execute("SELECT ts,body FROM telemetry WHERE host_id=? ORDER BY id DESC LIMIT 1", (hid,)).fetchone()
            metrics = telemetry_rates(metrics, json.loads(previous_sample["body"]) if previous_sample else None, timestamp, previous_sample["ts"] if previous_sample else None)
            db.execute("INSERT INTO telemetry(host_id,ts,body) VALUES(?,?,?)", (hid, timestamp, json.dumps(mask_metadata(metrics))))
            cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
            db.execute("DELETE FROM telemetry WHERE ts < ?", (cutoff,))
        for event in telemetry_thresholds(host, metrics):
            state = "high" if event["active"] else "recovered"
            message = host["name"] + ": " + event["metric"] + " " + state + " (" + str(event["value"]) + "; threshold " + str(event["threshold"]) + ")"
            store.audit("telemetry." + state, "warning" if event["active"] else "success", message, host_id=hid)
            queue_notification(store, "telemetry:" + hid + ":" + event["metric"] + ":" + now(), message)
        store.put("hosts", host)
        if previous != "online":
            store.audit("host.online", "success", "Agent connected", host_id=hid)
        return host

    async def refresh_host(hid):
        host = require("hosts", hid)
        if demo:
            return host
        try:
            metrics = await agent_request(host, "GET", "/telemetry")
            if not isinstance(metrics, dict):
                raise HTTPException(502, "Agent returned invalid telemetry")
            if host.get("physical_host_id") and metrics.get("physical_host_id") != host["physical_host_id"]:
                raise HTTPException(409, "Agent physical-host identity does not match this registration")
            async with lock:
                host = record_host_metrics(hid, metrics, host)
            try:
                result = await agent_request(host, "POST", "/scan", {"include_system": True}, timeout=30)
                async with lock:
                    update_observations(hid, result)
            except HTTPException:
                # Telemetry proved the agent is online. A missing runtime must
                # not turn a connected host into an offline host.
                pass
        except HTTPException as exc:
            async with lock:
                host = require("hosts", hid)
                previous = host.get("status")
                last_seen = host.get("last_seen")
                recent = last_seen and (datetime.now(timezone.utc) - datetime.fromisoformat(last_seen)).total_seconds() < 150
                host.update(status="stale" if recent else "offline", error=str(exc.detail))
                store.put("hosts", host)
                if previous != host["status"]:
                    store.audit("host." + host["status"], "warning", str(exc.detail), host_id=hid)
                    if host["status"] == "offline":
                        queue_notification(store, "offline:" + hid + ":" + str(host.get("last_seen")), "Host offline: " + host["name"])
        return host

    def remember_containers(hid, result):
        if "docker" not in result.get("completed_runtimes", []):
            if any(warning.get("runtime") == "docker" for warning in result.get("warnings", [])):
                with store.connection() as db:
                    cached = db.execute("SELECT body FROM container_inventory WHERE host_id=?", (hid,)).fetchone()
                    if cached:
                        rows = json.loads(cached["body"])
                        for row in rows:
                            row["unverified"] = True
                        db.execute("UPDATE container_inventory SET body=? WHERE host_id=?", (json.dumps(rows), hid))
            return
        rows = result.get("containers", [])
        if not isinstance(rows, list) or len(rows) > 1000:
            raise HTTPException(502, "Invalid container inventory")
        refs = [row.get("agent_ref") for row in rows if isinstance(row, dict)]
        if len(refs) != len(rows) or any(not isinstance(ref, str) for ref in refs) or len(set(refs)) != len(refs):
            raise HTTPException(502, "Invalid container references")
        for row in rows:
            if not isinstance(row.get("name"), str) or not row["name"] or len(row["name"]) > 255 or not isinstance(row.get("capabilities", {}), dict):
                raise HTTPException(502, "Invalid container metadata")
            if any(isinstance(row.get(field), str) and redact(row[field]) != row[field] for field in ('name', 'agent_ref', 'project')):
                raise HTTPException(502, 'Sensitive container identity cannot be stored or controlled')
        rows = mask_metadata(rows)
        with store.connection() as db:
            db.execute("INSERT OR REPLACE INTO container_inventory VALUES(?,?,?)", (hid, now(), json.dumps(rows)))

    def containers_for(hid):
        host = require("hosts", hid)
        if demo:
            rows = []
            for service in store.all("services"):
                if service["host_id"] == hid and service["runtime"] in ("docker", "compose"):
                    names = service.get("components") or [service["control_handle"].get("container") or service["id"] + "-app"]
                    for name in names:
                        rows.append({"agent_ref": "docker-" + hashlib.sha256(name.encode()).hexdigest()[:12], "name": name,
                                     "project": service["control_handle"].get("project"), "image": "example/" + service["id"] + ":demo",
                                     "status": service.get("status", "unknown"), "ports": service.get("ports", []), "paths": service.get("paths", []),
                                     "runtime_details": service.get("runtime_details", {}), "control_handle": {"container": name},
                                     "capabilities": service.get("capabilities", {}), "service_id": service["id"]})
            timestamp = now()
        else:
            with store.connection() as db:
                cached = db.execute("SELECT * FROM container_inventory WHERE host_id=?", (hid,)).fetchone()
            rows, timestamp = (json.loads(cached["body"]), cached["ts"]) if cached else ([], None)
        stale = host.get("status") != "online" or not timestamp or (datetime.now(timezone.utc) - datetime.fromisoformat(timestamp)).total_seconds() > 150
        return [{**row, "host_id": hid, "host_name": host["name"], "observed_at": timestamp, "stale": stale or row.get("unverified", False),
                 "status": "unknown" if stale or row.get("unverified") else row.get("status", "unknown")} for row in rows]

    def require_container(hid, ref):
        for row in containers_for(hid):
            if row["agent_ref"] == ref:
                return row
        raise HTTPException(404, "Container not found; refresh host inventory")

    def host_operation_busy(hid, exclude=None, allow_power_pending=False):
        ids = {row["id"] for row in store.all("services") if row["host_id"] == hid}
        with store.connection() as db:
            if db.execute('SELECT 1 FROM boot_requests WHERE host_id=? AND active=1 AND id<>?',(hid,exclude or '')).fetchone():
                return True
            if db.execute('SELECT 1 FROM backup_runs WHERE host_id=? AND active=1 AND id<>?',(hid,exclude or '')).fetchone():
                return True
            return (not allow_power_pending and bool(db.execute('SELECT 1 FROM power_requests WHERE host_id=? AND active=1', (hid,)).fetchone())) or any(row["service_id"] in ids or row["service_id"] == 'host:' + hid or row["service_id"].startswith("container:" + hid + ":") for row in db.execute("SELECT service_id FROM operations WHERE status='running' AND id<>?", (exclude or '',)))

    def update_observations(hid, result):
        remember_containers(hid, result)
        existing = [row for row in store.all("services") if row["host_id"] == hid]
        seen = set()
        for candidate in proposals(require("hosts", hid), existing, result):
            old = next((row for row in existing if row["id"] == candidate["id"]), None)
            if old:
                seen.add(old["id"])
                record_secrets(store, old['id'], 'Observed discovery metadata', candidate.get('secret_categories', []))
                old['secret_scan_scope'] = candidate.get('secret_scan_scope', 'unavailable')
                old.setdefault("discovery_baseline", snapshot(old))
                old.update(status=candidate.get("status", "unknown"), capabilities=candidate.get("capabilities", {}),
                           agent_ref=candidate.get("agent_ref"), runtime_details=candidate.get("runtime_details", {}), observed_at=now())
                old["metrics"] = candidate.get("metrics")
                restart_count = candidate.get("runtime_details", {}).get("restart_count")
                previous_count = old.get("previous_restart_count")
                config = notification_settings(store)
                window = config["restart_window_s"]
                recent = [entry for entry in old.get("restart_observations", []) if (datetime.now(timezone.utc) - datetime.fromisoformat(entry["ts"])).total_seconds() < window]
                if isinstance(restart_count, int) and isinstance(previous_count, int) and restart_count > previous_count:
                    recent.append({"ts": now(), "count": restart_count - previous_count})
                if isinstance(restart_count, int) and isinstance(previous_count, int) and restart_count < previous_count:
                    recent = []
                old["restart_observations"] = recent[-100:]
                old["previous_restart_count"] = restart_count
                repeated = sum(entry["count"] for entry in recent) >= config["restart_threshold"]
                if repeated and not old.get("restart_alert_active"):
                    store.audit("service.restarts", "warning", "Repeated restarts observed", old["id"], hid)
                    queue_notification(store, "restarts:" + old["id"] + ":" + str(restart_count), "Repeated restarts: " + old["name"] + " (" + str(sum(entry["count"] for entry in recent)) + " within " + str(window) + " seconds)")
                old["restart_alert_active"] = repeated
                old["discovery_changes"] = candidate.get("diff", [])
                old["live_metadata"] = candidate.get("snapshot", {})
                if candidate["change"] != "gone" and old.get("source") != "manual":
                    for field in ("ports", "paths", "locations", "urls", "components"):
                        if field not in old.get("owned_fields", []):
                            old[field] = candidate.get(field, [])
                store.put("services", old)
        # Never keep claiming a missing/failed-to-observe service is running.
        for old in existing:
            if old["id"] not in seen:
                old.update(status="unknown", capabilities={"control": False, "logs": False, "files": False})
                store.put("services", old)

    async def run_health(sid):
        if sid in health_running:
            raise HTTPException(409, "A health check is already running")
        service = require("services", sid)
        check = HealthCheck.model_validate(service.get("health_check") or {})
        if not check.enabled:
            raise HTTPException(409, "Configure and enable a health check first")
        health_running.add(sid)
        try:
            if demo:
                result = {"ok": service.get("status") == "running", "latency_ms": 12.0, "detail": "Simulated demo check; no network request made"}
            elif check.type == "command":
                result = await agent_request(require("hosts", service["host_id"]), "POST", "/checks/run", {"profile": check.target, "timeout_s": check.timeout_s}, timeout=check.timeout_s + 5)
            else:
                result = await probe(check)
            record_health(store, sid, result, signature=check_key(check.model_dump()), interval_s=check.interval_s)
            if check_key((require("services", sid).get("health_check") or {})) == check_key(check.model_dump()):
                with store.connection() as db:
                    incident = db.execute("SELECT id,ended_at FROM incidents WHERE service_id=? AND check_key=? ORDER BY id DESC LIMIT 1", (sid, check_key(check.model_dump()))).fetchone()
                if incident:
                    state = "recovered" if result["ok"] else "failed"
                    queue_notification(store, "health:" + sid + ":" + str(incident["id"]) + ":" + state, "Service " + state + ": " + service["name"] + ". " + result["detail"])
            return result | {"demo": demo, "ts": now()}
        finally:
            health_running.discard(sid)

    async def poll():
        while True:
            for host in store.all("hosts"):
                if host.get('transport') == 'heartbeat' and host.get('last_seen'):
                    age = (datetime.now(timezone.utc) - datetime.fromisoformat(host['last_seen'])).total_seconds()
                    if age < 45:
                        continue
                    state = 'offline' if age >= 150 else 'stale'
                    if host.get('status') != state:
                        host.update(status=state, error='Persistent heartbeat missing')
                        store.put('hosts', host)
                        store.audit('host.' + state, 'warning', 'Persistent heartbeat missing', host_id=host['id'])
                        if state == 'offline':
                            queue_notification(store, 'offline:' + host['id'] + ':' + host['last_seen'], 'Host offline: ' + host['name'])
                    continue  # Explicit heartbeat enrollment keeps its own liveness policy.
                if host.get("agent_url"):
                    await refresh_host(host["id"])
                    host = require("hosts", host["id"])
                    if host.get("status") == "online" and discovery_due(host):
                        try:
                            await scan(host["id"], ScanOptions())
                        except HTTPException:
                            pass
            for service in store.all("services"):
                check = service.get("health_check") or {}
                if not check.get("enabled"):
                    continue
                with store.connection() as db:
                    previous = db.execute("SELECT ts FROM health_results WHERE service_id=? AND check_key=? ORDER BY id DESC LIMIT 1", (service["id"], check_key(check))).fetchone()
                if not previous or (datetime.now(timezone.utc) - datetime.fromisoformat(previous["ts"])).total_seconds() >= check.get("interval_s", 60):
                    try:
                        await run_health(service["id"])
                    except HTTPException:
                        pass
            await capture_due(store, capture_configuration, lock)
            idle_due = sorted([service for service in store.all('services') if service.get('idle_policy', {}).get('enabled')], key=lambda row: row.get('idle_state', {}).get('checked_at', ''))
            for service in idle_due[:5]:
                try:
                    await evaluate_idle(service['id'])
                except HTTPException:
                    pass
            await scheduler.tick()
            await backup_coordinator.tick()
            await flush_notifications(store, demo=demo)
            await asyncio.sleep(30)

    @asynccontextmanager
    async def lifespan(app):
        audit_journal.recover()
        scheduler.recover()
        backup_coordinator.recover()
        with store.connection() as db:
            db.execute("UPDATE operations SET status='unknown', detail='Controller restarted before result was recorded' WHERE status='running'")
            # A prepared snapshot proves intent, never that the remote write completed.
            db.execute("UPDATE config_versions SET status='unknown' WHERE status='prepared'")
        with store.connection() as db:
            db.execute("UPDATE notification_outbox SET status='pending' WHERE status='sending'")
        if not demo:
            for host in store.all('hosts'):
                if host.get('transport') == 'heartbeat':
                    host.update(status='stale', error='Controller restarted; awaiting authenticated heartbeat')
                    store.put('hosts', host)
        task = asyncio.create_task(poll()) if background and not demo else None
        async def reap_terminals():
            while True:
                await asyncio.sleep(2)
                await terminal_coordinator.sweep()
        terminal_task = asyncio.create_task(reap_terminals())
        try:
            yield
        finally:
            terminal_task.cancel()
            await asyncio.gather(terminal_task, return_exceptions=True)
            if task:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            await terminal_coordinator.close_all()
            await backup_coordinator.close()

    app = FastAPI(title="Pi Service Controller", version="0.1.0", lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store = store
    app.state.demo = demo
    owner_login.routes(app)

    @app.websocket('/api/v1/agents/{hid}/heartbeat')
    async def heartbeat(socket: WebSocket, hid: str):
        host = store.get('hosts', hid)
        secret = os.environ.get(host.get('token_env', ''), '') if host else ''
        key = os.environ.get(host.get('signing_env', ''), '') if host else ''
        target = socket.scope.get('raw_path', socket.url.path.encode()).decode('ascii')
        if demo or not host or socket.url.hostname not in allowed_hosts or socket.headers.get('origin') or socket.scope.get('query_string') or not secret or not hmac.compare_digest(socket.headers.get('authorization', '').encode(), ('Bearer ' + secret).encode()) or not valid_signature(key, 'GET', target, b'', socket.headers) or hid in heartbeat_channels:
            await socket.close(code=1008)
            return
        nonce = socket.headers['x-psc-nonce']
        try:
            with store.connection() as db:
                db.execute('DELETE FROM heartbeat_nonces WHERE expires < ?', (time.time(),))
                if db.execute('SELECT count(*) FROM heartbeat_nonces').fetchone()[0] >= 10000:
                    raise ValueError('Replay budget reached')
                db.execute('INSERT INTO heartbeat_nonces VALUES(?,?,?)', (hid, nonce, int(socket.headers['x-psc-time']) + SIGNATURE_WINDOW + 1))
        except Exception:
            await socket.close(code=1008)
            return
        heartbeat_channels.add(hid)
        try:
            await socket.accept()
            await socket.send_json({'status': 'ready', 'signature': frame_signature(key, nonce, -1, b'ready')})
            sequence, last = 0, None
            while True:
                raw = await asyncio.wait_for(socket.receive_text(), timeout=45)
                current_clock = asyncio.get_running_loop().time()
                if len(raw.encode()) > 4_000_000 or last is not None and current_clock - last < 5:
                    raise ValueError('Heartbeat size or rate limit exceeded')
                packet = json.loads(raw)
                if not isinstance(packet, dict) or type(packet.get('sequence')) is not int or packet['sequence'] != sequence or not isinstance(packet.get('signature'), str) or not isinstance(packet.get('payload'), dict):
                    raise ValueError('Invalid heartbeat frame')
                payload = packet['payload']
                encoded = json.dumps(payload, allow_nan=False, separators=(',', ':'), sort_keys=True).encode()
                if not hmac.compare_digest(packet['signature'].encode(), frame_signature(key, nonce, sequence, encoded).encode()):
                    raise ValueError('Invalid heartbeat frame signature')
                async with lock:
                    current_host = require('hosts', hid)
                    if any(current_host.get(field) != host.get(field) for field in ('agent_url', 'token_env', 'signing_env', 'physical_host_id')) or not hmac.compare_digest(os.environ.get(current_host.get('token_env', ''), '').encode(), secret.encode()) or not hmac.compare_digest(os.environ.get(current_host.get('signing_env', ''), '').encode(), key.encode()):
                        raise ValueError('Host credentials changed')
                    # Validate runtime identity/prose before persisting any heartbeat.
                    if 'inventory' in payload:
                        proposals(current_host, [row for row in store.all('services') if row['host_id'] == hid], payload['inventory'])
                    host = record_host_metrics(hid, payload.get('metrics'), host, transport='heartbeat')
                    if 'inventory' in payload:
                        update_observations(hid, payload['inventory'])
                await socket.send_json({'status': 'accepted', 'sequence': sequence, 'signature': frame_signature(key, nonce, sequence, b'accepted')})
                sequence += 1
                last = current_clock
        except (WebSocketDisconnect, TimeoutError, HTTPException, ValueError, TypeError, AttributeError):
            current_host = store.get('hosts', hid)
            if current_host and current_host.get('transport') == 'heartbeat':
                current_host.update(status='stale', error='Persistent heartbeat disconnected; controls unavailable until reconnect')
                store.put('hosts', current_host)
                store.audit('host.stale', 'warning', 'Persistent heartbeat disconnected', host_id=hid)
            try:
                await socket.close(code=1008)
            except RuntimeError:
                pass
        finally:
            heartbeat_channels.discard(hid)

    @app.middleware("http")
    async def protect(request: Request, call_next):
        if request.url.hostname not in allowed_hosts:
            return JSONResponse({"detail": "Host not allowed; configure PSC_ORIGINS for your controller URL"}, 403)
        if request.url.path.startswith("/api/"):
            supplied = request.headers.get("authorization", "").removeprefix("Bearer ")
            public_auth = request.url.path in ('/api/v1/auth/status', '/api/v1/auth/login')
            session_valid = owner_login.authorized(request.cookies.get(COOKIE))
            bearer_valid = bool(token and hmac.compare_digest(supplied.encode(), token.encode()))
            if (token or owner_login.enabled) and not public_auth and not (bearer_valid or session_valid):
                return JSONResponse({"detail": "Controller token required"}, 401)
            if not (token or owner_login.enabled) and request.client and request.client.host not in ("127.0.0.1", "::1", "testclient"):
                return JSONResponse({"detail": "Local-only mode; configure PSC_TOKEN for remote access"}, 403)
            origin = request.headers.get("origin")
            if origin and origin not in allowed_origins:
                return JSONResponse({"detail": "Origin not allowed"}, 403)
            if request.method in ("POST", "PUT", "PATCH"):
                if "application/json" not in request.headers.get("content-type", ""):
                    return JSONResponse({"detail": "JSON content type required"}, 415)
                try:
                    size = int(request.headers.get("content-length", "0"))
                except ValueError:
                    return JSONResponse({"detail": "Invalid content length"}, 400)
                limit = 4_200_000 if request.url.path.endswith(("/files", "/files/validate")) else 1_200_000
                if size > limit:
                    return JSONResponse({"detail": "Request too large"}, 413)
        response = await audit_journal.run(request, call_next)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["X-Frame-Options"] = "DENY"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return JSONResponse({"detail": [{"field": ".".join(str(x) for x in e["loc"]), "message": e["msg"]}
                                         for e in exc.errors()]}, 422)

    def require(table, identifier):
        record = store.get(table, identifier)
        if not record:
            raise HTTPException(404, "Host or service not found")
        return heartbeat_liveness(record) if table == 'hosts' and not demo else record

    def decorate(service, reverse=None, registry=None, parents=None):
        host = heartbeat_liveness(store.get("hosts", service["host_id"]) or {}) if not demo else store.get("hosts", service["host_id"]) or {}
        service = dict(service)
        service["host_name"] = host.get("name", service["host_id"])
        service["host_status"] = host.get("status", "unknown")
        service["observed_status"] = service.get("status", "unknown")
        if registry is None:
            registry = {row["id"]: row for row in store.all("services")}
        if parents is None:
            parents, _ = validate_groups(registry)
        service["group_parent_id"] = parents.get(service["id"])
        service["suggested_components"] = component_suggestions(service, registry, parents)
        members = [registry[sid] for sid in service.get("component_ids", [])]
        service["component_names"] = [item["name"] for item in members]
        service["linked_components"] = [{"id": item["id"], "name": item["name"], "runtime": item["runtime"], "status": item.get("status", "unknown"), "locations": item.get("locations", {})} for item in members]
        if members:
            observed = {row.get("status", "unknown") for row in [service, *members]}
            service["status"] = "running" if observed == {"running"} else "stopped" if observed == {"stopped"} else "failed" if "failed" in observed else "unknown"
            service["capabilities"] = dict(service.get("capabilities", {}))
            service["capabilities"]["control"] = all(row.get("capabilities", {}).get("control") for row in [registry[service["id"]], *members])
            service["group_metrics"] = {key: sum(row["metrics"][key] for row in [registry[service["id"]], *members]) if all(isinstance((row.get("metrics") or {}).get(key), (int, float)) for row in [registry[service["id"]], *members]) else None for key in ("cpu_percent", "memory_mb")}
        if demo:
            service["metrics"] = service.get("metrics") or {"cpu_percent": 3.2 if service["status"] == "running" else 0, "memory_mb": 384 if service["status"] == "running" else 0, "scope": "simulated demo"}
            service["runtime_details"] = {"restart_policy": "unless-stopped" if service["runtime"] in ("docker", "compose") else "on-failure", "enabled_state": "enabled", "restart_count": 1,
                                          "started_at": service.get("created_at"), **service.get("runtime_details", {})}
        service["health"] = latest_health(store, service["id"])
        if service["runtime"] == "windows":
            service["guides"] = software_guides(service["name"], kind="service")
        service["dependents"] = reverse.get(service["id"], []) if reverse is not None else [row["id"] for row in store.all("services") if service["id"] in row.get("dependencies", [])]
        if host.get("status") != "online":
            service["status"] = "unknown"
        return service

    @app.get("/api/v1/status")
    def status():
        return {"name": "Hearth", "version": "0.1.0", "demo": demo, "authenticated": bool(token or owner_login.enabled), "login_method": "password_totp" if owner_login.enabled else "token" if token else "local",
                "workspace": str(store.root), "obsidian_path": str(store.root / "obsidian"),
                "features": {"manifests": True, "obsidian": True, "agent": True, "telemetry": True,
                             "health": True, "credentials": True, "ai": True, "terminal": True, "backups": True,
                             "boot_policy": True, "kuma": True, "host_browsing": True, "vault_verification": True, "listener_suggestions": True, "app_store": False}}

    @app.get("/api/v1/hosts")
    def hosts():
        result = []
        for host in store.all("hosts"):
            if not demo:
                host = heartbeat_liveness(host)
            with store.connection() as db:
                row = db.execute("SELECT body,ts FROM telemetry WHERE host_id=? ORDER BY id DESC LIMIT 1", (host["id"],)).fetchone()
            result.append(host | {"telemetry": json.loads(row["body"]) if row else None, "telemetry_at": row["ts"] if row else None})
        return result

    @app.post("/api/v1/hosts")
    async def save_host(body: HostDefinition):
        async with lock:
            if any(host["id"] != body.id and host["id"].casefold() == body.id.casefold() for host in store.all("hosts")):
                raise HTTPException(409, "Host IDs differing only by case would collide in the Markdown vault")
            old = store.get("hosts", body.id) or {}
            if old and host_operation_busy(body.id):
                raise HTTPException(409, "Wait for the host operation before changing its connection")
            fields = body.model_dump(exclude_unset=True) if old else body.model_dump()
            connection_changed = any(key in fields and fields[key] != old.get(key, "") for key in ("agent_url", "token_env", "signing_env"))
            host = old | fields | {"status": "unknown" if connection_changed else old.get("status", "unknown"), "demo": demo}
            store.put("hosts", host)
            store.audit("host.configured", "success", body.name, host_id=body.id)
        return host

    @app.post("/api/v1/hosts/{hid}/refresh")
    async def host_refresh(hid: str):
        return await refresh_host(hid)

    @app.put("/api/v1/hosts/{hid}/telemetry-policy")
    async def telemetry_policy(hid: str, body: TelemetryPolicy):
        async with lock:
            host = require("hosts", hid)
            host.update(telemetry_policy=body.model_dump(), telemetry_alerts={}, telemetry_streaks={})
            store.put("hosts", host)
            store.audit("telemetry.policy", "success", "Host threshold policy saved", host_id=hid)
        return body.model_dump()

    @app.get("/api/v1/hosts/{hid}/telemetry")
    def host_telemetry(hid: str):
        require("hosts", hid)
        with store.connection() as db:
            rows = db.execute("SELECT ts,body FROM telemetry WHERE host_id=? ORDER BY id DESC LIMIT 120", (hid,)).fetchall()
        return [{"ts": row["ts"], **json.loads(row["body"])} for row in reversed(rows)]

    @app.get("/api/v1/hosts/{hid}/windows")
    def windows_inventory(hid: str):
        host = require("hosts", hid)
        with store.connection() as db:
            cached = db.execute("SELECT ts,body FROM host_inventory WHERE host_id=? AND provider='windows'", (hid,)).fetchone()
        result = json.loads(cached["body"]) if cached else windows_demo() if demo else None
        if not result:
            return {"inventory": None, "demo": demo, "stale": True, "observed_at": None}
        rows = [decorate(item) for item in store.all("services") if item["host_id"] == hid and item["runtime"] == "windows"]
        if demo and not rows:
            rows = [{"id": "demo-windows-update", "name": "Windows Update", "status": "unknown", "guides": software_guides("Windows Update", kind="service")},
                    {"id": "demo-autodesk-licensing", "name": "Autodesk Licensing Service", "status": "unknown", "guides": software_guides("Autodesk Licensing Service", kind="service")}]
        return {"inventory": result | {"services": rows}, "demo": demo, "observed_at": cached["ts"] if cached else None,
                "stale": not demo and (host.get("status") != "online" or host.get("active_os", host.get("os")) != "Windows" or not cached or (datetime.now(timezone.utc) - datetime.fromisoformat(cached["ts"])).total_seconds() > 300)}

    @app.post("/api/v1/hosts/{hid}/windows/refresh")
    async def windows_refresh(hid: str):
        host = require("hosts", hid)
        if hid in inventory_running:
            raise HTTPException(409, "Windows inventory refresh is already running")
        if not demo and (host.get("status") != "online" or host.get("active_os", host.get("os")) != "Windows"):
            raise HTTPException(409, "Windows inventory requires an online host currently running Windows")
        inventory_running.add(hid)
        try:
            payload = windows_demo() if demo else await agent_request(host, "GET", "/inventory/windows", timeout=45)
            if not demo and host.get("physical_host_id") and (not isinstance(payload, dict) or payload.get("physical_host_id") != host["physical_host_id"]):
                raise HTTPException(409, "Windows agent physical-host identity does not match")
            result = verify_windows(payload)
            async with lock:
                current = require("hosts", hid)
                if not demo and any(current.get(key) != host.get(key) for key in ("agent_url", "token_env", "signing_env", "active_os", "physical_host_id")):
                    raise HTTPException(409, "Host connection or active OS changed during inventory; refresh again")
                with store.connection() as db:
                    db.execute("INSERT OR REPLACE INTO host_inventory VALUES(?,?,?,?)", (hid, "windows", now(), json.dumps(result)))
                    store.audit("windows.inventory", "success", "Read-only Windows inventory refreshed", host_id=hid, db=db)
            return windows_inventory(hid)
        finally:
            inventory_running.discard(hid)

    @app.get('/api/v1/hosts/{hid}/software')
    def software_inventory(hid: str):
        host = require('hosts', hid)
        system = host.get('active_os') or host.get('os')
        if system == 'Windows':
            return windows_inventory(hid)
        with store.connection() as db:
            cached = db.execute("SELECT ts,body FROM host_inventory WHERE host_id=? AND provider='software'", (hid,)).fetchone()
        value = json.loads(cached['body']) if cached else None
        if demo:
            system = 'Darwin' if system in ('Darwin', 'macOS') else 'Linux'
            value = verify_windows({'os': system, 'completed': ['applications'], 'warnings': [], 'truncated': [],
                'coverage': 'Synthetic platform example; no real host was read.',
                'applications': [{'id': 'demo-platform-app', 'name': 'Microsoft Word' if system == 'Darwin' else 'nginx',
                    'version': 'sample', 'publisher': '', 'source': 'macOS app bundle' if system == 'Darwin' else 'dpkg', 'scope': 'machine'}],
                'processes': [], 'ports': [], 'events': []}, system)
        stale = not demo and (not cached or host.get('status') != 'online' or value.get('os') != system or
            (datetime.now(timezone.utc) - datetime.fromisoformat(cached['ts'])).total_seconds() > 300)
        return {'inventory': value, 'observed_at': cached['ts'] if cached else None, 'stale': stale, 'demo': demo}

    @app.post('/api/v1/hosts/{hid}/software/refresh')
    async def software_refresh(hid: str):
        host = require('hosts', hid)
        system = host.get('active_os') or host.get('os')
        if system == 'Windows':
            return await windows_refresh(hid)
        if demo:
            return software_inventory(hid)
        if host.get('status') != 'online' or system not in ('Linux', 'Darwin'):
            raise HTTPException(409, 'Software inventory requires an online Linux, macOS or Windows agent')
        if hid in inventory_running:
            raise HTTPException(409, 'Host inventory refresh is already running')
        inventory_running.add(hid)
        try:
            payload = await agent_request(host, 'GET', '/inventory/software', timeout=45)
            if host.get('physical_host_id') and (not isinstance(payload, dict) or payload.get('physical_host_id') != host['physical_host_id']):
                raise HTTPException(409, 'Agent physical-host identity does not match')
            value = verify_windows(payload, system)
            async with lock:
                current = require('hosts', hid)
                if current.get('status') != 'online' or any(current.get(key) != host.get(key) for key in ('agent_url', 'token_env', 'signing_env', 'active_os', 'os', 'physical_host_id')):
                    raise HTTPException(409, 'Host connection or active OS changed during inventory; refresh again')
                with store.connection() as db:
                    db.execute('INSERT OR REPLACE INTO host_inventory VALUES(?,?,?,?)', (hid, 'software', now(), json.dumps(value)))
                    store.audit('software.inventory', 'success', 'Read-only software inventory refreshed', host_id=hid, db=db)
            return software_inventory(hid)
        finally:
            inventory_running.discard(hid)

    @app.get("/api/v1/services")
    def services(q: str = "", host: str = "", state: str = "", tag: str = ""):
        rows = store.all("services")
        registry = {row["id"]: row for row in rows}
        parents, _ = validate_groups(registry)
        reverse = {}
        for row in rows:
            for dependency in row.get("dependencies", []):
                reverse.setdefault(dependency, []).append(row["id"])
        result = [decorate(x, reverse, registry, parents) for x in rows]
        if q:
            result = [x for x in result if q.casefold() in json.dumps({k: x.get(k) for k in
                      ("name", "description", "notes", "tags", "ports", "paths", "runtime", "host_name", "component_names")}).casefold()]
        return [x for x in result if (not host or x["host_id"] == host) and (not state or x["status"] == state)
                and (not tag or tag in x["tags"])]

    @app.get("/api/v1/services/{sid}")
    def service(sid: str):
        return decorate(require("services", sid))

    @app.patch("/api/v1/services/{sid}")
    async def edit_service(sid: str, body: ServiceEdit):
        async with lock:
            old = require("services", sid)
            if old["revision"] != body.revision:
                raise HTTPException(409, "This service changed since you opened it. Reload before saving.")
            updates = body.model_dump(exclude_none=True, exclude={"revision"})
            prospective = old | updates
            if 'idle_policy' in updates:
                if host_operation_busy(old['host_id']):
                    raise HTTPException(409, 'Wait for host operations before changing auto-stop policy')
            if (prospective["host_id"] != old["host_id"] or prospective.get("component_ids", []) != old.get("component_ids", [])) and host_operation_busy(old["host_id"]):
                raise HTTPException(409, "Wait for the host operation before changing application components")
            if prospective["host_id"] != old["host_id"] and host_operation_busy(old["host_id"]):
                raise HTTPException(409, "Wait for the current host operation before moving this service")
            require("hosts", prospective["host_id"])
            records = {row["id"]: row for row in store.all("services")}
            records[sid] = prospective
            validate_dependencies(records)
            validate_groups(records)
            for key in ("notes", "description"):
                if key in updates and redact(updates[key]) != updates[key]:
                    raise HTTPException(422, "Possible secret detected. Store it in your vault and add a reference instead.")
            if "notes" in updates and ("<!-- psc:notes:start -->" in updates["notes"] or "<!-- psc:notes:end -->" in updates["notes"]):
                raise HTTPException(422, "Owner notes cannot contain reserved sync markers")
            with store.connection() as db:
                if 'documentation' in updates and updates['documentation'] != old.get('documentation', {}):
                    db.execute('INSERT INTO documentation_history(service_id,ts,revision,body) VALUES(?,?,?,?)', (sid, now(), old['revision'], json.dumps(old.get('documentation', {}))))
                if "notes" in updates and updates["notes"] != old.get("notes", ""):
                    db.execute("INSERT INTO note_history(service_id,ts,revision,notes) VALUES(?,?,?,?)",
                               (sid, now(), old["revision"], old.get("notes", "")))
                updated = old | updates | {"revision": old["revision"] + 1, "updated_at": now()}
                updated["owned_fields"] = sorted(set(old.get("owned_fields", [])) | set(updates))
                if 'idle_policy' in updates and updates['idle_policy'] != old.get('idle_policy') or prospective['host_id'] != old['host_id'] or prospective.get('component_ids') != old.get('component_ids'):
                    updated['idle_state'] = {}
                if prospective["host_id"] != old["host_id"]:
                    updated.update(status="unknown", capabilities={"control": False, "logs": False, "files": False}, agent_ref=None, runtime_details={})
                store.put("services", updated, db)
                store.audit("service.edited", "success", "Updated " + ", ".join(updates), sid, old["host_id"], db)
        return decorate(updated)

    @app.get("/api/v1/services/{sid}/history")
    def history(sid: str):
        require("services", sid)
        with store.connection() as db:
            notes = [dict(x) for x in db.execute("SELECT * FROM note_history WHERE service_id=? ORDER BY id DESC LIMIT 50", (sid,))]
            documentation = [{**dict(row), 'body': json.loads(row['body'])} for row in db.execute('SELECT * FROM documentation_history WHERE service_id=? ORDER BY id DESC LIMIT 50', (sid,))]
        health = health_history(store, sid)
        with store.connection() as db:
            configuration = [dict(row) for row in db.execute("SELECT * FROM config_versions WHERE service_id=? AND status IN ('checkpoint','applied') ORDER BY id DESC LIMIT 50", (sid,))]
        return {"actions": store.events(sid), "notes": notes, "documentation": documentation, "incidents": health["incidents"], "incident_notes": health["incident_notes"], "configuration": configuration}

    @app.post("/api/v1/services/{sid}/incident-notes")
    async def add_incident_note(sid: str, body: IncidentNote):
        require("services", sid)
        if redact(body.note) != body.note or redact(body.model) != body.model:
            raise HTTPException(422, "Remove secret values before saving an incident note")
        async with lock:
            with store.connection() as db:
                if body.incident_id and not db.execute("SELECT id FROM incidents WHERE id=? AND service_id=?", (body.incident_id, sid)).fetchone():
                    raise HTTPException(404, "Incident not found for this service")
                cursor = db.execute("INSERT INTO incident_notes(service_id,incident_id,ts,note,source,model) VALUES(?,?,?,?,?,?)", (sid, body.incident_id, now(), body.note, body.source, body.model))
                store.audit("incident.note", "success", "Saved " + body.source + " incident note", sid, db=db)
        return {"id": cursor.lastrowid, "saved": True}

    @app.patch("/api/v1/services/{sid}/incidents/{incident_id}")
    async def edit_incident(sid: str, incident_id: int, body: IncidentEdit):
        require("services", sid)
        if redact(body.cause) != body.cause:
            raise HTTPException(422, "Remove secret values from the incident cause")
        async with lock:
            with store.connection() as db:
                if not db.execute("SELECT id FROM incidents WHERE id=? AND service_id=?", (incident_id, sid)).fetchone():
                    raise HTTPException(404, "Incident not found")
                db.execute("UPDATE incidents SET cause=? WHERE id=?", (body.cause, incident_id))
                store.audit("incident.cause", "success", "Incident cause updated", sid, db=db)
        return {"saved": True}

    @app.get("/api/v1/services/{sid}/health")
    def service_health(sid: str):
        service = require("services", sid)
        return health_history(store, sid) | {"check": service.get("health_check")}

    @app.put("/api/v1/services/{sid}/health-check")
    async def configure_health(sid: str, body: HealthEdit):
        async with lock:
            service = require("services", sid)
            if service["revision"] != body.revision:
                raise HTTPException(409, "Service changed. Reload before configuring the check.")
            if redact(body.check.target) != body.check.target:
                raise HTTPException(422, "Health target contains a recognized secret pattern")
            old_key = check_key(service.get("health_check"))
            if not body.check.enabled or old_key != check_key(body.check.model_dump()):
                with store.connection() as db:
                    db.execute("UPDATE incidents SET ended_at=?,resolution=? WHERE service_id=? AND check_key=? AND ended_at IS NULL", (now(), "check_disabled" if not body.check.enabled else "check_reconfigured", sid, old_key))
            service.update(health_check=body.check.model_dump(), revision=service["revision"] + 1, updated_at=now())
            store.put("services", service)
            store.audit("health.configured", "success", "Check enabled" if body.check.enabled else "Check disabled", sid, service["host_id"])
        return decorate(service)

    @app.post("/api/v1/services/{sid}/health/check")
    async def check_health(sid: str):
        return await run_health(sid)

    @app.get("/api/v1/services/{sid}/health-profiles")
    async def health_profiles(sid: str):
        service = require("services", sid)
        if demo:
            return [{"id": "app-ready", "label": "Demo application readiness"}, {"id": "storage-ready", "label": "Demo storage readiness"}]
        return await agent_request(require("hosts", service["host_id"]), "GET", "/checks")

    @app.get('/api/v1/services/{sid}/secret-findings')
    def secret_findings(sid: str):
        service = require('services', sid)
        return {'findings': list_secrets(store, sid), 'file_scan_scope': service.get('secret_scan_scope', 'unavailable'),
                'scope': 'Discovery metadata, locally approved exact files and rejected configuration drafts. Secret-bearing filenames are flagged without reading content. No filesystem crawl or vault verification. Absence of findings does not prove absence of secrets.'}

    @app.put('/api/v1/services/{sid}/secret-findings/{fid}')
    async def review_secret(sid: str, fid: str, body: SecretFindingReview):
        async with lock:
            service = require('services', sid)
            with store.connection() as db:
                result = db.execute('UPDATE secret_findings SET vault_ref=?,revision=revision+1 WHERE id=? AND service_id=? AND revision=?',
                                    (body.pointer.vault_ref, fid, sid, body.revision))
                if result.rowcount != 1:
                    raise HTTPException(409, 'Finding changed or unavailable; reload before linking')
                store.audit('secret.linked', 'success', 'Owner updated a vault reference; existence and remediation remain unverified', sid, service['host_id'], db=db)
        return {'findings': list_secrets(store, sid)}

    @app.put("/api/v1/services/{sid}/credentials")
    async def credentials(sid: str, body: CredentialEdit):
        async with lock:
            service = require("services", sid)
            if service["revision"] != body.revision:
                raise HTTPException(409, "Service changed. Reload before updating credential pointers.")
            rows = [row.model_dump() for row in body.credentials]
            if any(redact(value) != value for row in rows for value in row.values()):
                raise HTTPException(422, "Use credential pointers and hints, not secret values")
            service.update(credentials=rows, revision=service["revision"] + 1, updated_at=now())
            store.put("services", service)
            store.audit("credentials.updated", "success", f"{len(rows)} vault pointers saved", sid, service["host_id"])
        return decorate(service)

    @app.post("/api/v1/services/{sid}/control")
    async def control(sid: str, body: Action):
        service = require("services", sid)
        if not service.get("component_ids"):
            return await control_single(sid, body)
        return await control_group(sid, body)

    async def control_group(sid: str, body: Action, idle_expected=None, idle_host=None, origin='manual', schedule_guard=None):
        if not body.acknowledge_components:
            raise HTTPException(409, "Confirm this action for the application and all linked runtime components")
        operation_id = str(uuid.uuid4())
        async with lock:
            registry = {row["id"]: row for row in store.all("services")}
            service = registry[sid]
            if schedule_guard is not None:
                schedule_guard([])
            if idle_expected is not None:
                if not service.get('idle_policy', {}).get('enabled') or not service.get('idle_state', {}).get('ready') or any(registry.get(key) != value for key, value in idle_expected.items()):
                    raise HTTPException(409, 'Application activity decision changed; no automatic stop was sent')
            targets, external = group_plan(registry, sid, body.action)
            host = require("hosts", service["host_id"])
            if idle_host is not None and any(host.get(key) != idle_host.get(key) for key in ('status', 'agent_url', 'token_env', 'signing_env', 'active_os', 'os', 'physical_host_id')):
                raise HTTPException(409, 'Application host changed after activity checks; no automatic stop was sent')
            if host.get("status") != "online" or host_operation_busy(host["id"]):
                raise HTTPException(409, "Application host must be online and free of other operations")
            if any(not registry[target].get("capabilities", {}).get("control") for target in targets):
                raise HTTPException(403, "Every linked runtime component requires its own agent control permission")
            if body.action in ("stop", "restart") and not body.acknowledge_dependencies:
                related = [row["name"] for row in registry.values() if row['id'] not in targets and row.get("status") == "running" and any(target in row.get("dependencies", []) for target in targets)]
                if related:
                    raise HTTPException(409, "Running dependents: " + ", ".join(related))
            if body.action in ("start", "restart") and any(registry[dep].get("status") != "running" or require("hosts", registry[dep]["host_id"]).get("status") != "online" for dep in external):
                raise HTTPException(409, "Start and verify external application dependencies before this group action")
            with store.connection() as db:
                db.execute("INSERT INTO operations VALUES(?,?,?,?,?,?)", (operation_id, sid, "group." + body.action, "running", now(), ""))
        outcome, results = "unknown", []
        try:
            for target in targets:
                # External dependents were preflighted for the entire reserved
                # group; internal dependents stop first in reverse order.
                completed = [row['service']['id'] for row in results]
                result = await control_single(target, body.model_copy(update={'acknowledge_dependencies': True}), reservation=operation_id,
                                              origin='idle' if idle_expected is not None else origin,
                                              schedule_guard=(lambda: schedule_guard(completed)) if schedule_guard is not None else None)
                results.append(result)
                desired = "stopped" if body.action == "stop" else "running"
                if result["status"] != "success" or require("services", target).get("status") != desired:
                    outcome = "unknown" if result["status"] == "success" else result["status"]
                    break
            else:
                outcome = "success"
            if idle_expected is not None:
                async with lock:
                    parent = require('services', sid)
                    parent['idle_state'] = {'asleep': outcome == 'success' and all(require('services', target).get('status') == 'stopped' for target in targets)}
                    store.put('services', parent)
            return {"operation_id": operation_id, "status": outcome, "detail": "Application component action finished; inspect individual observed outcomes", "components": results, "service": decorate(require("services", sid))}
        finally:
            if idle_expected is not None and outcome != 'success':
                parent = require('services', sid)
                parent['idle_state'] = {'asleep': False, 'ready': False, 'signal': 'unknown'}
                store.put('services', parent)
            with store.connection() as db:
                db.execute("UPDATE operations SET status=?,detail=? WHERE id=?", (outcome, "Completed " + str(len(results)) + " of " + str(len(targets)) + " component actions", operation_id))
                store.audit("group." + body.action, outcome, "Confirmed linked-component action", sid, host["id"], db=db)

    async def control_single(sid: str, body: Action, reservation=None, idle_revision=None, origin='manual', schedule_guard=None):
        if body.action == "start":
            registry = {row["id"]: row for row in store.all("services")}
            require("services", sid)
            order = startup_order(registry, sid)
            pending = [dep for dep in order[:-1] if registry[dep].get("status") != "running" or (store.get("hosts", registry[dep]["host_id"]) or {}).get("status") != "online"]
            if pending and not body.start_dependencies:
                raise HTTPException(409, {"message": "Start the required dependencies first, or confirm dependency startup", "dependencies": pending})
            if pending:
                # Preflight the whole plan before starting anything.
                for dependency in pending + [sid]:
                    item = registry[dependency]
                    host = require("hosts", item["host_id"])
                    if host.get("status") != "online" or not item.get("capabilities", {}).get("control"):
                        raise HTTPException(409, f"Dependency plan cannot control {item['name']} on its current host")
                    if host_operation_busy(host["id"], reservation):
                        raise HTTPException(409, "A host in the dependency plan is already running an operation")
                for dependency in pending:
                    result = await control(dependency, Action(action="start", start_dependencies=True))
                    if result["status"] != "success" or result["service"]["status"] != "running":
                        raise HTTPException(409, f"Dependency {registry[dependency]['name']} did not reach a verified running state; startup stopped")
        operation_id = str(uuid.uuid4())
        async with lock:
            service = require("services", sid)
            host = require("hosts", service["host_id"])
            if schedule_guard is not None:
                schedule_guard()
            if idle_revision is not None:
                parents, _ = validate_groups({row['id']: row for row in store.all('services')})
                if service['revision'] != idle_revision or not service.get('idle_policy', {}).get('enabled') or not service.get('idle_state', {}).get('ready') or service.get('status') != 'running' or service.get('component_ids') or sid in parents:
                    raise HTTPException(409, 'Idle decision changed; no automatic stop was sent')
            if host_operation_busy(host["id"], reservation):
                raise HTTPException(409, "Another runtime operation is running on this host")
            if host.get("status") != "online":
                raise HTTPException(409, "Host is offline or has not been verified online")
            if not service.get("capabilities", {}).get("control"):
                raise HTTPException(403, "Control is not enabled in this host's agent allow-list")
            related = [x["name"] for x in store.all("services") if sid in x.get("dependencies", []) and x.get("status") == "running"]
            if body.action in ("stop", "restart") and related and not body.acknowledge_dependencies:
                raise HTTPException(409, "Running dependents: " + ", ".join(related))
            with store.connection() as db:
                active = db.execute("SELECT id FROM operations WHERE service_id=? AND status='running' AND id<>?", (sid, reservation or '')).fetchone()
                if active:
                    raise HTTPException(409, "Another operation is still running for this service")
                db.execute("INSERT INTO operations VALUES(?,?,?,?,?,?)", (operation_id, sid, body.action, "running", now(), ""))
            store.audit("control." + body.action, "running", "Demo simulation" if demo else "Sent to host agent", sid, host["id"])
        try:
            observed = None
            if demo:
                await asyncio.sleep(0.25)
                result = {"output": "Simulated action completed. No machine was changed."}
            else:
                result = await agent_request(host, "POST", "/control", {"runtime": service["runtime"],
                                             "handle": service["control_handle"], "action": body.action}, timeout=50)
            outcome, detail = "success", redact(result.get("output", ""))
            if not demo:
                try:
                    observed = await agent_request(host, "POST", "/scan", {}, timeout=30)
                except HTTPException:
                    detail = (detail + "\nCommand completed; resulting state could not be verified.").strip()
        except HTTPException as exc:
            outcome = "unknown" if exc.status_code in (503, 504) else "failed"
            detail = str(exc.detail)
        except BaseException:
            # A disconnected caller or unexpected failure cannot prove whether a
            # command reached the agent. Finalize the durable reservation before
            # propagating cancellation; never leave controls permanently busy.
            service = require("services", sid)
            service.update(status="unknown", observed_at=now())
            service['last_control'] = {'action': body.action, 'source': 'idle' if idle_revision is not None else origin,
                                       'ts': now(), 'operation_id': operation_id, 'outcome': 'unknown', 'verified': False}
            store.put("services", service)
            with store.connection() as db:
                db.execute("UPDATE operations SET status='unknown',detail=? WHERE id=?", ("Interrupted; inspect runtime state before retrying", operation_id))
                store.audit("control." + body.action, "unknown", "Interrupted; resulting state unverified", sid, host["id"], db=db)
            raise
        try:
            async with lock:
                service = require("services", sid)
                # Real commands are not observations. Require a scan to verify resulting runtime state.
                service["status"] = ("stopped" if body.action == "stop" else "running") if demo and outcome == "success" else "unknown"
                service["observed_at"] = now()
                store.put("services", service)
                if outcome == "success" and observed is not None:
                    update_observations(host["id"], observed)
                    service = require("services", sid)
                if outcome == 'success' and service['status'] == ('stopped' if body.action == 'stop' else 'running'):
                    service['idle_state'] = {'asleep': idle_revision is not None and body.action == 'stop'}
                    store.put('services', service)
                service['last_control'] = {'action': body.action, 'source': 'idle' if idle_revision is not None else origin,
                                           'ts': now(), 'operation_id': operation_id, 'outcome': outcome,
                                           'verified': outcome == 'success' and service['status'] == ('stopped' if body.action == 'stop' else 'running')}
                store.put('services', service)
                with store.connection() as db:
                    db.execute("UPDATE operations SET status=?,detail=? WHERE id=?", (outcome, detail, operation_id))
                store.audit("control." + body.action, outcome, detail, sid, host["id"])
        except BaseException:
            service = require('services', sid)
            service.update(status='unknown', observed_at=now())
            service['last_control'] = {'action': body.action, 'source': 'idle' if idle_revision is not None else origin,
                                       'ts': now(), 'operation_id': operation_id, 'outcome': 'unknown', 'verified': False}
            store.put('services', service)
            with store.connection() as db:
                db.execute("UPDATE operations SET status='unknown',detail=? WHERE id=?", ('Interrupted while verifying state; inspect before retrying', operation_id))
                store.audit('control.' + body.action, 'unknown', 'Interrupted while verifying state', sid, host['id'], db=db)
            raise
        return {"operation_id": operation_id, "status": outcome, "detail": detail, "service": decorate(service)}

    async def dispatch_schedule(expected, action, context, minute):
        def guard(completed=None):
            current = require('services', expected['id'])
            if schedule_fingerprint(current) != schedule_fingerprint(expected) or scheduler.clock().replace(second=0, microsecond=0) != minute:
                raise HTTPException(409, 'Schedule changed or its minute expired; no command sent')
            observed = schedule_preflight(store, current['id'], action, scheduler.clock())
            for target in completed or []:
                if target in observed and target in context and observed[target]['state'] == ('running' if action == 'start' else 'stopped'):
                    observed[target]['state'] = context[target]['state']
            if observed != context:
                raise HTTPException(409, 'Schedule dependency or host context changed; no command sent')
        if expected.get('component_ids'):
            return await control_group(expected['id'], Action(action=action, acknowledge_components=True), origin='schedule', schedule_guard=guard)
        return await control_single(expected['id'], Action(action=action), origin='schedule', schedule_guard=guard)

    scheduler = Scheduler(store, dispatch_schedule)
    app.state.scheduler = scheduler

    @app.get('/api/v1/services/{sid}/schedule')
    def schedule_details(sid: str):
        service = require('services', sid)
        policy = service.get('schedule_policy', SchedulePolicy().model_dump())
        with store.connection() as db:
            runs = [dict(row) for row in db.execute('SELECT * FROM schedule_runs WHERE service_id=? ORDER BY minute DESC LIMIT 30', (sid,))]
        return {'policy': policy, 'revision': service['revision'], 'next_windows': schedule_preview(policy['rules'], scheduler.clock(), policy['timezone']) if policy['enabled'] else [],
                'runs': runs, 'last_control': service.get('last_control'), 'demo': demo,
                'limitations': 'Missed/offline/blocked windows never retry. Nonexistent DST minutes are skipped; repeated wall-clock minutes run only at their first occurrence. Controller must remain running.'}

    @app.put('/api/v1/services/{sid}/schedule')
    async def schedule_save(sid: str, body: ScheduleEdit):
        async with lock:
            service = require('services', sid)
            if service['revision'] != body.revision or host_operation_busy(service['host_id']):
                raise HTTPException(409, 'Service changed or its host is busy; reload before saving schedules')
            prospective = {row['id']: row for row in store.all('services')}
            prospective[sid] = service | {'schedule_policy': body.policy.model_dump()}
            parents, _ = validate_groups(prospective)
            if body.policy.enabled and (sid in parents or service.get('component_ids') and not body.policy.acknowledge_components):
                raise HTTPException(409, 'Schedule through the application parent and explicitly approve every linked component')
            service.update(schedule_policy=body.policy.model_dump(), revision=service['revision'] + 1, updated_at=now())
            with store.connection() as db:
                store.put('services', service, db=db)
                store.audit('schedule.updated', 'success', 'Owner saved timezone-scoped start/stop rules; missed windows never replay', sid, service['host_id'], db=db)
            scheduler.arm(service)
        return schedule_details(sid)

    @app.post('/api/v1/services/{sid}/idle/evaluate')
    async def evaluate_idle(sid: str):
        service = require('services', sid)
        host = require('hosts', service['host_id'])
        policy = IdlePolicy.model_validate(service.get('idle_policy', {}))
        if not policy.enabled:
            raise HTTPException(409, 'Auto-stop is disabled for this service')
        if sid in idle_running:
            raise HTTPException(409, 'Activity evaluation already running')
        idle_running.add(sid)
        try:
            registry = {row['id']: row for row in store.all('services')}
            parents, _ = validate_groups(registry)
            targets = {sid, *service.get('component_ids', [])}
            expected = {key: registry[key] for key in targets}
            eligible = host.get('status') == 'online' and all(registry[key].get('status') == 'running' and registry[key].get('capabilities', {}).get('control') for key in targets) and sid not in parents and not host_operation_busy(host['id'])
            if service.get('component_ids'):
                eligible = eligible and not any(row['id'] not in targets and row.get('status') == 'running' and targets.intersection(row.get('dependencies', [])) for row in registry.values())
            context = hashlib.sha256(json.dumps({key: {field: item.get(field) for field in ('revision', 'host_id', 'runtime', 'control_handle', 'component_ids', 'idle_policy')} for key, item in sorted(expected.items())}, sort_keys=True).encode()).hexdigest() if service.get('component_ids') else None
            signal = None
            if eligible:
                try:
                    signals = []
                    for profile in [policy.profile, *policy.component_profiles.values()]:
                        result = {'idle': False} if demo else await agent_request(host, 'POST', '/idle/check', {'profile': profile, 'timeout_s': 5}, timeout=8)
                        signals.append(result.get('idle') if isinstance(result, dict) and type(result.get('idle')) is bool else None)
                    signal = False if False in signals else None if None in signals else True
                except HTTPException:
                    pass
            async with lock:
                current = require('services', sid)
                current_host = require('hosts', host['id'])
                if any(current.get(field) != service.get(field) for field in ('revision', 'host_id', 'status', 'observed_at', 'control_handle')) or any(current_host.get(field) != host.get(field) for field in ('status', 'agent_url', 'token_env', 'signing_env', 'active_os', 'os', 'physical_host_id')):
                    signal = None
                if any(require('services', key) != value for key, value in expected.items()) or host_operation_busy(host['id']):
                    signal = None
                previous = current.get('idle_state', {})
                if context and previous.get('context') != context:
                    previous = {}
                current['idle_state'] = idle_observe(previous, signal, policy.minutes)
                if context:
                    current['idle_state']['context'] = context
                store.put('services', current)
                ready = current['idle_state']['ready']
                expected[sid] = current
            if ready:
                result = await control_group(sid, Action(action='stop', acknowledge_components=True), idle_expected=expected, idle_host=host) if service.get('component_ids') else await control_single(sid, Action(action='stop'), idle_revision=service['revision'])
                store.audit('idle.stop', result['status'], 'Stopped after explicit consecutive idle observations; manual wake available after verified sleep', sid, host['id'])
            return decorate(require('services', sid))
        finally:
            idle_running.discard(sid)

    def persistence_cached(hid):
        host = require('hosts', hid)
        with store.connection() as db:
            row = db.execute("SELECT ts,body FROM host_inventory WHERE host_id=? AND provider='persistence'", (hid,)).fetchone()
        result = json.loads(row['body']) if row else persistence_view(persistence_demo(), []) if demo else {'rows': [], 'changes': [], 'warnings': [], 'gaps': [], 'fingerprint': '', 'baseline_rows': []}
        stamp = row['ts'] if row else now() if demo else None
        result.update(ts=stamp, stale=host.get('status') != 'online' or not stamp or (datetime.now(timezone.utc) - datetime.fromisoformat(stamp)).total_seconds() > 300 or result.get('active_os', host.get('active_os')) != host.get('active_os'))
        return result

    @app.get('/api/v1/hosts/{hid}/persistence')
    def persistence_inventory(hid: str):
        value = persistence_cached(hid)
        return {key: item for key, item in value.items() if key != 'baseline_rows'}

    @app.post('/api/v1/hosts/{hid}/persistence/refresh')
    async def persistence_refresh(hid: str):
        host = require('hosts', hid)
        if host.get('status') != 'online':
            raise HTTPException(409, 'Persistence review requires an online verified host')
        key = 'persistence:' + hid
        if key in inventory_running:
            raise HTTPException(409, 'Persistence inventory is already refreshing')
        inventory_running.add(key)
        try:
            payload = persistence_demo() if demo else await agent_request(host, 'GET', '/inventory/persistence', timeout=20)
            current = verified_persistence(payload)
            async with lock:
                updated = require('hosts', hid)
                if any(updated.get(field) != host.get(field) for field in ('agent_url', 'token_env', 'signing_env', 'physical_host_id', 'active_os')) or updated.get('status') != 'online':
                    raise HTTPException(409, 'Host identity or connection changed during the inventory read')
                previous = persistence_cached(hid)
                baseline = previous.get('baseline_rows', []) if previous.get('active_os', host.get('active_os')) == host.get('active_os') else []
                value = persistence_view(current, baseline)
                value['active_os'] = host.get('active_os')
                with store.connection() as db:
                    db.execute('INSERT OR REPLACE INTO host_inventory VALUES(?,?,?,?)', (hid, 'persistence', now(), json.dumps(value)))
                    store.audit('persistence.scanned', 'warning' if value['changes'] else 'success', str(len(value['changes'])) + ' unreviewed metadata changes; no runtime permissions granted', host_id=hid, db=db)
            return persistence_inventory(hid)
        finally:
            inventory_running.discard(key)

    @app.post('/api/v1/hosts/{hid}/persistence/review')
    async def persistence_review(hid: str, body: InventoryReview):
        async with lock:
            value = persistence_cached(hid)
            if value['stale'] or value['fingerprint'] != body.fingerprint:
                raise HTTPException(409, 'Persistence inventory changed or became stale; refresh and review again')
            # Incomplete providers retain their old baseline rather than losing
            # entries and later reporting false "new" or "gone" changes.
            baseline = {row['id']: row for row in value.get('baseline_rows', []) if row['kind'] not in value.get('complete', [])}
            baseline.update({row['id']: row for row in value['rows']})
            value.update(baseline_rows=list(baseline.values()), changes=[])
            for field in ('ts', 'stale'):
                value.pop(field, None)
            with store.connection() as db:
                db.execute('INSERT OR REPLACE INTO host_inventory VALUES(?,?,?,?)', (hid, 'persistence', now(), json.dumps(value)))
                store.audit('persistence.reviewed', 'success', 'Metadata baseline acknowledged; no execution or allow-list changes', host_id=hid, db=db)
        return persistence_inventory(hid)

    @app.get("/api/v1/containers")
    def container_inventory():
        return [row for host in store.all("hosts") for row in containers_for(host["id"])]

    @app.get("/api/v1/hosts/{hid}/containers/{ref}/logs")
    async def container_logs(hid: str, ref: str, lines: int = Query(300, ge=1, le=5000), download: bool = False):
        row = require_container(hid, ref)
        if row["stale"] or not row.get("capabilities", {}).get("logs"):
            raise HTTPException(403, "Container logs require current inventory and an agent allow-list entry")
        result = {"content": f"{now()} [DEMO] {row['name']} container output. No real host was contacted.\n"} if demo else await agent_request(require("hosts", hid), "POST", "/logs", {"runtime": "docker", "handle": {"container": row["name"]}, "lines": lines})
        if download:
            store.audit("container.logs.download", "success", "Container snapshot downloaded: " + row["name"], host_id=hid)
            return Response(result.get("content", ""), media_type="text/plain", headers={"Content-Disposition": 'attachment; filename="container-logs.txt"'})
        return result

    @app.post("/api/v1/hosts/{hid}/containers/{ref}/control")
    async def container_control(hid: str, ref: str, body: Action):
        operation_id = str(uuid.uuid4())
        async with lock:
            row = require_container(hid, ref)
            host = require("hosts", hid)
            if row["stale"] or not row.get("capabilities", {}).get("control"):
                raise HTTPException(403, "Container control requires current inventory and an agent allow-list entry")
            if row.get("project") and not body.acknowledge_dependencies:
                raise HTTPException(409, "This container belongs to a Compose project; confirm the effect on its service")
            if host_operation_busy(hid):
                raise HTTPException(409, "Another runtime operation is running on this host")
            with store.connection() as db:
                db.execute("INSERT INTO operations VALUES(?,?,?,?,?,?)", (operation_id, "container:" + hid + ":" + ref, body.action, "running", now(), ""))
                if not demo:
                    inventory = db.execute("SELECT body FROM container_inventory WHERE host_id=?", (hid,)).fetchone()
                    rows = json.loads(inventory["body"])
                    for item in rows:
                        if item["agent_ref"] == ref:
                            item["unverified"] = True
                    db.execute("UPDATE container_inventory SET body=? WHERE host_id=?", (json.dumps(rows), hid))
            if not demo:
                for linked in store.all("services"):
                    handle = linked.get("control_handle", {})
                    if linked["host_id"] == hid and (handle.get("container") == row["name"] or row.get("project") and handle.get("project") == row["project"]):
                        linked["status"] = "unknown"
                        store.put("services", linked)
            store.audit("container." + body.action, "running", row["name"], host_id=hid)
        try:
            result = {"output": "Demo simulation; no real host changed"} if demo else await agent_request(host, "POST", "/control", {"runtime": "docker", "handle": {"container": row["name"]}, "action": body.action}, timeout=50)
            outcome, detail = "success", redact(result.get("output", ""))
            if demo:
                linked = store.get("services", row.get("service_id", ""))
                if linked:
                    linked["status"] = "stopped" if body.action == "stop" else "running"
                    store.put("services", linked)
            else:
                try:
                    observed = await agent_request(host, "POST", "/scan", {"include_system": True}, timeout=30)
                    async with lock:
                        update_observations(hid, observed)
                except HTTPException:
                    detail += "\nCommand completed; resulting inventory could not be verified."
        except HTTPException as exc:
            outcome, detail = ("unknown" if exc.status_code in (503, 504) else "failed"), str(exc.detail)
        with store.connection() as db:
            db.execute("UPDATE operations SET status=?,detail=? WHERE id=?", (outcome, detail, operation_id))
            store.audit("container." + body.action, outcome, row["name"] + ": " + detail, host_id=hid, db=db)
        return {"operation_id": operation_id, "status": outcome, "detail": detail, "container": require_container(hid, ref) if any(r["agent_ref"] == ref for r in containers_for(hid)) else None}

    @app.get("/api/v1/services/{sid}/logs")
    async def logs(sid: str, lines: int = Query(300, ge=1, le=5000)):
        service = require("services", sid)
        if not service.get("capabilities", {}).get("logs"):
            raise HTTPException(403, "Log access is not enabled on this agent")
        if demo:
            return {"content": f"{now()} [DEMO] {service['name']} log preview\n{now()} [INFO] Configuration loaded\n{now()} [INFO] Service state: {service.get('status', 'unknown')}\n{now()} [INFO] This is sample output. No live host is connected.\n",
                    "mode": "snapshot", "demo": True}
        host = require("hosts", service["host_id"])
        return await agent_request(host, "POST", "/logs", {"runtime": service["runtime"], "handle": {**service["control_handle"], "agent_ref": service.get('agent_ref', '')}, "action": "start", "lines": lines})

    @app.get('/api/v1/services/{sid}/logs/stream')
    async def service_log_stream(sid: str, lines: int = Query(300, ge=1, le=5000)):
        service = require('services', sid)
        host = require('hosts', service['host_id'])
        if host.get('status') != 'online' or not service.get('capabilities', {}).get('logs'):
            raise HTTPException(403, 'Live logs require an online host and explicit log permission')
        payload = {'runtime': service['runtime'], 'handle': {**service['control_handle'], 'agent_ref': service.get('agent_ref', '')}, 'lines': lines}
        headers = {} if demo else agent_headers(host, 'POST', '/logs/stream', payload)
        if len(log_followers) >= 8:
            raise HTTPException(429, 'Controller log follower limit reached')
        async def generate():
            ticket = object()
            if len(log_followers) >= 8:
                yield log_frame('error', 'Controller log follower limit reached')
                return
            log_followers.add(ticket)
            store.audit('logs.follow', 'running', 'Bounded read-only log follower opened', sid, host['id'])
            try:
                if demo:
                    for index in range(150):
                        yield log_frame('log', f'{now()} [DEMO] {service["name"]}: illustrative live output {index + 1}\n')
                        await asyncio.sleep(2)
                    yield log_frame('end', 'Demo follower ended')
                else:
                    async with asyncio.timeout(310):
                        async with httpx.AsyncClient(timeout=httpx.Timeout(30, read=20), follow_redirects=False, trust_env=False) as client:
                            async with client.stream('POST', host['agent_url'] + '/logs/stream', json=payload, headers=headers) as response:
                                if response.status_code != 200:
                                    yield log_frame('error', 'Agent refused the log follower; verify permissions and availability')
                                    return
                                buffer, total = b'', 0
                                async for chunk in response.aiter_bytes():
                                    total += len(chunk)
                                    buffer += chunk
                                    if len(buffer) > 650000 or total > 16_000_000:
                                        yield log_frame('error', 'Agent log stream exceeded size limits')
                                        return
                                    while b'\n' in buffer:
                                        raw, buffer = buffer.split(b'\n', 1)
                                        if len(raw) > 650000:
                                            raise ValueError('Oversized frame')
                                        row = json.loads(raw)
                                        if not isinstance(row, dict) or row.get('kind') not in ('log', 'heartbeat', 'end', 'error') or not isinstance(row.get('content'), str) or len(row['content']) > 100001:
                                            raise ValueError('Invalid log frame')
                                        yield log_frame(row['kind'], redact(row['content']))
                                    current_host = require('hosts', host['id'])
                                    current_service = require('services', sid)
                                    if any(current_host.get(key) != host.get(key) for key in ('agent_url', 'token_env', 'signing_env', 'active_os')) or current_host.get('status') != 'online' or current_service.get('host_id') != host['id'] or not current_service.get('capabilities', {}).get('logs'):
                                        yield log_frame('end', 'Host connection or log permission changed; follower closed')
                                        return
            except (httpx.HTTPError, TimeoutError, ValueError):
                yield log_frame('error', 'Log stream ended or returned invalid data; reconnect after checking the host')
            finally:
                log_followers.discard(ticket)
                store.audit('logs.follow', 'finished', 'Read-only follower closed', sid, host['id'])
        return StreamingResponse(generate(), media_type='application/x-ndjson', headers={'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no'})

    @app.get('/api/v1/events/stream')
    async def event_stream(after: int = Query(0, ge=0)):
        if len(event_followers) >= 8:
            raise HTTPException(429, 'Event follower limit reached')
        async def generate():
            ticket = object()
            if len(event_followers) >= 8:
                return
            event_followers.add(ticket)
            cursor = after
            deadline = asyncio.get_running_loop().time() + 300
            try:
                while asyncio.get_running_loop().time() < deadline:
                    with store.connection() as db:
                        rows = [dict(row) for row in db.execute('SELECT * FROM audit WHERE id>? ORDER BY id LIMIT 100', (cursor,))]
                    for row in rows:
                        cursor = row['id']
                        row['detail'] = redact(row['detail'])[:100000]
                        yield 'id: ' + str(cursor) + '\ndata: ' + json.dumps(row) + '\n\n'
                    yield ': heartbeat\n\n'
                    await asyncio.sleep(2)
            finally:
                event_followers.discard(ticket)
        return StreamingResponse(generate(), media_type='text/event-stream', headers={'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no'})

    def socket_authorized(socket):
        if socket.url.hostname not in allowed_hosts or socket.headers.get('origin') and socket.headers['origin'] not in allowed_origins:
            return False
        supplied = socket.headers.get('authorization', '').removeprefix('Bearer ')
        if token or owner_login.enabled:
            return bool(token and hmac.compare_digest(supplied.encode(), token.encode())) or owner_login.authorized(socket.cookies.get(COOKIE))
        return bool(socket.client and socket.client.host in ('127.0.0.1', '::1', 'testclient'))

    @app.websocket('/api/v1/events/ws')
    async def events_socket(socket: WebSocket, after: int = Query(0, ge=0)):
        if not socket_authorized(socket):
            await socket.close(code=1008)
            return
        source = None
        try:
            response = await event_stream(after)
            source = response.body_iterator
            await socket.accept()
            async for row in source:
                if row.startswith('id: '):
                    data = json.loads(row.split('\ndata: ', 1)[1])
                    await socket.send_json({'kind': 'event', 'event': data})
                else:
                    await socket.send_json({'kind': 'heartbeat'})
        except (WebSocketDisconnect, HTTPException, RuntimeError):
            pass
        finally:
            if source:
                await source.aclose()
            try:
                await socket.close()
            except RuntimeError:
                pass

    @app.websocket('/api/v1/state/ws')
    async def state_socket(socket: WebSocket):
        if not socket_authorized(socket) or len(state_followers) >= 8:
            await socket.close(code=1008)
            return
        ticket = object()
        state_followers.add(ticket)
        try:
            await socket.accept()
            deadline = asyncio.get_running_loop().time() + 300
            while asyncio.get_running_loop().time() < deadline:
                snapshot = {'kind': 'state', 'hosts': [{key: row.get(key) for key in ('id', 'name', 'status', 'active_os', 'last_seen', 'transport')} for row in hosts()],
                    'services': [{key: row.get(key) for key in ('id', 'name', 'host_id', 'host_status', 'runtime', 'status', 'observed_status', 'observed_at', 'capabilities', 'metrics', 'group_parent_id')} for row in services()]}
                encoded = json.dumps(snapshot, allow_nan=False)
                if len(encoded.encode()) > 4_000_000:
                    await socket.send_json({'kind': 'error', 'detail': 'State inventory exceeds supported size; use filtered REST queries'})
                    break
                await socket.send_text(encoded)
                await asyncio.sleep(15)
        except (WebSocketDisconnect, RuntimeError, ValueError):
            pass
        finally:
            state_followers.discard(ticket)
            try:
                await socket.close()
            except RuntimeError:
                pass

    @app.websocket('/api/v1/services/{sid}/logs/ws')
    async def logs_socket(socket: WebSocket, sid: str, lines: int = Query(300, ge=1, le=5000)):
        if not socket_authorized(socket):
            await socket.close(code=1008)
            return
        source = None
        try:
            response = await service_log_stream(sid, lines)
            source = response.body_iterator
            await socket.accept()
            async for row in source:
                await socket.send_text(row)
        except (WebSocketDisconnect, HTTPException, RuntimeError):
            pass
        finally:
            if source:
                await source.aclose()
            try:
                await socket.close()
            except RuntimeError:
                pass

    @app.get("/api/v1/services/{sid}/logs/download")
    async def download_logs(sid: str, lines: int = Query(300, ge=1, le=5000)):
        result = await logs(sid, lines)
        store.audit("logs.download", "success", f"Downloaded snapshot (up to {lines} lines)", sid)
        return Response(result.get("content", ""), media_type="text/plain", headers={"Content-Disposition": f'attachment; filename="{sid}-logs.txt"'})

    @app.get("/api/v1/services/{sid}/runtime")
    async def runtime_documents(sid: str):
        service = require("services", sid)
        locations = service.get("locations") or {}
        paths = locations.get("configuration") or service.get("runtime_details", {}).get("configuration", [])
        if demo:
            if service["runtime"] == "compose":
                try:
                    sample = await files(sid, "compose.yaml", 0)
                    document = {"path": "compose.yaml", "content": sample["content"], "readonly": True}
                except HTTPException as exc:
                    document = {"path": "compose.yaml", "error": str(exc.detail)}
                return {"details": service.get("runtime_details", {}), "documents": [document], "demo": True}
            return {"details": service.get("runtime_details", {}), "documents": [{"path": "compose.yaml" if service["runtime"] == "compose" else service["id"] + ".service", "content": "# Simulated runtime configuration; no real host read.\n" + ("services:\n  app:\n    image: example/demo:1\n    restart: unless-stopped\n" if service["runtime"] == "compose" else "[Unit]\nDescription=Demo service\n[Service]\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n"), "readonly": True}], "demo": True}
        documents = []
        from urllib.parse import urlencode
        async def read_document(path):
            if not service.get("capabilities", {}).get("files"):
                return {"path": path, "error": "Configuration preview requires an approved file root"}
            host = require("hosts", service["host_id"])
            if host.get("status") != "online":
                return {"path": path, "error": "Host is offline; configuration cannot be read"}
            query = urlencode({"ref": service.get("agent_ref") or service["control_handle"].get("agent_ref", ""), "path": path})
            try:
                result = await agent_request(host, "GET", "/documents?" + query, timeout=6)
                return {**result, "path": path}
            except HTTPException as exc:
                return {"path": path, "error": str(exc.detail)}
        documents = await asyncio.gather(*(read_document(path) for path in paths[:5]))
        documents += [{"path": path, "error": "Additional document: use Files to preview it (five automatic previews per request)"} for path in paths[5:30]]
        return {"details": service.get("runtime_details", {}), "documents": documents, "demo": False}

    @app.get("/api/v1/services/{sid}/files")
    async def files(sid: str, path: str = "", root_index: int = Query(0, ge=0)):
        service = require("services", sid)
        if not service.get("capabilities", {}).get("files"):
            raise HTTPException(403, "No read-only file roots are configured on this agent")
        if demo:
            if path == "":
                return {"kind": "directory", "path": "", "entries": [{"name": "compose.yaml", "directory": False, "size": 142},
                        {"name": "README.md", "directory": False, "size": 86}], "roots": service.get("paths", []), "readonly": True}
            samples = {"compose.yaml": f"# Demonstration only\nservices:\n  {service['id']}:\n    image: example/{service['id']}:pinned-version\n    restart: unless-stopped\n",
                       "README.md": "# Sample service files\n\nConnect an agent and explicitly configure file_roots to browse real configuration.\n"}
            if path not in samples:
                raise HTTPException(404, "Sample file not found")
            with store.connection() as db:
                edited = db.execute("SELECT body FROM demo_files WHERE service_id=? AND path=?", (sid, path)).fetchone()
            content = edited["body"] if edited else samples[path]
            return {"kind": "file", "path": path, "content": content, "readonly": False, "editable": True,
                    "etag": hashlib.sha256(content.encode()).hexdigest(), "resolved_path": "demo:" + sid + ":" + path, "root_index": root_index}
        from urllib.parse import urlencode
        query = urlencode({"ref": service.get("agent_ref") or service["control_handle"].get("agent_ref", ""), "path": path, "root_index": root_index})
        return await agent_request(require("hosts", service["host_id"]), "GET", "/files?" + query)

    async def current_configuration(sid, path, root_index):
        service = require("services", sid)
        info = await files(sid, path, root_index)
        if (not isinstance(info, dict) or not isinstance(info.get("content"), str) or not isinstance(info.get("etag"), str)
                or not re.fullmatch(r"[a-f0-9]{64}", info["etag"]) or info.get("path") != path or not isinstance(info.get("resolved_path"), str)):
            raise HTTPException(502, "Agent returned incomplete file metadata; reload before saving")
        if info.get("kind") != "file" or info.get("truncated") or info.get("secret_excluded") or secret_reasons(info.get("content", "")):
            raise HTTPException(403, "This file cannot be included in configuration history")
        info["root_index"] = root_index
        return service, info

    @app.post("/api/v1/services/{sid}/files/validate")
    def config_validate(sid: str, body: ConfigEdit):
        require("services", sid)
        record_secrets(store, sid, 'Rejected configuration draft', secret_reasons(body.content) + (['Secret-bearing filename; content was not read'] if secret_filename(body.path) else []))
        return validate_configuration(body.path, body.content)

    @app.put("/api/v1/services/{sid}/files")
    async def config_save(sid: str, body: ConfigEdit):
        async with config_lock:
            operation_id = str(uuid.uuid4())
            async with lock:
                service = require("services", sid)
                host = require("hosts", service["host_id"])
                if host_operation_busy(host["id"]):
                    raise HTTPException(409, "Wait for the host operation before changing its configuration")
                if not demo and host.get("status") != "online":
                    raise HTTPException(409, "Host must be verified online before saving configuration")
                with store.connection() as db:
                    db.execute("INSERT INTO operations VALUES(?,?,?,?,?,?)", (operation_id, sid, "config.save", "running", now(), ""))
            prepared, write_attempted = None, False
            outcome, detail = "failed", "Configuration save stopped before writing"
            try:
                _, info = await current_configuration(sid, body.path, body.root_index)
                if info.get("etag") != body.etag:
                    raise HTTPException(409, "File changed since it was opened; reload before saving")
                if not info.get("editable"):
                    raise HTTPException(403, "Config edits require an explicit agent allow_file_edits entry")
                record_secrets(store, sid, 'Rejected configuration draft', secret_reasons(body.content) + (['Secret-bearing filename; content was not read'] if secret_filename(body.path) else []))
                validation = validate_configuration(body.path, body.content)
                if secret_reasons(body.message):
                    raise HTTPException(422, "Commit messages cannot contain secret values")
                key = file_key(service, info)
                with store.connection() as db:
                    captured = db.execute("SELECT id FROM config_versions WHERE service_id=? AND file_key=? AND etag=? AND status IN ('checkpoint','applied')", (sid, key, body.etag)).fetchone()
                if not captured:
                    await asyncio.to_thread(config_snapshot, store, service, info, info["content"], "Before first managed edit", "checkpoint")
                prepared = await asyncio.to_thread(config_snapshot, store, service, info, body.content, body.message, "prepared")
                async with lock:
                    current = require("services", sid)
                    current_host = require("hosts", host["id"])
                    if any(current.get(field) != service.get(field) for field in ("host_id", "agent_ref", "control_handle")) or any(current_host.get(field) != host.get(field) for field in ("agent_url", "token_env", "signing_env")):
                        raise HTTPException(409, "Service connection changed during save; reload before retrying")
                    if not demo and current_host.get("status") != "online":
                        raise HTTPException(409, "Host became unavailable before the configuration write")
                write_attempted = True
                if demo:
                    content = body.content.replace("\r\n", "\n")
                    result = {"kind": "file", "path": body.path, "content": content, "etag": hashlib.sha256(content.encode()).hexdigest(), "editable": True, "readonly": False, "resolved_path": info["resolved_path"]}
                    with store.connection() as db:
                        db.execute("INSERT OR REPLACE INTO demo_files VALUES(?,?,?)", (sid, body.path, content))
                else:
                    from urllib.parse import urlencode
                    query = urlencode({"ref": service.get("agent_ref") or service["control_handle"].get("agent_ref", ""), "path": body.path, "root_index": body.root_index})
                    result = await agent_request(host, "PUT", "/files?" + query, {"content": body.content, "etag": body.etag, "validate_runtime": body.validate_runtime}, timeout=25)
                if (not isinstance(result, dict) or result.get("kind") != "file" or result.get("path") != body.path
                        or not isinstance(result.get("etag"), str) or not re.fullmatch(r"[a-f0-9]{64}", result["etag"])
                        or result.get("content") != body.content.replace("\r\n", "\n")
                        or result.get("etag") not in {hashlib.sha256(body.content.replace("\r\n", "\n").encode()).hexdigest(), hashlib.sha256(body.content.replace("\r\n", "\n").replace("\n", "\r\n").encode()).hexdigest()}
                        or result.get("resolved_path") != info.get("resolved_path")):
                    raise HTTPException(502, "Agent save result could not be verified; outcome is unknown. Reload before retrying")
                with store.connection() as db:
                    db.execute("UPDATE config_versions SET status='applied',etag=? WHERE id=?", (result["etag"], prepared))
                outcome, detail = "success", "Configuration saved with local Git history: " + body.path
                return result | {"version_id": prepared, "validation": validation, "demo": demo}
            except HTTPException as exc:
                outcome = "unknown" if write_attempted and exc.status_code not in (400, 401, 403, 404, 409, 413, 415, 422) else "failed"
                detail = "Save did not return a verified result; reload before retrying"
                raise
            except BaseException:
                outcome = "unknown" if write_attempted else "failed"
                detail = "Configuration save interrupted; reload before retrying"
                raise
            finally:
                # Synchronous finalization also runs when the request is cancelled.
                with store.connection() as db:
                    if prepared and outcome != "success":
                        db.execute("UPDATE config_versions SET status=? WHERE id=?", (outcome, prepared))
                    db.execute("UPDATE operations SET status=?,detail=? WHERE id=?", (outcome, detail, operation_id))
                    store.audit("config.saved", outcome, detail, sid, host["id"], db=db)

    @app.post("/api/v1/services/{sid}/config-capture")
    async def capture_configuration(sid: str):
        service = require("services", sid)
        if not service.get("track_configuration"):
            raise HTTPException(409, "Enable external configuration tracking in Notes & setup first")
        if sid in config_capturing:
            raise HTTPException(409, "Configuration capture is already running")
        config_capturing.add(sid)
        operation_id = None
        outcome = "failed"
        try:
            async with config_lock:
                async with lock:
                    service = require("services", sid)
                    if not service.get("track_configuration"):
                        raise HTTPException(409, "External configuration tracking was disabled")
                    if host_operation_busy(service["host_id"]):
                        raise HTTPException(409, "Wait for the host operation before capturing configuration")
                    operation_id = str(uuid.uuid4())
                    with store.connection() as db:
                        db.execute("INSERT INTO operations VALUES(?,?,?,?,?,?)", (operation_id, sid, "config.capture", "running", now(), ""))
                paths = (service.get("locations") or {}).get("configuration") or service.get("runtime_details", {}).get("configuration", [])
                if demo and not paths:
                    paths = ["compose.yaml"]
                captured, skipped = [], []
                from urllib.parse import urlencode
                for path in paths[:5]:
                    try:
                        if demo:
                            info = await files(sid, path.split('/')[-1], 0)
                        else:
                            if not service.get("capabilities", {}).get("files"):
                                raise HTTPException(403, "No approved configuration roots")
                            host = require("hosts", service["host_id"])
                            if host.get("status") != "online":
                                raise HTTPException(409, "Host is offline")
                            query = urlencode({"ref": service.get("agent_ref") or service["control_handle"].get("agent_ref", ""), "path": path})
                            info = await agent_request(host, "GET", "/documents?" + query, timeout=6)
                        if (not isinstance(info, dict) or info.get("kind") != "file" or not isinstance(info.get("content"), str)
                                or not isinstance(info.get("etag"), str) or not re.fullmatch(r"[a-f0-9]{64}", info["etag"])
                                or not isinstance(info.get("resolved_path"), str) or not isinstance(info.get("path"), str)):
                            raise HTTPException(502, "Agent returned incomplete configuration metadata")
                        if info.get("truncated") or info.get("secret_excluded") or secret_reasons(info["content"]):
                            raise HTTPException(403, "Secret-bearing, large or incomplete configuration is excluded")
                        key = file_key(service, info)
                        with store.connection() as db:
                            last = db.execute("SELECT etag FROM config_versions WHERE service_id=? AND file_key=? AND status IN ('checkpoint','applied') ORDER BY id DESC LIMIT 1", (sid, key)).fetchone()
                        if not last or last["etag"] != info.get("etag"):
                            version_id = await asyncio.to_thread(config_snapshot, store, service, info, info["content"], "External edit observed" if last else "External configuration baseline", "applied" if last else "checkpoint")
                            captured.append(version_id)
                            store.audit("config.external", "success", "Captured approved configuration: " + info["path"], sid)
                    except HTTPException as exc:
                        skipped.append({"path": path, "reason": str(exc.detail)})
                outcome = "success" if not skipped else "warning"
                return {"captured": captured, "skipped": skipped, "limited": len(paths) > 5, "demo": demo}
        finally:
            config_capturing.discard(sid)
            if operation_id:
                with store.connection() as db:
                    db.execute("UPDATE operations SET status=?,detail=? WHERE id=?", (outcome, "Configuration capture finished; see per-file results", operation_id))

    @app.get("/api/v1/services/{sid}/config-versions")
    async def configuration_versions(sid: str, path: str, root_index: int = Query(0, ge=0)):
        service, info = await current_configuration(sid, path, root_index)
        with store.connection() as db:
            rows = [dict(row) for row in db.execute("SELECT * FROM config_versions WHERE service_id=? AND file_key=? ORDER BY id DESC LIMIT 100", (sid, file_key(service, info)))]
        return {"versions": rows, "current_etag": info.get("etag")}

    @app.get("/api/v1/services/{sid}/config-version")
    async def configuration_version(sid: str, version_id: int, path: str, root_index: int = Query(0, ge=0)):
        service, info = await current_configuration(sid, path, root_index)
        return await asyncio.to_thread(config_version, store, sid, file_key(service, info), version_id)

    @app.get("/api/v1/services/{sid}/config-diff")
    async def configuration_diff(sid: str, before: int, after: int, path: str, root_index: int = Query(0, ge=0)):
        service, info = await current_configuration(sid, path, root_index)
        key = file_key(service, info)
        first, second = await asyncio.gather(asyncio.to_thread(config_version, store, sid, key, before), asyncio.to_thread(config_version, store, sid, key, after))
        difference = ''.join(difflib.unified_diff(first["content"].splitlines(keepends=True), second["content"].splitlines(keepends=True), fromfile='Version ' + str(before), tofile='Version ' + str(after)))
        return {"diff": difference[:100000], "truncated": len(difference) > 100000}

    @app.post("/api/v1/services/{sid}/config-restore")
    async def configuration_restore(sid: str, body: ConfigRestore):
        service, info = await current_configuration(sid, body.path, body.root_index)
        restored = await asyncio.to_thread(config_version, store, sid, file_key(service, info), body.version_id)
        result = await config_save(sid, ConfigEdit(path=body.path, root_index=body.root_index, etag=body.etag, content=restored["content"], message="Restored configuration version " + str(body.version_id), validate_runtime=body.validate_runtime))
        store.audit("config.restored", "success", "Restored version " + str(body.version_id), sid)
        return result

    @app.get("/api/v1/services/{sid}/files/download")
    async def file_download(sid: str, path: str, root_index: int = Query(0, ge=0)):
        service = require("services", sid)
        if not service.get("capabilities", {}).get("files"):
            raise HTTPException(403, "No read-only file roots are configured on this agent")
        if demo:
            data = (await files(sid, path, root_index)).get("content", "").encode("utf-8")
        else:
            from urllib.parse import urlencode
            query = urlencode({"ref": service.get("agent_ref") or service["control_handle"].get("agent_ref", ""), "path": path, "root_index": root_index, "download": "true"})
            result = await agent_request(require("hosts", service["host_id"]), "GET", "/files?" + query)
            try:
                data = base64.b64decode(result["data"], validate=True)
            except (KeyError, ValueError) as exc:
                raise HTTPException(502, "Agent returned an invalid file download") from exc
            if len(data) > 2_000_000:
                raise HTTPException(413, "File download exceeds the 2 MB limit")
        store.audit("files.download", "success", "Downloaded approved read-only file", sid)
        # Generic attachment prevents executable HTML/SVG from opening inline.
        return Response(data, media_type="application/octet-stream", headers={"Content-Disposition": f'attachment; filename="{sid}-file.bin"', "X-Content-Type-Options": "nosniff"})

    @app.post("/api/v1/hosts/{hid}/scan")
    async def scan(hid: str, options: ScanOptions):
        host = require("hosts", hid)
        if demo:
            result = {"services": [{"agent_ref": "compose-demo-grafana", "name": "Grafana", "runtime": "compose", "status": "running",
                      "description": "Sample discovery candidate. Review before adding to your demo registry.", "tags": ["monitoring"],
                      "ports": ["3000/tcp"], "urls": [], "paths": ["/opt/services/grafana"], "dependencies": [],
                      "control_handle": {"project": "grafana", "path": "/opt/services/grafana"},
                      "capabilities": {"control": True, "logs": True, "files": True}}], "containers": [], "warnings": [], "completed_runtimes": []}
        else:
            result = await agent_request(host, "POST", "/scan", options.model_dump(), timeout=30)
        existing = [x for x in store.all("services") if x["host_id"] == hid]
        candidates = proposals(host, existing, result)
        scan_id = str(uuid.uuid4())
        review = {"scan_id": scan_id, "host_id": hid, "candidates": candidates, "created_at": now(),
                  "warnings": result.get("warnings", []), "containers": result.get("containers", []), "demo": demo, "reviewed": False}
        save_scan(store, review)
        async with lock:
            host = require("hosts", hid)
            if not demo:
                host.update(status="online", last_seen=now())
                store.put("hosts", host)
                update_observations(hid, result)
            host.update(discovery_checked_at=review["created_at"], discovery_pending=sum(candidate["change"] != "unchanged" for candidate in candidates))
            store.put("hosts", host)
            for candidate in candidates:
                old = store.get("services", candidate["id"])
                if old:
                    old.update(status=candidate["status"], capabilities=candidate["capabilities"], agent_ref=candidate["agent_ref"], observed_at=now())
                    store.put("services", old)
            store.audit("discovery.scan", "success", f"{len(candidates)} candidates", host_id=hid)
        return review

    @app.get("/api/v1/hosts/{hid}/discovery")
    def latest_discovery(hid: str):
        require("hosts", hid)
        return get_scan(store, host_id=hid)

    @app.post("/api/v1/discovery/accept")
    async def accept(body: DiscoveryAccept):
        async with lock:
            result = get_scan(store, scan_id=body.scan_id)
            if not result or result.get("reviewed") or (datetime.now(timezone.utc) - datetime.fromisoformat(result["created_at"])).total_seconds() > 86400:
                raise HTTPException(409, "Discovery expired. Scan again.")
            if host_operation_busy(result["host_id"]):
                raise HTTPException(409, "Wait for the host operation before accepting discovery")
            candidates = {x["agent_ref"]: x for x in result["candidates"]}
            if not set(body.refs).issubset(candidates):
                raise HTTPException(422, "Selection contains unknown candidates")
            # Preflight every selection before applying any part of a review.
            # Owner edits and host reassignment must not be overwritten by an old proposal.
            for ref in set(body.refs):
                candidate = candidates[ref]
                current = store.get("services", candidate["id"])
                if candidate.get("existing_id"):
                    if not current or current["host_id"] != result["host_id"] or current.get("revision", 0) != candidate.get("review_revision"):
                        raise HTTPException(409, "A selected service changed since discovery. Scan again before accepting.")
                elif current:
                    raise HTTPException(409, "A selected service ID now exists. Scan again before accepting.")
            for ref in set(body.refs):
                candidate = dict(candidates[ref])
                change = candidate.pop("change", None)
                candidate.pop("diff", None)
                candidate.pop("existing_id", None)
                candidate.pop("review_revision", None)
                baseline = candidate.pop("snapshot", {})
                old = store.get("services", candidate["id"]) or {}
                candidate.update(source=old.get("source", "discovery"), demo=demo, revision=old.get("revision", 0) + 1,
                                 created_at=old.get("created_at", now()), updated_at=now(), observed_at=now(), reviewed_at=now(),
                                 discovery_baseline=baseline, discovery_changes=[], inventory_status="gone" if change == "gone" else "present")
                # Keep owner-written documentation and manual definitions intact.
                for key in set(("name", "description", "icon", "notes", "tags", "dependencies", "schedule_policy")) | set(old.get("owned_fields", [])):
                    if key in old:
                        candidate[key] = old[key]
                if old.get("source") == "manual":
                    for key in ("paths", "locations", "urls", "ports", "control_handle"):
                        candidate[key] = old[key]
                store.put("services", old | candidate)
                record_secrets(store, candidate['id'], 'Observed discovery metadata', candidate.get('secret_categories', []))
                store.audit("discovery.accept", "success", "Reviewed candidate accepted", candidate["id"], result["host_id"])
            result["reviewed"] = True
            result["accepted_refs"] = sorted(set(body.refs))
            result["rejected_refs"] = sorted(set(candidates) - set(body.refs))
            with store.connection() as db:
                db.execute("UPDATE discovery_scans SET body=? WHERE id=?", (json.dumps(result), body.scan_id))
                store.audit("discovery.reviewed", "success", f"{len(set(body.refs))} accepted; {len(result['rejected_refs'])} left unaccepted", host_id=result["host_id"], db=db)
            host = require("hosts", result["host_id"])
            host["discovery_pending"] = 0
            store.put("hosts", host)
        return {"accepted": len(set(body.refs))}

    @app.post("/api/v1/manifests/preview")
    async def preview(body: ManifestInput):
        async with lock:
            return plan_manifest(store, parse_manifest(body.content))

    @app.post("/api/v1/manifests/apply")
    async def apply(body: ManifestApply):
        async with lock:
            manifest = parse_manifest(body.content)
            affected_hosts = {host.id for host in manifest.hosts} | {item.host_id for item in manifest.services}
            affected_hosts.update(old["host_id"] for item in manifest.services if (old := store.get("services", item.id)))
            if any(host_operation_busy(hid) for hid in affected_hosts):
                raise HTTPException(409, "Wait for host operations before importing definitions")
            plan = plan_manifest(store, manifest)
            if not hmac.compare_digest(plan["fingerprint"], body.fingerprint):
                raise HTTPException(409, "Registry changed since preview. Preview again before applying.")
            return apply_manifest(store, manifest, demo)

    @app.get("/api/v1/audit")
    def audit():
        return store.events(limit=200)

    @app.get("/api/v1/notifications")
    def notifications_status():
        with store.connection() as db:
            rows = [dict(row) for row in db.execute("SELECT id,ts,message,status,attempts,detail FROM notification_outbox ORDER BY id DESC LIMIT 30")]
        return notification_settings(store) | {"deliveries": rows, "demo": demo}

    @app.put("/api/v1/notifications")
    async def notifications_save(body: NotificationSettings):
        async with lock:
            changed = notification_key(notification_settings(store)) != notification_key(body.model_dump())
            with store.connection() as db:
                if changed:
                    db.execute("UPDATE notification_outbox SET status='cancelled',detail='Notification settings changed' WHERE status='pending'")
                db.execute("INSERT OR REPLACE INTO settings VALUES('notifications',?)", (body.model_dump_json(),))
                store.audit("notification.configured", "success", "Notification destination preferences saved", db=db)
        return notifications_status()

    @app.post("/api/v1/notifications/test")
    async def notifications_test():
        if not notification_settings(store)["configured"]:
            raise HTTPException(409, "Configure and enable a notification channel first")
        queue_notification(store, "test:" + str(uuid.uuid4()), "Hearth test notification: your homelab alert channel is configured.")
        return {"outcomes": await flush_notifications(store, demo=demo), "demo": demo}

    @app.get("/api/v1/ai")
    def ai_settings():
        return ai_configuration(store) | {"demo": demo}

    @app.put("/api/v1/ai")
    async def ai_save(body: AISettings):
        if redact(body.model) != body.model:
            raise HTTPException(422, "Model names cannot contain secret assignments")
        async with lock:
            with store.connection() as db:
                db.execute("INSERT INTO settings(key,body) VALUES('ai',?) ON CONFLICT(key) DO UPDATE SET body=excluded.body", (body.model_dump_json(),))
                store.audit("ai.configured", "success", "Local AI preferences saved", db=db)
        return ai_configuration(store) | {"demo": demo}

    @app.get("/api/v1/ai/health")
    async def ai_health():
        config = ai_configuration(store)
        if demo:
            return config | {"available": config["enabled"], "demo": True, "reason": "Demo explanations are simulated; no Ollama request is made" if config["enabled"] else "Local AI is disabled in Settings"}
        return await ai_availability(config)

    @app.post("/api/v1/services/{sid}/explain")
    async def explain_service(sid: str, body: ExplainRequest):
        service = require("services", sid)
        if not ai_configuration(store)["enabled"]:
            raise HTTPException(409, "Local AI is disabled in Settings")
        if demo:
            return {"explanation": "## Demo explanation\n\nThis is sample service output. No Ollama request was made.\n\nFor a real diagnosis, configure a private Ollama endpoint in live mode, then inspect the logs and recent changes.\n\n**Confidence:** No diagnosis can be inferred from synthetic demo logs.",
                    "model": "demo", "context_lines": 0, "advice_only": True, "demo": True}
        text = body.selected_logs
        if not text:
            text = (await logs(sid)).get("content", "")
        with store.connection() as db:
            recent = [dict(row) for row in db.execute("SELECT * FROM config_versions WHERE service_id=? AND status IN ('checkpoint','applied') ORDER BY id DESC LIMIT 10", (sid,))]
        changes = []
        grouped = {}
        for row in recent:
            grouped.setdefault(row["file_key"], []).append(row)
        for key, rows in list(grouped.items())[:3]:
            if len(rows) >= 2:
                try:
                    before = await asyncio.to_thread(config_version, store, sid, key, rows[1]["id"])
                    after = await asyncio.to_thread(config_version, store, sid, key, rows[0]["id"])
                    changes.append({"path": after["path"], "diff": ''.join(difflib.unified_diff(before["content"].splitlines(keepends=True), after["content"].splitlines(keepends=True)))[:8000]})
                except HTTPException:
                    continue
        service = service | {"configuration_diffs": changes}
        result = await ai_explain(service, text, store.events(sid), config=ai_configuration(store), incidents=health_history(store, sid)["incidents"])
        store.audit("ai.explain", "success", "Advice generated by " + result["model"], sid, service["host_id"])
        return result

    @app.post('/api/v1/services/{sid}/summary-draft')
    async def summary_draft(sid: str):
        from controller.ai import draft
        service = require('services', sid)
        config = ai_configuration(store)
        if not config['enabled']:
            raise HTTPException(409, 'Local AI is disabled in Settings')
        context = {key: service.get(key) for key in ('name', 'runtime', 'image', 'ports', 'description', 'runtime_details')}
        context['configuration'] = []
        with store.connection() as db:
            rows = db.execute("SELECT * FROM config_versions WHERE service_id=? AND status IN ('checkpoint','applied') ORDER BY id DESC LIMIT 5", (sid,)).fetchall()
        seen = set()
        for row in rows:
            if row['file_key'] in seen or len(seen) >= 2:
                continue
            seen.add(row['file_key'])
            try:
                version = await asyncio.to_thread(config_version, store, sid, row['file_key'], row['id'])
                if not secret_reasons(version['content']):
                    context['configuration'].append({'path':row['path'], 'content':version['content'][:15000]})
            except HTTPException:
                continue
        result = {'draft':'[DEMO] ' + service['name'] + ' is shown as a ' + service['runtime'] + ' service. This editable description is synthetic; purpose and deployment remain unverified.', 'model':'demo', 'advice_only':True, 'verified':False} if demo else await draft('summary', context, config)
        store.audit('ai.summary', 'success', 'Generated editable description draft; not saved or executed', sid, service['host_id'])
        return result

    @app.get("/api/v1/export")
    def export():
        return Response(export_zip(store), media_type="application/zip", headers={"Content-Disposition": 'attachment; filename="homelab-vault.zip"'})

    @app.get("/api/v1/services/{sid}/markdown")
    def markdown(sid: str):
        service = require("services", sid)
        return Response(service_note(service, {x["id"]: x for x in store.all("hosts")}), media_type="text/markdown",
                        headers={"Content-Disposition": f'attachment; filename="Service--{sid}.md"'})

    @app.post("/api/v1/obsidian/sync")
    async def obsidian_sync():
        async with lock:
            try:
                return sync_vault(store)
            except (OSError, ValueError) as exc:
                raise HTTPException(409, "Vault sync could not complete: " + str(exc)) from exc

    dist = ROOT / "web" / "dist"
    if (dist / "assets").exists():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

    @app.get("/favicon.svg")
    def favicon():
        return FileResponse(ROOT / "web" / "public" / "favicon.svg")

    @app.get("/")
    def index():
        if (dist / "index.html").exists():
            return FileResponse(dist / "index.html")
        return JSONResponse({"message": "Build the frontend with npm run build in web/, or run the Vite development server."})

    @app.get("/{shell_file}")
    def app_shell(shell_file: str):
        if shell_file not in {"index.html", "manifest.webmanifest", "sw.js", "icon-192.png", "icon-512.png"} or not (dist / shell_file).is_file():
            raise HTTPException(404, "Not found")
        media = "application/manifest+json" if shell_file == "manifest.webmanifest" else "application/javascript" if shell_file == "sw.js" else None
        return FileResponse(dist / shell_file, media_type=media, headers={"Cache-Control": "no-cache"})

    terminal_coordinator = Terminals(app, store, demo, require, lock, host_operation_busy, agent_request, allowed_origins, allowed_hosts, owner_login, token)
    app.state.terminals = terminal_coordinator
    from controller.wake import register as register_wake
    register_wake(app, store, demo, require, lock, lambda hid: host_operation_busy(hid, allow_power_pending=True))
    from controller.power import register as register_power
    register_power(app, store, demo, require, lock, host_operation_busy, agent_request)
    from controller.boot import register as register_boot
    from controller.vault import register as register_vault
    register_boot(app,store,demo,require,lock,host_operation_busy,agent_request)
    register_vault(app,store,demo,require,agent_request)
    from controller.host_files import register as register_host_files
    register_host_files(app,demo,require,agent_request)
    from controller.kuma import register as register_kuma
    register_kuma(app,store,demo,require,lock,host_operation_busy)
    from controller.backups import Coordinator as BackupCoordinator
    async def backup_control(sid, action, reservation, guard):
        return await control_single(sid,Action(action=action),reservation=reservation,origin='backup',schedule_guard=guard)
    backup_coordinator = BackupCoordinator(app,store,demo,require,lock,host_operation_busy,agent_request,backup_control,run_health)
    app.state.backups = backup_coordinator
    audit_journal = AuditJournal(app, store)
    app.state.audit_journal = audit_journal

    @app.get('/api/v1/audit/requests')
    def audit_requests():
        return audit_journal.rows()

    @app.get('/api/v1/services/{sid}/audit/requests')
    def service_audit_requests(sid: str):
        require('services', sid)
        return audit_journal.rows(sid)
    return app
