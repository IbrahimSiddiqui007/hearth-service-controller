from __future__ import annotations

import asyncio
import hashlib
import json
import platform
import time
from datetime import datetime, timedelta, timezone

import httpx

from controller.store import Store, now
from shared.models import HealthCheck


def check_key(check: dict | None):
    check = check or {}
    # Changing intervals preserves comparable history; changing destinations
    # starts a new series without deleting results from the previous target.
    return hashlib.sha256(json.dumps({key: check.get(key) for key in ("type", "target", "port")}, sort_keys=True).encode()).hexdigest()


async def probe(check: HealthCheck):
    if check.type == "command":
        raise ValueError("Custom health checks must be dispatched through an agent profile")
    started = time.perf_counter()
    ok, detail = False, ""
    try:
        if check.type == "http":
            async with httpx.AsyncClient(timeout=check.timeout_s, follow_redirects=False, trust_env=False) as client:
                response = await client.get(check.target)
            ok = 200 <= response.status_code < 400
            detail = f"HTTP {response.status_code}"
        elif check.type == "tcp":
            reader, writer = await asyncio.wait_for(asyncio.open_connection(check.target, check.port), check.timeout_s)
            writer.close()
            await writer.wait_closed()
            ok, detail = True, "TCP connection accepted"
        else:
            args = (["ping", "-n", "1", "-w", str(check.timeout_s * 1000), check.target] if platform.system() == "Windows"
                    else ["ping", "-n", "-c", "1", "-W", str(check.timeout_s), "--", check.target])
            process = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            try:
                await asyncio.wait_for(process.communicate(), check.timeout_s + 1)
                ok = process.returncode == 0
                detail = "ICMP reply received" if ok else "No ICMP reply (host unreachable or ping blocked)"
            except (asyncio.TimeoutError, asyncio.CancelledError):
                if process.returncode is None:
                    process.kill()
                    await process.communicate()
                raise
    except (httpx.TimeoutException, asyncio.TimeoutError):
        detail = "Check timed out"
    except (httpx.HTTPError, OSError):
        detail = "Ping is unavailable or cannot run" if check.type == "icmp" else "Connection failed"
    return {"ok": ok, "latency_ms": round((time.perf_counter() - started) * 1000, 1), "detail": detail}


def record(store: Store, sid: str, result: dict, signature: str | None = None, interval_s: int | None = None):
    active_check = (store.get("services", sid) or {}).get("health_check") or {}
    key = signature or check_key(active_check)
    interval = interval_s or ((store.get("services", sid) or {}).get("health_check") or {}).get("interval_s", 60)
    timestamp = now()
    with store.connection() as db:
        previous = db.execute("SELECT ok FROM health_results WHERE service_id=? AND check_key=? ORDER BY id DESC LIMIT 1", (sid, key)).fetchone()
        db.execute("INSERT INTO health_results(service_id,ts,ok,latency_ms,detail,check_key,interval_s) VALUES(?,?,?,?,?,?,?)",
                   (sid, timestamp, int(result["ok"]), result["latency_ms"], result["detail"], key, interval))
        opened = db.execute("SELECT id FROM incidents WHERE service_id=? AND check_key=? AND ended_at IS NULL", (sid, key)).fetchone()
        active_series = key == check_key(active_check) and active_check.get("enabled", True)
        if active_series and result["ok"] and opened:
            db.execute("UPDATE incidents SET ended_at=?,resolution='recovered' WHERE id=?", (timestamp, opened["id"]))
        elif active_series and not result["ok"] and not opened:
            db.execute("INSERT INTO incidents(service_id,check_key,started_at,detail) VALUES(?,?,?,?)", (sid, key, timestamp, result["detail"]))
        if not previous or bool(previous["ok"]) != result["ok"]:
            store.audit("health.recovered" if result["ok"] else "health.failed", "success" if result["ok"] else "warning",
                        result["detail"], sid, db=db)
        db.execute("DELETE FROM health_results WHERE ts < ?", ((datetime.now(timezone.utc) - timedelta(days=30)).isoformat(),))


def history(store: Store, sid: str):
    key = check_key((store.get("services", sid) or {}).get("health_check"))
    with store.connection() as db:
        rows = [dict(row) for row in db.execute("SELECT * FROM health_results WHERE service_id=? AND check_key=? ORDER BY id DESC LIMIT 120", (sid, key))]
        windows = {}
        for days, label in ((1, "24h"), (7, "7d"), (30, "30d")):
            cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
            aggregate = db.execute("SELECT COUNT(*) count, SUM(ok) successful FROM health_results WHERE service_id=? AND check_key=? AND ts>=?", (sid, key, cutoff)).fetchone()
            windows[label] = {"samples": aggregate["count"], "success_percent": round(100 * aggregate["successful"] / aggregate["count"], 2) if aggregate["count"] else None}
        cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        timeline = [dict(row) for row in db.execute("SELECT ts,ok,interval_s FROM health_results WHERE service_id=? AND check_key=? AND ts>=? ORDER BY ts,id", (sid, key, cutoff))]
        incidents = [dict(row) for row in db.execute("SELECT * FROM incidents WHERE service_id=? ORDER BY id DESC LIMIT 100", (sid,))]
        notes = [dict(row) for row in db.execute("SELECT * FROM incident_notes WHERE service_id=? ORDER BY id DESC LIMIT 50", (sid,))]
    current = datetime.now(timezone.utc)
    latest = rows[0] if rows else None
    if latest:
        latest["stale"] = (current - datetime.fromisoformat(latest["ts"])).total_seconds() > max(latest["interval_s"] * 3, 60)
    return {"results": list(reversed(rows)), "windows": windows, "uptime": weighted_uptime(timeline, current), "latest": latest,
            "incidents": incidents, "incident_notes": notes,
            "method": "Time-weighted observed uptime. Each result carries forward for at most three check intervals; uncovered time is unknown. Coverage shows how much of the window was observed."}


def latest(store: Store, sid: str):
    key = check_key((store.get("services", sid) or {}).get("health_check"))
    with store.connection() as db:
        row = db.execute("SELECT * FROM health_results WHERE service_id=? AND check_key=? ORDER BY id DESC LIMIT 1", (sid, key)).fetchone()
    if not row:
        return None
    result = dict(row)
    result["stale"] = (datetime.now(timezone.utc) - datetime.fromisoformat(result["ts"])).total_seconds() > max(result["interval_s"] * 3, 60)
    return result


def weighted_uptime(rows: list[dict], current: datetime):
    windows = {label: {"up_s": 0.0, "down_s": 0.0, "window_s": days * 86400} for days, label in ((1, "24h"), (7, "7d"), (30, "30d"))}
    points = [(datetime.fromisoformat(row["ts"]), row) for row in rows]
    for index, (start, row) in enumerate(points):
        end = min(current, start + timedelta(seconds=max(row.get("interval_s", 60) * 3, 60)))
        if index + 1 < len(points):
            end = min(end, points[index + 1][0])
        for window in windows.values():
            cutoff = current - timedelta(seconds=window["window_s"])
            duration = max(0, (end - max(start, cutoff)).total_seconds())
            window["up_s" if row["ok"] else "down_s"] += duration
    for window in windows.values():
        observed = window["up_s"] + window["down_s"]
        window.update(observed_s=round(observed, 1), unknown_s=round(max(0, window["window_s"] - observed), 1),
                      uptime_percent=round(window["up_s"] / observed * 100, 2) if observed else None,
                      coverage_percent=round(observed / window["window_s"] * 100, 3))
        window["up_s"], window["down_s"] = round(window["up_s"], 1), round(window["down_s"], 1)
    return windows
