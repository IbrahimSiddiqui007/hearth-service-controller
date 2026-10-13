import json
import hashlib
from datetime import datetime, timezone

from fastapi import HTTPException
from pydantic import ValidationError

from shared.catalogue import enrich
from shared.models import ServiceDefinition, redact, mask_metadata
from controller.secret_findings import categories
from shared.secret_findings import CATEGORIES

OBSERVED_FIELDS = ("name", "description", "icon", "runtime", "ports", "paths", "locations", "urls", "control_handle", "components", "image", "images")


def snapshot(row):
    result = {key: row.get(key, [] if key in ("ports", "paths", "urls", "components", "images") else "auto" if key == "icon" else "" if key in ("description", "image") else {}) for key in OBSERVED_FIELDS}
    result["control_handle"] = {key: value for key, value in row.get("control_handle", {}).items() if key != "agent_ref"}
    for key in ("ports", "paths", "urls", "components", "images"):
        result[key] = sorted(result[key] or [])
    return result


def match_candidate(existing, row):
    ref = row.get("agent_ref")
    return next((item for item in existing if item["runtime"] == row["runtime"] and
                 (item.get("agent_ref") == ref or item.get("control_handle", {}).get("agent_ref") == ref or
                  {key: value for key, value in item.get("control_handle", {}).items() if key != "agent_ref"} == row.get("control_handle"))), None)


def proposals(host: dict, existing: list[dict], result: dict):
    rows = result.get("services", [])
    if not isinstance(rows, list) or len(rows) > 1000:
        raise HTTPException(502, "Agent returned an invalid or oversized service inventory")
    candidates, seen, refs = [], set(), set()
    for raw in rows:
        try:
            if not isinstance(raw, dict) or not isinstance(raw.get("agent_ref"), str):
                raise ValueError("Invalid agent reference")
            if raw["agent_ref"] in refs:
                raise ValueError("Duplicate agent reference")
            handle = raw.get('control_handle', {})
            if redact(raw['agent_ref']) != raw['agent_ref'] or not isinstance(handle, dict) or any(not isinstance(value, str) or redact(value) != value for value in handle.values()):
                raise ValueError('Sensitive runtime identity cannot be stored or controlled')
            refs.add(raw["agent_ref"])
            row = mask_metadata(enrich(raw, host.get("address") or host["name"]))
            old = match_candidate(existing, row)
            prefix = host["id"] if len(host["id"]) <= 40 else host["id"][:28] + "-" + hashlib.sha256(host["id"].encode()).hexdigest()[:10]
            sid = old["id"] if old else prefix + "--" + row["agent_ref"]
            definition = ServiceDefinition(id=sid, host_id=host["id"], name=row["name"], runtime=row["runtime"],
                     locations=row.get("locations", {}),
                     icon=row.get("icon", "auto"), description=row.get("description", ""), tags=row.get("tags", []),
                     ports=row.get("ports", []), urls=row.get("urls", []), paths=row.get("paths", []),
                     control_handle=row.get("control_handle", {}) | {"agent_ref": row["agent_ref"]})
            latest = snapshot(row)
            baseline = old.get("discovery_baseline") or snapshot(old) if old else {}
            diff = [{"field": key, "before": baseline.get(key), "after": latest[key]} for key in OBSERVED_FIELDS if old and baseline.get(key) != latest[key]]
            if old and old.get("inventory_status") == "gone":
                diff.append({"field": "availability", "before": "missing", "after": "present"})
            change = "new" if not old else "changed" if diff else "unchanged"
            candidates.append(definition.model_dump() | {"status": row.get("status", "unknown"),
                    "capabilities": row.get("capabilities", {}), "change": change, "agent_ref": row["agent_ref"],
                    "diff": diff, "snapshot": latest, "runtime_details": row.get("runtime_details", {}),
                    "metrics": row.get("metrics"),
                    "existing_id": old["id"] if old else None, "review_revision": old.get("revision", 0) if old else None,
                    "components": row.get("components", []), "fingerprint": row.get("fingerprint"), "system_unit": row.get("system_unit", False)})
            supplied = raw.get('secret_categories', [])
            if not isinstance(supplied, list) or any(reason not in CATEGORIES for reason in supplied):
                raise ValueError('Invalid secret finding categories')
            candidates[-1]['secret_categories'] = sorted(set(categories(raw) + supplied))
            candidates[-1]['secret_scan_scope'] = raw.get('secret_scan_scope') if raw.get('secret_scan_scope') in ('disabled', 'complete', 'incomplete', 'unavailable') else 'unavailable'
            if old:
                seen.add(old["id"])
        except (ValidationError, KeyError, TypeError, ValueError) as exc:
            raise HTTPException(502, "Agent returned an invalid service definition; check its version and metadata") from exc
    completed = set(result.get("completed_runtimes", []))
    # Older agents do not prove provider completeness. Never infer disappearance
    # from an incomplete scan or a failed provider.
    for old in existing:
        scope = 'launchd_scope' if old.get('runtime') == 'launchd' else 'systemd_scope'
        if old.get("system_unit") and result.get(scope) != "all":
            continue
        tracked = old.get("agent_ref") or old.get("control_handle", {}).get("agent_ref")
        if old["id"] not in seen and tracked and old["runtime"] in completed and old.get("inventory_status") != "gone":
            candidates.append({**old, "change": "gone", "agent_ref": tracked, "status": "unknown", "capabilities": {"control": False, "logs": False, "files": False},
                               "existing_id": old["id"], "review_revision": old.get("revision", 0),
                               "diff": [{"field": "availability", "before": "present", "after": "missing"}], "snapshot": old.get("discovery_baseline", {})})
    return candidates


def save_scan(store, scan: dict):
    with store.connection() as db:
        db.execute("INSERT INTO discovery_scans(id,host_id,ts,body) VALUES(?,?,?,?)", (scan["scan_id"], scan["host_id"], scan["created_at"], json.dumps(scan)))
        db.execute("DELETE FROM discovery_scans WHERE host_id=? AND id NOT IN (SELECT id FROM discovery_scans WHERE host_id=? ORDER BY ts DESC LIMIT 50)", (scan["host_id"], scan["host_id"]))


def get_scan(store, scan_id=None, host_id=None):
    with store.connection() as db:
        row = db.execute("SELECT body FROM discovery_scans WHERE id=?", (scan_id,)).fetchone() if scan_id else db.execute("SELECT body FROM discovery_scans WHERE host_id=? ORDER BY ts DESC LIMIT 1", (host_id,)).fetchone()
    return json.loads(row["body"]) if row else None


def due(host, current=None):
    current = current or datetime.now(timezone.utc)
    last = host.get("discovery_checked_at")
    return not last or (current - datetime.fromisoformat(last)).total_seconds() >= host.get("discovery_interval_s", 21600)
