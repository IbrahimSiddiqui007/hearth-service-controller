from __future__ import annotations

import hashlib
import json

import yaml
from fastapi import HTTPException
from pydantic import ValidationError

from controller.store import Store, now
from controller.dependencies import validate_dependencies
from controller.groups import validate_groups
from shared.models import HostDefinition, Manifest, ServiceDefinition, redact


def parse_manifest(content: str) -> Manifest:
    try:
        if any(isinstance(token, yaml.tokens.AliasToken) for token in yaml.scan(content)):
            raise ValueError("YAML aliases are not supported; expand the values explicitly")
        raw = yaml.safe_load(content)
        manifest = Manifest.model_validate(raw)
        # References are supported; recognized literal secrets should not be persisted.
        for service in manifest.services:
            for value in (service.notes, service.description):
                if redact(value) != value:
                    raise ValueError("Possible secret detected in notes/description; use a vault reference")
        return manifest
    except (yaml.YAMLError, ValidationError, ValueError, RecursionError) as exc:
        # Validation errors may contain the original secret-bearing input. Do not echo it.
        if isinstance(exc, ValidationError):
            detail = [{"field": ".".join(str(x) for x in e["loc"]), "message": e["msg"]} for e in exc.errors(include_input=False)]
        elif isinstance(exc, yaml.YAMLError):
            detail = "Invalid YAML/JSON. Check indentation and syntax."
        else:
            detail = str(exc)
        raise HTTPException(422, detail) from exc


def normalized(row: dict, model):
    return model.model_validate({key: row[key] for key in model.model_fields if key in row}).model_dump()


def plan_manifest(store: Store, manifest: Manifest):
    existing_hosts = {x["id"]: x for x in store.all("hosts")}
    existing_services = {x["id"]: x for x in store.all("services")}
    hosts = existing_hosts | {x.id: x.model_dump() for x in manifest.hosts}
    services = existing_services | {x.id: x.model_dump() for x in manifest.services}
    for records in (hosts, services):
        identifiers = [key.casefold() for key in records]
        if len(identifiers) != len(set(identifiers)):
            raise HTTPException(422, "IDs differing only by case would collide in the Markdown vault")
    for service in services.values():
        if service["host_id"] not in hosts:
            raise HTTPException(422, f"Unknown host for service {service['id']}: {service['host_id']}")
        for dependency in service.get("dependencies", []):
            if dependency not in services:
                raise HTTPException(422, f"Unknown dependency for {service['id']}: {dependency}")
    validate_dependencies(services)
    validate_groups(services)
    changes = []
    for kind, incoming, existing, model in (("host", manifest.hosts, existing_hosts, HostDefinition),
                                             ("service", manifest.services, existing_services, ServiceDefinition)):
        for item in incoming:
            old = existing.get(item.id)
            change = "new" if not old else "unchanged" if normalized(old, model) == item.model_dump() else "update"
            fields = [] if not old else [key for key, value in item.model_dump().items() if old.get(key) != value]
            changes.append({"kind": kind, "id": item.id, "name": item.name, "change": change, "fields": fields})
    fingerprint = hashlib.sha256(json.dumps({"manifest": manifest.model_dump(),
                     "hosts": {key: normalized(value, HostDefinition) for key, value in existing_hosts.items()},
                     "services": {key: normalized(value, ServiceDefinition) for key, value in existing_services.items()}},
                     sort_keys=True).encode()).hexdigest()
    return {"changes": changes, "fingerprint": fingerprint,
            "summary": {key: sum(x["change"] == key for x in changes) for key in ("new", "update", "unchanged")}}


def apply_manifest(store: Store, manifest: Manifest, demo: bool):
    plan = plan_manifest(store, manifest)
    changes = {(x["kind"], x["id"]): x for x in plan["changes"]}
    with store.connection() as db:
        for host in manifest.hosts:
            if changes[("host", host.id)]["change"] == "unchanged":
                continue
            old = store.get("hosts", host.id) or {}
            store.put("hosts", old | host.model_dump() | {"demo": demo, "status": old.get("status", "unknown")}, db)
        for service in manifest.services:
            if changes[("service", service.id)]["change"] == "unchanged":
                continue
            old = store.get("services", service.id) or {}
            body = old | service.model_dump() | {"source": "manual", "demo": demo, "revision": old.get("revision", 0) + 1,
                                                "updated_at": now(), "created_at": old.get("created_at", now())}
            body.setdefault("status", "unknown")
            body.setdefault("capabilities", {"control": False, "logs": False, "files": False})
            if old and old.get("notes") != service.notes:
                db.execute("INSERT INTO note_history(service_id,ts,revision,notes) VALUES(?,?,?,?)",
                           (service.id, now(), old["revision"], old.get("notes", "")))
            store.put("services", body, db)
            store.audit("manifest.import", "success", "Service definition imported", service.id, service.host_id, db)
        store.audit("manifest.applied", "success", json.dumps(plan["summary"]), db=db)
    return plan
