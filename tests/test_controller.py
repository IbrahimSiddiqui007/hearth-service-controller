import io
import json
import zipfile

import pytest
import yaml
from fastapi.testclient import TestClient

from controller.app import create_app
from controller.obsidian import END, START


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path / "demo", demo=True, token="", background=False)) as connection:
        yield connection


def minimal_manifest(**overrides):
    service = {"id": "test-service", "name": "Test service", "host_id": "worker-node1", "runtime": "compose",
               "control_handle": {"project": "test", "path": "/opt/test"}, "notes": "Useful setup notes"}
    service.update(overrides)
    return yaml.safe_dump({"version": 1, "services": [service]})


def import_manifest(client, content):
    preview = client.post("/api/v1/manifests/preview", json={"content": content})
    assert preview.status_code == 200, preview.text
    return client.post("/api/v1/manifests/apply", json={"content": content, "fingerprint": preview.json()["fingerprint"]})


def test_demo_seed_and_search(client):
    assert client.get("/api/v1/status").json()["demo"] is True
    assert len(client.get("/api/v1/services").json()) == 8
    assert [x["id"] for x in client.get("/api/v1/services?q=25565").json()] == ["minecraft"]
    assert all(x["host_id"] == "controller1" for x in client.get("/api/v1/services?host=controller1").json())
    assert client.get("/api/v1/services/playground").json()["status"] == "unknown"


def test_live_starts_empty_and_is_separate(tmp_path):
    with TestClient(create_app(tmp_path / "live", token="", background=False)) as live:
        assert live.get("/api/v1/services").json() == []
        assert live.get("/api/v1/hosts").json() == []
        assert not live.get("/api/v1/status").json()["demo"]


def test_note_revisions_detect_conflicts_and_preserve_history(client):
    service = client.get("/api/v1/services/minecraft").json()
    result = client.patch("/api/v1/services/minecraft", json={"notes": "New notes with [[Service--ollama]]", "revision": service["revision"]})
    assert result.status_code == 200
    assert result.json()["revision"] == service["revision"] + 1
    stale = client.patch("/api/v1/services/minecraft", json={"notes": "Stale content", "revision": service["revision"]})
    assert stale.status_code == 409
    history = client.get("/api/v1/services/minecraft/history").json()
    assert history["notes"][0]["notes"] == service["notes"]
    assert history["actions"][0]["action"] == "service.edited"


@pytest.mark.parametrize("notes", ["API_TOKEN=do-not-store-this", "password: do-not-store-this", START + "\nextra\n" + END])
def test_secret_and_marker_notes_rejected(client, notes):
    response = client.patch("/api/v1/services/minecraft", json={"notes": notes, "revision": 1})
    assert response.status_code == 422
    assert "do-not-store-this" not in response.text
    assert "do-not-store-this" not in client.get("/api/v1/services/minecraft").text


def test_manifest_preview_apply_idempotent(client):
    content = minimal_manifest()
    assert import_manifest(client, content).status_code == 200
    stored = client.get("/api/v1/services/test-service").json()
    assert stored["source"] == "manual"
    assert stored["capabilities"]["control"] is False
    repeat = import_manifest(client, content)
    assert repeat.json()["summary"] == {"new": 0, "update": 0, "unchanged": 1}
    assert client.get("/api/v1/services/test-service").json()["revision"] == stored["revision"]
    assert len(client.get("/api/v1/services").json()) == 9


def test_manifest_stale_preview_rejected(client):
    content = minimal_manifest()
    preview = client.post("/api/v1/manifests/preview", json={"content": content}).json()
    client.patch("/api/v1/services/minecraft", json={"notes": "Changed elsewhere", "revision": 1})
    response = client.post("/api/v1/manifests/apply", json={"content": content, "fingerprint": preview["fingerprint"]})
    assert response.status_code == 409
    assert client.get("/api/v1/services/test-service").status_code == 404


@pytest.mark.parametrize("content", [
    "version: 99\nservices: []",
    "version: 1\nservices: [",
    "version: 1\nhosts: &a []\nservices: *a",
    minimal_manifest(host_id="missing"),
    minimal_manifest(dependencies=["missing"]),
    minimal_manifest(dependencies=["test-service"]),
    minimal_manifest(control_handle={"command": "anything"}),
    minimal_manifest(id="../../escape"),
    minimal_manifest(urls=["javascript:alert(1)"]),
    minimal_manifest(notes="PASSWORD=do-not-store-this"),
])
def test_invalid_manifests_do_not_change_registry(client, content):
    before = client.get("/api/v1/services").json()
    response = client.post("/api/v1/manifests/preview", json={"content": content})
    assert response.status_code == 422, response.text
    assert "do-not-store-this" not in response.text
    assert client.get("/api/v1/services").json() == before


def test_duplicate_manifest_ids_rejected(client):
    doc = yaml.safe_load(minimal_manifest())
    doc["services"].append(doc["services"][0].copy())
    assert client.post("/api/v1/manifests/preview", json={"content": yaml.safe_dump(doc)}).status_code == 422


def test_demo_controls_are_audited_and_protected(client):
    result = client.post("/api/v1/services/minecraft/control", json={"action": "stop"})
    assert result.status_code == 200 and result.json()["status"] == "success"
    assert client.get("/api/v1/services/minecraft").json()["status"] == "stopped"
    assert client.post("/api/v1/services/tailscale/control", json={"action": "stop"}).status_code == 403
    assert client.post("/api/v1/services/playground/control", json={"action": "start"}).status_code == 409
    assert client.post("/api/v1/services/minecraft/control", json={"action": "rm -rf"}).status_code == 422
    audit = client.get("/api/v1/audit").json()
    assert any(x["action"] == "control.stop" and x["result"] == "success" for x in audit)


def test_dependency_control_requires_acknowledgment(client):
    child = client.app.state.store.get("services", "ollama")
    child["dependencies"] = ["minecraft"]
    client.app.state.store.put("services", child)
    assert client.post("/api/v1/services/minecraft/control", json={"action": "stop"}).status_code == 409
    assert client.post("/api/v1/services/minecraft/control", json={"action": "stop", "acknowledge_dependencies": True}).status_code == 200


def test_discovery_requires_review_and_server_side_candidates(client):
    scan = client.post("/api/v1/hosts/worker-node1/scan", json={}).json()
    assert len(client.get("/api/v1/services").json()) == 8
    assert client.post("/api/v1/discovery/accept", json={"scan_id": scan["scan_id"], "refs": ["fabricated"]}).status_code == 422
    ref = scan["candidates"][0]["agent_ref"]
    assert client.post("/api/v1/discovery/accept", json={"scan_id": scan["scan_id"], "refs": [ref]}).status_code == 200
    assert len(client.get("/api/v1/services").json()) == 9
    assert client.post("/api/v1/discovery/accept", json={"scan_id": scan["scan_id"], "refs": [ref]}).status_code == 409


def test_export_is_portable_and_has_backlinks(client):
    response = client.get("/api/v1/export")
    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert "docs/Home.md" in archive.namelist()
        assert "docs/Host--worker-node1.md" in archive.namelist()
        minecraft = archive.read("docs/Service--minecraft.md").decode()
        assert "[[Host--worker-node1|worker-node1]]" in minecraft
        assert START in minecraft and END in minecraft
        manifest = archive.read("lab.yaml").decode()
        assert client.post("/api/v1/manifests/preview", json={"content": manifest}).status_code == 200


def test_obsidian_roundtrip_and_conflict_preservation(client):
    from pathlib import Path
    result = client.post("/api/v1/obsidian/sync", json={}).json()
    assert result["written"] == 12
    assert result["conflicts"] == []
    root = Path(result["path"])
    path = root / "Service--minecraft.md"
    original = client.get("/api/v1/services/minecraft").json()
    path.write_text(path.read_text(encoding="utf-8").replace(original["notes"], "Notes from Obsidian"), encoding="utf-8")
    result = client.post("/api/v1/obsidian/sync", json={}).json()
    assert result["imported"] == ["minecraft"]
    updated = client.get("/api/v1/services/minecraft").json()
    assert updated["notes"] == "Notes from Obsidian"
    assert updated["revision"] == original["revision"] + 1
    path.write_text(path.read_text(encoding="utf-8").replace("Notes from Obsidian", "Another local edit"), encoding="utf-8")
    client.patch("/api/v1/services/minecraft", json={"notes": "Different dashboard edit", "revision": updated["revision"]})
    conflict = client.post("/api/v1/obsidian/sync", json={}).json()
    assert conflict["conflicts"][0]["id"] == "minecraft"
    assert "Another local edit" in path.read_text(encoding="utf-8")
    assert client.get("/api/v1/services/minecraft").json()["notes"] == "Different dashboard edit"


def test_obsidian_preserves_unknown_files_and_broken_markers(client):
    from pathlib import Path
    result = client.post("/api/v1/obsidian/sync", json={}).json()
    root = Path(result["path"])
    other = root / "Personal.md"
    other.write_text("This belongs to me", encoding="utf-8")
    note = root / "Service--minecraft.md"
    note.write_text("Owner removed the markers", encoding="utf-8")
    result = client.post("/api/v1/obsidian/sync", json={}).json()
    assert other.read_text() == "This belongs to me"
    assert note.read_text() == "Owner removed the markers"
    assert result["conflicts"][0]["id"] == "minecraft"


def test_host_token_is_a_reference_only(client):
    assert client.post("/api/v1/hosts", json={"id": "test", "name": "Test", "token_env": "actual-secret-value"}).status_code == 422
    assert client.post("/api/v1/hosts", json={"id": "test", "name": "Test", "agent_url": "http://user:password@localhost:8788"}).status_code == 422


def test_auth_origin_and_dns_rebinding_protection(tmp_path):
    with TestClient(create_app(tmp_path, token="a" * 32, background=False)) as client:
        assert client.get("/api/v1/status").status_code == 401
        headers = {"Authorization": "Bearer " + "a" * 32}
        assert client.get("/api/v1/status", headers=headers).status_code == 200
        assert client.post("/api/v1/obsidian/sync", json={}, headers=headers | {"Origin": "https://evil.example"}).status_code == 403
        assert client.get("/api/v1/status", headers=headers | {"Host": "evil.example"}).status_code == 403
        assert client.post("/api/v1/obsidian/sync", content="{}", headers=headers | {"Content-Type": "text/plain"}).status_code == 415


def test_demo_never_calls_real_agents(client, monkeypatch):
    async def forbidden(*args, **kwargs):
        raise AssertionError("Demo attempted a real agent connection")
    monkeypatch.setattr("httpx.AsyncClient.request", forbidden)
    assert client.post("/api/v1/hosts/controller1/refresh", json={}).status_code == 200
    assert client.post("/api/v1/hosts/controller1/scan", json={}).status_code == 200
    assert client.get("/api/v1/services/minecraft/logs").status_code == 200
    assert client.post("/api/v1/services/minecraft/control", json={"action": "restart"}).status_code == 200


def test_health_configuration_results_and_demo_network_isolation(client, monkeypatch):
    async def forbidden(*args, **kwargs):
        raise AssertionError("Demo made an actual health request")
    monkeypatch.setattr("httpx.AsyncClient.request", forbidden)
    configured = client.put("/api/v1/services/minecraft/health-check", json={"revision": 1, "check": {
        "enabled": True, "type": "tcp", "target": "worker-node1", "port": 25565}})
    assert configured.status_code == 200
    assert configured.json()["revision"] == 2
    assert client.post("/api/v1/services/minecraft/health/check", json={}).json()["ok"] is True
    history = client.get("/api/v1/services/minecraft/health").json()
    assert history["windows"]["24h"] == {"samples": 1, "success_percent": 100.0}
    client.post("/api/v1/services/minecraft/control", json={"action": "stop"})
    assert client.post("/api/v1/services/minecraft/health/check", json={}).json()["ok"] is False
    history = client.get("/api/v1/services/minecraft/health").json()
    assert history["windows"]["24h"]["success_percent"] == 50.0
    assert history["latest"]["ok"] == 0
    assert any(x["action"] == "health.failed" for x in client.get("/api/v1/audit").json())


@pytest.mark.parametrize("check", [
    {"enabled": True, "type": "http", "target": "file:///etc/passwd"},
    {"enabled": True, "type": "http", "target": "http://name:secret@localhost"},
    {"enabled": True, "type": "tcp", "target": "localhost", "port": 70000},
    {"enabled": True, "type": "tcp", "target": "localhost"},
    {"enabled": True, "type": "http", "target": ""},
])
def test_invalid_health_settings_rejected(client, check):
    assert client.put("/api/v1/services/minecraft/health-check", json={"revision": 1, "check": check}).status_code == 422
    assert client.post("/api/v1/services/minecraft/health/check", json={}).status_code == 409


def test_credential_pointers_export_and_reject_secret_fields(client):
    pointers = [{"label": "RCON", "username": "admin", "vault_ref": "https://vault.example/#/vault?itemId=abc", "hint": "RCON_PASSWORD in .env"}]
    saved = client.put("/api/v1/services/minecraft/credentials", json={"revision": 1, "credentials": pointers})
    assert saved.status_code == 200
    assert saved.json()["credentials"] == pointers
    assert "RCON_PASSWORD in .env" in client.get("/api/v1/services/minecraft/markdown").text
    assert client.put("/api/v1/services/minecraft/credentials", json={"revision": 2, "credentials": [{"label": "Secret", "password": "never-persist"}]}).status_code == 422
    response = client.put("/api/v1/services/minecraft/credentials", json={"revision": 2, "credentials": [{"label": "Secret", "hint": "PASSWORD=never-persist"}]})
    assert response.status_code == 422 and "never-persist" not in response.text
    assert client.post("/api/v1/manifests/preview", json={"content": minimal_manifest(credentials=[{"label": "Secret", "hint": "TOKEN=never-persist"}])}).status_code == 422


def test_live_agent_flow_and_verified_control(tmp_path, monkeypatch):
    import httpx
    monkeypatch.setenv("PSC_AGENT_TEST", "test-token")
    runtime_state = {"status": "running"}
    candidate = {"agent_ref": "systemd-test", "name": "Test", "runtime": "systemd", "description": "Test unit", "tags": [],
                 "ports": [], "urls": [], "paths": [], "dependencies": [], "control_handle": {"unit": "test.service"},
                 "capabilities": {"control": True, "logs": True, "files": True}}
    calls = []

    async def request(self, method, url, **kwargs):
        calls.append((method, url, kwargs))
        assert kwargs["headers"]["Authorization"] == "Bearer test-token"
        path = url.split("8788")[-1]
        if path == "/telemetry":
            body = {"cpu_percent": 12, "memory_percent": 20}
        elif path == "/scan":
            body = {"services": [candidate | runtime_state], "warnings": [], "containers": []}
        elif path == "/control":
            runtime_state["status"] = "stopped"
            body = {"accepted": True, "output": ""}
        elif path.startswith("/files?"):
            assert "ref=systemd-test" in path
            body = {"kind": "directory", "entries": [], "readonly": True}
        else:
            raise AssertionError(path)
        return httpx.Response(200, json=body, request=httpx.Request(method, url))

    monkeypatch.setattr("httpx.AsyncClient.request", request)
    with TestClient(create_app(tmp_path, token="", background=False)) as live:
        assert live.post("/api/v1/hosts", json={"id": "worker-node1", "name": "worker-node1", "agent_url": "http://127.0.0.1:8788", "token_env": "PSC_AGENT_TEST"}).status_code == 200
        assert import_manifest(live, minimal_manifest(runtime="systemd", control_handle={"unit": "test.service"})).status_code == 200
        assert live.post("/api/v1/services/test-service/control", json={"action": "stop"}).status_code == 409
        assert live.post("/api/v1/hosts/worker-node1/refresh", json={}).json()["status"] == "online"
        service = live.get("/api/v1/services/test-service").json()
        assert service["status"] == "running" and service["capabilities"]["control"]
        assert live.get("/api/v1/services/test-service/files").status_code == 200
        result = live.post("/api/v1/services/test-service/control", json={"action": "stop"})
        assert result.json()["status"] == "success"
        assert result.json()["service"]["status"] == "stopped"
        assert "Agent" not in live.get("/api/v1/export").text


def test_changed_health_destination_starts_a_new_series(client):
    check = {"enabled": True, "type": "tcp", "target": "worker-node1", "port": 25565}
    client.put("/api/v1/services/minecraft/health-check", json={"revision": 1, "check": check})
    client.post("/api/v1/services/minecraft/health/check", json={})
    assert client.get("/api/v1/services/minecraft/health").json()["windows"]["24h"]["samples"] == 1
    check["target"] = "different-host"
    client.put("/api/v1/services/minecraft/health-check", json={"revision": 2, "check": check})
    assert client.get("/api/v1/services/minecraft/health").json()["windows"]["24h"]["samples"] == 0
    with client.app.state.store.connection() as db:
        assert db.execute("SELECT COUNT(*) FROM health_results WHERE service_id='minecraft'").fetchone()[0] == 1


def test_non_ascii_authentication_does_not_raise(tmp_path):
    with TestClient(create_app(tmp_path, token="a" * 32, background=False)) as client:
        headers = {"Authorization": "Bearer " + "wrong"}
        assert client.get("/api/v1/status", headers=headers).status_code == 401


def test_custom_local_port_origin_supported(tmp_path):
    with TestClient(create_app(tmp_path, token="", background=False, port=9999)) as client:
        assert client.post("/api/v1/obsidian/sync", json={}, headers={"Origin": "http://127.0.0.1:9999"}).status_code == 200


def test_demo_explanations_do_not_call_ollama(client, monkeypatch):
    async def forbidden(*args, **kwargs):
        raise AssertionError("Demo attempted an Ollama call")
    monkeypatch.setattr("httpx.AsyncClient.post", forbidden)
    result = client.post("/api/v1/services/minecraft/explain", json={"selected_logs": "sample"})
    assert result.status_code == 200 and result.json()["demo"] is True


def test_vault_filename_case_collisions_and_embedded_markers_rejected(client):
    response = client.post("/api/v1/manifests/preview", json={"content": minimal_manifest(id="Minecraft")})
    assert response.status_code == 422
    assert client.post("/api/v1/hosts", json={"id": "CONTROLLER1", "name": "Duplicate"}).status_code == 409
    content = minimal_manifest(notes=START + "\nconflicting marker\n" + END)
    assert client.post("/api/v1/manifests/preview", json={"content": content}).status_code == 422
