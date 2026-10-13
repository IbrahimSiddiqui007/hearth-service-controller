import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent.app import create_agent, docker_inventory, safe_path


@pytest.fixture
def client(tmp_path):
    (tmp_path / "config.yaml").write_text("hello: world\n", encoding="utf-8")
    config = {"allow_containers": ["minecraft"], "allow_units": ["ollama.service"],
              "allow_projects": {"minecraft": str(tmp_path)}, "file_roots": {"approved": [str(tmp_path)]}, "discover": []}
    with TestClient(create_agent(config, token="test-token")) as client:
        client.headers["Authorization"] = "Bearer test-token"
        yield client


def test_agent_refuses_missing_or_wrong_token(client):
    assert client.get("/health").status_code == 200
    assert client.get("/health", headers={"Authorization": "Bearer wrong"}).status_code == 401
    with TestClient(create_agent({}, token="")) as locked:
        assert locked.get("/health").status_code == 401


def test_only_allowlisted_argument_vectors_execute(client, monkeypatch):
    calls = []
    monkeypatch.setattr("agent.app.command", lambda args, **kwargs: calls.append(args) or "ok")
    for name in ("not-allowed", "minecraft; whoami", "-all"):
        response = client.post("/control", json={"runtime": "docker", "handle": {"container": name}, "action": "stop"})
        assert response.status_code == 403
    assert calls == []
    allowed = client.post("/control", json={"runtime": "docker", "handle": {"container": "minecraft"}, "action": "stop"})
    assert allowed.status_code == 200
    assert calls == [["docker", "stop", "minecraft"]]
    assert client.post("/control", json={"runtime": "systemd", "handle": {"unit": "sshd.service"}, "action": "stop"}).status_code == 403
    assert client.post("/control", json={"runtime": "process", "handle": {}, "action": "start"}).status_code == 409


def test_compose_path_must_match_agent_policy(client, monkeypatch):
    monkeypatch.setattr("agent.app.command", lambda *args, **kwargs: "should not be called")
    assert client.post("/control", json={"runtime": "compose", "handle": {"project": "minecraft", "path": "/wrong"}, "action": "start"}).status_code == 403


def test_readonly_file_scope_and_secret_exclusion(client, tmp_path):
    assert client.get("/files?ref=approved").json()["kind"] == "directory"
    result = client.get("/files?ref=approved&path=config.yaml")
    assert result.json()["content"] == "hello: world\n"
    assert result.json()["readonly"] is True
    assert client.get("/files?ref=unknown").status_code == 403
    assert client.get("/files?ref=approved&path=../outside.txt").status_code == 403
    assert client.get("/files?ref=approved&path=missing").status_code == 404
    (tmp_path / ".env").write_text("PASSWORD=hidden", encoding="utf-8")
    assert client.get("/files?ref=approved&path=.env").status_code == 403
    (tmp_path / "secret.txt").write_text("token: hidden", encoding="utf-8")
    assert "hidden" not in client.get("/files?ref=approved&path=secret.txt").text
    assert client.put("/files?ref=approved&path=config.yaml", json={"content": "changed", "etag": result.json()["etag"]}).status_code in (403, 409)


def test_symlink_escape_is_rejected(tmp_path):
    root = tmp_path / "approved"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("private", encoding="utf-8")
    try:
        (root / "escape").symlink_to(outside)
    except OSError:
        pytest.skip("Symlink creation requires privileges on this Windows installation")
    with pytest.raises(Exception) as exc:
        safe_path(root, "escape")
    assert getattr(exc.value, "status_code", None) == 403


def test_compose_discovery_groups_and_does_not_return_environment(monkeypatch):
    objects = []
    for name in ("web", "db"):
        objects.append({"Name": "/" + name, "State": {"Status": "running"},
                        "Config": {"Image": "sample:1", "Env": ["PASSWORD=never-export"],
                                   "Labels": {"com.docker.compose.project": "test", "com.docker.compose.project.working_dir": "/opt/test"}},
                        "NetworkSettings": {"Ports": {"80/tcp": [{"HostPort": "8080"}]}}, "Mounts": []})
    monkeypatch.setattr("agent.app.command", lambda args, **kwargs: "a\nb\n" if args[1] == "ps" else json.dumps(objects))
    services, containers = docker_inventory({})
    assert len(services) == 1 and len(containers) == 2
    assert services[0]["runtime"] == "compose"
    assert services[0]["ports"] == ["8080/tcp"]
    assert services[0]["capabilities"]["control"] is False
    assert "never-export" not in json.dumps((services, containers))


def test_agent_browser_control_is_rejected(client):
    assert client.post("/scan", json={}, headers={"Origin": "http://localhost:8787"}).status_code == 403


def test_agent_cli_refuses_root_before_reading_configuration(monkeypatch, capsys):
    from agent.app import main
    monkeypatch.setattr("os.getuid", lambda: 0, raising=False)
    monkeypatch.setattr("sys.argv", ["psc-agent", "--config", "does-not-exist.yaml"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2
    assert "non-root" in capsys.readouterr().err
