import asyncio

import httpx

from controller.health import probe
from shared.models import HealthCheck


def test_http_health_status_and_redirect_handling(monkeypatch):
    async def get(self, target):
        assert self.follow_redirects is False
        return httpx.Response(503, request=httpx.Request("GET", target))
    monkeypatch.setattr("httpx.AsyncClient.get", get)
    result = asyncio.run(probe(HealthCheck(enabled=True, target="http://example.invalid/health")))
    assert result["ok"] is False
    assert result["detail"] == "HTTP 503"


def test_health_timeout_does_not_echo_target_secrets(monkeypatch):
    async def get(self, target):
        raise httpx.ReadTimeout("sensitive internals")
    monkeypatch.setattr("httpx.AsyncClient.get", get)
    result = asyncio.run(probe(HealthCheck(enabled=True, target="http://example.invalid/health")))
    assert result["detail"] == "Check timed out"
    assert result["ok"] is False


def test_tcp_probe_closes_connection(monkeypatch):
    calls = []
    class Writer:
        def close(self):
            calls.append("closed")
        async def wait_closed(self):
            calls.append("waited")
    async def connect(target, port):
        assert target == "host" and port == 1234
        return object(), Writer()
    monkeypatch.setattr("asyncio.open_connection", connect)
    result = asyncio.run(probe(HealthCheck(enabled=True, type="tcp", target="host", port=1234)))
    assert result["ok"] is True
    assert calls == ["closed", "waited"]
