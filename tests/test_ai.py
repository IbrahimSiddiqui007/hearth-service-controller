import asyncio
import json

import httpx
import pytest
from fastapi import HTTPException

from controller.ai import configuration, explain
from controller.ai import draft


def test_ai_is_disabled_without_explicit_configuration(monkeypatch):
    monkeypatch.delenv("PSC_OLLAMA_URL", raising=False)
    monkeypatch.delenv("PSC_OLLAMA_MODEL", raising=False)
    assert configuration()["configured"] is False
    with pytest.raises(HTTPException) as exc:
        asyncio.run(explain({"name": "test", "runtime": "docker"}, "", []))
    assert exc.value.status_code == 409


def test_ai_masks_known_secret_patterns_and_never_executes(monkeypatch):
    monkeypatch.setenv("PSC_OLLAMA_URL", "http://ollama.example:11434")
    monkeypatch.setenv("PSC_OLLAMA_MODEL", "test-model")
    calls = []
    async def post(self, url, **kwargs):
        calls.append((url, kwargs))
        assert "never-send-this" not in kwargs["json"]["prompt"]
        assert "untrusted observed data" in kwargs["json"]["prompt"]
        assert kwargs["json"]["stream"] is False
        return httpx.Response(200, json={"response": "Likely a port conflict. Confidence: medium."}, request=httpx.Request("POST", url))
    monkeypatch.setattr("httpx.AsyncClient.post", post)
    result = asyncio.run(explain({"name": "test", "runtime": "docker"}, "TOKEN=never-send-this\nport already in use", []))
    assert result["advice_only"] is True
    assert result["model"] == "test-model"
    assert len(calls) == 1 and calls[0][0].endswith("/api/generate")


@pytest.mark.parametrize("endpoint", ["file:///etc", "http://user:secret@example.com", "http://host/path", "http://host?token=secret"])
def test_ai_configuration_rejects_unsafe_origins(monkeypatch, endpoint):
    monkeypatch.setenv("PSC_OLLAMA_URL", endpoint)
    monkeypatch.setenv("PSC_OLLAMA_MODEL", "model")
    assert not configuration()["configured"]


def test_draft_masks_context_and_remains_unverified(monkeypatch):
    config={'configured':True,'endpoint':'http://model.invalid','model':'mock','timeout_s':5}
    async def post(self,url,**kwargs):
        assert 'private-value' not in kwargs['json']['prompt']
        assert 'untrusted observed data' in kwargs['json']['prompt']
        assert not kwargs['json']['stream']
        return httpx.Response(200,json={'response':'Review this inferred setup before use.'})
    monkeypatch.setattr('httpx.AsyncClient.post',post)
    result=asyncio.run(draft('installation',{'command':'echo PASSWORD=private-value'},config))
    assert result['advice_only'] and not result['verified']


@pytest.mark.parametrize('status,response',[(500,{}),(200,{'response':''}),(200,{'response':'token: ghp_123456789012345678901234567890abcdefghijk'})])
def test_draft_rejects_bad_model_responses(monkeypatch,status,response):
    config={'configured':True,'endpoint':'http://model.invalid','model':'mock','timeout_s':5}
    async def post(self,url,**kwargs):return httpx.Response(status,json=response)
    monkeypatch.setattr('httpx.AsyncClient.post',post)
    with pytest.raises(HTTPException):asyncio.run(draft('summary',{},config))
