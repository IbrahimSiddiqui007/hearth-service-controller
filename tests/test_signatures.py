import asyncio
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from agent.app import create_agent
from shared.signatures import headers, valid
from test_config_operations import endpoint, live_app

KEY = 'unit-test-only-signature-key-32bytes-long'


def signed(method, target, body=b'', **kwargs):
    return {'Authorization': 'Bearer dummy', **headers(KEY, method, target, body, **kwargs)}


@pytest.fixture
def agent(tmp_path, monkeypatch):
    monkeypatch.setenv('PSC_AGENT_SIGN_TEST', KEY)
    tmp_path.chmod(0o700)
    return create_agent({'signing_key_env': 'PSC_AGENT_SIGN_TEST', 'state_dir': str(tmp_path)}, token='dummy')


def test_signed_read_body_query_and_durable_replay(agent, tmp_path):
    first = signed('GET', '/health')
    with TestClient(agent) as client:
        assert client.get('/health', headers=first).status_code == 200
        assert client.get('/health', headers=first).status_code == 401
        assert client.get('/health', headers={'Authorization': 'Bearer dummy'}).status_code == 401
        body = b'{"include_system":false}'
        target = '/scan?test=a%20b'
        reply = client.post(target, content=body, headers={**signed('POST', target, body), 'Content-Type': 'application/json'})
        assert reply.status_code == 200
        assert client.post('/scan', content=body, headers={**signed('POST', '/scan', body + b' '), 'Content-Type': 'application/json'}).status_code == 401
        assert client.get('/health?changed=1', headers=signed('GET', '/health')).status_code == 401
        assert client.get('/health', headers=signed('GET', '/health', timestamp=int(time.time()) - 121)).status_code == 401
    restarted = create_agent({'signing_key_env': 'PSC_AGENT_SIGN_TEST', 'state_dir': str(tmp_path)}, token='dummy')
    with TestClient(restarted) as client:
        assert client.get('/health', headers=first).status_code == 401


def test_short_key_and_invalid_nonce_fail_closed(tmp_path, monkeypatch):
    monkeypatch.setenv('PSC_AGENT_SIGN_TEST', 'short')
    with pytest.raises(ValueError):
        create_agent({'signing_key_env': 'PSC_AGENT_SIGN_TEST', 'state_dir': str(tmp_path)}, token='dummy')
    assert not valid(KEY, 'GET', '/health', b'', {'x-psc-time': str(int(time.time())), 'x-psc-nonce': '\u00e9' * 48, 'x-psc-signature': '0' * 64})


def test_controller_signs_exact_serialized_request(tmp_path, monkeypatch):
    app = live_app(tmp_path / 'controller', monkeypatch)
    state = tmp_path / 'agent-state'
    state.mkdir(mode=0o700)
    monkeypatch.setenv('PSC_AGENT_SIGN_TEST', KEY)
    agent = create_agent({'signing_key_env': 'PSC_AGENT_SIGN_TEST', 'state_dir': str(state), 'discover': []}, token='test-only-reference')
    host = app.state.store.get('hosts', 'worker-node1')
    host['signing_env'] = 'PSC_AGENT_SIGN_TEST'
    app.state.store.put('hosts', host)
    real_client = httpx.AsyncClient
    class LocalClient(real_client):
        def __init__(self, **kwargs):
            super().__init__(transport=httpx.ASGITransport(app=agent), **kwargs)
    monkeypatch.setattr('controller.app.httpx.AsyncClient', LocalClient)
    result = asyncio.run(endpoint(app, '/api/v1/hosts/{hid}/scan', 'POST')('worker-node1', __import__('shared.models', fromlist=['ScanOptions']).ScanOptions()))
    assert result['host_id'] == 'worker-node1'
