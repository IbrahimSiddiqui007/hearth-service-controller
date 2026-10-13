import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from agent.heartbeat import target, run
from controller.app import create_app
from controller.heartbeats import liveness
from shared.models import HostDefinition
from shared.signatures import headers, frame_signature

KEY = 'mock-only-heartbeat-signing-key-at-least32'
PATH = '/api/v1/agents/worker/heartbeat'


def fixture_app(tmp_path, monkeypatch):
    monkeypatch.setenv('PSC_AGENT_TEST', 'test-token')
    monkeypatch.setenv('PSC_AGENT_TEST_SIGNING', KEY)
    app = create_app(tmp_path, token='', background=False)
    app.state.store.put('hosts', HostDefinition(id='worker', name='worker', token_env='PSC_AGENT_TEST', signing_env='PSC_AGENT_TEST_SIGNING', physical_host_id='machine').model_dump())
    return app


def packet(nonce, payload, sequence=0):
    raw = json.dumps(payload, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    return {'sequence': sequence, 'payload': payload, 'signature': frame_signature(KEY, nonce, sequence, raw)}


def test_signed_channel_host_inventory_disconnect_replay_and_no_demo(tmp_path, monkeypatch):
    app = fixture_app(tmp_path, monkeypatch)
    auth = {'Authorization': 'Bearer test-token', **headers(KEY, 'GET', PATH, b'')}
    nonce = auth['X-PSC-Nonce']
    with TestClient(app) as client:
        with client.websocket_connect(PATH, headers=auth) as socket:
            ready = socket.receive_json()
            assert ready['signature'] == frame_signature(KEY, nonce, -1, b'ready')
            socket.send_json(packet(nonce, {'metrics': {'os': 'Windows', 'physical_host_id': 'machine', 'cpu_percent': 10}, 'inventory': {'services': [], 'completed_runtimes': ['windows']}}))
            assert socket.receive_json()['status'] == 'accepted'
            host = client.get('/api/v1/hosts').json()[0]
            assert host['status'] == 'online' and host['transport'] == 'heartbeat' and host['identity_verified']
        assert client.get('/api/v1/hosts').json()[0]['status'] == 'stale'
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(PATH, headers=auth):
                pass
    demo = create_app(tmp_path / 'demo', demo=True, token='', background=False)
    with TestClient(demo) as client:
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(PATH, headers=auth):
                pass


@pytest.mark.parametrize('failure', ['tamper', 'physical', 'sequence', 'origin'])
def test_bad_channel_frames_never_become_online(tmp_path, monkeypatch, failure):
    app = fixture_app(tmp_path, monkeypatch)
    auth = {'Authorization': 'Bearer test-token', **headers(KEY, 'GET', PATH, b'')}
    if failure == 'origin':
        auth['Origin'] = 'http://testserver'
    with TestClient(app) as client:
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(PATH, headers=auth) as socket:
                socket.receive_json()
                row = packet(auth['X-PSC-Nonce'], {'metrics': {'os': 'Linux', 'physical_host_id': 'other' if failure == 'physical' else 'machine'}}, sequence=1 if failure == 'sequence' else 0)
                if failure == 'tamper':
                    row['payload']['metrics']['os'] = 'Windows'
                socket.send_json(row)
                socket.receive_json()
        assert client.get('/api/v1/hosts').json()[0].get('status') != 'online'


def test_liveness_three_and_ten_missed_beats():
    clock = datetime.now(timezone.utc)
    host = {'transport': 'heartbeat', 'status': 'online', 'last_seen': clock.isoformat()}
    assert liveness(host, clock + timedelta(seconds=44))['status'] == 'online'
    assert liveness(host, clock + timedelta(seconds=45))['status'] == 'stale'
    assert liveness(host, clock + timedelta(seconds=150))['status'] == 'offline'


def test_heartbeat_destination_and_client_mutual_proof(tmp_path, monkeypatch):
    config = {'heartbeat_controller': 'ws://100.64.1.2:8787', 'controller_host_id': 'worker', 'signing_key_env': 'PSC_AGENT_TEST_SIGNING'}
    monkeypatch.setenv('PSC_AGENT_TEST_SIGNING', KEY)
    assert target(config).endswith(PATH)
    with pytest.raises(ValueError):
        target({**config, 'heartbeat_controller': 'ws://public.invalid'})
    collected = []
    class Socket:
        def __init__(self, nonce):
            self.nonce, self.sequence = nonce, None
        async def recv(self):
            if self.sequence is None:
                return json.dumps({'status': 'ready', 'signature': frame_signature(KEY, self.nonce, -1, b'ready')})
            return json.dumps({'status': 'accepted', 'sequence': self.sequence, 'signature': frame_signature(KEY, self.nonce, self.sequence, b'accepted')})
        async def send(self, body):
            row = json.loads(body)
            self.sequence = row['sequence']
            assert row == packet(self.nonce, row['payload'], self.sequence)
    class Connection:
        def __init__(self, url, **kwargs):
            assert kwargs['proxy'] is None and kwargs['compression'] is None
            self.socket = Socket(kwargs['additional_headers']['X-PSC-Nonce'])
        async def __aenter__(self): return self.socket
        async def __aexit__(self, *args): pass
    def collect(inventory):
        collected.append(inventory)
        return {'metrics': {'os': 'Linux', 'physical_host_id': 'machine'}}
    async def stop(delay):
        assert delay == 15
        raise asyncio.CancelledError()
    monkeypatch.setattr('agent.heartbeat.asyncio.sleep', stop)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(run(config, 'test-token', collect, connect=Connection))
    assert collected == [True]
