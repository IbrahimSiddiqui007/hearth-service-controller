import hashlib
import json
import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from agent.terminal import TerminalManager, TerminalOpen, TerminalInput, environment, profile
from controller.app import create_app
from controller.terminals import Recording
from test_config_operations import live_app, fake_agent
from agent.app import create_agent
from shared.signatures import headers as signed_headers, valid
import httpx


class FakePTY:
    def __init__(self, item):
        self.chunks, self.inputs, self.sizes, self.closed = [], [], [], False
    def read(self): return self.chunks.pop(0) if self.chunks else None
    def write(self, data): self.inputs.append(data)
    def resize(self, rows, cols): self.sizes.append((rows, cols))
    def close(self): self.closed = True


@pytest.fixture
def manager(tmp_path, monkeypatch):
    monkeypatch.setattr('agent.terminal.ordinary_account', lambda: True)
    config = {'terminal_profiles': {'ref': {'shell': {'argv': [str(tmp_path / 'shell'), '--no-profile'], 'cwd': str(tmp_path)}}}}
    clock = [0]
    manager = TerminalManager(config, FakePTY, lambda: clock[0])
    item = manager.profiles('ref')[0]
    body = TerminalOpen(ref='ref', profile='shell', fingerprint=item['fingerprint'], confirmed=True)
    return manager, body, clock


def test_terminal_confirmation_profile_hash_and_limits(manager):
    manager, body, clock = manager
    with pytest.raises(HTTPException): manager.open(body.model_copy(update={'confirmed': False}))
    with pytest.raises(HTTPException): manager.open(body.model_copy(update={'fingerprint': 'f' * 64}))
    first = manager.open(body)['id']
    manager.open(body)
    with pytest.raises(HTTPException) as rejected: manager.open(body)
    assert rejected.value.status_code == 429
    manager.close(first)
    assert len(manager.sessions) == 1


def test_input_idle_timeout_polling_and_resize_do_not_keep_session_alive(manager):
    manager, body, clock = manager
    identifier = manager.open(body)['id']
    pty = manager.sessions[identifier]['pty']
    for second in range(1, 901):
        clock[0] = second
        if second < 900:
            manager.read(identifier)
            manager.input(identifier, TerminalInput(rows=24, cols=80))
    manager.sweep()
    assert pty.closed and identifier not in manager.sessions


def test_lost_controller_polling_and_changed_profile_revoke_session(manager):
    manager, body, clock = manager
    identifier = manager.open(body)['id']
    pty = manager.sessions[identifier]['pty']
    clock[0] = 16
    manager.sweep()
    assert pty.closed
    identifier = manager.open(body)['id']
    pty = manager.sessions[identifier]['pty']
    manager.config['terminal_profiles']['ref']['shell']['argv'].append('--changed')
    with pytest.raises(HTTPException): manager.input(identifier, TerminalInput(data='dangerous retry'))
    assert pty.closed and pty.inputs == []


def test_output_unicode_streaming_and_budget_close(manager):
    manager, body, clock = manager
    identifier = manager.open(body)['id']
    pty = manager.sessions[identifier]['pty']
    pty.chunks = [b'\xe2', b'\x82\xac']
    assert manager.read(identifier)['content'] == ''
    assert manager.read(identifier)['content'] == '\u20ac'
    manager.sessions[identifier]['output_bytes'] = 2_000_000
    pty.chunks = [b'overflow']
    assert manager.read(identifier)['ended'] and pty.closed


def test_child_environment_never_inherits_controller_credentials(monkeypatch):
    monkeypatch.setenv('PSC_AGENT_TOKEN', 'private')
    monkeypatch.setenv('SSH_AUTH_SOCKET', 'private')
    monkeypatch.setenv('MCRCON_PASS', 'private')
    assert 'private' not in str(environment()) and environment()['HISTSIZE'] == '0'


def test_recording_buffers_split_secrets_private_keys_and_sensitive_prompts():
    entries = []
    recorder = Recording(lambda direction, content: entries.append((direction, content)))
    recorder.feed('input', 'PASSWORD=')
    assert entries == []
    recorder.feed('input', 'private\n')
    recorder.feed('output', 'Password: ')
    recorder.feed('input', 'another-secret\r')
    recorder.feed('output', '\n-----BEGIN PRIVATE KEY-----\nprivate key body\n-----END PRIVATE KEY-----\n')
    recorder.finish()
    assert 'private' not in str(entries).lower().replace('private key material', '')
    assert 'another-secret' not in str(entries) and 'Sensitive prompt input omitted' in str(entries)


def test_recording_entry_limit_is_bounded():
    rows = []
    recorder = Recording(lambda *args: rows.append(args))
    recorder.feed('input', '\n' * 6000)
    assert len(rows) == 5000


def demo_open(client, recording=False):
    profiles = client.get('/api/v1/services/minecraft/terminal/profiles').json()
    selected = profiles['profiles'][0]
    response = client.post('/api/v1/services/minecraft/terminal/open', json={'profile': selected['id'], 'fingerprint': selected['fingerprint'], 'confirmed': True, 'recording': recording})
    assert response.status_code == 200, response.text
    return response.json()


def test_demo_terminal_audits_metadata_only_without_recording_and_never_executes(tmp_path, monkeypatch):
    monkeypatch.setattr('controller.app.httpx.AsyncClient', lambda *a, **k: pytest.fail('Demo contacted agent'))
    app = create_app(tmp_path, demo=True, background=False)
    with TestClient(app) as client:
        opened = demo_open(client)
        path = '/api/v1/services/minecraft/terminal/sessions/' + opened['id'] + '/ws'
        with client.websocket_connect(path, headers={'Origin': 'http://127.0.0.1:8787'}) as socket:
            socket.send_json({'ticket': opened['ticket']})
            assert socket.receive_json()['kind'] == 'ready'
            assert 'never executed' in socket.receive_json()['content']
            socket.send_json({'data': 'PASSWORD=private\r'})
            assert '[DEMO]' in socket.receive_json()['content']
            socket.send_json({'kind': 'close'})
            assert socket.receive_json()['kind'] == 'end'
        record = client.get('/api/v1/services/minecraft/terminal/sessions/' + opened['id']).json()
        assert record['entries'] == [] and record['session']['status'] == 'closed'
        assert 'private' not in str(app.state.store.events())
        with app.state.store.connection() as db:
            assert not db.execute("SELECT 1 FROM operations WHERE status='running'").fetchone()


def test_optin_recording_masked_and_ticket_single_use(tmp_path):
    app = create_app(tmp_path, demo=True, background=False)
    with TestClient(app) as client:
        opened = demo_open(client, True)
        path = '/api/v1/services/minecraft/terminal/sessions/' + opened['id'] + '/ws'
        with client.websocket_connect(path) as socket:
            socket.send_json({'ticket': opened['ticket']})
            socket.receive_json();socket.receive_json()
            socket.send_json({'data': 'TOKEN=private\r'})
            socket.receive_json()
            socket.send_json({'kind': 'close'});socket.receive_json()
        result = client.get('/api/v1/services/minecraft/terminal/sessions/' + opened['id']).json()
        assert result['entries'] and 'private' not in str(result['entries'])
        cast = client.get('/api/v1/services/minecraft/terminal/sessions/' + opened['id'] + '/cast')
        lines = [json.loads(line) for line in cast.text.splitlines()]
        assert lines[0]['version'] == 2 and lines[0]['width'] == 80 and lines[0]['height'] == 24
        assert all(len(event) == 3 and event[0] >= 0 and event[1] in ('o','r') for event in lines[1:])
        assert 'private' not in cast.text and 'attachment' in cast.headers['content-disposition']
        saved = (tmp_path/'recordings'/(opened['id']+'.cast')).read_text(encoding='utf-8')
        assert saved==cast.text and json.loads(saved.splitlines()[0])['version']==2
        with pytest.raises(Exception):
            with client.websocket_connect(path) as socket: socket.receive_json()
        assert client.get('/api/v1/services/ollama/terminal/sessions/' + opened['id']).status_code == 404


def test_terminal_confirmation_wrong_ticket_origin_and_host_reservation(tmp_path):
    app = create_app(tmp_path, demo=True, background=False)
    with TestClient(app) as client:
        assert client.post('/api/v1/services/minecraft/terminal/open', json={'profile':'demo','fingerprint':'0'*64}).status_code == 409
        opened = demo_open(client)
        assert client.post('/api/v1/services/minecraft/control', json={'action':'stop'}).status_code == 409
        path = '/api/v1/services/minecraft/terminal/sessions/' + opened['id'] + '/ws'
        with pytest.raises(Exception):
            with client.websocket_connect(path, headers={'Origin':'https://evil.invalid'}) as socket: socket.receive_json()
        with client.websocket_connect(path) as socket:
            socket.send_json({'ticket':'incorrect'})
            assert socket.receive_json()['kind'] == 'end'
        assert not app.state.terminals.sessions


def test_service_or_host_changes_end_active_terminal(tmp_path):
    app = create_app(tmp_path, demo=True, background=False)
    with TestClient(app) as client:
        opened = demo_open(client)
        path = '/api/v1/services/minecraft/terminal/sessions/' + opened['id'] + '/ws'
        with client.websocket_connect(path) as socket:
            socket.send_json({'ticket':opened['ticket']});socket.receive_json();socket.receive_json()
            row = app.state.store.get('hosts','worker-node1');row['status']='offline';app.state.store.put('hosts',row)
            assert socket.receive_json()['kind'] == 'end'


def test_live_gateway_signs_every_agent_request_and_cleans_up(tmp_path, monkeypatch):
    app = live_app(tmp_path, monkeypatch)
    host = app.state.store.get('hosts','worker-node1')
    host.update(signing_env='PSC_TERMINAL_TEST_SIGNING', active_os='Linux', physical_host_id='expected')
    app.state.store.put('hosts',host)
    monkeypatch.setenv('PSC_TERMINAL_TEST_SIGNING','test-only-signing-key-material-32-bytes')
    calls = []
    async def response(method, url, **kwargs):
        calls.append(url)
        prepared = httpx.Request(method,url,json=kwargs.get('json'))
        assert valid('test-only-signing-key-material-32-bytes',method,prepared.url.raw_path.decode(),prepared.content,httpx.Headers(kwargs['headers']))
        if '/profiles?' in url:
            return httpx.Response(200,json={'os':'Linux','physical_host_id':'expected','profiles':[{'id':'shell','label':'Approved shell','cwd':'/approved','fingerprint':'1'*64}]})
        if url.endswith('/open'):
            assert kwargs['json']['confirmed']
            return httpx.Response(200,json={'id':'a'*32})
        if url.endswith('/output'):
            return httpx.Response(200,json={'content':'Observed shell output\n','ended':True})
        return httpx.Response(200,json={'closed':True})
    fake_agent(monkeypatch,response)
    with TestClient(app) as client:
        opened = client.post('/api/v1/services/minecraft/terminal/open',json={'profile':'shell','fingerprint':'1'*64,'confirmed':True}).json()
        path='/api/v1/services/minecraft/terminal/sessions/'+opened['id']+'/ws'
        with client.websocket_connect(path) as socket:
            socket.send_json({'ticket':opened['ticket']})
            assert socket.receive_json()['kind']=='ready'
            assert socket.receive_json()['content']=='Observed shell output\n'
            assert socket.receive_json()['kind']=='end'
        assert any(url.endswith('/close') for url in calls)
        assert app.state.store.get('services','minecraft')['status']=='unknown'


def test_terminal_reauth_policy_denies_without_recent_owner_login(tmp_path, monkeypatch):
    app=live_app(tmp_path,monkeypatch)
    monkeypatch.setenv('PSC_TERMINAL_REAUTH','1')
    fake_agent(monkeypatch,lambda *args,**kwargs:pytest.fail('Reauthentication denial contacted agent'))
    with TestClient(app) as client:
        result=client.post('/api/v1/services/minecraft/terminal/open',json={'profile':'shell','fingerprint':'1'*64,'confirmed':True})
        assert result.status_code==401


def test_agent_terminal_requires_signing_and_uses_mock_owned_pty(tmp_path, monkeypatch):
    monkeypatch.setattr('agent.terminal.ordinary_account',lambda:True)
    monkeypatch.setenv('PSC_TERMINAL_AGENT_KEY','test-only-signing-key-material-32-bytes')
    config={'state_dir':str(tmp_path),'signing_key_env':'PSC_TERMINAL_AGENT_KEY','terminal_profiles':{'ref':{'shell':{'argv':[str(tmp_path/'shell')],'cwd':str(tmp_path)}}}}
    app=create_agent(config,token='test')
    app.state.terminals.factory=FakePTY
    def headers(method,path,body):
        return {'Authorization':'Bearer test','Content-Type':'application/json',**signed_headers('test-only-signing-key-material-32-bytes',method,path,body)}
    with TestClient(app) as client:
        path='/terminal/profiles?ref=ref'
        result=client.get(path,headers=headers('GET',path,b'')).json()
        body={'ref':'ref','profile':'shell','fingerprint':result['profiles'][0]['fingerprint'],'confirmed':True}
        raw=json.dumps(body,separators=(',',':')).encode()
        request_headers=headers('POST','/terminal/open',raw)
        opened=client.post('/terminal/open',content=raw,headers=request_headers)
        assert opened.status_code==200,opened.text
        assert client.post('/terminal/open',content=raw,headers=request_headers).status_code==401
        identifier=opened.json()['id']
        path='/terminal/'+identifier+'/input'
        raw=b'{"data":"  echo hello\\r"}'
        assert client.post(path,content=raw,headers=headers('POST',path,raw)).status_code==200
        assert app.state.terminals.sessions[identifier]['pty'].inputs==['  echo hello\r']
        path='/terminal/'+identifier+'/close'
        assert client.post(path,content=b'{}',headers=headers('POST',path,b'{}')).status_code==200
        assert not app.state.terminals.sessions
