import asyncio
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from agent.app import create_agent, systemd_inventory
from controller.ai import availability, configuration
from controller.app import create_app
from controller.dependencies import startup_order, validate_dependencies
from controller.discovery import due, proposals, snapshot
from controller.health import check_key, history, record, weighted_uptime
from controller.store import Store
from shared.models import AISettings


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path / 'demo', demo=True, token='', background=False)) as connection:
        yield connection


def patch(client, sid, **fields):
    service = client.get('/api/v1/services/' + sid).json()
    return client.patch('/api/v1/services/' + sid, json={'revision': service['revision'], **fields})


def test_identity_host_and_dependency_validation(client):
    result = patch(client, 'minecraft', icon='documents', tags=['custom', 'custom'], dependencies=['paperless'])
    assert result.status_code == 200, result.text
    assert result.json()['tags'] == ['custom']
    assert result.json()['icon'] == 'documents'
    assert 'minecraft' in client.get('/api/v1/services/paperless').json()['dependents']
    assert patch(client, 'paperless', dependencies=['minecraft']).status_code == 422
    assert patch(client, 'minecraft', dependencies=['absent']).status_code == 422
    assert patch(client, 'minecraft', host_id='absent').status_code == 404
    assert patch(client, 'minecraft', icon='bad').status_code == 422
    moved = patch(client, 'minecraft', host_id='laptop').json()
    assert moved['status'] == 'unknown'
    assert not any(moved['capabilities'].values())
    assert moved.get('agent_ref') is None


def test_dependency_start_requires_confirmation_and_preflights_all_hosts(client):
    assert patch(client, 'minecraft', dependencies=['paperless']).status_code == 200
    result = client.post('/api/v1/services/minecraft/control', json={'action': 'start'})
    assert result.status_code == 409
    assert result.json()['detail']['dependencies'] == ['paperless']
    accepted = client.post('/api/v1/services/minecraft/control', json={'action': 'start', 'start_dependencies': True})
    assert accepted.status_code == 200, accepted.text
    assert client.get('/api/v1/services/paperless').json()['status'] == 'running'
    actions = [x for x in client.get('/api/v1/audit').json() if x['action'] == 'control.start' and x['result'] == 'success']
    assert [x['service_id'] for x in actions[:2]] == ['minecraft', 'paperless']
    patch(client, 'minecraft', dependencies=['playground'])
    count = len(client.get('/api/v1/audit').json())
    assert client.post('/api/v1/services/minecraft/control', json={'action': 'start', 'start_dependencies': True}).status_code == 409
    assert len(client.get('/api/v1/audit').json()) == count


def test_dependency_diamonds_and_deep_graphs():
    graph = {'a': {'dependencies': ['b', 'c']}, 'b': {'dependencies': ['d']}, 'c': {'dependencies': ['d']}, 'd': {}}
    assert startup_order(graph, 'a') == ['d', 'b', 'c', 'a']
    graph = {str(i): {'dependencies': [str(i + 1)] if i < 1500 else []} for i in range(1501)}
    assert len(startup_order(graph, '0')) == 1501
    graph['1500']['dependencies'] = ['0']
    with pytest.raises(HTTPException):
        validate_dependencies(graph)


def observed(**fields):
    return {'agent_ref': 'docker-web', 'name': 'web', 'runtime': 'docker', 'control_handle': {'container': 'web'}, 'ports': ['8080/tcp'], 'paths': ['/data'], 'status': 'running', **fields}


def test_discovery_diffs_and_missing_require_successful_provider():
    host = {'id': 'worker', 'name': 'worker', 'address': '192.0.2.1'}
    initial = proposals(host, [], {'services': [observed()], 'completed_runtimes': ['docker']})[0]
    old = {**initial, 'discovery_baseline': initial['snapshot'], 'notes': 'Owner context'}
    assert proposals(host, [old], {'services': [observed()]})[0]['change'] == 'unchanged'
    changed = proposals(host, [old], {'services': [observed(ports=['9999/tcp'])]})[0]
    assert changed['diff'] == [{'field': 'ports', 'before': ['8080/tcp'], 'after': ['9999/tcp']}]
    assert proposals(host, [old], {'services': [], 'warnings': [{'runtime': 'docker', 'detail': 'failed'}]}) == []
    gone = proposals(host, [old], {'services': [], 'completed_runtimes': ['docker']})[0]
    assert gone['change'] == 'gone' and gone['notes'] == 'Owner context'
    assert not any(gone['capabilities'].values())
    returned = proposals(host, [{**old, 'inventory_status': 'gone'}], {'services': [observed()]})[0]
    assert returned['diff'][-1]['after'] == 'present'


def test_known_app_enrichment_uses_published_port():
    row = proposals({'id': 'pi', 'name': 'pi', 'address': '192.0.2.1'}, [], {'services': [observed(image='ollama/ollama:latest', ports=['11435/tcp'])]})[0]
    assert row['name'] == 'Ollama' and row['icon'] == 'ai'
    assert row['urls'] == ['http://192.0.2.1:11435']


def test_discovery_review_survives_restart_and_empty_selection(tmp_path):
    path = tmp_path / 'demo'
    with TestClient(create_app(path, demo=True, token='', background=False)) as c:
        scan = c.post('/api/v1/hosts/worker-node1/scan', json={'include_system': True}).json()
    with TestClient(create_app(path, demo=True, token='', background=False)) as c:
        assert c.get('/api/v1/hosts/worker-node1/discovery').json()['scan_id'] == scan['scan_id']
        result = c.post('/api/v1/discovery/accept', json={'scan_id': scan['scan_id'], 'refs': []})
        assert result.status_code == 200
        assert c.get('/api/v1/hosts/worker-node1/discovery').json()['reviewed']
        assert c.post('/api/v1/discovery/accept', json={'scan_id': scan['scan_id'], 'refs': []}).status_code == 409


def test_six_hour_rescan_boundary():
    current = datetime.now(timezone.utc)
    assert due({}, current)
    assert not due({'discovery_checked_at': (current - timedelta(seconds=21599)).isoformat()}, current)
    assert due({'discovery_checked_at': (current - timedelta(hours=6)).isoformat()}, current)


def test_systemd_enabled_unloaded_and_os_unhide(monkeypatch):
    def command(args, **kwargs):
        if 'list-units' in args:
            return json.dumps([{'unit': 'systemd-resolved.service', 'active': 'active', 'description': 'SSH'}])
        if 'list-unit-files' in args:
            return 'custom.service enabled enabled\nsystemd-resolved.service enabled enabled\ndisabled.service disabled disabled\n'
        return ''
    monkeypatch.setattr('agent.app.command', command)
    visible = systemd_inventory({})
    assert [r['name'] for r in visible] == ['custom']
    assert visible[0]['runtime_details']['loaded'] is False
    assert visible[0]['runtime_details']['enabled_state'] == 'enabled'
    unhidden = systemd_inventory({}, include_system=True)
    assert set(r['name'] for r in unhidden) == {'custom', 'systemd-resolved'}


def test_weighted_uptime_gaps_and_unequal_intervals():
    current = datetime(2026, 1, 1, tzinfo=timezone.utc)
    rows = [{'ts': (current - timedelta(seconds=1000)).isoformat(), 'ok': 1, 'interval_s': 60},
            {'ts': (current - timedelta(seconds=100)).isoformat(), 'ok': 0, 'interval_s': 30}]
    result = weighted_uptime(rows, current)['24h']
    assert result['up_s'] == 180 and result['down_s'] == 90
    assert result['uptime_percent'] == 66.67
    assert result['unknown_s'] == 86400 - 270
    assert weighted_uptime([], current)['30d']['uptime_percent'] is None


def test_incident_lifecycle_and_old_inflight_checks(tmp_path):
    store = Store(tmp_path / 'store')
    check = {'enabled': True, 'type': 'tcp', 'target': 'host', 'port': 80, 'interval_s': 30}
    store.put('services', {'id': 'web', 'health_check': check})
    failure = {'ok': False, 'latency_ms': 1, 'detail': 'Connection failed'}
    record(store, 'web', failure)
    record(store, 'web', failure)
    assert len(history(store, 'web')['incidents']) == 1
    record(store, 'web', {**failure, 'ok': True})
    incident = history(store, 'web')['incidents'][0]
    assert incident['ended_at'] and incident['resolution'] == 'recovered'
    record(store, 'web', failure, signature=check_key({**check, 'port': 81}))
    assert len(history(store, 'web')['incidents']) == 1


def test_incident_notes_scope_and_secret_rejection(client):
    note = client.post('/api/v1/services/minecraft/incident-notes', json={'note': 'Port conflict; checked the listener', 'source': 'owner'})
    assert note.status_code == 200
    assert client.get('/api/v1/services/minecraft/history').json()['incident_notes'][0]['note'].startswith('Port conflict')
    assert client.post('/api/v1/services/minecraft/incident-notes', json={'note': 'TOKEN=do-not-store'}).status_code == 422
    assert client.post('/api/v1/services/minecraft/incident-notes', json={'note': 'test', 'incident_id': 999}).status_code == 404


def test_log_snapshot_lines_download_and_redaction(client, monkeypatch):
    assert client.get('/api/v1/services/minecraft/logs?lines=5001').status_code == 422
    result = client.get('/api/v1/services/minecraft/logs/download?lines=1000')
    assert result.status_code == 200 and result.headers['content-type'].startswith('text/plain')
    assert 'DEMO' in result.text
    calls = []
    monkeypatch.setattr('agent.app.command', lambda args, **kwargs: calls.append(args) or 'TOKEN=private-value\nerror: failed')
    with TestClient(create_agent({'allow_containers': ['web']}, token='test')) as a:
        a.headers['Authorization'] = 'Bearer test'
        result = a.post('/logs', json={'runtime': 'docker', 'handle': {'container': 'web'}, 'lines': 1000})
        assert result.status_code == 200 and 'private-value' not in result.text
        assert calls[0] == ['docker', 'logs', '--tail', '1000', '--timestamps', 'web']
        assert a.post('/logs', json={'runtime': 'docker', 'handle': {'container': 'web'}, 'lines': -1}).status_code == 422


def test_ai_preferences_persist_and_demo_never_probes(tmp_path, monkeypatch):
    async def forbidden(*args, **kwargs):
        raise AssertionError('Demo must never access Ollama')
    monkeypatch.setattr('httpx.AsyncClient.get', forbidden)
    path = tmp_path / 'demo'
    prefs = {'enabled': True, 'endpoint': 'http://192.0.2.1:11434', 'model': 'local-test', 'timeout_s': 90, 'context_lines': 100}
    with TestClient(create_app(path, demo=True, token='', background=False)) as c:
        assert c.put('/api/v1/ai', json=prefs).status_code == 200
        assert c.get('/api/v1/ai/health').json()['available']
    with TestClient(create_app(path, demo=True, token='', background=False)) as c:
        saved = c.get('/api/v1/ai').json()
        assert all(saved[k] == v for k, v in prefs.items())


def test_ai_model_availability_missing_and_unreachable(monkeypatch):
    config = AISettings(endpoint='http://ollama:11434', model='test').model_dump() | {'configured': True}
    async def get(self, url, **kwargs):
        return httpx.Response(200, json={'models': [{'name': 'test:latest'}]}, request=httpx.Request('GET', url))
    monkeypatch.setattr('httpx.AsyncClient.get', get)
    assert asyncio.run(availability(config))['available']
    assert not asyncio.run(availability({**config, 'model': 'missing'}))['available']
    async def fail(*args, **kwargs):
        raise httpx.ConnectError('unreachable')
    monkeypatch.setattr('httpx.AsyncClient.get', fail)
    assert not asyncio.run(availability(config))['available']
import base64
from pathlib import Path


def test_large_text_binary_download_and_blocked_secrets(tmp_path):
    root = tmp_path / 'files'
    root.mkdir()
    (root / 'large.txt').write_bytes(('Large text ✓\n' * 180000).encode())
    (root / 'data.bin').write_bytes(b'\x00\xff\x80\x01')
    (root / '.env').write_text('TOKEN=hidden')
    (root / 'config.txt').write_text('TOKEN=hidden\nport=8080')
    with TestClient(create_agent({'file_roots': {'approved': [str(root)]}}, token='test')) as c:
        c.headers['Authorization'] = 'Bearer test'
        large = c.get('/files', params={'ref': 'approved', 'path': 'large.txt'})
        assert large.status_code == 200, large.text[:100]
        assert large.json()['truncated'] and large.json()['readonly']
        assert not large.json()['downloadable']
        assert 'Large text' in large.json()['content']
        assert c.get('/files', params={'ref': 'approved', 'path': 'large.txt', 'download': True}).status_code == 413
        binary = c.get('/files', params={'ref': 'approved', 'path': 'data.bin'}).json()
        assert binary['kind'] == 'binary' and 'content' not in binary
        payload = c.get('/files', params={'ref': 'approved', 'path': 'data.bin', 'download': True}).json()
        assert base64.b64decode(payload['data']) == b'\x00\xff\x80\x01'
        text = c.get('/files', params={'ref': 'approved', 'path': 'config.txt', 'download': True}).json()
        assert b'hidden' not in base64.b64decode(text['data'])
        assert c.get('/files', params={'ref': 'approved', 'path': '.env', 'download': True}).status_code == 403
        assert c.get('/files', params={'ref': 'approved', 'path': '../outside', 'download': True}).status_code == 403


def test_demo_file_download_is_attachment(client):
    result = client.get('/api/v1/services/minecraft/files/download?path=README.md')
    assert result.status_code == 200
    assert result.headers['x-content-type-options'] == 'nosniff'
    assert 'attachment' in result.headers['content-disposition']
    assert 'Sample service files' in result.text
    store = client.app.state.store
    service = store.get('services', 'playground')
    service['capabilities']['files'] = False
    store.put('services', service)
    assert client.get('/api/v1/services/playground/files/download?path=README.md').status_code == 403


def test_os_filter_cannot_falsely_mark_hidden_unit_missing():
    host = {'id': 'worker', 'name': 'worker'}
    old = {**observed(runtime='systemd', control_handle={'unit': 'systemd-resolved.service'}, system_unit=True), 'id': 'resolved', 'host_id': 'worker'}
    assert proposals(host, [old], {'services': [], 'completed_runtimes': ['systemd'], 'systemd_scope': 'user'}) == []
    assert proposals(host, [old], {'services': [], 'completed_runtimes': ['systemd'], 'systemd_scope': 'all'})[0]['change'] == 'gone'
    with pytest.raises(HTTPException):
        proposals(host, [], {'services': [observed(), observed()]})


def test_demo_ai_disabled_is_respected(client):
    assert client.put('/api/v1/ai', json={'enabled': False}).status_code == 200
    assert client.get('/api/v1/ai/health').json()['available'] is False
    assert client.post('/api/v1/services/minecraft/explain', json={}).status_code == 409


def test_pwa_shell_and_manifest_are_served(client):
    manifest = client.get('/manifest.webmanifest').json()
    assert manifest['display'] == 'standalone'
    assert {icon['sizes'] for icon in manifest['icons']} == {'192x192', '512x512'}
    worker = client.get('/sw.js').text
    assert '__BUILD_VERSION__' not in worker
    assert "url.pathname.startsWith('/api/')" in worker
    assert client.get('/icon-192.png').content.startswith(b'\x89PNG')


def test_container_inventory_controls_logs_and_compose_confirmation(client):
    rows = client.get('/api/v1/containers').json()
    minecraft = next(row for row in rows if row.get('service_id') == 'minecraft')
    path = f"/api/v1/hosts/{minecraft['host_id']}/containers/{minecraft['agent_ref']}"
    assert client.get(path + '/logs?lines=100').status_code == 200
    assert client.get(path + '/logs?download=true').headers['content-type'].startswith('text/plain')
    assert client.post(path + '/control', json={'action': 'stop'}).status_code == 409
    result = client.post(path + '/control', json={'action': 'stop', 'acknowledge_dependencies': True})
    assert result.status_code == 200, result.text
    assert result.json()['container']['status'] == 'stopped'
    assert client.get('/api/v1/services/minecraft').json()['status'] == 'stopped'
    assert client.post(path + '/control', json={'action': 'start', 'acknowledge_dependencies': True}).status_code == 200
    assert client.post(path + '/control', json={'action': 'start', 'handle': {'container': 'other'}}).status_code == 422
    offline = next(row for row in rows if row['host_id'] == 'laptop')
    assert offline['stale'] and offline['status'] == 'unknown'
    assert client.post(f"/api/v1/hosts/laptop/containers/{offline['agent_ref']}/control", json={'action': 'start'}).status_code == 403


def test_live_container_state_requires_observation_and_host_operations_serialize(tmp_path, monkeypatch):
    monkeypatch.setenv('PSC_AGENT_TEST', 'test-token')
    with TestClient(create_app(tmp_path / 'live', token='', background=False)) as c:
        store = c.app.state.store
        store.put('hosts', {'id': 'pi', 'name': 'pi', 'status': 'online', 'agent_url': 'http://agent', 'token_env': 'PSC_AGENT_TEST'})
        row = observed() | {'capabilities': {'control': True, 'logs': True}, 'image': 'example/web'}
        from controller.store import now
        with store.connection() as db:
            db.execute('INSERT INTO container_inventory VALUES(?,?,?)', ('pi', now(), json.dumps([row])))
        calls = []
        async def request(self, method, url, **kwargs):
            calls.append((url, kwargs.get('json')))
            payload = {'output': 'completed'} if url.endswith('/control') else {'services': [], 'containers': [{**row, 'status': 'stopped'}], 'completed_runtimes': ['docker']}
            return httpx.Response(200, json=payload, request=httpx.Request(method, url))
        monkeypatch.setattr('httpx.AsyncClient.request', request)
        path = '/api/v1/hosts/pi/containers/docker-web'
        assert c.post(path + '/control', json={'action': 'stop'}).json()['container']['status'] == 'stopped'
        assert calls[0][1]['handle'] == {'container': 'web'}
        async def unverifiable(self, method, url, **kwargs):
            if url.endswith('/scan'):
                raise httpx.ConnectError('gone')
            return httpx.Response(200, json={'output': 'completed'}, request=httpx.Request(method, url))
        monkeypatch.setattr('httpx.AsyncClient.request', unverifiable)
        result = c.post(path + '/control', json={'action': 'start'})
        assert result.json()['container']['status'] == 'unknown' and result.json()['container']['stale']
        assert c.post(path + '/control', json={'action': 'start'}).status_code == 403
        with store.connection() as db:
            db.execute('UPDATE container_inventory SET body=? WHERE host_id=?', (json.dumps([row]), 'pi'))
            db.execute("INSERT INTO operations VALUES('busy','container:pi:other','restart','running',?,'')", (now(),))
        assert c.post(path + '/control', json={'action': 'start'}).status_code == 409
from pydantic import ValidationError
from shared.models import HealthCheck
from controller.health import probe


@pytest.mark.parametrize('os_name', ['Windows', 'Linux'])
def test_icmp_uses_fixed_arguments_and_records_outcome(monkeypatch, os_name):
    calls = []
    class Process:
        returncode = 0
        async def communicate(self):
            return None, None
    async def spawn(*args, **kwargs):
        calls.append(args)
        return Process()
    monkeypatch.setattr('controller.health.platform.system', lambda: os_name)
    monkeypatch.setattr('asyncio.create_subprocess_exec', spawn)
    result = asyncio.run(probe(HealthCheck(enabled=True, type='icmp', target='192.0.2.1', timeout_s=3)))
    assert result['ok'] and result['detail'] == 'ICMP reply received'
    assert calls == [('ping', '-n', '1', '-w', '3000', '192.0.2.1')] if os_name == 'Windows' else calls == [('ping', '-n', '-c', '1', '-W', '3', '--', '192.0.2.1')]
    for bad in ('-all', 'host;whoami', 'host\nwhoami', 'http://host'):
        with pytest.raises(ValidationError):
            HealthCheck(enabled=True, type='icmp', target=bad)


def test_icmp_timeout_kills_child_and_demo_does_not_spawn(client, monkeypatch):
    class Process:
        returncode = None
        killed = False
        async def communicate(self):
            if not self.killed:
                raise asyncio.TimeoutError()
            return None, None
        def kill(self):
            self.killed = True
    process = Process()
    async def spawn(*args, **kwargs):
        return process
    monkeypatch.setattr('asyncio.create_subprocess_exec', spawn)
    assert asyncio.run(probe(HealthCheck(enabled=True, type='icmp', target='host')))['detail'] == 'Check timed out'
    assert process.killed
    async def forbidden(*args, **kwargs):
        raise AssertionError('Demo must not run ping')
    monkeypatch.setattr('asyncio.create_subprocess_exec', forbidden)
    service = client.get('/api/v1/services/minecraft').json()
    assert client.put('/api/v1/services/minecraft/health-check', json={'revision': service['revision'], 'check': {'enabled': True, 'type': 'icmp', 'target': 'host'}}).status_code == 200
    assert client.post('/api/v1/services/minecraft/health/check', json={}).status_code == 200



def test_discovery_selection_preflight_preserves_owner_edits(client):
    first = client.post('/api/v1/hosts/worker-node1/scan', json={}).json()
    ref = first['candidates'][0]['agent_ref']
    assert client.post('/api/v1/discovery/accept', json={'scan_id': first['scan_id'], 'refs': [ref]}).status_code == 200
    scan = client.post('/api/v1/hosts/worker-node1/scan', json={}).json()
    candidate = scan['candidates'][0]
    assert patch(client, candidate['id'], notes='New owner context').status_code == 200
    assert client.post('/api/v1/discovery/accept', json={'scan_id': scan['scan_id'], 'refs': [ref]}).status_code == 409
    assert client.get('/api/v1/services/' + candidate['id']).json()['notes'] == 'New owner context'


def test_long_host_ids_cannot_collide_in_discovery():
    prefix = 'a' * 45
    ids = [proposals({'id': prefix + suffix, 'name': 'worker'}, [], {'services': [observed()]})[0]['id'] for suffix in ('-one', '-two')]
    assert ids[0] != ids[1] and all(len(sid) <= 80 for sid in ids)


def test_live_discovery_gone_review_keeps_notebook(tmp_path, monkeypatch):
    monkeypatch.setenv('PSC_AGENT_TEST', 'test-token')
    from shared.models import ServiceDefinition
    with TestClient(create_app(tmp_path / 'live', token='', background=False)) as c:
        store = c.app.state.store
        store.put('hosts', {'id': 'pi', 'name': 'pi', 'status': 'online', 'agent_url': 'http://agent', 'token_env': 'PSC_AGENT_TEST'})
        service = ServiceDefinition(id='web', host_id='pi', name='My web app', runtime='docker', notes='Owner recovery instructions', control_handle={'container': 'web'}).model_dump()
        service.update(revision=1, source='discovery', status='running', agent_ref='docker-web', discovery_baseline=snapshot(observed()))
        store.put('services', service)
        async def request(self, method, url, **kwargs):
            return httpx.Response(200, json={'services': [], 'containers': [], 'completed_runtimes': ['docker']}, request=httpx.Request(method, url))
        monkeypatch.setattr('httpx.AsyncClient.request', request)
        scan = c.post('/api/v1/hosts/pi/scan', json={}).json()
        assert scan['candidates'][0]['change'] == 'gone'
        assert c.post('/api/v1/discovery/accept', json={'scan_id': scan['scan_id'], 'refs': ['docker-web']}).status_code == 200
        kept = c.get('/api/v1/services/web').json()
        assert kept['inventory_status'] == 'gone' and kept['notes'] == 'Owner recovery instructions'
        assert kept['status'] == 'unknown' and not any(kept['capabilities'].values())


def test_dependency_preflight_and_host_move_refuse_active_operations(client):
    from controller.store import now
    assert patch(client, 'minecraft', dependencies=['paperless']).status_code == 200
    with client.app.state.store.connection() as db:
        db.execute("INSERT INTO operations VALUES('busy','minecraft','restart','running',?,'')", (now(),))
    assert client.post('/api/v1/services/minecraft/control', json={'action': 'start', 'start_dependencies': True}).status_code == 409
    assert client.get('/api/v1/services/paperless').json()['status'] == 'stopped'
    assert patch(client, 'minecraft', host_id='laptop').status_code == 409
    assert patch(client, 'minecraft', notes='Owner documentation can still be edited').status_code == 200
