import asyncio
import json
import socket
from contextlib import nullcontext
from types import SimpleNamespace

import httpx
import psutil
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from agent.app import create_agent
from agent.windows_observability import event_inventory, package_apps, port_inventory, process_inventory, registry_apps, snapshot
from controller.app import create_app
from controller.windows_inventory import demo_snapshot, verified
from shared.software_guides import AUTODESK_REMOVE, MICROSOFT_REMOVE, guides
from test_config_operations import endpoint, fake_agent, live_app


def test_product_specific_microsoft_links():
    office = guides('Microsoft 365')
    assert office['documentation_url'].endswith('/microsoft-365/')
    assert 'uninstall-microsoft-365-or-office-from-a-pc' in office['removal_url']
    assert guides('Microsoft Edge')['documentation_url'].endswith('/edge/')


def test_registry_metadata_never_reads_uninstall_commands_and_deduplicates_views():
    fields = {'DisplayName': 'Autodesk AutoCAD 2026', 'Publisher': 'Autodesk', 'DisplayVersion': '2026',
              'UninstallString': 'do-not-execute', 'URLInfoAbout': 'https://untrusted.invalid'}
    queries = []
    class Registry:
        HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, KEY_WOW64_64KEY, KEY_WOW64_32KEY, KEY_READ = range(5)
        def OpenKey(self, *args):
            return nullcontext('parent' if 'Uninstall' in str(args[1]) else 'app')
        def QueryInfoKey(self, key):
            return (1,)
        def EnumKey(self, key, index):
            return 'autocad'
        def QueryValueEx(self, key, name):
            queries.append(name)
            if name not in fields:
                raise FileNotFoundError()
            return fields[name], 1
    rows, warnings = registry_apps(Registry())
    assert len(rows) == 2 and warnings == []  # machine + agent user; duplicate 32/64 views collapsed
    assert all(row['removal_url'] == AUTODESK_REMOVE for row in rows)
    assert not {'UninstallString', 'QuietUninstallString', 'URLInfoAbout'}.intersection(queries)
    assert 'do-not-execute' not in json.dumps(rows) and 'untrusted.invalid' not in json.dumps(rows)


def test_package_inventory_fixed_read_only_command_and_nonremovable_metadata():
    calls = []
    def command(argv, **kwargs):
        calls.append((argv, kwargs))
        return json.dumps([{'Name': 'Microsoft.WindowsCalculator', 'Version': '1', 'Publisher': 'Microsoft', 'NonRemovable': True}])
    rows = package_apps(command)
    assert rows[0]['non_removable'] and rows[0]['removal_url'] == MICROSOFT_REMOVE
    assert 'Get-AppxPackage' in calls[0][0][-1] and 'Remove-' not in calls[0][0][-1]
    assert calls[0][1]['timeout'] == 15


def test_process_inventory_omits_command_lines_and_ports_include_udp(monkeypatch):
    monkeypatch.setattr('agent.windows_observability.psutil.process_iter', lambda attrs: [SimpleNamespace(info={'pid': 1, 'name': 'acad.exe', 'exe': 'C:/acad.exe', 'create_time': 1000, 'cmdline': 'TOKEN=private'})])
    assert 'private' not in str(process_inventory())
    monkeypatch.setattr('agent.windows_observability.psutil.net_connections', lambda **kwargs: [
        SimpleNamespace(type=socket.SOCK_STREAM, status=psutil.CONN_LISTEN, laddr=SimpleNamespace(ip='127.0.0.1', port=80), pid=1),
        SimpleNamespace(type=socket.SOCK_DGRAM, status=psutil.CONN_NONE, laddr=SimpleNamespace(ip='0.0.0.0', port=53), pid=2),
        SimpleNamespace(type=socket.SOCK_STREAM, status=psutil.CONN_ESTABLISHED, laddr=SimpleNamespace(ip='127.0.0.1', port=123), pid=3),
    ])
    assert [row['protocol'] for row in port_inventory()] == ['tcp', 'udp']


def test_event_logs_fixed_command_masks_and_bounds_messages():
    calls = []
    def command(argv, **kwargs):
        calls.append(argv)
        return json.dumps({'Id': 1000, 'Message': 'TOKEN=private', 'ProviderName': 'App', 'LogName': 'Application'})
    rows = event_inventory(command)
    assert len(rows) == 1 and 'private' not in str(rows)
    assert '-MaxEvents 40' in calls[0][-1] and 'System' in calls[0][-1] and 'Security' not in calls[0][-1]


def test_snapshot_reports_permission_gaps_without_claiming_empty_complete_scopes(monkeypatch):
    monkeypatch.setattr('agent.windows_observability.platform.system', lambda: 'Windows')
    monkeypatch.setattr('agent.windows_observability.registry_apps', lambda: ([], ['Protected registry view unavailable']))
    monkeypatch.setattr('agent.windows_observability.process_inventory', lambda: [])
    def denied():
        raise psutil.AccessDenied()
    monkeypatch.setattr('agent.windows_observability.port_inventory', denied)
    result = snapshot({'windows_packages': False}, lambda *args: (_ for _ in ()).throw(AssertionError('Unexpected command')))
    assert 'ports' not in result['completed'] and result['ports'] == []
    assert result['warnings'] and 'other users' in result['coverage']


def test_windows_agent_endpoint_is_authenticated_scoped_and_no_uninstall_route(monkeypatch):
    monkeypatch.setattr('agent.app.windows_snapshot', lambda config, command: {'os': 'Windows', 'applications': []})
    with TestClient(create_agent({}, token='test')) as c:
        assert c.get('/inventory/windows').status_code == 401
        c.headers['Authorization'] = 'Bearer test'
        assert c.get('/inventory/windows').status_code == 200
        assert c.post('/inventory/windows/uninstall', json={}).status_code == 404


def test_remote_links_and_extra_actions_are_ignored_and_secret_events_masked():
    payload = demo_snapshot()
    payload['applications'][0].update(removal_url='https://untrusted.invalid', uninstall_command='delete-everything')
    payload['events'][0]['message'] = 'API_TOKEN=private'
    clean = verified(payload)
    assert clean['applications'][0]['removal_url'] == AUTODESK_REMOVE
    assert 'untrusted.invalid' not in str(clean) and 'delete-everything' not in str(clean) and 'private' not in str(clean)
    with pytest.raises(HTTPException):
        verified({**payload, 'applications': 'bad'})
    assert 'service' in guides('Windows Update', kind='service')['removal_note'].lower()


def test_demo_windows_inventory_never_contacts_agents_and_preserves_host_metadata(tmp_path, monkeypatch):
    def prohibited(*args, **kwargs):
        raise AssertionError('Demo contacted Windows agent')
    monkeypatch.setattr('controller.app.httpx.AsyncClient', prohibited)
    app = create_app(tmp_path, demo=True, token='', background=False)
    before = app.state.store.get('hosts', 'laptop')
    with TestClient(app) as c:
        result = c.post('/api/v1/hosts/laptop/windows/refresh', json={})
        assert result.status_code == 200 and result.json()['demo']
        assert result.json()['inventory']['applications'][0]['name'] == 'Autodesk AutoCAD 2026'
        assert app.state.store.get('hosts', 'laptop') == before


def test_live_inventory_keeps_last_windows_observation_stale_after_os_switch(tmp_path, monkeypatch):
    app = live_app(tmp_path, monkeypatch)
    store = app.state.store
    host = store.get('hosts', 'laptop')
    host.update(active_os='Windows', physical_host_id='same-laptop')
    store.put('hosts', host)
    async def request(*args, **kwargs):
        return httpx.Response(200, json={**demo_snapshot(), 'physical_host_id': 'same-laptop'})
    fake_agent(monkeypatch, request)
    result = asyncio.run(endpoint(app, '/api/v1/hosts/{hid}/windows/refresh', 'POST')('laptop'))
    assert not result['stale']
    host['active_os'] = 'Linux'
    store.put('hosts', host)
    cached = endpoint(app, '/api/v1/hosts/{hid}/windows', 'GET')('laptop')
    assert cached['stale'] and cached['inventory']['applications']
    with pytest.raises(HTTPException) as rejected:
        asyncio.run(endpoint(app, '/api/v1/hosts/{hid}/windows/refresh', 'POST')('laptop'))
    assert rejected.value.status_code == 409


def test_wrong_physical_identity_does_not_replace_cached_inventory(tmp_path, monkeypatch):
    app = live_app(tmp_path, monkeypatch)
    host = app.state.store.get('hosts', 'laptop')
    host.update(active_os='Windows', physical_host_id='expected')
    app.state.store.put('hosts', host)
    async def request(*args, **kwargs):
        return httpx.Response(200, json={**demo_snapshot(), 'physical_host_id': 'wrong'})
    fake_agent(monkeypatch, request)
    with pytest.raises(HTTPException) as rejected:
        asyncio.run(endpoint(app, '/api/v1/hosts/{hid}/windows/refresh', 'POST')('laptop'))
    assert rejected.value.status_code == 409
    with app.state.store.connection() as db:
        assert not db.execute('SELECT 1 FROM host_inventory').fetchone()


def test_os_switch_clears_previous_runtime_access_even_when_scan_fails(tmp_path, monkeypatch):
    app = live_app(tmp_path, monkeypatch)
    store = app.state.store
    service = store.get('services', 'minecraft')
    host = store.get('hosts', service['host_id'])
    host.update(active_os='Linux', physical_host_id='worker')
    store.put('hosts', host)
    async def request(method, url, **kwargs):
        return httpx.Response(200, json={'os': 'Windows', 'physical_host_id': 'worker'}) if url.endswith('/telemetry') else httpx.Response(503, json={'detail': 'Scan unavailable'})
    fake_agent(monkeypatch, request)
    updated = asyncio.run(endpoint(app, '/api/v1/hosts/{hid}/refresh', 'POST')(host['id']))
    saved = store.get('services', 'minecraft')
    assert updated['active_os'] == 'Windows' and updated['identity_verified']
    assert saved['status'] == 'unknown' and not any(saved['capabilities'].values())
    assert saved['notes'] == service['notes'] and saved['revision'] == service['revision']
    assert updated['os_history'][-1]['os'] == 'Linux'


def test_wrong_physical_identity_never_marks_agent_online(tmp_path, monkeypatch):
    app = live_app(tmp_path, monkeypatch)
    store = app.state.store
    host = store.get('hosts', 'laptop')
    host.update(status='offline', last_seen=None, physical_host_id='expected')
    store.put('hosts', host)
    async def request(*args, **kwargs):
        return httpx.Response(200, json={'os': 'Windows', 'physical_host_id': 'wrong'})
    fake_agent(monkeypatch, request)
    updated = asyncio.run(endpoint(app, '/api/v1/hosts/{hid}/refresh', 'POST')('laptop'))
    assert updated['status'] == 'offline' and 'identity' in updated['error']
