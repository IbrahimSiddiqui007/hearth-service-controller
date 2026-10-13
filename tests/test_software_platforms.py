import asyncio
import json
import plistlib
from types import SimpleNamespace

import httpx
import psutil
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from agent.app import create_agent
from agent.macos import launchd_inventory, startup_rows
from agent.software_inventory import desktop_apps, linux_packages, mac_apps, snapshot
from controller.app import create_app
from controller.windows_inventory import verified
from shared.models import ServiceDefinition
from shared.software_guides import guides
from test_config_operations import endpoint, fake_agent, live_app


@pytest.mark.parametrize('distro,output,argv,source', [
    ({'ID': 'ubuntu'}, 'installed\tnginx\t1.0\nconfig-files\told\t0\n', 'dpkg-query', 'dpkg'),
    ({'ID': 'cachyos', 'ID_LIKE': 'arch'}, 'nginx 1.0\n', 'pacman', 'pacman'),
    ({'ID': 'fedora'}, 'nginx\t1.0\n', 'rpm', 'rpm')])
def test_linux_package_providers_only_query_local_database(distro, output, argv, source):
    calls = []
    def command(args, **kwargs):
        calls.append(args)
        return output
    rows, truncated = linux_packages({}, command, distro)
    assert len(rows) == 1 and rows[0]['source'] == source and not truncated
    assert calls[0][0] == argv and not any(word in calls[0] for word in ('install', 'remove', '-S', '-R'))


def test_desktop_metadata_omits_exec_urls_hidden_entries_and_invalid_files(tmp_path):
    (tmp_path / 'app.desktop').write_text('[Desktop Entry]\nType=Application\nName=Editor\nExec=SECRET_COMMAND\nURL=https://evil.invalid\n')
    (tmp_path / 'hidden.desktop').write_text('[Desktop Entry]\nType=Application\nName=Hidden\nHidden=true\n')
    (tmp_path / 'bad.desktop').write_text('invalid')
    rows, warnings, truncated = desktop_apps([tmp_path])
    assert [row['name'] for row in rows] == ['Editor'] and warnings and not truncated
    assert 'SECRET_COMMAND' not in str(rows) and 'evil.invalid' not in str(rows)


def bundle(root, name='Office', **metadata):
    contents = root / (name + '.app') / 'Contents'
    contents.mkdir(parents=True)
    (contents / 'Info.plist').write_bytes(plistlib.dumps({'CFBundleName': name, 'CFBundleIdentifier': 'com.microsoft.office', **metadata}))
    return contents


def test_mac_bundle_reads_selected_metadata_without_launching(tmp_path):
    bundle(tmp_path, CFBundleShortVersionString='1.0', EnvironmentVariables={'TOKEN': 'private'}, CFBundleExecutable='do-not-execute')
    rows, warnings, truncated = mac_apps({}, [tmp_path])
    assert rows[0]['name'] == 'Office' and rows[0]['version'] == '1.0' and not warnings and not truncated
    assert 'private' not in str(rows) and 'do-not-execute' not in str(rows)
    (tmp_path / 'Office.app/Contents/Info.plist').write_bytes(b'x' * 262145)
    assert mac_apps({}, [tmp_path])[1]


@pytest.mark.parametrize('system', ['Linux', 'Darwin'])
def test_snapshot_scopes_physical_identity_and_permission_gaps(monkeypatch, system):
    monkeypatch.setattr('agent.software_inventory.platform.system', lambda: system)
    monkeypatch.setattr('agent.software_inventory.desktop_apps', lambda: ([], [], False))
    monkeypatch.setattr('agent.software_inventory.mac_apps', lambda config: ([], [], False))
    monkeypatch.setattr('agent.software_inventory.process_inventory', lambda: [{'pid': 1, 'name': 'example'}])
    def denied():
        raise psutil.AccessDenied()
    monkeypatch.setattr('agent.software_inventory.port_inventory', denied)
    result = snapshot({'software_packages': False, 'physical_host_id': 'physical'}, lambda *a, **k: pytest.fail('Unexpected command'))
    assert result['physical_host_id'] == 'physical' and result['processes'][0]['pid'] == 1
    assert 'ports' not in result['completed'] and result['warnings']


def payload(system):
    return {'os': system, 'applications': [{'id': 'app', 'name': 'Microsoft Word' if system == 'Darwin' else 'nginx', 'source': 'macOS app bundle' if system == 'Darwin' else 'pacman', 'removal_url': 'https://evil.invalid', 'command': 'private'}],
            'processes': [], 'ports': [], 'events': [], 'warnings': [], 'completed': ['applications'], 'truncated': []}


def test_platform_guides_do_not_return_windows_removal_links_or_remote_urls():
    assert 'office-for-mac' in guides('Microsoft Word', os_name='Darwin')['removal_url']
    assert 'support.apple.com' in guides('Example', os_name='Darwin')['removal_url']
    assert 'archlinux.org' in guides('nginx', os_name='Linux', source='pacman')['removal_url']
    assert not guides('Example', os_name='Linux', source='desktop entry')['removal_url']
    for system in ('Linux', 'Darwin'):
        assert 'evil.invalid' not in str(verified(payload(system), system))
        with pytest.raises(HTTPException):
            verified(payload(system), 'Windows')


@pytest.mark.parametrize('system', ['Linux', 'Darwin'])
def test_software_refresh_identity_cache_and_os_switch(tmp_path, monkeypatch, system):
    app = live_app(tmp_path, monkeypatch)
    host = app.state.store.get('hosts', 'laptop')
    host.update(active_os=system, physical_host_id='physical')
    app.state.store.put('hosts', host)
    async def response(*args, **kwargs):
        return httpx.Response(200, json=payload(system) | {'physical_host_id': 'physical'})
    fake_agent(monkeypatch, response)
    refresh = endpoint(app, '/api/v1/hosts/{hid}/software/refresh', 'POST')
    result = asyncio.run(refresh('laptop'))
    assert not result['stale'] and result['inventory']['os'] == system
    host['active_os'] = 'Darwin' if system == 'Linux' else 'Linux'
    app.state.store.put('hosts', host)
    assert endpoint(app, '/api/v1/hosts/{hid}/software', 'GET')('laptop')['stale']
    with pytest.raises(HTTPException):
        asyncio.run(refresh('laptop'))


def test_software_identity_rejection_and_demo_no_contact(tmp_path, monkeypatch):
    app = live_app(tmp_path, monkeypatch)
    host = app.state.store.get('hosts', 'laptop')
    host.update(active_os='Linux', physical_host_id='expected')
    app.state.store.put('hosts', host)
    async def response(*args, **kwargs):
        return httpx.Response(200, json=payload('Linux') | {'physical_host_id': 'wrong'})
    fake_agent(monkeypatch, response)
    with pytest.raises(HTTPException):
        asyncio.run(endpoint(app, '/api/v1/hosts/{hid}/software/refresh', 'POST')('laptop'))
    demo = create_app(tmp_path / 'demo', demo=True, background=False)
    monkeypatch.setattr('controller.app.httpx.AsyncClient', lambda *a, **k: pytest.fail('Demo contacted agent'))
    with TestClient(demo) as client:
        hid = demo.state.store.all('hosts')[0]['id']
        result = client.post('/api/v1/hosts/' + hid + '/software/refresh', json={})
        assert result.status_code == 200 and result.json()['demo']


def test_macos_scan_defaults_to_readonly_launchd_and_filters_apple_jobs(monkeypatch):
    monkeypatch.setattr('agent.app.platform.system', lambda: 'Darwin')
    calls = []
    def command(argv, **kwargs):
        calls.append(argv)
        return 'PID Status Label\n42 0 org.example.server\n- 7 org.example.failed\n- 0 com.apple.example\n'
    monkeypatch.setattr('agent.app.command', command)
    with TestClient(create_agent({}, token='test')) as client:
        client.headers['Authorization'] = 'Bearer test'
        result = client.post('/scan', json={}).json()
        assert result['completed_runtimes'] == ['launchd'] and len(result['services']) == 2
        assert calls == [['/bin/launchctl', 'list']]
        assert result['services'][1]['status'] == 'failed'
        assert all(not row['capabilities']['control'] for row in result['services'])
        # Newly discovered runtime passes the persisted registry schema.
        row = result['services'][0]
        ServiceDefinition.model_validate({key: value for key, value in (row | {'id': 'launchd-job', 'host_id': 'mac'}).items() if key in ServiceDefinition.model_fields})


def test_macos_startup_fingerprint_does_not_export_program_arguments(tmp_path):
    path = tmp_path / 'server.plist'
    path.write_bytes(plistlib.dumps({'Label': 'org.example.server', 'ProgramArguments': ['private-command'], 'EnvironmentVariables': {'TOKEN': 'private'}}))
    before = startup_rows([tmp_path])
    assert 'private' not in json.dumps(before)
    path.write_bytes(plistlib.dumps({'Label': 'org.example.server', 'ProgramArguments': ['changed']}))
    after = startup_rows([tmp_path])
    assert before[0]['id'] == after[0]['id'] and before[0]['fingerprint'] != after[0]['fingerprint']
    path.write_bytes(b'invalid')
    with pytest.raises(OSError):
        startup_rows([tmp_path])
