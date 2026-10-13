import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from agent.app import create_agent, docker_inventory, systemd_inventory
from agent.observability import _samples, counter_cpu, memory_mb, process_sample
from controller.telemetry import rates


def test_cpu_warmup_and_pid_lifetime(monkeypatch):
    _samples.clear()
    times = iter([10, 12, 14])
    monkeypatch.setattr('agent.observability.time.monotonic', lambda: next(times))
    assert counter_cpu('unit', 3) is None
    assert counter_cpu('unit', 4) == 50
    assert counter_cpu('unit', 1) is None
    assert memory_mb('64MiB / 1GiB') == 64
    assert memory_mb('1GB / 2GB') == 953.67
    assert memory_mb('unknown') is None


def test_process_memory_start_and_permissions(monkeypatch):
    class Process:
        def __init__(self, pid):
            pass
        def oneshot(self):
            from contextlib import nullcontext
            return nullcontext()
        def create_time(self):
            return 1000
        def cpu_times(self):
            return SimpleNamespace(user=1, system=2)
        def memory_info(self):
            return SimpleNamespace(rss=64 * 1024 ** 2)
    monkeypatch.setattr('agent.observability.psutil.Process', Process)
    _samples.clear()
    result = process_sample(4321)
    assert result['metrics']['memory_mb'] == 64
    assert result['metrics']['cpu_percent'] is None
    assert result['started_at'].startswith('1970-01-01')
    import psutil
    def denied(pid):
        raise psutil.AccessDenied(pid)
    monkeypatch.setattr('agent.observability.psutil.Process', denied)
    assert process_sample(4321)['metrics']['memory_mb'] is None


def test_docker_resources_locations_policy_and_group_aggregation(monkeypatch):
    inspected = []
    for name in ('web', 'db'):
        inspected.append({'Name': '/' + name, 'State': {'Status': 'running', 'StartedAt': '2026-01-01T00:00:00Z'}, 'RestartCount': 2,
            'Config': {'Image': 'example/' + name, 'Env': ['TOKEN=never-export'], 'WorkingDir': '/app', 'Labels': {'com.docker.compose.project': 'stack', 'com.docker.compose.project.working_dir': '/opt/stack', 'com.docker.compose.project.config_files': 'compose.yaml'}},
            'Mounts': [{'Source': '/opt/stack/app.yaml', 'Destination': '/app/config.yaml'}], 'LogPath': '/var/log/' + name,
            'HostConfig': {'RestartPolicy': {'Name': 'unless-stopped'}}, 'NetworkSettings': {'Ports': {}}})
    def command(args, **kwargs):
        if args[1] == 'ps':
            return 'a\nb'
        if args[1] == 'stats':
            return '\n'.join(json.dumps({'Name': name, 'CPUPerc': '5.5%', 'MemUsage': '64MiB / 1GiB'}) for name in ('web', 'db'))
        return json.dumps(inspected)
    monkeypatch.setattr('agent.app.command', command)
    services, containers = docker_inventory({})
    assert services[0]['metrics']['cpu_percent'] == 11
    assert services[0]['metrics']['memory_mb'] == 128
    assert services[0]['locations']['configuration'] == ['/opt/stack/compose.yaml']
    assert services[0]['runtime_details']['restart_count'] == 4
    assert containers[0]['runtime_details']['restart_policy'] == 'unless-stopped'
    assert containers[0]['locations']['configuration'] == ['/opt/stack/app.yaml']
    assert 'never-export' not in json.dumps((services, containers))


def test_systemd_metadata_and_cgroup_sampling(monkeypatch):
    def command(args, **kwargs):
        if 'list-units' in args:
            return json.dumps([{'unit': 'app.service', 'active': 'active'}])
        if 'list-unit-files' in args:
            return 'app.service enabled enabled'
        return 'Id=app.service\nFragmentPath=/etc/systemd/system/app.service\nDropInPaths=/etc/systemd/system/app.service.d/override.conf\nWorkingDirectory=/opt/app\nMainPID=0\nNRestarts=4\nRestart=on-failure\nCPUUsageNSec=1000000000\nMemoryCurrent=67108864\nActiveEnterTimestampMonotonic=123\n'
    monkeypatch.setattr('agent.app.command', command)
    _samples.clear()
    row = systemd_inventory({})[0]
    assert row['metrics']['memory_mb'] == 64 and row['metrics']['cpu_percent'] is None
    assert row['runtime_details']['restart_count'] == 4
    assert row['locations']['working_directory'] == '/opt/app'
    assert len(row['locations']['configuration']) == 2


def test_runtime_documents_keep_approved_roots_and_masking(tmp_path):
    (tmp_path / 'app.service').write_text('[Service]\nAPI_TOKEN=never-return\nRestart=on-failure')
    with TestClient(create_agent({'file_roots': {'unit': [str(tmp_path)]}}, token='test')) as c:
        c.headers['Authorization'] = 'Bearer test'
        response = c.get('/documents', params={'ref': 'unit', 'path': str(tmp_path / 'app.service')})
        assert response.status_code == 200 and 'never-return' not in response.text
        assert c.get('/documents', params={'ref': 'unit', 'path': 'relative.service'}).status_code == 403
        assert c.get('/documents', params={'ref': 'unit', 'path': str(tmp_path.parent / 'outside.service')}).status_code == 403
        (tmp_path / '.env').write_text('TOKEN=private')
        assert c.get('/documents', params={'ref': 'unit', 'path': str(tmp_path / '.env')}).status_code == 403


def test_rates_reset_gaps_and_interfaces_are_unknown():
    old = {'boot_time': 10, 'network_recv_bytes': 100, 'network_sent_bytes': 100, 'interfaces': {'eth0': {'received_bytes': 100, 'sent_bytes': 100}}}
    current = {'boot_time': 10, 'network_recv_bytes': 400, 'network_sent_bytes': 50, 'interfaces': {'eth0': {'received_bytes': 400, 'sent_bytes': 150}, 'new': {'received_bytes': 10}}}
    result = rates(current, old, '2026-01-01T00:00:30+00:00', '2026-01-01T00:00:00+00:00')
    assert result['network_recv_bps'] == 10 and result['network_sent_bps'] is None
    assert result['interface_rates']['eth0']['sent_bps'] == 1.7
    assert result['interface_rates']['new']['received_bps'] is None
    assert rates({**current, 'boot_time': 11}, old, '2026-01-01T00:00:30+00:00', '2026-01-01T00:00:00+00:00')['network_recv_bps'] is None
    assert rates(current, old, '2026-01-01T00:10:00+00:00', '2026-01-01T00:00:00+00:00')['network_recv_bps'] is None


def test_sampling_opt_out_skips_systemd_and_windows_process_reads(monkeypatch):
    def prohibited(*args, **kwargs):
        raise AssertionError('Sampling was disabled')
    monkeypatch.setattr('agent.app.process_sample', prohibited)
    monkeypatch.setattr('agent.app.counter_cpu', prohibited)
    monkeypatch.setattr('agent.app.systemd_details', lambda *args: {'app.service': {'MainPID': '123', 'CPUUsageNSec': '1000000', 'MemoryCurrent': '67108864'}})
    monkeypatch.setattr('agent.app.command', lambda args: json.dumps([{'unit': 'app.service', 'active': 'active'}]) if 'list-units' in args else '')
    row = systemd_inventory({'resource_samples': False})[0]
    assert row['metrics'] == {'cpu_percent': None, 'memory_mb': None, 'scope': 'sampling disabled'}
    from agent.app import windows_inventory
    item = SimpleNamespace(as_dict=lambda: {'name': 'app', 'display_name': 'App', 'status': 'running', 'pid': 123})
    monkeypatch.setattr('agent.app.psutil.win_service_iter', lambda: [item], raising=False)
    assert windows_inventory({'resource_samples': False})[0]['metrics']['memory_mb'] is None


def test_demo_telemetry_upgrade_preserves_existing_data_and_is_idempotent(tmp_path):
    from controller.app import create_app
    app = create_app(tmp_path, demo=True, token='', background=False)
    store = app.state.store
    service = store.get('services', 'minecraft')
    service['notes'] = 'Preserve my notebook'
    store.put('services', service)
    with store.connection() as db:
        initial = [tuple(row) for row in db.execute('SELECT * FROM telemetry ORDER BY id')]
        newest = json.loads(db.execute("SELECT body FROM telemetry WHERE host_id='worker-node1' ORDER BY id DESC LIMIT 1").fetchone()['body'])
        assert newest['network_recv_bps'] > 0 and newest['volumes'] and newest['demo']
        assert db.execute('SELECT COUNT(*) FROM telemetry').fetchone()[0] == 120
    second = create_app(tmp_path, demo=True, token='', background=False)
    assert second.state.store.get('services', 'minecraft')['notes'] == service['notes']
    with store.connection() as db:
        assert [tuple(row) for row in db.execute('SELECT * FROM telemetry ORDER BY id')] == initial


def test_live_start_does_not_append_demo_telemetry(tmp_path):
    from controller.app import create_app
    app = create_app(tmp_path, token='', background=False)
    with app.state.store.connection() as db:
        assert db.execute('SELECT COUNT(*) FROM telemetry').fetchone()[0] == 0
