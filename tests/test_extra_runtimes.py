import json
from types import SimpleNamespace

import psutil
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from agent.app import create_agent, safe_path
from agent.extra_runtimes import file_log, managed_process, pm2_args, pm2_inventory, process_control, process_inventory, process_profile, reference, save_state, state_file


@pytest.fixture
def pm2(tmp_path, monkeypatch):
    (tmp_path / 'pm2.pid').write_text('123')
    monkeypatch.setattr('pathlib.Path.is_socket', lambda path: path.name == 'rpc.sock')
    monkeypatch.setattr('agent.extra_runtimes.psutil.Process', lambda pid: SimpleNamespace(is_running=lambda: True, cmdline=lambda: ['PM2 GodDaemon'], uids=lambda: SimpleNamespace(real=0)))
    monkeypatch.setattr('agent.extra_runtimes.os.getuid', lambda: 0, raising=False)
    return {'pm2_home': str(tmp_path), 'allow_pm2': ['web']}


def processes():
    return [{'name': 'web', 'pm_id': 4, 'pm2_env': {'status': 'online', 'TOKEN': 'private', 'pm_cwd': '/opt/web', 'pm_uptime': 100000, 'restart_time': 3}, 'monit': {'cpu': 5, 'memory': 67108864}},
            {'name': 'other', 'pm_id': 5, 'pm2_env': {'namespace': 'web', 'status': 'stopped'}}]


def test_pm2_inventory_omits_env_and_actions_use_verified_numeric_instance(pm2):
    rows = pm2_inventory(pm2, lambda *args, **kwargs: json.dumps(processes()))
    assert rows[0]['metrics']['memory_mb'] == 64
    assert rows[0]['control_handle'] == {'name': 'web', 'pm_id': '4'}
    assert 'private' not in json.dumps(rows)
    assert pm2_args(pm2, rows[0]['control_handle'], 'stop', lambda *args, **kwargs: json.dumps(processes())) == ['pm2', 'stop', '4']
    for handle in ({'name': 'web', 'pm_id': '5'}, {'name': 'web', 'pm_id': 'all'}, {'name': 'other', 'pm_id': '5'}):
        with pytest.raises(HTTPException):
            pm2_args(pm2, handle, 'restart', lambda *args, **kwargs: json.dumps(processes()))


def test_pm2_refuses_missing_daemon_without_cli_call(tmp_path):
    def prohibited(*args, **kwargs):
        raise AssertionError('pm2 would bootstrap a daemon')
    with pytest.raises(HTTPException) as refused:
        pm2_inventory({'pm2_home': str(tmp_path)}, prohibited)
    assert refused.value.status_code == 409


def test_pm2_agent_scan_control_and_logs_keep_exact_instance(pm2, monkeypatch):
    calls = []
    def command(argv, **kwargs):
        calls.append(argv)
        return json.dumps(processes()) if argv == ['pm2', 'jlist'] else 'TOKEN=private\nApplication ready'
    monkeypatch.setattr('agent.app.command', command)
    with TestClient(create_agent({**pm2, 'discover': ['pm2']}, token='test')) as c:
        c.headers['Authorization'] = 'Bearer test'
        row = c.post('/scan', json={}).json()['services'][0]
        assert row['capabilities']['control']
        body = {'runtime': 'pm2', 'handle': row['control_handle'], 'action': 'restart'}
        assert c.post('/control', json=body).status_code == 200
        assert ['pm2', 'restart', '4'] in calls
        result = c.post('/logs', json={**body, 'lines': 100})
        assert result.status_code == 200 and 'private' not in result.text
        assert ['pm2', 'logs', '4', '--raw', '--lines', '100', '--nostream'] in calls


@pytest.fixture(params=['Linux', 'Darwin'])
def process_config(tmp_path, monkeypatch, request):
    monkeypatch.setattr('agent.extra_runtimes.platform.system', lambda: request.param)
    return {'state_dir': str(tmp_path / 'state'), 'allow_processes': ['worker'], 'process_commands': {'worker': {'argv': ['/usr/bin/worker', '--safe'], 'cwd': str(tmp_path)}}}


def bind_process(config, monkeypatch, *, created_at=100, actual_created_at=100, executable='/usr/bin/worker', actual_executable='/usr/bin/worker', timeout=False):
    calls = []
    class Process:
        pid = 999
        def __init__(self, pid):
            assert pid == 999
        def create_time(self):
            return actual_created_at
        def exe(self):
            return actual_executable
        def is_running(self):
            return True
        def status(self):
            return psutil.STATUS_RUNNING
        def terminate(self):
            calls.append('terminate')
        def wait(self, timeout=None):
            calls.append('wait')
            if timeout == 10 and globals_timeout:
                raise psutil.TimeoutExpired(timeout)
    globals_timeout = timeout
    monkeypatch.setattr('agent.extra_runtimes.psutil.Process', Process)
    _, key = process_profile(config, 'worker')
    save_state(state_file(config, 'worker'), {'status': 'running', 'pid': 999, 'created_at': created_at, 'executable': executable, 'profile_key': key})
    return calls


@pytest.mark.parametrize('values', [{'actual_created_at': 101}, {'actual_executable': '/usr/bin/other'}])
def test_configured_process_pid_reuse_or_exec_change_never_signals(process_config, monkeypatch, values):
    calls = bind_process(process_config, monkeypatch, **values)
    with pytest.raises(HTTPException) as refused:
        process_control(process_config, 'worker', 'stop')
    assert refused.value.status_code == 409 and calls == []


def test_process_stop_timeout_never_force_kills_or_restarts(process_config, monkeypatch):
    calls = bind_process(process_config, monkeypatch, timeout=True)
    monkeypatch.setattr('agent.extra_runtimes.subprocess.Popen', lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError('Restarted despite failed stop')))
    with pytest.raises(HTTPException) as refused:
        process_control(process_config, 'worker', 'restart')
    assert refused.value.status_code == 504 and calls == ['terminate', 'wait']


def test_process_start_fixed_argv_persists_identity_and_does_not_inherit_agent_tokens(process_config, monkeypatch):
    monkeypatch.setenv('PSC_AGENT_TOKEN', 'must-not-inherit')
    calls = []
    class Process:
        def __init__(self, pid):
            assert pid == 999
        def exe(self):
            return '/usr/bin/worker'
        def create_time(self):
            return 100
        def status(self):
            return psutil.STATUS_RUNNING
        def is_running(self):
            return True
    monkeypatch.setattr('agent.extra_runtimes.psutil.Process', Process)
    def launch(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(pid=999)
    monkeypatch.setattr('agent.extra_runtimes.subprocess.Popen', launch)
    assert 'started' in process_control(process_config, 'worker', 'start')
    assert calls[0][0] == ['/usr/bin/worker', '--safe'] and calls[0][1]['shell'] is False
    assert 'PSC_AGENT_TOKEN' not in calls[0][1]['env']
    assert managed_process(process_config, 'worker').is_running()
    assert process_control(process_config, 'worker', 'start') == 'Configured process is already running'
    assert len(calls) == 1


def test_uncertain_launch_remains_unknown_and_cannot_launch_again(process_config, monkeypatch):
    monkeypatch.setattr('agent.extra_runtimes.subprocess.Popen', lambda *args, **kwargs: SimpleNamespace(pid=999))
    monkeypatch.setattr('agent.extra_runtimes.psutil.Process', lambda pid: SimpleNamespace(exe=lambda: '/usr/bin/other'))
    with pytest.raises(HTTPException):
        process_control(process_config, 'worker', 'start')
    assert process_inventory(process_config)[0]['status'] == 'unknown'
    assert not process_inventory(process_config)[0]['capabilities']['control']
    with pytest.raises(HTTPException):
        process_control(process_config, 'worker', 'start')


def test_file_logs_are_rooted_bounded_and_masked(tmp_path):
    log = tmp_path / 'app.log'
    log.write_text('old line\nTOKEN=private\nnew line\n')
    config = {'log_files': {'approved': str(log)}, 'file_roots': {'approved': [str(tmp_path)]}}
    assert file_log(config, 'approved', 2, safe_path) == 'TOKEN=[REDACTED]\nnew line'
    config['log_files']['approved'] = str(tmp_path.parent / 'outside.log')
    with pytest.raises(HTTPException) as refused:
        file_log(config, 'approved', 2, safe_path)
    assert refused.value.status_code == 403
