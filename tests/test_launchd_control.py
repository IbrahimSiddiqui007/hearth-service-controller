from pathlib import Path
from types import SimpleNamespace
import plistlib
import stat

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from agent.app import create_agent
from agent.macos import gui_job, launchd_control, launchd_inventory, launchd_profile


@pytest.fixture
def profile(tmp_path, monkeypatch):
    path = tmp_path / 'Library/LaunchAgents/org.example.server.plist'
    path.parent.mkdir(parents=True)
    path.write_bytes(plistlib.dumps({'Label': 'org.example.server', 'ProgramArguments': ['/opt/example/server'], 'WorkingDirectory': '/opt/example'}))
    monkeypatch.setattr('agent.macos.platform.system', lambda: 'Darwin')
    monkeypatch.setattr('agent.macos.os.getuid', lambda: 501, raising=False)
    monkeypatch.setattr('agent.macos.Path.home', lambda: tmp_path)
    actual = Path.stat
    def metadata(path, *args, **kwargs):
        info = actual(path, *args, **kwargs)
        return SimpleNamespace(st_mode=(stat.S_IFDIR | 0o700) if stat.S_ISDIR(info.st_mode) else (stat.S_IFREG | 0o600), st_uid=501, st_size=info.st_size)
    monkeypatch.setattr('agent.macos.Path.stat', metadata)
    config = {'allow_launchd': {'org.example.server': str(path)}}
    return path, config


def observe(path, *, loaded=True, state='running', identity=None, domain='gui/501'):
    calls = []
    def command(argv, **kwargs):
        calls.append(argv)
        if argv == ['/bin/launchctl', 'list']:
            return 'PID Status Label\n123 0 org.example.server\n'
        if argv == ['/bin/launchctl', 'print', domain]:
            return domain + ' = {\n type = login\n}'
        if argv[:2] == ['/bin/launchctl', 'print']:
            if not loaded:
                raise HTTPException(502, 'Could not find service "org.example.server" in domain for user gui: 501')
            return domain + '/org.example.server = {\n path = ' + str(identity or path) + '\n state = ' + state + '\n pid = 123\n}'
        return ''
    return command, calls


@pytest.mark.parametrize('action,loaded,expected', [
    ('stop', True, [['/bin/launchctl', 'bootout', 'gui/501/org.example.server']]),
    ('stop', False, []),
    ('start', True, []),
    ('restart', True, [['/bin/launchctl', 'kickstart', '-k', 'gui/501/org.example.server']]),
    ('start', False, 'bootstrap')])
def test_launchagent_actions_are_exact_current_user_domain(profile, action, loaded, expected):
    path, config = profile
    _, fingerprint, _, domain = launchd_profile(config, 'org.example.server')
    command, calls = observe(path, loaded=loaded)
    result = launchd_control(config, {'name': 'org.example.server', 'domain': domain, 'plist_hash': fingerprint}, action, command)
    mutations = [args for args in calls if args[1] not in ('print', 'list')]
    if expected == 'bootstrap':
        expected = [['/bin/launchctl', 'bootstrap', 'gui/501', str(path)], ['/bin/launchctl', 'kickstart', 'gui/501/org.example.server']]
    assert mutations == expected and result
    assert not any('sudo' in args or 'enable' in args or 'disable' in args or 'system/' in str(args) for args in calls)


def test_inventory_keeps_unloaded_approved_jobs_and_never_exports_argv(profile):
    path, config = profile
    command, calls = observe(path, loaded=False)
    rows = launchd_inventory(config, command)
    assert len(rows) == 1 and rows[0]['status'] == 'stopped' and rows[0]['capabilities']['control']
    assert rows[0]['control_handle']['domain'] == 'gui/501'
    assert 'ProgramArguments' not in str(rows) and '/opt/example/server' not in str(rows)


@pytest.mark.parametrize('changes', [{'domain': 'system'}, {'plist_hash': 'changed'}, {'name': 'com.apple.server'}])
def test_wrong_domain_changed_hash_or_apple_job_never_mutates(profile, changes):
    path, config = profile
    _, fingerprint, _, domain = launchd_profile(config, 'org.example.server')
    command, calls = observe(path)
    with pytest.raises(HTTPException):
        launchd_control(config, {'name': 'org.example.server', 'domain': domain, 'plist_hash': fingerprint} | changes, 'restart', command)
    assert calls == []


def test_loaded_job_identity_mismatch_and_unknown_state_never_mutate(profile):
    path, config = profile
    _, fingerprint, _, domain = launchd_profile(config, 'org.example.server')
    for kwargs in ({'identity': path.parent / 'other.plist'}, {'state': 'unrecognized'}):
        command, calls = observe(path, **kwargs)
        with pytest.raises(HTTPException):
            launchd_control(config, {'name': 'org.example.server', 'domain': domain, 'plist_hash': fingerprint}, 'stop', command)
        assert all(args[1] == 'print' for args in calls)


def test_scope_user_name_and_root_account_are_rejected(profile, monkeypatch):
    path, config = profile
    path.write_bytes(plistlib.dumps({'Label': 'org.example.server', 'UserName': 'root'}))
    with pytest.raises(HTTPException): launchd_profile(config, 'org.example.server')
    monkeypatch.setattr('agent.macos.os.getuid', lambda: 0)
    with pytest.raises(HTTPException): launchd_profile(config, 'org.example.server')


def test_changed_plist_during_query_stops_before_bootstrap(profile):
    path, config = profile
    _, fingerprint, _, domain = launchd_profile(config, 'org.example.server')
    original, calls = observe(path, loaded=False)
    def command(argv, **kwargs):
        if argv[-1] == 'gui/501':
            path.write_bytes(plistlib.dumps({'Label': 'org.example.server', 'ProgramArguments': ['/changed']}))
        return original(argv, **kwargs)
    with pytest.raises(HTTPException):
        launchd_control(config, {'name': 'org.example.server', 'domain': domain, 'plist_hash': fingerprint}, 'start', command)
    assert all(args[1] == 'print' for args in calls)
