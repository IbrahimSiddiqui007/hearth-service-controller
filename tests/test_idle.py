import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from agent.app import create_agent
from controller.app import Action, create_app
from controller.idle import observe
from shared.models import ServiceEdit
from test_config_operations import endpoint, fake_agent, live_app
from agent.idle_activity import check as activity_check
from types import SimpleNamespace
import psutil


def test_only_continuous_explicit_idle_counts_and_unknown_or_gap_resets():
    current = datetime.now(timezone.utc)
    state = observe({}, True, 5, current)
    for index in range(1, 11):
        state = observe(state, True, 5, current + timedelta(seconds=30 * index))
    assert state['ready'] and state['idle_seconds'] == 300
    assert not observe(state, None, 5, current + timedelta(seconds=330))['ready']
    assert observe(state, False, 5, current + timedelta(seconds=330))['idle_since'] is None
    assert not observe(state, True, 5, current + timedelta(seconds=500))['ready']


def test_agent_activity_profiles_fixed_argv_and_unknown_outputs(monkeypatch, tmp_path):
    calls = []
    def command(argv, **kwargs):
        calls.append(argv)
        return 'idle' if len(calls) == 1 else 'PASSWORD=hidden'
    monkeypatch.setattr('agent.app.command', command)
    probe = str(tmp_path / 'probe')
    app = create_agent({'idle_checks': {'activity': {'argv': [probe, '--clients']}}}, token='test')
    with TestClient(app) as client:
        client.headers['Authorization'] = 'Bearer test'
        assert client.post('/idle/check', json={'profile': 'activity', 'timeout_s': 5}).json()['idle'] is True
        unknown = client.post('/idle/check', json={'profile': 'activity', 'timeout_s': 5})
        assert unknown.json()['idle'] is None and 'hidden' not in unknown.text
        assert client.post('/idle/check', json={'profile': 'arbitrary', 'timeout_s': 5}).status_code == 403
    assert calls == [[probe, '--clients']] * 2


def test_verified_idle_stop_and_manual_wake_with_mock_agent(tmp_path, monkeypatch):
    app = live_app(tmp_path, monkeypatch)
    store = app.state.store
    service = store.get('services', 'minecraft')
    stamp = datetime.now(timezone.utc)
    service.update(idle_policy={'enabled': True, 'profile': 'activity', 'minutes': 5},
                   idle_state={'checked_at': (stamp - timedelta(seconds=30)).isoformat(), 'idle_since': (stamp - timedelta(seconds=300)).isoformat()})
    store.put('services', service)
    actions = []
    async def request(method, url, **kwargs):
        if url.endswith('/idle/check'):
            return httpx.Response(200, json={'idle': True})
        if url.endswith('/control'):
            actions.append(kwargs['json']['action'])
            return httpx.Response(200, json={'output': 'accepted'})
        return httpx.Response(200, json={'services': [{**service, 'agent_ref': 'compose-minecraft', 'status': 'stopped' if actions[-1] == 'stop' else 'running'}], 'completed_runtimes': ['compose']})
    fake_agent(monkeypatch, request)
    slept = asyncio.run(endpoint(app, '/api/v1/services/{sid}/idle/evaluate', 'POST')('minecraft'))
    assert slept['status'] == 'stopped' and slept['idle_state']['asleep']
    woke = asyncio.run(endpoint(app, '/api/v1/services/{sid}/control', 'POST')('minecraft', Action(action='start')))
    assert woke['service']['status'] == 'running' and not woke['service']['idle_state']['asleep']
    assert actions == ['stop', 'start']


def test_disabled_offline_and_policy_change_never_stop(tmp_path, monkeypatch):
    app = live_app(tmp_path, monkeypatch)
    store = app.state.store
    service = store.get('services', 'minecraft')
    service.update(idle_policy={'enabled': True, 'profile': 'activity', 'minutes': 5})
    store.put('services', service)
    calls = []
    async def request(method, url, **kwargs):
        calls.append(url)
        current = store.get('services', 'minecraft')
        current.update(revision=current['revision'] + 1, idle_policy={'enabled': False, 'profile': 'activity', 'minutes': 5})
        store.put('services', current)
        return httpx.Response(200, json={'idle': True})
    fake_agent(monkeypatch, request)
    evaluated = asyncio.run(endpoint(app, '/api/v1/services/{sid}/idle/evaluate', 'POST')('minecraft'))
    assert not evaluated['idle_state']['ready'] and evaluated['idle_state']['signal'] == 'unknown'
    assert len(calls) == 1 and calls[0].endswith('/idle/check')


def test_idle_refuses_stop_with_running_dependents(tmp_path, monkeypatch):
    app = live_app(tmp_path, monkeypatch)
    store = app.state.store
    stamp = datetime.now(timezone.utc)
    service = store.get('services', 'minecraft')
    service.update(idle_policy={'enabled': True, 'profile': 'activity', 'minutes': 5}, idle_state={'checked_at': (stamp - timedelta(seconds=30)).isoformat(), 'idle_since': (stamp - timedelta(seconds=300)).isoformat()})
    store.put('services', service)
    dependent = store.get('services', 'ollama')
    dependent.update(status='running', dependencies=['minecraft'])
    store.put('services', dependent)
    calls = []
    async def request(method, url, **kwargs):
        calls.append(url)
        return httpx.Response(200, json={'idle': True})
    fake_agent(monkeypatch, request)
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as rejected:
        asyncio.run(endpoint(app, '/api/v1/services/{sid}/idle/evaluate', 'POST')('minecraft'))
    assert rejected.value.status_code == 409
    assert len(calls) == 1 and calls[0].endswith('/idle/check')
    with store.connection() as db:
        assert not db.execute('SELECT 1 FROM operations').fetchone()


def test_native_tcp_probe_requires_listener_and_treats_connections_as_active(monkeypatch):
    rows = []
    monkeypatch.setattr('agent.idle_activity.psutil.net_connections', lambda **kwargs: rows)
    profile = {'type': 'tcp_connections', 'ports': [25565]}
    assert activity_check(profile, None) is None
    rows.append(SimpleNamespace(laddr=SimpleNamespace(port=25565), status=psutil.CONN_LISTEN))
    assert activity_check(profile, None) is True
    rows.append(SimpleNamespace(laddr=SimpleNamespace(port=25565), status=psutil.CONN_ESTABLISHED))
    assert activity_check(profile, None) is False
    def denied(**kwargs): raise psutil.AccessDenied()
    monkeypatch.setattr('agent.idle_activity.psutil.net_connections', denied)
    assert activity_check(profile, None) is None


def test_minecraft_probe_fixed_local_list_command_never_puts_password_in_argv(tmp_path, monkeypatch):
    monkeypatch.setenv('PSC_IDLE_MC_PASSWORD', 'test-only-rcon-password')
    monkeypatch.setenv('PSC_AGENT_TOKEN', 'must-not-inherit')
    profile = {'type': 'minecraft_players', 'executable': str(tmp_path / 'mcrcon'), 'password_env': 'PSC_IDLE_MC_PASSWORD'}
    calls = []
    output = ['There are 0 of a max of 20 players online:', 'There are 2 of a max of 20 players online: user1, user2', 'Unexpected localized response']
    def command(argv, **kwargs):
        calls.append((argv, kwargs))
        assert 'test-only-rcon-password' not in str(argv)
        assert kwargs['env']['MCRCON_PASS'] == 'test-only-rcon-password'
        assert 'PSC_AGENT_TOKEN' not in kwargs['env']
        return output[len(calls) - 1]
    assert activity_check(profile, command) is True
    assert activity_check(profile, command) is False
    assert activity_check(profile, command) is None
    assert all(args == [profile['executable'], '-c', '-H', '127.0.0.1', '-P', '25575', 'list'] for args, _ in calls)
