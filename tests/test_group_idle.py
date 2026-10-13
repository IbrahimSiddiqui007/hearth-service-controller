import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from controller.app import Action
from controller.groups import validate_groups
from controller.idle import observe
from test_config_operations import endpoint, fake_agent, live_app
from test_groups import grouped


def setup_group(tmp_path, monkeypatch):
    app = live_app(tmp_path, monkeypatch)
    store = grouped(app)
    parent = store.get('services', 'minecraft')
    parent.update(idle_policy={'enabled': True, 'profile': 'players', 'minutes': 5, 'component_profiles': {'ollama': 'requests'}})
    # An internal dependency must not block dependency-ordered group stop.
    parent['dependencies'] = ['ollama']
    store.put('services', parent)
    clock = [datetime.now(timezone.utc)]
    def timed(previous, signal, minutes):
        result = observe(previous, signal, minutes, clock[0])
        clock[0] += timedelta(seconds=30)
        return result
    monkeypatch.setattr('controller.app.idle_observe', timed)
    return app, store


@pytest.mark.parametrize('signal', [False, None, 'idle'])
def test_component_active_unknown_or_invalid_inhibits_entire_group(tmp_path, monkeypatch, signal):
    app, store = setup_group(tmp_path, monkeypatch)
    calls = []
    async def response(method, url, **kwargs):
        calls.append(url)
        assert url.endswith('/idle/check')
        return httpx.Response(200, json={'idle': True if kwargs['json']['profile'] == 'players' else signal})
    fake_agent(monkeypatch, response)
    for _ in range(11):
        result = asyncio.run(endpoint(app, '/api/v1/services/{sid}/idle/evaluate', 'POST')('minecraft'))
    assert not result['idle_state']['ready'] and len(calls) == 22
    assert store.get('services', 'minecraft')['status'] == 'running'


def test_continuous_all_component_activity_stops_in_order_and_manual_wake(tmp_path, monkeypatch):
    app, store = setup_group(tmp_path, monkeypatch)
    actions = []
    states = {'minecraft': 'running', 'ollama': 'running'}
    async def response(method, url, **kwargs):
        if url.endswith('/idle/check'):
            return httpx.Response(200, json={'idle': True})
        if url.endswith('/control'):
            body = kwargs['json']
            sid = 'minecraft' if body['runtime'] == 'compose' else 'ollama'
            actions.append((sid, body['action']))
            states[sid] = 'stopped' if body['action'] == 'stop' else 'running'
            return httpx.Response(200, json={'output': 'accepted'})
        rows = []
        for sid in states:
            row = store.get('services', sid)
            rows.append(row | {'agent_ref': row.get('agent_ref') or ('compose-minecraft' if sid == 'minecraft' else 'systemd-ollama'), 'status': states[sid]})
        return httpx.Response(200, json={'services': rows, 'completed_runtimes': ['compose', 'systemd']})
    fake_agent(monkeypatch, response)
    for _ in range(11):
        result = asyncio.run(endpoint(app, '/api/v1/services/{sid}/idle/evaluate', 'POST')('minecraft'))
    assert actions == [('minecraft', 'stop'), ('ollama', 'stop')]
    assert result['idle_state']['asleep'] and all(store.get('services', sid)['status'] == 'stopped' for sid in states)
    woke = asyncio.run(endpoint(app, '/api/v1/services/{sid}/control', 'POST')('minecraft', Action(action='start', acknowledge_components=True)))
    assert woke['status'] == 'success' and not store.get('services', 'minecraft')['idle_state']['asleep']
    assert actions[-2:] == [('ollama', 'start'), ('minecraft', 'start')]


def test_changed_component_resets_continuous_activity_window(tmp_path, monkeypatch):
    app, store = setup_group(tmp_path, monkeypatch)
    async def response(method, url, **kwargs):
        assert url.endswith('/idle/check')
        return httpx.Response(200, json={'idle': True})
    fake_agent(monkeypatch, response)
    evaluate = endpoint(app, '/api/v1/services/{sid}/idle/evaluate', 'POST')
    for _ in range(10):
        asyncio.run(evaluate('minecraft'))
    component = store.get('services', 'ollama')
    component['revision'] += 1
    store.put('services', component)
    result = asyncio.run(evaluate('minecraft'))
    assert result['idle_state']['idle_seconds'] == 0 and not result['idle_state']['ready']


def test_group_profile_coverage_and_independent_child_policy_rejected(tmp_path, monkeypatch):
    app, store = setup_group(tmp_path, monkeypatch)
    with TestClient(app) as client:
        client.headers['Authorization'] = 'Bearer test'
        parent = store.get('services', 'minecraft')
        result = client.patch('/api/v1/services/minecraft', json={'revision': parent['revision'], 'idle_policy': {'enabled': True, 'profile': 'players', 'minutes': 5}})
        assert result.status_code == 422
        child = store.get('services', 'ollama')
        result = client.patch('/api/v1/services/ollama', json={'revision': child['revision'], 'idle_policy': {'enabled': True, 'profile': 'requests', 'minutes': 5}})
        assert result.status_code == 422


def test_missing_component_permission_and_external_dependents_prevent_all_probes(tmp_path, monkeypatch):
    app, store = setup_group(tmp_path, monkeypatch)
    async def response(*args, **kwargs):
        pytest.fail('Ineligible group contacted agent')
    fake_agent(monkeypatch, response)
    child = store.get('services', 'ollama')
    child['capabilities']['control'] = False
    store.put('services', child)
    evaluate = endpoint(app, '/api/v1/services/{sid}/idle/evaluate', 'POST')
    assert asyncio.run(evaluate('minecraft'))['idle_state']['signal'] == 'unknown'
    child['capabilities']['control'] = True
    store.put('services', child)
    external = store.get('services', 'tailscale')
    external['dependencies'] = ['ollama']
    store.put('services', external)
    assert asyncio.run(evaluate('minecraft'))['idle_state']['signal'] == 'unknown'


def test_component_changes_while_activity_probe_waits_prevent_stop(tmp_path, monkeypatch):
    app, store = setup_group(tmp_path, monkeypatch)
    async def response(method, url, **kwargs):
        assert url.endswith('/idle/check')
        row = store.get('services', 'ollama')
        row['revision'] += 1
        store.put('services', row)
        return httpx.Response(200, json={'idle': True})
    fake_agent(monkeypatch, response)
    result = asyncio.run(endpoint(app, '/api/v1/services/{sid}/idle/evaluate', 'POST')('minecraft'))
    assert result['idle_state']['signal'] == 'unknown'


def test_unverified_group_stop_halts_and_never_claims_application_asleep(tmp_path, monkeypatch):
    app, store = setup_group(tmp_path, monkeypatch)
    actions = []
    async def response(method, url, **kwargs):
        if url.endswith('/idle/check'):
            return httpx.Response(200, json={'idle': True})
        if url.endswith('/control'):
            actions.append(kwargs['json']['action'])
            return httpx.Response(200, json={'output': 'accepted'})
        # A command acknowledgement is insufficient to prove a stopped state.
        return httpx.Response(200, json={'services': [], 'completed_runtimes': ['compose', 'systemd']})
    fake_agent(monkeypatch, response)
    for _ in range(11):
        result = asyncio.run(endpoint(app, '/api/v1/services/{sid}/idle/evaluate', 'POST')('minecraft'))
    assert actions == ['stop'] and not result['idle_state']['asleep'] and not result['idle_state']['ready']
    with store.connection() as db:
        assert not db.execute("SELECT 1 FROM operations WHERE status='running'").fetchone()
