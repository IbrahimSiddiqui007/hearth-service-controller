import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from fastapi import HTTPException

from agent.power import Power, profile
from agent.replay import ReplayGuard
from controller.app import Action
from shared.power import PowerRequest, PowerReview, PowerAcknowledge
from test_config_operations import endpoint, fake_agent, live_app


@pytest.mark.parametrize('system,approved,argv', [
    ('Linux', 'suspend', ['/usr/bin/systemctl', '--no-ask-password', 'suspend']),
    ('Linux', 'shutdown', ['/usr/bin/systemctl', '--no-ask-password', 'poweroff']),
    ('Darwin', 'suspend', ['/usr/bin/pmset', 'sleepnow']),
    ('Windows', 'shutdown', ['C:\\Windows\\System32\\shutdown.exe', '/s', '/t', '0'])])
def test_fixed_native_power_profiles_durable_hold_and_no_replay(tmp_path, monkeypatch, system, approved, argv):
    monkeypatch.setattr('agent.power.platform.system', lambda: system)
    monkeypatch.setattr('agent.power.ordinary_account', lambda: True)
    monkeypatch.setattr('agent.power.Path.is_file', lambda self: True)
    config = {'power_actions': [approved]}
    replay = ReplayGuard(str(tmp_path))
    calls = []
    def execute(args, **kwargs):
        calls.append(args)
        with pytest.raises(HTTPException):
            power.acknowledge(PowerAcknowledge(operation_id='a'*32,confirmed=True))
    power = Power(config, replay, execute)
    body = PowerRequest(action=approved, confirmed=True, fingerprint=power.plan()['fingerprint'], operation_id='a' * 32)
    assert power.request(body)['verified'] is False
    assert calls == [argv]
    with pytest.raises(HTTPException):
        power.request(body)
    restarted = Power(config, replay, lambda *args, **kwargs: pytest.fail('No native retry'))
    assert restarted.plan()['pending'] == body.operation_id
    acknowledgement = PowerAcknowledge(operation_id=body.operation_id, confirmed=True)
    assert restarted.acknowledge(acknowledgement)['power_state_verified'] is False
    assert restarted.acknowledge(acknowledgement)['status'] == 'acknowledged'
    assert restarted.plan()['pending'] is None
    with pytest.raises(HTTPException):
        restarted.request(body)  # operation IDs cannot be reused after acknowledgement either


def test_power_disabled_unsupported_elevated_and_uncertain_native_failure(tmp_path, monkeypatch):
    monkeypatch.setattr('agent.power.platform.system', lambda: 'Darwin')
    monkeypatch.setattr('agent.power.ordinary_account', lambda: True)
    with pytest.raises(HTTPException):
        profile({'power_actions': ['shutdown']})  # GUI domain approval is absent.
    assert not profile({})['actions']
    with pytest.raises(HTTPException):
        Power({}, None, None).plan()
    replay = ReplayGuard(str(tmp_path))
    monkeypatch.setattr('agent.power.Path.is_file', lambda self: True)
    def uncertain(*args, **kwargs): raise HTTPException(504, 'timeout')
    power = Power({'power_actions': ['suspend']}, replay, uncertain)
    body = PowerRequest(action='suspend', confirmed=True, fingerprint=power.plan()['fingerprint'], operation_id='b' * 32)
    with pytest.raises(HTTPException) as result:
        power.request(body)
    assert result.value.status_code == 503 and power.plan()['pending'] == body.operation_id
    monkeypatch.setattr('agent.power.ordinary_account', lambda: False)
    with pytest.raises(HTTPException):
        power.plan()


def prepare(app, monkeypatch):
    store = app.state.store
    host = store.get('hosts', 'worker-node1')
    host.update(signing_env='PSC_POWER_SIGNING_TEST', physical_host_id='synthetic-worker', active_os='Linux', last_seen=datetime.now(timezone.utc).isoformat())
    store.put('hosts', host)
    for row in store.all('services'):
        if row['host_id'] == host['id']:
            row['observed_at'] = datetime.now(timezone.utc).isoformat()
            store.put('services', row)
    monkeypatch.setenv('PSC_POWER_HOSTS', json.dumps([host['id']]))
    monkeypatch.setenv('PSC_POWER_SIGNING_TEST', 'p' * 32)
    return host


def profile_payload():
    return {'fingerprint': 'a' * 64, 'actions': {'shutdown': ['/usr/bin/systemctl', '--no-ask-password', 'poweroff']}, 'os': 'Linux', 'physical_host_id': 'synthetic-worker', 'pending': None}


def test_controller_plan_reservations_unknown_outcome_ack_and_no_auto_writes(tmp_path, monkeypatch):
    app = live_app(tmp_path, monkeypatch)
    host = prepare(app, monkeypatch)
    dependent = app.state.store.get('services', 'playground')
    dependent['dependencies'] = ['minecraft']; app.state.store.put('services', dependent)
    indirect = app.state.store.get('services', 'vaultwarden')
    indirect['dependencies'] = ['playground']; app.state.store.put('services', indirect)
    calls = []
    async def request(method, url, **kwargs):
        calls.append(url)
        if url.endswith('/power/profile'):
            return httpx.Response(200, json=profile_payload())
        if url.endswith('/power/acknowledge'):
            return httpx.Response(200, json={'status': 'acknowledged', 'power_state_verified': False})
        if url.endswith('/power'):
            # Controller intent and host reservation exist before native dispatch.
            with app.state.store.connection() as db:
                assert db.execute('SELECT active FROM power_requests').fetchone()['active'] == 1
            with pytest.raises(HTTPException):
                await endpoint(app, '/api/v1/services/{sid}/control', 'POST')('minecraft', Action(action='stop'))
            with pytest.raises(HTTPException):
                await endpoint(app, '/api/v1/hosts/{hid}/power/acknowledge', 'POST')(host['id'], PowerAcknowledge(operation_id=kwargs['json']['operation_id'], confirmed=True))
            raise httpx.ReadTimeout('Synthetic unknown result')
        pytest.fail('Unexpected network call')
    fake_agent(monkeypatch, request)
    plan = asyncio.run(endpoint(app, '/api/v1/hosts/{hid}/power-plan', 'GET')(host['id']))
    assert any(row['name'] == 'Minecraft' and row['status'] == 'running' for row in plan['affected'])
    assert 'playground' in plan['external_dependents'] and 'vaultwarden' in plan['external_dependents']
    with pytest.raises(HTTPException):
        asyncio.run(endpoint(app, '/api/v1/hosts/{hid}/power', 'POST')(host['id'], PowerReview(action='shutdown', fingerprint=plan['fingerprint'])))
    with pytest.raises(HTTPException):
        asyncio.run(endpoint(app, '/api/v1/hosts/{hid}/power', 'POST')(host['id'], PowerReview(action='shutdown', fingerprint=plan['fingerprint'], confirmed=True)))
    status = endpoint(app, '/api/v1/hosts/{hid}/power-status', 'GET')(host['id'])['requests'][0]
    assert status['status'] == 'unknown' and status['active']
    assert app.state.store.get('hosts', host['id'])['status'] == 'stale'
    assert app.state.store.get('services', 'minecraft')['status'] == 'unknown'
    with pytest.raises(HTTPException):
        asyncio.run(endpoint(app, '/api/v1/hosts/{hid}/power-plan', 'GET')(host['id']))
    # Owner obtains fresh observations after inspecting the actual host.
    current = datetime.now(timezone.utc).isoformat()
    host.update(status='online', last_seen=current)
    app.state.store.put('hosts', host)
    for row in app.state.store.all('services'):
        if row['host_id'] == host['id']:
            row.update(status='stopped', observed_at=current); app.state.store.put('services', row)
    ack = PowerAcknowledge(operation_id=status['id'], confirmed=True)
    result = asyncio.run(endpoint(app, '/api/v1/hosts/{hid}/power/acknowledge', 'POST')(host['id'], ack))
    assert result['power_state_verified'] is False
    assert not endpoint(app, '/api/v1/hosts/{hid}/power-status', 'GET')(host['id'])['requests'][0]['active']
    assert sum(url.endswith('/power') for url in calls) == 1


def test_power_plan_requires_local_approval_identity_freshness_and_no_busy_operations(tmp_path, monkeypatch):
    app = live_app(tmp_path, monkeypatch)
    plan = endpoint(app, '/api/v1/hosts/{hid}/power-plan', 'GET')
    with pytest.raises(HTTPException) as missing:
        asyncio.run(plan('worker-node1'))
    assert missing.value.status_code == 403
    host = prepare(app, monkeypatch)
    async def request(*args, **kwargs):
        return httpx.Response(200, json=profile_payload() | {'physical_host_id': 'wrong-device'})
    fake_agent(monkeypatch, request)
    with pytest.raises(HTTPException):
        asyncio.run(plan(host['id']))
    host['last_seen'] = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat(); app.state.store.put('hosts', host)
    with pytest.raises(HTTPException):
        asyncio.run(plan(host['id']))


def test_acknowledging_unreceived_intent_tombstones_delayed_dispatch(tmp_path, monkeypatch):
    monkeypatch.setattr('agent.power.platform.system', lambda: 'Linux')
    monkeypatch.setattr('agent.power.ordinary_account', lambda: True)
    monkeypatch.setattr('agent.power.Path.is_file', lambda self: True)
    power = Power({'power_actions': ['suspend']}, ReplayGuard(str(tmp_path)), lambda *args, **kwargs: pytest.fail('Delayed power must not run'))
    power.acknowledge(PowerAcknowledge(operation_id='c' * 32, confirmed=True))
    with pytest.raises(HTTPException):
        power.request(PowerRequest(action='suspend', operation_id='c' * 32, fingerprint=power.plan()['fingerprint'], confirmed=True))


def test_macos_shutdown_valid_invalid_and_null_domain(tmp_path, monkeypatch):
    monkeypatch.setattr('agent.power.platform.system', lambda: 'Darwin')
    monkeypatch.setattr('agent.power.ordinary_account', lambda: True)
    uid=tmp_path.stat().st_uid
    monkeypatch.setattr('agent.power.os.getuid', lambda: uid, raising=False)
    monkeypatch.setattr('agent.power.Path.is_file', lambda self: True)
    calls = []
    config = {'power_actions': ['shutdown'], 'macos_power_domain': 'gui/'+str(uid)}
    power = Power(config, ReplayGuard(str(tmp_path)), lambda argv, **kwargs: calls.append(argv))
    power.request(PowerRequest(action='shutdown', confirmed=True, fingerprint=power.plan()['fingerprint'], operation_id='d' * 32))
    assert calls == [['/usr/bin/osascript', '-e', 'tell application "System Events" to shut down']]
    for domain in ('gui/'+str(uid+1), None):
        with pytest.raises(HTTPException):
            profile(config | {'macos_power_domain': domain})


@pytest.mark.parametrize('result', [True, False])
def test_windows_suspend_success_and_refusal_are_mocked(tmp_path, monkeypatch, result):
    monkeypatch.setattr('agent.power.platform.system', lambda: 'Windows')
    monkeypatch.setattr('agent.power.ordinary_account', lambda: True)
    monkeypatch.setattr('agent.power.Path.is_file', lambda self: True)
    calls = []
    def suspend():
        calls.append('suspend')
        if not result:
            raise OSError('Denied')
    monkeypatch.setattr('agent.power.windows_suspend', suspend)
    power = Power({'power_actions': ['suspend']}, ReplayGuard(str(tmp_path)), lambda *args, **kwargs: pytest.fail('No subprocess or rundll32 for suspend'))
    body = PowerRequest(action='suspend', confirmed=True, fingerprint=power.plan()['fingerprint'], operation_id='e' * 32)
    if result:
        assert power.request(body)['status'] == 'dispatched'
    else:
        with pytest.raises(HTTPException):
            power.request(body)
    assert calls == ['suspend'] and power.plan()['pending'] == body.operation_id
