import asyncio
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from controller.app import create_app
from controller.notifications import deliver, enqueue, flush, settings
from controller.store import Store, now
from controller.telemetry import thresholds
from shared.models import NotificationSettings


def configure(store, **values):
    config = NotificationSettings(enabled=True, endpoint='https://notify.invalid', topic='lab', **values)
    with store.connection() as db:
        db.execute("INSERT OR REPLACE INTO settings VALUES('notifications',?)", (config.model_dump_json(),))
    return config.model_dump()


def rows(store):
    with store.connection() as db:
        return [dict(row) for row in db.execute('SELECT * FROM notification_outbox ORDER BY id')]


@pytest.mark.parametrize('values', [dict(endpoint='https://user:secret@notify.invalid'), dict(endpoint='https://notify.invalid/path'), dict(endpoint='https://notify.invalid?token=private'), dict(topic='lab/other'), dict(token_env='raw-secret'), dict(chat_id='chat/unsafe'), dict(restart_threshold=1), dict(restart_window_s=1)])
def test_notification_profile_rejects_unsafe_destinations_and_literal_tokens(values):
    with pytest.raises(ValidationError):
        NotificationSettings(**values)


def test_environment_references_disabled_defaults_and_secret_exclusion(tmp_path, monkeypatch):
    store = Store(tmp_path)
    assert not settings(store)['configured']
    assert enqueue(store, 'disabled', 'message') is None
    configure(store, token_env='PSC_NOTIFY_TEST')
    assert not settings(store)['configured']
    monkeypatch.setenv('PSC_NOTIFY_TEST', 'private-environment-value')
    assert settings(store)['configured']
    assert 'private-environment-value' not in json.dumps(settings(store))
    assert enqueue(store, 'event', 'API_TOKEN=must-not-persist')
    assert enqueue(store, 'event', 'duplicate') is None
    assert 'must-not-persist' not in json.dumps(rows(store))
    configure(store, channel='telegram', token_env='PSC_NOTIFY_TEST', chat_id='-123')
    assert settings(store)['configured']


def test_delivery_transports_do_not_follow_redirects_or_leak_tokens(monkeypatch):
    monkeypatch.setenv('PSC_NOTIFY_TEST', 'private-environment-value')
    calls = []
    replies = [httpx.Response(302), httpx.Response(200, json={'ok': True}), httpx.Response(200, content=b'not-json')]
    class Client:
        def __init__(self, **kwargs):
            assert kwargs == dict(timeout=5, follow_redirects=False, trust_env=False)
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def post(self, url, **kwargs):
            calls.append((url, kwargs))
            return replies.pop(0)
    monkeypatch.setattr('controller.notifications.httpx.AsyncClient', Client)
    ntfy = NotificationSettings(enabled=True, endpoint='https://notify.invalid', topic='lab', token_env='PSC_NOTIFY_TEST').model_dump()
    assert not asyncio.run(deliver(ntfy, 'hello'))[0]
    assert calls[0] == ('https://notify.invalid/lab', dict(content=b'hello', headers={'Authorization': 'Bearer private-environment-value'}))
    telegram = {**ntfy, 'channel': 'telegram', 'chat_id': '-123'}
    assert asyncio.run(deliver(telegram, 'hello'))[0]
    assert calls[1][1]['json'] == {'chat_id': '-123', 'text': 'hello'}
    result = asyncio.run(deliver(telegram, 'hello'))
    assert not result[0] and 'private-environment-value' not in result[1]


def test_three_attempts_backoff_and_batch_limit(tmp_path, monkeypatch):
    store = Store(tmp_path)
    configure(store)
    calls = []
    async def unavailable(*args):
        calls.append(args)
        return False, 'Unavailable'
    monkeypatch.setattr('controller.notifications.deliver', unavailable)
    for index in range(6):
        enqueue(store, str(index), 'message')
    started = datetime.now(timezone.utc)
    assert len(asyncio.run(flush(store))) == 5
    pending = rows(store)
    delay = (datetime.fromisoformat(pending[0]['next_at']) - started).total_seconds()
    assert 89 <= delay < 100 and pending[0]['attempts'] == 1
    for attempt in (2, 3):
        with store.connection() as db:
            db.execute("UPDATE notification_outbox SET next_at=? WHERE id<=5", ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),))
        started = datetime.now(timezone.utc)
        asyncio.run(flush(store))
        first = rows(store)[0]
        assert first['attempts'] == attempt
        if attempt == 2:
            assert 269 <= (datetime.fromisoformat(first['next_at']) - started).total_seconds() < 280
        else:
            assert first['status'] == 'failed'


def test_concurrent_flush_claims_once_and_rechecks_changed_preferences(tmp_path, monkeypatch):
    store = Store(tmp_path)
    configure(store)
    for key in ('one', 'two'):
        enqueue(store, key, key)
    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()
        calls = []
        async def slow(config, message):
            calls.append(message)
            entered.set()
            await release.wait()
            return True, 'Delivered'
        monkeypatch.setattr('controller.notifications.deliver', slow)
        first = asyncio.create_task(flush(store))
        await entered.wait()
        # Change profile before either worker can deliver the second row.
        configure(store, channel='telegram', chat_id='123', token_env='PSC_NOTIFY_MISSING')
        second = await flush(store)
        release.set()
        await first
        assert calls == ['one'] and second == []
        assert [row['status'] for row in rows(store)] == ['delivered', 'cancelled']
    asyncio.run(scenario())


def test_concurrent_flush_does_not_deliver_same_row_twice(tmp_path, monkeypatch):
    store = Store(tmp_path)
    configure(store)
    enqueue(store, 'one', 'message')
    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()
        calls = []
        async def slow(*args):
            calls.append(args)
            entered.set()
            await release.wait()
            return True, 'Delivered'
        monkeypatch.setattr('controller.notifications.deliver', slow)
        first = asyncio.create_task(flush(store))
        await entered.wait()
        assert await flush(store) == []
        release.set()
        await first
        assert len(calls) == 1
    asyncio.run(scenario())


def test_settings_cancel_only_changed_profiles_and_demo_never_sends(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('Demo attempted network delivery')
    monkeypatch.setattr('controller.notifications.deliver', forbidden)
    app = create_app(tmp_path, demo=True, token='', background=False)
    with TestClient(app) as c:
        config = NotificationSettings(enabled=True, endpoint='https://notify.invalid', topic='lab').model_dump()
        assert c.put('/api/v1/notifications', json=config).status_code == 200
        enqueue(app.state.store, 'pending', 'message')
        assert c.put('/api/v1/notifications', json=config).json()['deliveries'][0]['status'] == 'pending'
        changed = c.put('/api/v1/notifications', json={**config, 'topic': 'other'}).json()
        assert changed['deliveries'][0]['status'] == 'cancelled'
        assert c.post('/api/v1/notifications/test', json={}).json()['outcomes'][0]['status'] == 'simulated'
        result = c.put('/api/v1/notifications', json={**config, 'enabled': False})
        assert result.status_code == 200
        assert c.post('/api/v1/notifications/test', json={}).status_code == 409
        assert 'private-environment-value' not in c.get('/api/v1/notifications').text


def test_startup_requeues_interrupted_delivery(tmp_path, monkeypatch):
    app = create_app(tmp_path, demo=True, token='', background=False)
    configure(app.state.store)
    enqueue(app.state.store, 'interrupted', 'message')
    with app.state.store.connection() as db:
        db.execute("UPDATE notification_outbox SET status='sending',attempts=1")
    with TestClient(app):
        assert rows(app.state.store)[0]['status'] == 'pending'
        assert asyncio.run(flush(app.state.store, demo=True))[0]['status'] == 'simulated'


def test_sustained_thresholds_unknown_recovery_and_disabled_state():
    host = {'telemetry_policy': {'enabled': True, 'sustained_samples': 3}}
    assert thresholds(host, {'cpu_percent': 95}) == []
    assert thresholds(host, {'cpu_percent': None}) == []
    assert host['telemetry_streaks']['cpu_percent'] == 0
    for _ in range(2):
        assert thresholds(host, {'cpu_percent': 95}) == []
    assert thresholds(host, {'cpu_percent': 95})[0]['active']
    assert thresholds(host, {'cpu_percent': float('nan')}) == []
    assert host['telemetry_alerts']['cpu_percent']
    assert thresholds(host, {'cpu_percent': 95}) == []
    assert thresholds(host, {'cpu_percent': 20})[0]['active'] is False
    host['telemetry_policy']['enabled'] = False
    assert thresholds(host, {'cpu_percent': 95}) == []
    assert host['telemetry_alerts'] == host['telemetry_streaks'] == {}


def test_volume_thresholds_ignore_unknown_and_malformed_readings():
    host = {'telemetry_policy': {'enabled': True, 'sustained_samples': 1}}
    event = thresholds(host, {'disk_percent': 30, 'volumes': [{'percent': None}, {}, {'percent': 94}]})
    assert event == [{'metric': 'disk_percent', 'active': True, 'value': 94, 'threshold': 90}]
    assert thresholds(host, {'volumes': [{'percent': None}, {'percent': float('inf')}]}) == []
    assert host['telemetry_alerts']['disk_percent']
    assert not thresholds(host, {'disk_percent': 30, 'volumes': [{'percent': 40}]})[0]['active']


def test_policy_api_resets_alerts_and_preserves_host_metadata(tmp_path):
    app = create_app(tmp_path, demo=True, token='', background=False)
    host = app.state.store.get('hosts', 'controller1')
    host.update(monitoring_urls=['https://monitor.invalid'], telemetry_alerts={'cpu_percent': True}, telemetry_streaks={'cpu_percent': 3})
    app.state.store.put('hosts', host)
    with TestClient(app) as c:
        assert c.put('/api/v1/hosts/controller1/telemetry-policy', json={'enabled': True, 'sustained_samples': 2}).status_code == 200
        saved = app.state.store.get('hosts', 'controller1')
        assert saved['monitoring_urls'] == host['monitoring_urls'] and saved['hardware'] == host['hardware']
        assert saved['telemetry_alerts'] == saved['telemetry_streaks'] == {}
        assert c.put('/api/v1/hosts/controller1/telemetry-policy', json={'cpu_percent': 101}).status_code == 422


def test_health_failure_and_recovery_enqueue_once_per_incident(tmp_path):
    app = create_app(tmp_path, demo=True, token='', background=False)
    configure(app.state.store)
    service = app.state.store.get('services', 'paperless')
    service['health_check'] = {'enabled': True, 'type': 'http', 'target': 'https://health.invalid'}
    app.state.store.put('services', service)
    with TestClient(app) as c:
        for _ in range(2):
            assert c.post('/api/v1/services/paperless/health/check', json={}).status_code == 200
        assert len(rows(app.state.store)) == 1
        service['status'] = 'running'
        app.state.store.put('services', service)
        assert c.post('/api/v1/services/paperless/health/check', json={}).status_code == 200
        assert len(rows(app.state.store)) == 2
        assert [row['event_key'].split(':')[-1] for row in rows(app.state.store)] == ['failed', 'recovered']


def test_restart_baseline_threshold_and_offline_transition_events(tmp_path, monkeypatch):
    from test_config_operations import endpoint, fake_agent, live_app
    app = live_app(tmp_path, monkeypatch)
    configure(app.state.store)
    store = app.state.store
    service = store.get('services', 'minecraft')
    service.update(agent_ref='docker-web', runtime='docker', control_handle={'container': 'web'})
    store.put('services', service)
    hid = service['host_id']
    host = store.get('hosts', hid)
    host['telemetry_policy'] = {'enabled': True, 'sustained_samples': 1}
    store.put('hosts', host)
    counter, offline = 10, False
    async def request(method, url, **kwargs):
        if offline:
            return httpx.Response(503, json={'detail': 'Unavailable'})
        if url.endswith('/telemetry'):
            return httpx.Response(200, json={'boot_time': 1, 'cpu_percent': 95})
        row = {'agent_ref': 'docker-web', 'name': 'web', 'runtime': 'docker', 'status': 'running', 'control_handle': {'container': 'web'}, 'runtime_details': {'restart_count': counter}}
        return httpx.Response(200, json={'services': [row], 'completed_runtimes': []})
    fake_agent(monkeypatch, request)
    refresh = endpoint(app, '/api/v1/hosts/{hid}/refresh', 'POST')
    async def scenario():
        nonlocal counter, offline
        await refresh(hid)
        assert not any(row['event_key'].startswith('restarts:') for row in rows(store))
        counter = 13
        await refresh(hid)
        await refresh(hid)
        assert len([row for row in rows(store) if row['event_key'].startswith('restarts:')]) == 1
        assert len([row for row in rows(store) if row['event_key'].startswith('telemetry:')]) == 1
        offline = True
        host = store.get('hosts', hid)
        host['last_seen'] = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        store.put('hosts', host)
        await refresh(hid)
        await refresh(hid)
        assert len([row for row in rows(store) if row['event_key'].startswith('offline:')]) == 1
    asyncio.run(scenario())


def test_notification_transport_error_never_echoes_token_url(monkeypatch):
    monkeypatch.setenv('PSC_NOTIFY_TEST', 'private-environment-value')
    async def unavailable(self, url, **kwargs):
        raise httpx.ReadTimeout(url)
    monkeypatch.setattr('httpx.AsyncClient.post', unavailable)
    config = NotificationSettings(enabled=True, channel='telegram', token_env='PSC_NOTIFY_TEST', chat_id='123').model_dump()
    result = asyncio.run(deliver(config, 'hello'))
    assert not result[0] and 'private-environment-value' not in result[1]


def test_existing_host_update_preserves_omitted_connection_and_policy(tmp_path):
    app = create_app(tmp_path, demo=True, token='', background=False)
    host = app.state.store.get('hosts', 'controller1')
    host.update(agent_url='https://agent.invalid', token_env='PSC_AGENT_TEST', monitoring_urls=['https://monitor.invalid'], telemetry_policy={'enabled': True})
    app.state.store.put('hosts', host)
    with TestClient(app) as c:
        response = c.post('/api/v1/hosts', json={'id': 'controller1', 'name': 'Updated label'})
        assert response.status_code == 200
        saved = response.json()
        for key in ('agent_url', 'token_env', 'monitoring_urls', 'telemetry_policy', 'hardware', 'architecture', 'status'):
            assert saved[key] == host[key]
