import asyncio
import hashlib
import json

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from controller.app import Action, create_app
from shared.models import ConfigEdit, HostDefinition, ServiceEdit


def endpoint(app, path, method):
    return next(route.endpoint for route in app.routes if route.path == path and method in route.methods)


def live_app(tmp_path, monkeypatch):
    seeded = create_app(tmp_path, demo=True, token='', background=False)
    store = seeded.state.store
    for host in store.all('hosts'):
        host.update(status='online', agent_url='http://agent.invalid', token_env='PSC_AGENT_TEST')
        store.put('hosts', host)
    monkeypatch.setenv('PSC_AGENT_TEST', 'test-only-reference')
    return create_app(tmp_path, token='', background=False)


def fake_agent(monkeypatch, request):
    class Client:
        def __init__(self, **kwargs):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def request(self, method, url, **kwargs):
            return await request(method, url, **kwargs)
    monkeypatch.setattr('controller.app.httpx.AsyncClient', Client)


def info(content='safe: true\n'):
    return dict(kind='file', path='config.yaml', resolved_path='/approved/config.yaml', editable=True,
                content=content, etag=hashlib.sha256(content.encode()).hexdigest())


def test_save_reserves_host_before_read_and_blocks_controls_moves_connections(tmp_path, monkeypatch):
    app = live_app(tmp_path, monkeypatch)
    store = app.state.store
    service = store.get('services', 'minecraft')
    host_id = service['host_id']

    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()
        calls = []
        async def request(method, url, **kwargs):
            calls.append(method)
            if method == 'GET':
                entered.set()
                await release.wait()
                return httpx.Response(200, json=info())
            return httpx.Response(200, json=info('safe: false\n'))
        fake_agent(monkeypatch, request)
        save = endpoint(app, '/api/v1/services/{sid}/files', 'PUT')
        task = asyncio.create_task(save('minecraft', ConfigEdit(path='config.yaml', content='safe: false\n', etag=info()['etag'])))
        await entered.wait()
        actions = [
            (endpoint(app, '/api/v1/services/{sid}/control', 'POST'), ('minecraft', Action(action='restart', acknowledge_dependencies=True))),
            (endpoint(app, '/api/v1/services/{sid}', 'PATCH'), ('minecraft', ServiceEdit(revision=service['revision'], host_id='laptop'))),
            (endpoint(app, '/api/v1/hosts', 'POST'), (HostDefinition.model_validate({key: value for key, value in store.get('hosts', host_id).items() if key in HostDefinition.model_fields}),)),
        ]
        # Insert current component inventory; component permission is independent.
        row = dict(agent_ref='component', name='minecraft', capabilities={'control': True}, status='running')
        with store.connection() as db:
            from controller.store import now
            db.execute('INSERT OR REPLACE INTO container_inventory VALUES(?,?,?)', (host_id, now(), json.dumps([row])))
        actions.append((endpoint(app, '/api/v1/hosts/{hid}/containers/{ref}/control', 'POST'), (host_id, 'component', Action(action='restart'))))
        for action, args in actions:
            with pytest.raises(HTTPException) as rejected:
                await action(*args)
            assert rejected.value.status_code == 409
        release.set()
        assert (await task)['content'] == 'safe: false\n'
        assert calls == ['GET', 'PUT']
        with store.connection() as db:
            assert db.execute("SELECT status FROM operations WHERE action='config.save'").fetchone()['status'] == 'success'
        # Reservation has been released: moving the service now succeeds.
        await endpoint(app, '/api/v1/services/{sid}', 'PATCH')('minecraft', ServiceEdit(revision=service['revision'], host_id='laptop'))
    asyncio.run(scenario())


@pytest.mark.parametrize('reply', [{}, [], {'kind': 'file', 'etag': 'bad'}, info('different: content\n')])
def test_malformed_remote_success_is_unknown_and_releases_reservation(tmp_path, monkeypatch, reply):
    app = live_app(tmp_path, monkeypatch)
    async def request(method, url, **kwargs):
        return httpx.Response(200, json=info() if method == 'GET' else reply)
    fake_agent(monkeypatch, request)
    with pytest.raises(HTTPException) as rejected:
        asyncio.run(endpoint(app, '/api/v1/services/{sid}/files', 'PUT')('minecraft', ConfigEdit(path='config.yaml', content='safe: false\n', etag=info()['etag'])))
    assert rejected.value.status_code == 502
    with app.state.store.connection() as db:
        assert db.execute("SELECT status FROM config_versions ORDER BY id DESC LIMIT 1").fetchone()['status'] == 'unknown'
        assert not db.execute("SELECT 1 FROM operations WHERE status='running'").fetchone()
    assert app.state.store.events()[0]['result'] == 'unknown'


def test_restart_marks_prepared_versions_unknown_and_retains_checkpoints(tmp_path):
    app = create_app(tmp_path, demo=True, token='', background=False)
    with app.state.store.connection() as db:
        for state in ('prepared', 'checkpoint', 'applied'):
            db.execute('INSERT INTO config_versions(service_id,file_key,path,root_index,ts,git_commit,etag,message,status) VALUES(?,?,?,?,?,?,?,?,?)', ('minecraft', 'key', 'config.yaml', 0, 'time', 'commit', 'etag', 'message', state))
        db.execute('INSERT INTO operations VALUES(?,?,?,?,?,?)', ('interrupted', 'minecraft', 'config.save', 'running', 'time', ''))
    with TestClient(app):
        with app.state.store.connection() as db:
            assert [row['status'] for row in db.execute('SELECT status FROM config_versions ORDER BY id')] == ['unknown', 'checkpoint', 'applied']
            assert db.execute('SELECT status FROM operations').fetchone()['status'] == 'unknown'


def test_cancelled_remote_save_is_unknown_and_releases_reservation(tmp_path, monkeypatch):
    app = live_app(tmp_path, monkeypatch)
    async def scenario():
        writing = asyncio.Event()
        async def request(method, url, **kwargs):
            if method == 'GET':
                return httpx.Response(200, json=info())
            writing.set()
            await asyncio.Event().wait()
        fake_agent(monkeypatch, request)
        task = asyncio.create_task(endpoint(app, '/api/v1/services/{sid}/files', 'PUT')('minecraft', ConfigEdit(path='config.yaml', content='safe: false\n', etag=info()['etag'])))
        await writing.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        with app.state.store.connection() as db:
            assert db.execute("SELECT status FROM operations").fetchone()['status'] == 'unknown'
            assert db.execute('SELECT status FROM config_versions ORDER BY id DESC LIMIT 1').fetchone()['status'] == 'unknown'
    asyncio.run(scenario())


def test_git_preparation_failure_never_calls_remote_write(tmp_path, monkeypatch):
    app = live_app(tmp_path, monkeypatch)
    calls = []
    async def request(method, url, **kwargs):
        calls.append(method)
        return httpx.Response(200, json=info())
    fake_agent(monkeypatch, request)
    def unavailable(*args, **kwargs):
        raise HTTPException(409, 'Git unavailable')
    monkeypatch.setattr('controller.app.config_snapshot', unavailable)
    with pytest.raises(HTTPException):
        asyncio.run(endpoint(app, '/api/v1/services/{sid}/files', 'PUT')('minecraft', ConfigEdit(path='config.yaml', content='safe: false\n', etag=info()['etag'])))
    assert calls == ['GET']
    with app.state.store.connection() as db:
        assert db.execute('SELECT status FROM operations').fetchone()['status'] == 'failed'


def test_config_save_refuses_already_reserved_runtime_host(tmp_path):
    app = create_app(tmp_path, demo=True, token='', background=False)
    with app.state.store.connection() as db:
        db.execute('INSERT INTO operations VALUES(?,?,?,?,?,?)', ('runtime', 'minecraft', 'restart', 'running', 'time', ''))
    with pytest.raises(HTTPException) as rejected:
        asyncio.run(endpoint(app, '/api/v1/services/{sid}/files', 'PUT')('minecraft', ConfigEdit(path='compose.yaml', content='safe: false\n', etag='stale')))
    assert rejected.value.status_code == 409
    assert not (tmp_path / 'config-history').exists()


def test_connection_is_rechecked_after_preparation_and_before_write(tmp_path, monkeypatch):
    from controller.config_history import snapshot
    app = live_app(tmp_path, monkeypatch)
    calls = []
    async def request(method, url, **kwargs):
        calls.append(method)
        return httpx.Response(200, json=info())
    fake_agent(monkeypatch, request)
    def changed(store, service, *args):
        version = snapshot(store, service, *args)
        if args[-1] == 'prepared':
            current = store.get('services', service['id'])
            current['host_id'] = 'laptop'
            store.put('services', current)
        return version
    monkeypatch.setattr('controller.app.config_snapshot', changed)
    with pytest.raises(HTTPException) as rejected:
        asyncio.run(endpoint(app, '/api/v1/services/{sid}/files', 'PUT')('minecraft', ConfigEdit(path='config.yaml', content='safe: false\n', etag=info()['etag'])))
    assert rejected.value.status_code == 409 and calls == ['GET']
    with app.state.store.connection() as db:
        assert db.execute('SELECT status FROM config_versions ORDER BY id DESC LIMIT 1').fetchone()['status'] == 'failed'


def test_live_ai_context_includes_scoped_verified_config_diff_without_model_request(tmp_path, monkeypatch):
    from controller.app import ExplainRequest
    from controller.config_history import snapshot
    app = live_app(tmp_path, monkeypatch)
    store = app.state.store
    service = store.get('services', 'minecraft')
    snapshot(store, service, info(), 'safe: true\n', 'Baseline', 'checkpoint')
    snapshot(store, service, info(), 'safe: false\n', 'Changed', 'applied')
    snapshot(store, service, info(), 'safe: unknown\n', 'Unverified', 'unknown')
    other = store.get('services', 'ollama')
    snapshot(store, other, info(), 'other: baseline\n', 'Other baseline', 'checkpoint')
    snapshot(store, other, info(), 'other: changed\n', 'Other change', 'applied')
    contexts = []
    async def explain(service, *args, **kwargs):
        contexts.append(service)
        return {'model': 'mock', 'explanation': 'Mocked advice', 'advice_only': True}
    monkeypatch.setattr('controller.app.ai_explain', explain)
    asyncio.run(endpoint(app, '/api/v1/services/{sid}/explain', 'POST')('minecraft', ExplainRequest(selected_logs='Mocked error')))
    diffs = contexts[0]['configuration_diffs']
    assert len(diffs) == 1 and '-safe: true' in diffs[0]['diff'] and '+safe: false' in diffs[0]['diff']
    assert 'unknown' not in diffs[0]['diff'] and 'other:' not in diffs[0]['diff']
