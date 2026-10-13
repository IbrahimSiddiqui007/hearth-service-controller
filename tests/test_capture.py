import asyncio
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from controller.app import create_app
from test_config_operations import endpoint, fake_agent, info, live_app


def enable(app, paths, sid='minecraft'):
    service = app.state.store.get('services', sid)
    service.update(track_configuration=True, locations={'configuration': paths})
    app.state.store.put('services', service)


def test_demo_capture_opt_in_baseline_change_and_service_scope(tmp_path, monkeypatch):
    app = create_app(tmp_path, demo=True, token='', background=False)
    def forbidden(*args, **kwargs):
        raise AssertionError('Demo capture contacted an agent')
    monkeypatch.setattr('controller.app.httpx.AsyncClient', forbidden)
    with TestClient(app) as c:
        base = '/api/v1/services/minecraft'
        assert c.post(base + '/config-capture', json={}).status_code == 409
        enable(app, [])
        first = c.post(base + '/config-capture', json={}).json()
        assert len(first['captured']) == 1 and first['skipped'] == []
        assert c.post(base + '/config-capture', json={}).json()['captured'] == []
        with app.state.store.connection() as db:
            db.execute('INSERT INTO demo_files VALUES(?,?,?)', ('minecraft', 'compose.yaml', 'safe: changed\n'))
        second = c.post(base + '/config-capture', json={}).json()
        assert len(second['captured']) == 1
        versions = c.get(base + '/config-versions?path=compose.yaml').json()['versions']
        assert [row['status'] for row in versions] == ['applied', 'checkpoint']
        assert c.get('/api/v1/services/ollama/config-version', params={'path': 'compose.yaml', 'version_id': second['captured'][0]}).status_code == 404


def test_capture_exclusions_malformed_metadata_and_five_file_limit(tmp_path, monkeypatch):
    app = live_app(tmp_path, monkeypatch)
    paths = ['/approved/' + name for name in ['safe.yaml', 'secret.yaml', 'large.yaml', 'binary.dat', 'missing.yaml', 'sixth.yaml']]
    enable(app, paths)
    calls = []
    async def request(method, url, **kwargs):
        path = parse_qs(urlsplit(url).query)['path'][0]
        calls.append(path)
        result = {**info(), 'path': path, 'resolved_path': path}
        if path.endswith('secret.yaml'):
            result.update(content='TOKEN=do-not-store', secret_excluded=True)
        elif path.endswith('large.yaml'):
            result['truncated'] = True
        elif path.endswith('binary.dat'):
            result = {'kind': 'binary', 'path': path}
        elif path.endswith('missing.yaml'):
            result.pop('etag')
        return httpx.Response(200, json=result)
    fake_agent(monkeypatch, request)
    result = asyncio.run(endpoint(app, '/api/v1/services/{sid}/config-capture', 'POST')('minecraft'))
    assert result['limited'] and len(calls) == 5 and len(result['captured']) == 1 and len(result['skipped']) == 4
    with app.state.store.connection() as db:
        assert db.execute('SELECT COUNT(*) FROM config_versions').fetchone()[0] == 1
    assert 'do-not-store' not in str(result)


def test_capture_concurrent_requests_and_host_moves_are_refused(tmp_path, monkeypatch):
    app = live_app(tmp_path, monkeypatch)
    enable(app, ['/approved/config.yaml'])
    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()
        async def request(*args, **kwargs):
            entered.set()
            await release.wait()
            return httpx.Response(200, json=info())
        fake_agent(monkeypatch, request)
        capture = endpoint(app, '/api/v1/services/{sid}/config-capture', 'POST')
        task = asyncio.create_task(capture('minecraft'))
        await entered.wait()
        with pytest.raises(HTTPException) as rejected:
            await capture('minecraft')
        assert rejected.value.status_code == 409
        from shared.models import ServiceEdit
        service = app.state.store.get('services', 'minecraft')
        with pytest.raises(HTTPException) as rejected:
            await endpoint(app, '/api/v1/services/{sid}', 'PATCH')('minecraft', ServiceEdit(revision=service['revision'], host_id='laptop'))
        assert rejected.value.status_code == 409
        release.set()
        assert len((await task)['captured']) == 1
    asyncio.run(scenario())


def test_scheduled_capture_caps_three_and_honors_intervals_without_changing_notes(tmp_path):
    from controller.config_history import capture_due
    app = create_app(tmp_path, demo=True, token='', background=False)
    store = app.state.store
    for service in store.all('services'):
        service['track_configuration'] = True
        store.put('services', service)
    before = {row['id']: (row['notes'], row['revision']) for row in store.all('services')}
    calls = []
    async def capture(sid):
        calls.append(sid)
        if len(calls) == 1:
            raise HTTPException(409, 'Temporarily busy')
    async def scenario():
        lock = asyncio.Lock()
        assert await capture_due(store, capture, lock) == 3
        assert len(calls) == 3
        first = set(calls)
        assert await capture_due(store, capture, lock) == 3
        assert not first.intersection(calls[3:])
    asyncio.run(scenario())
    assert {row['id']: (row['notes'], row['revision']) for row in store.all('services')} == before
