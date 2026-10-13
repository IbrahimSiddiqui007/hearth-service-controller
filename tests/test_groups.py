import asyncio
import io
import zipfile

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from controller.app import Action, create_app
from controller.groups import group_plan, validate_groups
from shared.models import ServiceEdit
from test_config_operations import endpoint, fake_agent, live_app


def grouped(app):
    store = app.state.store
    parent = store.get('services', 'minecraft')
    member = store.get('services', 'ollama')
    member.update(host_id=parent['host_id'], dependencies=[], capabilities={'control': True}, status='running')
    parent.update(component_ids=['ollama'], dependencies=[], status='running')
    store.put('services', parent)
    store.put('services', member)
    return store


@pytest.mark.parametrize('change', ['crosshost', 'nested', 'multiple', 'cycle', 'compose'])
def test_invalid_groups(change):
    rows = {key: dict(id=key, host_id='host', runtime='systemd', dependencies=[], component_ids=[], control_handle={}) for key in ['a', 'b', 'c']}
    rows['a']['component_ids'] = ['b']
    if change == 'crosshost':
        rows['b']['host_id'] = 'other'
    elif change == 'nested':
        rows['b']['component_ids'] = ['c']
    elif change == 'multiple':
        rows['c']['component_ids'] = ['b']
    elif change == 'cycle':
        rows['b']['dependencies'] = ['a']
    else:
        rows['a'].update(runtime='compose', components=['b'])
        rows['b'].update(runtime='docker', control_handle={'container': 'b'})
    with pytest.raises(HTTPException):
        validate_groups(rows)


def test_group_order():
    rows = {key: dict(id=key, host_id='host', runtime='systemd', dependencies=[], component_ids=[]) for key in ['a', 'b', 'c', 'external']}
    rows['a']['component_ids'] = ['b', 'c']
    rows['c']['dependencies'] = ['b', 'external']
    assert group_plan(rows, 'a', 'start') == (['b', 'c', 'a'], ['external'])
    assert group_plan(rows, 'a', 'stop') == (['a', 'c', 'b'], ['external'])


def test_link_split_preserves_notebooks_and_export(tmp_path):
    app = create_app(tmp_path, demo=True, token='', background=False)
    store = grouped(app)
    original = {key: store.get('services', key)['notes'] for key in ['minecraft', 'ollama']}
    with TestClient(app) as client:
        parent = client.get('/api/v1/services/minecraft').json()
        assert parent['component_names'] == [store.get('services', 'ollama')['name']]
        assert client.get('/api/v1/services/ollama').json()['group_parent_id'] == 'minecraft'
        exported = client.get('/api/v1/export')
        with zipfile.ZipFile(io.BytesIO(exported.content)) as archive:
            assert 'component_ids:' in archive.read('lab.yaml').decode()
            assert 'docs/Service--ollama.md' in archive.namelist()
        assert client.patch('/api/v1/services/minecraft', json={'revision': parent['revision'], 'component_ids': []}).status_code == 200
        for key, notes in original.items():
            assert client.get('/api/v1/services/' + key).json()['notes'] == notes


def test_group_preflight_prevents_partial_actions(tmp_path):
    app = create_app(tmp_path, demo=True, token='', background=False)
    store = grouped(app)
    member = store.get('services', 'ollama')
    member['capabilities']['control'] = False
    store.put('services', member)
    with TestClient(app) as client:
        url = '/api/v1/services/minecraft/control'
        assert client.post(url, json={'action': 'stop'}).status_code == 409
        assert client.post(url, json={'action': 'stop', 'acknowledge_components': True}).status_code == 403
        member['capabilities']['control'] = True
        store.put('services', member)
        dependent = store.get('services', 'tailscale')
        dependent.update(dependencies=['ollama'], status='running')
        store.put('services', dependent)
        assert client.post(url, json={'action': 'stop', 'acknowledge_components': True}).status_code == 409
        with store.connection() as db:
            assert not db.execute('SELECT 1 FROM operations').fetchone()


def test_group_observed_failure_stops_sequence(tmp_path, monkeypatch):
    app = live_app(tmp_path, monkeypatch)
    grouped(app)
    calls = []
    async def request(method, url, **kwargs):
        calls.append(url)
        return httpx.Response(200, json={'output': 'ok'} if url.endswith('/control') else {'services': [], 'completed_runtimes': ['compose', 'systemd']})
    fake_agent(monkeypatch, request)
    result = asyncio.run(endpoint(app, '/api/v1/services/{sid}/control', 'POST')('minecraft', Action(action='start', acknowledge_components=True)))
    assert result['status'] == 'unknown'
    assert len(result['components']) == 1
    assert len([url for url in calls if url.endswith('/control')]) == 1


def test_group_reservation_and_cancel_release(tmp_path, monkeypatch):
    app = live_app(tmp_path, monkeypatch)
    store = grouped(app)
    async def scenario():
        entered = asyncio.Event()
        async def request(method, url, **kwargs):
            entered.set()
            await asyncio.Event().wait()
        fake_agent(monkeypatch, request)
        control = endpoint(app, '/api/v1/services/{sid}/control', 'POST')
        task = asyncio.create_task(control('minecraft', Action(action='stop', acknowledge_components=True)))
        await entered.wait()
        with pytest.raises(HTTPException) as rejection:
            await control('ollama', Action(action='restart'))
        assert rejection.value.status_code == 409
        with pytest.raises(HTTPException):
            await endpoint(app, '/api/v1/services/{sid}', 'PATCH')('minecraft', ServiceEdit(revision=1, component_ids=[]))
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        with store.connection() as db:
            assert not db.execute("SELECT 1 FROM operations WHERE status='running'").fetchone()
            assert {row['status'] for row in db.execute('SELECT status FROM operations')} == {'unknown'}
        assert store.get('services', 'minecraft')['status'] == 'unknown'
    asyncio.run(scenario())
