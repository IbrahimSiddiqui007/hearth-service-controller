import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from controller.app import create_app
from controller.store import now


@pytest.mark.parametrize('kind', ['valid', 'invalid', 'null'])
def test_write_audit_valid_invalid_null_preserves_values_outside_storage(tmp_path, kind):
    app = create_app(tmp_path, demo=True, token='', background=False)
    with TestClient(app) as client:
        service = client.get('/api/v1/services/minecraft').json()
        body = {'revision': service['revision'], 'notes': 'Owner notes'} if kind == 'valid' else {'revision': service['revision'], 'notes': 'PASSWORD=do-not-audit-this-value'} if kind == 'invalid' else None
        reply = client.patch('/api/v1/services/minecraft', json=body, headers={'Content-Type': 'application/json'})
        assert reply.status_code == (200 if kind == 'valid' else 422)
        rows = client.get('/api/v1/services/minecraft/audit/requests').json()
        assert len(rows) == 1 and rows[0]['route'] == '/api/v1/services/{sid}'
        assert rows[0]['status'] == ('accepted' if kind == 'valid' else 'refused')
        assert reply.headers['x-psc-request-id'] == rows[0]['id']
        assert rows[0]['finished_at'] and rows[0]['http_status'] == reply.status_code
        assert client.get('/api/v1/services/ollama/audit/requests').json() == []
    assert b'do-not-audit-this-value' not in (tmp_path / 'controller.sqlite3').read_bytes()


def test_future_restore_routes_are_automatically_audited_without_backup_execution(tmp_path):
    app = create_app(tmp_path, demo=True, token='', background=False)
    @app.post('/api/v1/services/{sid}/backups/restore')
    def mocked_restore(sid: str):
        raise HTTPException(503, 'Simulated unknown outcome')
    with TestClient(app) as client:
        assert client.post('/api/v1/services/minecraft/backups/restore', json={}).status_code == 503
        row = client.get('/api/v1/audit/requests').json()[0]
        assert row['status'] == 'unknown' and row['route'].endswith('/backups/restore')
        assert row['service_id'] == 'minecraft'


def test_interruption_and_restart_stay_unknown_and_never_replay(tmp_path):
    app = create_app(tmp_path, demo=True, token='', background=False)
    journal = app.state.audit_journal
    request = SimpleNamespace(method='POST',url=SimpleNamespace(path='/api/v1/services/minecraft/control'),
                              scope={'type':'http','path':'/api/v1/services/minecraft/control','method':'POST'})
    async def interrupted(_):
        raise asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(journal.run(request,interrupted))
    assert journal.rows()[0]['status'] == 'unknown'
    with app.state.store.connection() as db:
        db.execute('INSERT INTO request_audit VALUES(?,?,?,?,?,?,?,?,?)', ('interrupted',now(),None,'POST','/api/v1/services/{sid}/config-restore','minecraft','worker-node1','running',None))
    with TestClient(create_app(tmp_path,demo=True,token='',background=False)) as client:
        assert all(row['status']=='unknown' for row in client.get('/api/v1/audit/requests').json())


def test_unauthenticated_calls_do_not_create_owner_action_records(tmp_path):
    with TestClient(create_app(tmp_path,token='owner-token',background=False)) as client:
        assert client.post('/api/v1/hosts',json={}).status_code==401
        assert client.app.state.audit_journal.rows()==[]
