from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from agent.persistence import snapshot
from controller.app import create_app
from controller.persistence import verified, view


def row(kind='cron', fingerprint='2' * 64):
    return {'id': '1' * 64, 'kind': kind, 'source': '/etc/cron.d', 'name': 'example', 'fingerprint': fingerprint}


def test_read_only_cron_and_port_inventory_masks_and_omits_commands(tmp_path, monkeypatch):
    path = tmp_path / 'job'
    path.write_text('* * * * * user run PASSWORD=never-export\n')
    monkeypatch.setattr('agent.persistence.platform.system', lambda: 'Linux')
    monkeypatch.setattr('agent.persistence.cron_files', lambda: [path])
    monkeypatch.setattr('agent.persistence.psutil.net_connections', lambda **kwargs: [SimpleNamespace(status='LISTEN', laddr=SimpleNamespace(ip='127.0.0.1', port=9000))])
    with pytest.raises(HTTPException):
        snapshot({})
    value = snapshot({'persistence_inventory': True})
    assert value['complete'] == ['listener', 'cron']
    assert len(value['rows']) == 2
    assert 'never-export' not in str(value) and 'run PASSWORD' not in str(value)


def test_cron_job_metadata_excludes_command_and_changes_when_job_changes(tmp_path, monkeypatch):
    path = tmp_path / 'crontab'
    path.write_text('# comment\nMAILTO=user\n*/5 * * * * user command PASSWORD=private\n')
    monkeypatch.setattr('agent.persistence.platform.system', lambda: 'Linux')
    monkeypatch.setattr('agent.persistence.cron_files', lambda: [path])
    monkeypatch.setattr('agent.persistence.socket_rows', lambda: [])
    first = snapshot({'persistence_inventory': True})
    assert len(first['rows']) == 2
    assert first['rows'][1]['name'] == 'entry 3 · */5 * * * *'
    assert 'private' not in str(first) and 'command' not in str(first['rows'])
    path.write_text('# comment\nMAILTO=user\n*/5 * * * * user changed-command\n')
    second = snapshot({'persistence_inventory': True})
    assert any(row['change'] == 'changed' for row in view(second, first['rows'])['changes'])


def test_partial_provider_does_not_report_removal():
    baseline = [row()]
    assert view({'rows': [], 'complete': ['listener']}, baseline)['changes'] == []
    assert view({'rows': [], 'complete': ['cron']}, baseline)['changes'][0]['change'] == 'gone'
    assert view({'rows': [row(fingerprint='3' * 64)], 'complete': ['cron']}, baseline)['changes'][0]['change'] == 'changed'
    assert view({'rows': [row()], 'complete': ['cron']}, [])['changes'][0]['change'] == 'new'


def test_invalid_inventory_and_arbitrary_remote_fields():
    original = row()
    result = verified({'rows': [{**original, 'command': 'do-not-export'}], 'complete': ['cron']})
    assert 'command' not in str(result)
    with pytest.raises(HTTPException):
        verified({'rows': [{**original, 'fingerprint': 'invalid'}], 'complete': ['cron']})


def test_demo_review_stale_checks_and_no_runtime_permission_changes(tmp_path):
    app = create_app(tmp_path, demo=True, token='', background=False)
    with TestClient(app) as client:
        before = client.get('/api/v1/services').json()
        url = '/api/v1/hosts/worker-node1/persistence'
        first = client.post(url + '/refresh', json={}).json()
        assert len(first['changes']) == 1
        assert client.post(url + '/review', json={'fingerprint': '0' * 64}).status_code == 409
        assert client.post(url + '/review', json={'fingerprint': first['fingerprint']}).json()['changes'] == []
        assert client.post(url + '/refresh', json={}).json()['changes'] == []
        assert client.get('/api/v1/services').json() == before
        assert client.post('/api/v1/hosts/laptop/persistence/refresh', json={}).status_code == 409
