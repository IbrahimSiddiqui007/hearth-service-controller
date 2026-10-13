import json

from fastapi.testclient import TestClient

from controller.app import create_app
from controller.discovery import proposals
from controller.secret_findings import record, listing
from controller.store import Store
from agent.app import safe_path
from agent.secret_scan import scan
from shared.secret_findings import categories


def test_discovery_emits_categories_without_values():
    raw = {'agent_ref': 'web', 'name': 'Web', 'runtime': 'docker', 'control_handle': {'container': 'abc'},
           'description': 'PASSWORD=do-not-store-this-value', 'capabilities': {}}
    result = proposals({'id': 'host', 'name': 'Host'}, [], {'services': [raw]})
    assert result[0]['secret_categories']
    assert 'do-not-store-this-value' not in json.dumps(result)


def test_findings_are_bounded_deduplicated_and_do_not_hash_values(tmp_path):
    store = Store(tmp_path)
    for _ in range(5):
        record(store, 'web', 'Rejected configuration draft', ['Recognized secret assignment or credential URL'])
    rows = listing(store, 'web')
    assert len(rows) == 1 and rows[0]['revision'] == 1
    assert listing(store, 'other') == []
    assert rows[0]['verification'] == 'unverified'


def test_rejected_draft_review_is_scoped_revision_checked_and_value_free(tmp_path):
    with TestClient(create_app(tmp_path, demo=True, token='', background=False)) as client:
        base = '/api/v1/services/minecraft'
        result = client.post(base + '/files/validate', json={'path': 'compose.yaml', 'etag': 'old', 'content': 'PASSWORD=never-persist-me'})
        assert result.status_code == 422
        rows = client.get(base + '/secret-findings').json()['findings']
        assert len(rows) == 1
        row = rows[0]
        body = {'revision': row['revision'], 'pointer': {'label': 'Password', 'vault_ref': 'item-123'}}
        linked = client.put(base + '/secret-findings/' + row['id'], json=body)
        assert linked.status_code == 200
        assert linked.json()['findings'][0]['verification'] == 'unverified'
        assert client.put(base + '/secret-findings/' + row['id'], json=body).status_code == 409
        assert client.put('/api/v1/services/ollama/secret-findings/' + row['id'], json=body).status_code in (404, 409)
        body['revision'] = 2
        body['pointer']['vault_ref'] = 'https://user:password@vault.example/item'
        assert client.put(base + '/secret-findings/' + row['id'], json=body).status_code == 422
        assert client.get('/api/v1/services/missing/secret-findings').status_code == 404
    assert b'never-persist-me' not in (tmp_path / 'controller.sqlite3').read_bytes()


def test_safe_environment_reference_does_not_create_finding(tmp_path):
    with TestClient(create_app(tmp_path, demo=True, token='', background=False)) as client:
        base = '/api/v1/services/minecraft'
        assert client.post(base + '/files/validate', json={'path': 'compose.yaml', 'etag': 'old', 'content': 'PASSWORD: ${APP_PASSWORD}'}).status_code == 200
        assert client.get(base + '/secret-findings').json()['findings'] == []


def test_native_exact_file_scanning_preserves_exclusions_and_scope(tmp_path):
    (tmp_path / 'app.yaml').write_text('PASSWORD=never-export-from-file', encoding='utf-8')
    (tmp_path / '.env').write_text('PASSWORD=never-read-from-env', encoding='utf-8')
    (tmp_path / 'large.yaml').write_text('x' * 64_001, encoding='utf-8')
    config = {'file_roots': {'ref': [str(tmp_path)]}, 'secret_scan_files': {'ref': [{'root_index': 0, 'path': 'app.yaml'}, {'root_index': 0, 'path': '.env'}]}}
    result = scan(config, 'ref', safe_path)
    assert result['scope'] == 'complete' and len(result['categories']) == 2
    assert 'never-' not in json.dumps(result)
    config['secret_scan_files']['ref'].append({'root_index': 0, 'path': '../outside'})
    config['secret_scan_files']['ref'].append({'root_index': 0, 'path': 'large.yaml'})
    assert scan(config, 'ref', safe_path)['scope'] == 'incomplete'
    assert scan(config, 'other', safe_path)['scope'] == 'disabled'


def test_categories_detect_keys_but_do_not_scan_their_own_metadata():
    assert categories({'password': 'private-value'})
    assert categories(['PASSWORD=private-value'])
    assert not categories({'secret_scan_scope': 'complete', 'secret_categories': ['Private key or recognized credential token']})
    assert not categories(['PASSWORD=${APP_PASSWORD}'])
