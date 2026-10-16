import hashlib
import json
import shutil
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from agent.app import create_agent
from controller.app import create_app
from shared.configuration import secret_reasons
from shared.models import FileWrite, HealthCheck


@pytest.fixture
def editing_agent(tmp_path, monkeypatch):
    monkeypatch.setattr('agent.app.platform.system', lambda: 'Linux')
    monkeypatch.setattr('os.getuid', lambda: tmp_path.stat().st_uid, raising=False)
    (tmp_path / 'config.yaml').write_bytes(b'services:\r\n  web:\r\n    image: example:1\r\n')
    policy = {'file_roots': {'approved': [str(tmp_path)]}, 'allow_file_edits': ['approved']}
    with TestClient(create_agent(policy, token='test')) as c:
        c.headers['Authorization'] = 'Bearer test'
        yield c, tmp_path, policy


def test_config_content_whitespace_is_not_stripped():
    content = '\n  indented content\n'
    assert FileWrite(content=content, etag='hash').content == content


def test_managed_history_reads_versions_under_long_workspace_paths(tmp_path):
    from controller.config_history import file_key, repository, snapshot, version
    from controller.store import Store

    # Git for Windows probes <cwd>/<commit>:<filename> as a possible worktree
    # path. That can exceed MAX_PATH even when the snapshot file itself does not.
    padding = max(1, 170 - len(str(tmp_path.resolve())) - 49)
    store = Store(tmp_path / ('nested-' + 'x' * padding))
    service = {'id': 'long-path-service', 'host_id': 'host'}
    info = {'path': 'config.yaml', 'resolved_path': '/approved/config.yaml'}
    original = '\n  safe: true\n'
    before = snapshot(store, service, info, original, 'Baseline')
    after = snapshot(store, service, info, '\n  safe: false\n', 'Changed', 'applied')
    key = file_key(service, info)
    assert len(str(repository(store, service['id']).resolve())) + 107 > 260
    assert version(store, service['id'], key, before)['content'] == original
    assert version(store, service['id'], key, after)['content'] == '\n  safe: false\n'


def test_atomic_edit_permissions_etag_validation_and_line_endings(editing_agent):
    c, root, _ = editing_agent
    original = c.get('/files?ref=approved&path=config.yaml').json()
    assert original['editable']
    assert original['content'].endswith('\n')
    response = c.put('/files?ref=approved&path=config.yaml', json={'content': 'services:\n  web:\n    image: example:2\n', 'etag': original['etag']})
    assert response.status_code == 200, response.text
    raw = (root / 'config.yaml').read_bytes()
    assert b'example:2\r\n' in raw
    assert response.json()['etag'] == hashlib.sha256(raw).hexdigest()
    assert c.put('/files?ref=approved&path=config.yaml', json={'content': 'changed', 'etag': original['etag']}).status_code == 409
    latest = c.get('/files?ref=approved&path=config.yaml').json()
    assert c.put('/files?ref=approved&path=config.yaml', json={'content': 'broken: [', 'etag': latest['etag']}).status_code == 422
    assert c.put('/files?ref=approved&path=../outside', json={'content': 'changed', 'etag': latest['etag']}).status_code == 403
    assert not list(root.glob('.psc-edit-*'))


def test_secret_exclusion_and_environment_references(editing_agent):
    c, root, _ = editing_agent
    (root / 'app.yaml').write_text('API_TOKEN: literal-private\n')
    secret = c.get('/files?ref=approved&path=app.yaml').json()
    assert not secret['editable'] and secret['secret_excluded'] and 'literal-private' not in secret['content']
    assert c.put('/files?ref=approved&path=app.yaml', json={'content': 'safe: true\n', 'etag': secret['etag']}).status_code == 403
    (root / 'reference.yaml').write_text('API_TOKEN: ${PSC_TOKEN}\n')
    reference = c.get('/files?ref=approved&path=reference.yaml').json()
    assert reference['editable'] and '${PSC_TOKEN}' in reference['content']
    assert secret_reasons('key: -----BEGIN PRIVATE KEY-----')
    assert c.get('/files?ref=approved&path=.env').status_code == 404  # nonexistent; no information disclosed


def test_runtime_validator_failure_preserves_original(editing_agent, monkeypatch):
    c, root, policy = editing_agent
    policy['config_validators'] = {'approved': {'argv': ['check-config', '{file}']}}
    calls = []
    def command(args, **kwargs):
        calls.append(args)
        assert 'example:2' in Path(args[-1]).read_text()
        raise HTTPException(502, 'bad value: TOKEN=never-return')
    monkeypatch.setattr('agent.app.command', command)
    info = c.get('/files?ref=approved&path=config.yaml').json()
    assert info['validator_available']
    result = c.put('/files?ref=approved&path=config.yaml', json={'content': 'services:\n  web:\n    image: example:2\n', 'etag': info['etag'], 'validate_runtime': True})
    assert result.status_code == 422 and 'never-return' not in result.text
    assert b'example:1' in (root / 'config.yaml').read_bytes()
    assert calls and not list(root.glob('.psc-edit-*'))


def test_file_editing_is_opt_in_and_native_metadata_failure_is_readonly(tmp_path, monkeypatch):
    (tmp_path / 'config.yaml').write_text('safe: true\n')
    policy = {'file_roots': {'approved': [str(tmp_path)]}, 'allow_file_edits': []}
    with TestClient(create_agent(policy, token='test')) as c:
        c.headers['Authorization'] = 'Bearer test'
        info = c.get('/files?ref=approved&path=config.yaml').json()
        assert not info['editable']
        monkeypatch.setattr('agent.app.platform.system', lambda: 'Linux')
        assert c.put('/files?ref=approved&path=config.yaml', json={'content': 'safe: false', 'etag': info['etag']}).status_code == 403
        policy['allow_file_edits'] = ['approved']
        monkeypatch.setattr('agent.app.platform.system', lambda: 'Windows')
        def denied(*args): raise PermissionError('Native metadata is unavailable')
        monkeypatch.setattr('agent.config_files.security', denied)
        assert not c.get('/files?ref=approved&path=config.yaml').json()['editable']
        assert c.put('/files?ref=approved&path=config.yaml', json={'content': 'safe: false', 'etag': info['etag']}).status_code == 403


def test_editability_indicator_checks_ownership_and_original_symlink_path(tmp_path, monkeypatch):
    from agent.config_files import editable
    (tmp_path / 'config.yaml').write_text('safe: true\n')
    target = tmp_path / 'config.yaml'
    config = {'allow_file_edits': ['approved']}
    monkeypatch.setattr('os.getuid', lambda: target.stat().st_uid + 1, raising=False)
    assert not editable(config, 'approved', target, 'safe: true\n', False, 'Linux')
    monkeypatch.setattr('os.getuid', lambda: target.stat().st_uid, raising=False)
    monkeypatch.setattr('pathlib.Path.is_symlink', lambda self: self.name == 'link.yaml')
    assert not editable(config, 'approved', target, 'safe: true\n', False, 'Linux', tmp_path / 'link.yaml')
    assert editable(config, 'approved', target, 'safe: true\n', False, 'Linux', target)


@pytest.fixture
def demo(tmp_path):
    if not shutil.which('git'):
        pytest.skip('Git needed for configuration-history integration tests')
    with TestClient(create_app(tmp_path / 'demo', demo=True, token='', background=False)) as c:
        yield c


def test_git_versions_diff_restore_scope_and_whitespace(demo):
    base = '/api/v1/services/minecraft'
    info = demo.get(base + '/files?path=compose.yaml').json()
    original = info['content']
    changed = original.replace('pinned-version', 'version-2')
    saved = demo.put(base + '/files', json={'path': 'compose.yaml', 'content': changed, 'etag': info['etag'], 'message': 'Change image version'})
    assert saved.status_code == 200, saved.text
    versions = demo.get(base + '/config-versions?path=compose.yaml').json()['versions']
    assert len(versions) == 2
    assert versions[0]['status'] == 'applied' and versions[1]['status'] == 'checkpoint'
    diff = demo.get(base + f"/config-diff?path=compose.yaml&before={versions[1]['id']}&after={versions[0]['id']}")
    assert '-    image:' in diff.json()['diff'] and '+    image:' in diff.json()['diff']
    stored = demo.get(base + f"/config-version?path=compose.yaml&version_id={versions[1]['id']}").json()
    assert stored['content'] == original  # including trailing newline
    assert demo.get('/api/v1/services/ollama/config-version', params={'path': 'compose.yaml', 'version_id': versions[1]['id']}).status_code == 404
    stale = demo.post(base + '/config-restore', json={'path': 'compose.yaml', 'version_id': versions[1]['id'], 'etag': info['etag']})
    assert stale.status_code == 409
    restored = demo.post(base + '/config-restore', json={'path': 'compose.yaml', 'version_id': versions[1]['id'], 'etag': saved.json()['etag']})
    assert restored.status_code == 200
    assert demo.get(base + '/files?path=compose.yaml').json()['content'] == original
    assert demo.get(base + '/runtime').json()['documents'][0]['content'] == original
    assert len(demo.get(base + '/config-versions?path=compose.yaml').json()['versions']) == 3
    assert demo.get(base + '/history').json()['configuration']
    repos = list((demo.app.state.store.root / 'config-history').glob('*/.git'))
    assert len(repos) == 1


def test_secrets_and_invalid_config_never_enter_git(demo):
    base = '/api/v1/services/minecraft'
    info = demo.get(base + '/files?path=compose.yaml').json()
    for content in ('TOKEN=never-save-this', 'broken: ['):
        assert demo.put(base + '/files', json={'path': 'compose.yaml', 'content': content, 'etag': info['etag']}).status_code == 422
    assert not (demo.app.state.store.root / 'config-history').exists()
    assert demo.get(base + '/files?path=compose.yaml').json()['etag'] == info['etag']


def test_custom_checks_only_select_fixed_agent_profiles(monkeypatch):
    calls = []
    monkeypatch.setattr('agent.app.command', lambda args, **kwargs: calls.append((args, kwargs)) or 'Application ready')
    config = {'health_commands': {'ready': {'label': 'App readiness', 'argv': ['check-ready', '--safe'], 'timeout_s': 3}}}
    with TestClient(create_agent(config, token='test')) as c:
        c.headers['Authorization'] = 'Bearer test'
        assert c.get('/checks').json() == [{'id': 'ready', 'label': 'App readiness'}]
        assert c.post('/checks/run', json={'profile': 'not-allowed'}).status_code == 403
        assert c.post('/checks/run', json={'profile': 'ready', 'argv': ['unsafe']}).status_code == 422
        response = c.post('/checks/run', json={'profile': 'ready', 'timeout_s': 15})
        assert response.json()['ok'] and calls == [(['check-ready', '--safe'], {'timeout': 3})]
        assert HealthCheck(enabled=True, type='command', target='ready').target == 'ready'
