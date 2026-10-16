import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from agent.app import safe_path
from agent.config_files import atomic_edit, editable
from agent.file_metadata import ReplacementUncertain, replace, copy_metadata, windows_security, WindowsSecurity
from shared.models import FileWrite


@pytest.fixture
def files(tmp_path, monkeypatch):
    original = tmp_path / 'config.yaml'
    original.write_bytes(b'example: 1\r\n')
    monkeypatch.setattr('os.getuid', lambda: tmp_path.stat().st_uid, raising=False)
    config = {'allow_file_edits': ['approved'], 'file_roots': {'approved': [str(tmp_path)]}}
    body = FileWrite(content='example: 2\n', etag=hashlib.sha256(original.read_bytes()).hexdigest())
    return original, config, body


@pytest.mark.parametrize('system', ['Windows', 'Darwin'])
def test_native_edit_checks_metadata_before_and_after_candidate(files, monkeypatch, system):
    original, config, body = files
    calls = []
    monkeypatch.setattr('agent.config_files.security', lambda path, os_name: b'original-acl')
    def copy(source, candidate, os_name, permissions):
        calls.append(('copy', os_name, permissions))
        assert source == original and candidate.parent == original.parent
    def replacement(candidate, target, os_name, permissions):
        calls.append(('replace', os_name, permissions))
        os.replace(candidate, target)
    monkeypatch.setattr('agent.config_files.copy_metadata', copy)
    monkeypatch.setattr('agent.config_files.replace', replacement)
    assert editable(config, 'approved', original, 'example: 1', False, system)
    result = atomic_edit(config, 'approved', 0, 'config.yaml', body, safe_path, system)
    assert result['editable'] and original.read_bytes() == b'example: 2\r\n'
    assert calls == [('copy', system, b'original-acl'), ('replace', system, b'original-acl')]


def test_native_permission_copy_failure_preserves_original_and_cleans_candidate(files, monkeypatch):
    original, config, body = files
    monkeypatch.setattr('agent.config_files.security', lambda *args: b'acl')
    def denied(*args): raise PermissionError('ACL denied')
    monkeypatch.setattr('agent.config_files.copy_metadata', denied)
    with pytest.raises(HTTPException) as failure:
        atomic_edit(config, 'approved', 0, 'config.yaml', body, safe_path, 'Windows')
    assert failure.value.status_code == 403 and original.read_bytes() == b'example: 1\r\n'
    assert not list(original.parent.glob('.psc-edit-*'))


def test_partial_native_replacement_retains_candidate_and_reports_uncertain(files, monkeypatch):
    original, config, body = files
    monkeypatch.setattr('agent.config_files.security', lambda *args: b'acl')
    monkeypatch.setattr('agent.config_files.copy_metadata', lambda *args: None)
    def uncertain(*args): raise ReplacementUncertain('Recovery copies retained; inspect locally')
    monkeypatch.setattr('agent.config_files.replace', uncertain)
    with pytest.raises(HTTPException) as failure:
        atomic_edit(config, 'approved', 0, 'config.yaml', body, safe_path, 'Windows')
    assert failure.value.status_code == 503 and list(original.parent.glob('.psc-edit-*'))


def test_changed_acl_or_mutating_validator_blocks_replace(files, monkeypatch):
    original, config, body = files
    monkeypatch.setattr('agent.config_files.security', lambda *args: b'acl')
    monkeypatch.setattr('agent.config_files.copy_metadata', lambda *args: None)
    config['config_validators'] = {'approved': {'argv': ['validator', '{file}']}}
    def validator(argv, **kwargs): Path(argv[1]).write_text('changed: true')
    with pytest.raises(HTTPException) as failure:
        atomic_edit(config, 'approved', 0, 'config.yaml', body.model_copy(update={'validate_runtime': True}), safe_path, 'Darwin', validator)
    assert failure.value.status_code == 409 and original.read_bytes() == b'example: 1\r\n'


def test_windows_replace_never_ignores_acl_failures_and_keeps_recovery(tmp_path, monkeypatch):
    calls = []
    def native(target, candidate, backup, flags, exclude, reserved):
        calls.append((target, candidate, backup, flags))
        assert flags == 0 and backup.startswith(str(tmp_path))
        return False
    monkeypatch.setattr('agent.file_metadata.windows_api', lambda: (None, SimpleNamespace(ReplaceFileW=native)))
    with pytest.raises(ReplacementUncertain):
        replace(tmp_path / 'candidate', tmp_path / 'target', 'Windows', b'acl')
    assert len(calls) == 1


def test_metadata_unavailable_and_secret_files_stay_readonly(files, monkeypatch):
    original, config, body = files
    def unavailable(*args): raise OSError('native API unavailable')
    monkeypatch.setattr('agent.config_files.security', unavailable)
    assert not editable(config, 'approved', original, 'safe: true', False, 'Darwin')
    assert not editable(config, 'approved', original, 'PASSWORD=secret', False, 'Windows')


@pytest.mark.parametrize('repair_succeeds',[True,False])
def test_windows_replacement_restores_exact_inheritance_or_keeps_recovery(tmp_path,monkeypatch,repair_succeeds):
    expected=b'original-owner-acl-and-inheritance'
    observed=[b'native-materialized-inherited-aces']
    recovery=[]
    def native(target,candidate,backup,*args):
        Path(backup).write_bytes(b'original content');recovery.append(Path(backup));return True
    def restore_metadata(source,target,system,original):
        assert source==recovery[0] and original==expected
        if not repair_succeeds:raise PermissionError('Cannot restore exact inheritance')
        observed[0]=expected
    monkeypatch.setattr('agent.file_metadata.windows_api',lambda:(None,SimpleNamespace(ReplaceFileW=native)))
    monkeypatch.setattr('agent.file_metadata.security',lambda *args:observed[0])
    monkeypatch.setattr('agent.file_metadata.copy_metadata',restore_metadata)
    if repair_succeeds:
        replace(tmp_path/'candidate',tmp_path/'target','Windows',expected)
        assert observed[0]==expected and not recovery[0].exists()
    else:
        with pytest.raises(ReplacementUncertain):replace(tmp_path/'candidate',tmp_path/'target','Windows',expected)
        assert recovery[0].read_bytes()==b'original content'


def test_windows_security_compares_actual_acl_not_descriptor_layout():
    first = WindowsSecurity(b'layout-one', b'owner', b'ordered-aces', True)
    second = WindowsSecurity(b'layout-two', b'owner', b'ordered-aces', True)
    assert first == second
    assert first != WindowsSecurity(b'layout-one', b'owner', b'changed-aces', True)
    assert first != WindowsSecurity(b'layout-one', b'other-owner', b'ordered-aces', True)
    assert first != WindowsSecurity(b'layout-one', b'owner', b'ordered-aces', False)


def test_macos_native_copy_uses_only_metadata_flags_and_verifies_candidate(tmp_path, monkeypatch):
    source, candidate = tmp_path/'source', tmp_path/'candidate'
    source.write_bytes(b'original content')
    candidate.write_bytes(b'new content')
    calls=[]
    def fcopyfile(original_fd, candidate_fd, state, flags):
        calls.append(flags)
        return 0
    monkeypatch.setattr('agent.file_metadata.mac_library',lambda:SimpleNamespace(fcopyfile=fcopyfile))
    monkeypatch.setattr('agent.file_metadata.security',lambda *args:b'unchanged-acl-xattrs')
    copy_metadata(source,candidate,'Darwin',b'unchanged-acl-xattrs')
    assert calls==[7] and candidate.read_bytes()==b'new content'
