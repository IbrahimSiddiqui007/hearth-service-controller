from controller.store import Store
from shared.models import redact
from controller.discovery import proposals
from fastapi import HTTPException
import pytest


def test_multiline_keys_recognized_tokens_entropy_and_audit_storage(tmp_path):
    high_entropy = 'Ab7Xq2Lk9Wp4Yz8Cd5Ef6Gh1Ij3Mn0OpQrStUvWxYzABCDEF'
    examples = ['-----BEGIN PRIVATE KEY-----\nprivate-bytes\n-----END PRIVATE KEY-----', 'ghp_' + 'A' * 32, high_entropy]
    for value in examples:
        assert value not in redact(value)
    assert redact('checksum: ' + 'abcdef1234567890' * 4) == 'checksum: ' + 'abcdef1234567890' * 4
    assert redact('TOKEN=${PSC_AGENT_TEST}') == 'TOKEN=${PSC_AGENT_TEST}'
    store = Store(tmp_path)
    store.audit('masked', 'success', high_entropy)
    assert high_entropy not in store.events()[0]['detail']


def test_discovery_masks_observations_before_storage_and_refuses_sensitive_handles():
    host = {'id': 'host', 'name': 'host', 'address': ''}
    row = {'agent_ref': 'systemd-worker', 'name': 'worker', 'runtime': 'systemd', 'control_handle': {'unit': 'worker.service'}, 'description': 'PASSWORD=do-not-store', 'runtime_details': {'token': 'do-not-store'}}
    candidates = proposals(host, [], {'services': [row]})
    assert 'do-not-store' not in str(candidates)
    row['control_handle'] = {'unit': 'TOKEN=do-not-store.service'}
    with pytest.raises(HTTPException):
        proposals(host, [], {'services': [row]})
