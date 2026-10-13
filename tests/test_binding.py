import pytest
from shared.binding import private_listener, verified_listener
from types import SimpleNamespace
import json


@pytest.mark.parametrize('address', ['127.0.0.1', '::1', 'localhost', '100.64.0.1', '100.127.255.254', 'fd7a:115c:a1e0::abcd'])
def test_private_listener(address):
    assert private_listener(address)


@pytest.mark.parametrize('address', ['0.0.0.0', '::', '192.168.1.1', '8.8.8.8', '100.128.0.1', 'fd7a:115c:a1e1::1', 'example.ts.net'])
def test_refuses_broad_or_unresolved_listener(address):
    assert not private_listener(address)


def test_tailnet_listener_must_match_running_local_tailscale_identity(monkeypatch):
    calls = []
    value = {'BackendState': 'Running', 'Self': {'Online': True, 'TailscaleIPs': ['100.64.1.2']}}
    def status(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout=json.dumps(value))
    monkeypatch.setattr('shared.binding.subprocess.run', status)
    assert verified_listener('127.0.0.1') and not calls
    assert verified_listener('100.64.1.2')
    assert not verified_listener('100.64.1.3')
    value['Self']['Online'] = False
    assert not verified_listener('100.64.1.2')
    value['Self'] = 'malformed'
    assert not verified_listener('100.64.1.2')
    assert all(argv == ['tailscale', 'status', '--json'] for argv in calls)
