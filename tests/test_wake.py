import json

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from controller.app import create_app
from controller.wake import profile, send_magic


@pytest.mark.parametrize('value',[
    {'mac':'ff:ff:ff:ff:ff:ff','address':'192.168.1.255','port':9},
    {'mac':'00:00:00:00:00:00','address':'192.168.1.255','port':9},
    {'mac':'02:00:00:00:00:01','address':'8.8.8.8','port':9},
    {'mac':'02:00:00:00:00:01','address':'127.0.0.1','port':9},
    {'mac':'02:00:00:00:00:01','address':'192.168.1.255','port':22},
])
def test_wake_profiles_reject_unapproved_destinations(monkeypatch,value):
    monkeypatch.setenv('PSC_WAKE_PROFILES',json.dumps({'host':value}))
    with pytest.raises(HTTPException):profile('host',False)


def test_magic_packet_uses_only_configured_destination_with_mock_socket(monkeypatch):
    calls=[]
    class Socket:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def settimeout(self,value):assert value==2
        def setsockopt(self,*args):pass
        def sendto(self,packet,destination):calls.append((packet,destination));return len(packet)
    monkeypatch.setattr('controller.wake.socket.socket',lambda *a:Socket())
    selected={'mac':'02:00:00:00:00:01','address':'192.168.1.255','port':9}
    send_magic(selected)
    assert calls==[(b'\xff'*6+bytes.fromhex('020000000001')*16,('192.168.1.255',9))]


def test_demo_wake_confirmation_cooldown_and_no_inferred_online_state(tmp_path,monkeypatch):
    monkeypatch.setattr('controller.wake.send_magic',lambda *a:pytest.fail('Demo sent real packet'))
    app=create_app(tmp_path,demo=True,background=False)
    with TestClient(app) as client:
        path='/api/v1/hosts/worker-node1'
        old=app.state.store.get('hosts','worker-node1')
        plan=client.get(path+'/wake-plan').json()
        assert client.post(path+'/wake',json={'fingerprint':plan['fingerprint']}).status_code==409
        assert client.post(path+'/wake',json={'fingerprint':'0'*64,'confirmed':True}).status_code==409
        result=client.post(path+'/wake',json={'fingerprint':plan['fingerprint'],'confirmed':True})
        assert result.status_code==200 and not result.json()['host_state_verified']
        assert app.state.store.get('hosts','worker-node1')==old
        assert client.post(path+'/wake',json={'fingerprint':plan['fingerprint'],'confirmed':True}).status_code==429
        assert app.state.store.events()[0]['action']=='host.wake'


def test_live_wake_socket_failure_audits_unknown_and_releases_operation(tmp_path,monkeypatch):
    monkeypatch.setenv('PSC_WAKE_PROFILES',json.dumps({'worker-node1':{'mac':'02:00:00:00:00:01','address':'192.168.1.255','port':9}}))
    def fail(*args):raise OSError('synthetic socket failure')
    monkeypatch.setattr('controller.wake.send_magic',fail)
    app=create_app(tmp_path,demo=False,background=False)
    app.state.store.put('hosts',{'id':'worker-node1','name':'Worker','status':'offline'})
    with TestClient(app) as client:
        path='/api/v1/hosts/worker-node1'
        plan=client.get(path+'/wake-plan').json()
        assert client.post(path+'/wake',json={'confirmed':True,'fingerprint':plan['fingerprint']}).status_code==503
        assert app.state.store.events()[0]['result']=='unknown'
        with app.state.store.connection() as db:
            assert not db.execute("SELECT id FROM operations WHERE status='running'").fetchone()
