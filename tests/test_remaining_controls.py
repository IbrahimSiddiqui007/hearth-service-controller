import json
from types import SimpleNamespace

import psutil
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from agent.boot import plan, change
from agent.listeners import inventory
from agent.vault import VaultCheck, check
from controller.app import create_app
from shared.boot import BootTarget, BootChange


@pytest.mark.parametrize('case',['valid','invalid','edge'])
def test_listener_suggestions_are_scoped_readonly_and_do_not_read_arguments(monkeypatch, case):
    connection = SimpleNamespace(pid=123,laddr=SimpleNamespace(port=8080),type=1,status=psutil.CONN_LISTEN)
    monkeypatch.setattr('agent.listeners.psutil.net_connections',lambda **kwargs:[connection] if case!='edge' else [])
    process = SimpleNamespace(uids=lambda:SimpleNamespace(real=7 if case=='valid' else 8),exe=lambda:'/opt/app/server',create_time=lambda:12345,name=lambda:'server')
    monkeypatch.setattr('agent.listeners.psutil.Process',lambda pid:process)
    monkeypatch.setattr('agent.listeners.os.getuid',lambda:7,raising=False)
    rows=inventory([])
    assert len(rows)==(1 if case=='valid' else 0)
    if rows:
        assert rows[0]['ports']==['8080/tcp'] and not any(rows[0]['capabilities'].values())
        assert inventory([{'ports':['8080/tcp']}])==[]


@pytest.mark.parametrize('case',['valid','invalid','edge'])
def test_boot_fixed_commands_review_and_observation(case):
    config={'allow_boot_units':['app.service']}
    target=BootTarget(runtime='systemd',handle={'unit':'app.service'})
    state=['disabled']; calls=[]
    def command(argv):
        calls.append(argv)
        if 'show' in argv:return state[0]
        state[0]='enabled'
        return ''
    selected=plan(config,target,command)
    body=BootChange(**target.model_dump(),operation_id='a'*32,policy='enabled',confirmed=case!='edge',fingerprint=selected['fingerprint'] if case!='invalid' else '0'*64)
    if case=='valid':
        assert change(config,body,command)['verified']
        assert ['systemctl','--no-ask-password','enable','app.service'] in calls
    else:
        with pytest.raises(HTTPException):change(config,body,command)
        assert not any('enable' in argv for argv in calls)


@pytest.mark.parametrize('case',['valid','invalid','null-edge'])
def test_boot_api_current_stale_and_null_plans(tmp_path,case):
    with TestClient(create_app(tmp_path,demo=True,token='',background=False)) as client:
        base='/api/v1/services/minecraft/boot'
        selected=client.get(base).json()
        body={'fingerprint':selected['fingerprint'],'confirmed':True,'policy':'unless-stopped'}
        if case=='invalid':body['fingerprint']='0'*64
        if case=='null-edge':body['policy']=None
        result=client.post(base,json=body)
        assert result.status_code=={'valid':200,'invalid':409,'null-edge':422}[case]
        if case=='valid':assert result.json()['status']=='simulated'
        assert client.get('/api/v1/audit/requests').json()[0]['http_status']==result.status_code


@pytest.mark.parametrize('case',['valid','invalid','edge'])
def test_vault_check_returns_existence_only_and_never_secret_data(monkeypatch,case):
    identifier='12345678-1234-1234-1234-123456789012'
    config={'vault_check_items':[identifier],'vault_session_env':'PSC_VAULT_SESSION'}
    monkeypatch.setenv('PSC_VAULT_SESSION','session-private')
    calls=[]
    def run(argv,**kwargs):
        calls.append(argv)
        assert kwargs['env']['BW_SESSION']=='session-private'
        kwargs['stdout'].write(json.dumps({'id':identifier,'login':{'password':'never-return'}}).encode())
        return SimpleNamespace(returncode=0 if case!='edge' else 1)
    monkeypatch.setattr('agent.vault.subprocess.run',run)
    if case=='invalid':
        config['vault_check_items']=[]
        with pytest.raises(HTTPException):check(config,VaultCheck(item_id=identifier))
        assert calls==[]
    else:
        result=check(config,VaultCheck(item_id=identifier))
        assert result['exists'] is (True if case=='valid' else None)
        assert 'never-return' not in json.dumps(result) and 'session-private' not in json.dumps(result)


@pytest.mark.parametrize('case',['valid','invalid','null-edge'])
def test_vault_api_revision_item_and_null_validation(tmp_path,case):
    with TestClient(create_app(tmp_path,demo=True,token='',background=False)) as client:
        service=client.get('/api/v1/services/minecraft').json()
        saved=client.put('/api/v1/services/minecraft/credentials',json={'revision':service['revision'],'credentials':[{'label':'RCON','vault_ref':'12345678-1234-1234-1234-123456789012','username':'','hint':''}]}).json()
        body={'index':0,'revision':saved['revision']}
        if case=='invalid':body['revision']=service['revision']
        if case=='null-edge':body['index']=None
        result=client.post('/api/v1/services/minecraft/credentials/verify',json=body)
        assert result.status_code=={'valid':200,'invalid':409,'null-edge':422}[case]
        if case=='valid':assert result.json()['exists'] is None and result.json()['status']=='simulated'
