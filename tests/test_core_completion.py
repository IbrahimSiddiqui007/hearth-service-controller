import asyncio
import json
from datetime import datetime,timezone
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from agent.boot import Boot
from agent.host_files import read
from agent.replay import ReplayGuard
from controller.app import create_app
from controller.kuma import Selection,normalize
from shared.boot import BootTarget,BootChange,BootInspection


@pytest.mark.parametrize('case',['valid','invalid','null-edge'])
def test_host_browser_requires_separate_approval_and_never_exposes_secrets(tmp_path,case):
    root=tmp_path/'host';root.mkdir();(root/'readme.txt').write_text('Public configuration overview')
    (root/'credentials.json').write_text('{"password":"not-readable"}')
    config={'host_browse_roots':{'approved':str(root)}}
    if case=='valid':
        result=read(config,'approved','')
        assert result['readonly'] and [r['name'] for r in result['entries']]==['readme.txt']
        assert read(config,'approved','readme.txt')['content']=='Public configuration overview'
    elif case=='invalid':
        for path in ('../outside','credentials.json'):
            with pytest.raises(HTTPException):read(config,'approved',path)
    else:
        with pytest.raises(HTTPException):read({},'approved','')


@pytest.mark.parametrize('case',['valid','invalid','null-edge'])
def test_host_browser_api_explicit_open_and_unknown_profiles(tmp_path,case):
    with TestClient(create_app(tmp_path,demo=True,token='',background=False)) as client:
        base='/api/v1/hosts/worker-node1'
        assert client.get(base+'/browse-roots').json()['profiles']==['example']
        result=client.get(base+'/browse',params={'profile':'example' if case!='invalid' else 'unapproved','confirmed':case!='null-edge'})
        assert result.status_code=={'valid':200,'invalid':403,'null-edge':409}[case]
        if case=='valid':assert result.json()['readonly'] and result.json()['kind']=='directory'


def test_host_browser_refuses_private_content_hardlinks_and_state(tmp_path):
    root=tmp_path/'host';root.mkdir();state=root/'state';state.mkdir()
    (state/'request-nonces.sqlite3').write_bytes(b'private')
    (root/'normal.txt').write_text('password=private-value')
    config={'host_browse_roots':{'approved':str(root)}}
    for path in ('state/request-nonces.sqlite3','normal.txt'):
        with pytest.raises(HTTPException):read(config,'approved',path,state)
    import os
    (root/'data.txt').write_text('example')
    os.link(root/'data.txt',root/'hardlink.txt')
    with pytest.raises(HTTPException):read(config,'approved','hardlink.txt')


def test_boot_uncertainty_survives_restart_and_old_dispatch_never_replays(tmp_path):
    state=tmp_path/'state';state.mkdir(mode=0o700)
    replay=ReplayGuard(str(state));config={'allow_boot_units':['app.service']}
    def command(argv):
        if 'show' in argv:return 'disabled'
        raise HTTPException(503,'Synthetic native uncertainty')
    target=BootTarget(runtime='systemd',handle={'unit':'app.service'})
    engine=Boot(config,replay,command);selected=engine.plan(target)
    body=BootChange(**target.model_dump(),operation_id='a'*32,policy='enabled',confirmed=True,fingerprint=selected['fingerprint'])
    with pytest.raises(HTTPException):engine.change(body)
    reloaded=Boot(config,replay,command)
    with pytest.raises(HTTPException):reloaded.plan(target)
    assert reloaded.acknowledge(BootInspection(operation_id='a'*32,confirmed=True))['outcome_verified'] is False
    with pytest.raises(HTTPException):reloaded.change(body)
    reloaded.acknowledge(BootInspection(operation_id='b'*32,confirmed=True))
    with pytest.raises(HTTPException):reloaded.change(body.model_copy(update={'operation_id':'b'*32}))


def test_boot_controller_hold_blocks_other_actions_until_explicit_inspection(tmp_path):
    app=create_app(tmp_path,demo=True,token='',background=False)
    from controller.store import now
    with app.state.store.connection() as db:db.execute("INSERT INTO boot_requests VALUES(?,'minecraft','worker-node1',?,'unknown',1)",('a'*32,now()))
    with TestClient(app) as client:
        base='/api/v1/services/minecraft'
        assert client.post(base+'/control',json={'action':'stop'}).status_code==409
        assert client.get(base+'/boot').status_code==409
        assert client.post(base+'/boot/acknowledge',json={'operation_id':'a'*32,'confirmed':False}).status_code==409
        assert client.post(base+'/boot/acknowledge',json={'operation_id':'a'*32,'confirmed':True}).json()['outcome_verified'] is False
        assert client.get(base+'/boot').status_code==200


def test_compose_boot_scope_and_observed_container_recreation_are_bound():
    from agent.boot import plan,change
    config={'allow_boot_projects':{'app':'/approved/app'}}
    state=['no'];identity=['a'*64];calls=[]
    def command(argv):
        calls.append(argv)
        if argv[1]=='compose':return identity[0]
        if argv[1]=='inspect':return json.dumps([{'Id':identity[0],'HostConfig':{'RestartPolicy':{'Name':state[0]}},'Config':{'Labels':{'com.docker.compose.project':'app'}}}])
        if argv[1]=='update':state[0]='unless-stopped';return ''
        raise AssertionError(argv)
    target=BootTarget(runtime='compose',handle={'project':'app','path':'/approved/app'})
    selected=plan(config,target,command)
    body=BootChange(**target.model_dump(),operation_id='a'*32,policy='unless-stopped',confirmed=True,fingerprint=selected['fingerprint'])
    identity[0]='b'*64
    with pytest.raises(HTTPException):change(config,body,command)
    assert not any(c[1]=='update' for c in calls)
    body=body.model_copy(update={'fingerprint':plan(config,target,command)['fingerprint']})
    assert change(config,body,command)['verified']


@pytest.mark.parametrize('replacement', ['before', 'during'])
def test_docker_boot_uses_reviewed_identity_even_when_name_is_reused(replacement):
    from agent.boot import plan, change
    config = {'allow_boot_containers': ['app']}
    identity = ['a' * 64]
    policy = ['no']
    updates = []
    def command(argv):
        if argv[1] == 'inspect':
            return json.dumps([{'Id': identity[0], 'HostConfig': {'RestartPolicy': {'Name': policy[0]}}}])
        if argv[1] == 'update':
            updates.append(argv)
            identity[0] = 'b' * 64
            policy[0] = 'always'
            return ''
        raise AssertionError(argv)
    target = BootTarget(runtime='docker', handle={'container': 'app'})
    selected = plan(config, target, command)
    body = BootChange(**target.model_dump(), operation_id='a' * 32, policy='always', confirmed=True, fingerprint=selected['fingerprint'])
    if replacement == 'before':
        identity[0] = 'b' * 64
        with pytest.raises(HTTPException):
            change(config, body, command)
        assert updates == []
    else:
        assert change(config, body, command)['verified'] is False
        assert updates == [['docker', 'update', '--restart=always', 'a' * 64]]


def payload():
    return {'monitorList':[{'id':1,'name':'Owner website','type':'http','url':'https://private.invalid','password':'never-store'}],
            'heartbeatList':{'1':[{'time':'2026-10-01T00:00:00Z','status':1,'ping':5,'msg':'token=never-store'}]}}


@pytest.mark.parametrize('case',['valid','invalid','null-edge'])
def test_kuma_import_retains_available_history_without_changing_live_checks(tmp_path,case):
    with TestClient(create_app(tmp_path,demo=True,token='',background=False)) as client:
        base='/api/v1/services/minecraft';before=client.get(base).json()
        body={'monitor_id':1,'payload':json.dumps(payload())}
        selected=client.post(base+'/kuma/preview',json=body)
        assert selected.status_code==200
        assert 'never-store' not in selected.text and 'private.invalid' not in selected.text
        data=selected.json()
        body.update(fingerprint=data['fingerprint'],revision=data['revision'],confirmed=True)
        if case=='invalid':body['fingerprint']='0'*64
        if case=='null-edge':body['monitor_id']=None
        result=client.post(base+'/kuma/import',json=body)
        assert result.status_code=={'valid':200,'invalid':409,'null-edge':422}[case],result.text
        if case=='valid':
            assert result.json()['imported']['samples'][0]['status']==1
            assert client.post(base+'/kuma/import',json=body).status_code==200
            assert len(client.get(base+'/kuma').json()['imported']['samples'])==1
            assert client.get(base).json()['health_check']==before['health_check']
            assert 'never-store' not in (tmp_path/'controller.sqlite3').read_bytes().decode(errors='ignore')


@pytest.mark.parametrize('case',['valid','invalid','null-edge'])
def test_kuma_published_view_pulls_only_controller_approved_scope(tmp_path,monkeypatch,case):
    monkeypatch.setenv('PSC_KUMA_SOURCES',json.dumps({'lab':'https://kuma.example'}));calls=[]
    async def fetch(url):
        calls.append(url)
        return {'heartbeatList':payload()['heartbeatList']} if '/heartbeat/' in url else {'publicGroupList':[{'monitorList':payload()['monitorList']}]}
    monkeypatch.setattr('controller.kuma.fetch_json',fetch)
    with TestClient(create_app(tmp_path,demo=False,token='',background=False)) as client:
        # Live mode starts empty. Registering a fixture card does not enroll a host.
        app=client.app
        from controller.demo import seed
        seed(app.state.store)
        base='/api/v1/services/minecraft/kuma/preview'
        body={'source':'lab','slug':'services','monitor_id':1}
        if case=='invalid':body['source']='https://unapproved.invalid'
        if case=='null-edge':body['slug']=None
        result=client.post(base,json=body)
        assert result.status_code=={'valid':200,'invalid':422,'null-edge':422}[case],result.text
        if case=='valid':assert calls==['https://kuma.example/api/status-page/services','https://kuma.example/api/status-page/heartbeat/services']
        else:assert calls==[]


def test_kuma_unknown_states_and_conflicts_never_invent_uptime():
    value=payload();value['heartbeatList']['1'][0]['status']=2
    normalized=normalize(value,1)
    assert normalized['samples'][0]['status']==2
    value['heartbeatList']['1'].append(value['heartbeatList']['1'][0]|{'status':1})
    with pytest.raises(HTTPException):normalize(value,1)
    value['heartbeatList']['1']=[]
    assert normalize(value,1)['samples']==[]
