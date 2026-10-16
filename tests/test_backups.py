import asyncio
from datetime import datetime,timedelta,timezone
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from agent.backups import Backups
from agent.replay import ReplayGuard
from controller.app import create_app
from shared.backups import AgentBackupRequest,BackupInspection,BackupAction,BackupPolicyEdit


@pytest.fixture
def engine(tmp_path,monkeypatch):
    # This fixture tests backup orchestration. Native ACL providers have their
    # own tests and explicit real-tool opt-in; hosted runner ownership/ACLs vary.
    metadata=[]
    monkeypatch.setattr('agent.backups.security',lambda *args:b'synthetic-owned-acl')
    monkeypatch.setattr('agent.backups.copy_metadata',lambda *args:metadata.append('copy'))
    def replace(source,target,*args):
        metadata.append('replace');os.replace(source,target)
    monkeypatch.setattr('agent.backups.replace_preserving_metadata',replace)
    mount=tmp_path/'nas';repository=mount/'repo';repository.mkdir(parents=True);(repository/'config').write_text('owner provisioned')
    source=tmp_path/'data';source.mkdir();(source/'config.yaml').write_text('current: true\n');(source/'extra.txt').write_text('preserve')
    state=tmp_path/'state';state.mkdir(mode=0o700)
    monkeypatch.setattr('agent.backups.os.path.ismount',lambda path:path==mount)
    monkeypatch.setenv('PSC_BACKUP_TEST_PASSWORD','private-vault-password')
    config={'backup_profiles':{'app':{'storage_root':str(mount),'repository':str(repository),'paths':[str(source)],'password_env':'PSC_BACKUP_TEST_PASSWORD','consistency':'static','allow_restore':True,'allow_retention':True,'runtime':{'runtime':'systemd','handle':{'unit':'app.service'}}}}}
    calls=[];snapshots=[];restore_content='old: true\n';events=[]
    def execute(argv,env,**kwargs):
        assert env['RESTIC_PASSWORD']=='private-vault-password'
        assert 'private-vault-password' not in repr(argv)
        calls.append(argv)
        command=argv[4]
        if command=='snapshots':return json.dumps(snapshots)
        if command=='forget':return '[]'
        if command=='backup':
            identifier=hashlib.sha256(str(len(snapshots)).encode()).hexdigest()
            safety='hearth-safety' in argv
            snapshots.append({'id':identifier,'time':'2026-10-16T03:00:00Z','tags':['hearth:app','hearth-safety' if safety else 'hearth-data'],'summary':{'total_bytes_processed':32}})
            events.append('safety' if safety else 'backup')
            return json.dumps({'message_type':'summary','snapshot_id':identifier,'total_bytes_processed':32})
        if command=='ls':
            path='/'+source.as_posix().replace(':','').lstrip('/')+'/config.yaml'
            return '\n'.join([json.dumps({'struct_type':'snapshot'}),json.dumps({'struct_type':'node','path':path,'type':'file','size':len(restore_content)})])
        if command=='restore':
            assert 'safety' in events
            destination=Path(argv[argv.index('--target')+1])/source.as_posix().replace(':','').lstrip('/')/'config.yaml'
            destination.parent.mkdir(parents=True);destination.write_text(restore_content)
            events.append('restore')
            return '{}'
        raise AssertionError(argv)
    replay=ReplayGuard(str(state))
    observer=lambda:{'services':[{'runtime':'systemd','control_handle':{'unit':'app.service'},'status':'stopped'}]}
    backups=Backups(config,replay,execute,observer)
    return SimpleNamespace(backups=backups,calls=calls,config=config,source=source,mount=mount,snapshots=snapshots,events=events,replay=replay,metadata=metadata)


def request(engine,action='backup',**kwargs):
    return AgentBackupRequest(profile='app',operation_id=hashlib.md5(str(len(engine.calls)).encode()).hexdigest(),action=action,fingerprint=engine.backups.profile('app')['fingerprint'],confirmed=True,**kwargs)


@pytest.mark.parametrize('case',['valid','invalid','null-edge'])
def test_backup_scope_password_source_and_documentation(engine,case,monkeypatch):
    if case=='invalid':
        monkeypatch.setattr('agent.backups.os.path.ismount',lambda path:False)
        with pytest.raises(HTTPException):engine.backups.plan('app')
        assert engine.calls==[]
    elif case=='null-edge':
        monkeypatch.delenv('PSC_BACKUP_TEST_PASSWORD')
        with pytest.raises(HTTPException):engine.backups.plan('app')
        assert engine.calls==[]
    else:
        result=engine.backups.request(request(engine,documentation='# Owner recovery\nSafe notes'))
        assert result['documentation_included'] and result['status']=='success'
        argv=next(row for row in engine.calls if row[4]=='backup')
        assert str(engine.source) in argv and any(p.endswith('app.md') for p in argv)
        assert 'private-vault-password' not in json.dumps(result)


@pytest.mark.parametrize('case',['valid','invalid','edge'])
def test_restore_has_preview_safety_snapshot_and_preserves_extra_files(engine,case):
    identifier=engine.backups.request(request(engine))['snapshot_id']
    if case=='invalid':
        engine.config['backup_profiles']['app']['allow_restore']=False
        with pytest.raises(HTTPException):engine.backups.preview('app',identifier)
        assert engine.events==['backup']
    elif case=='edge':
        engine.backups.observer=lambda:{'services':[{'runtime':'systemd','control_handle':{'unit':'app.service'},'status':'unknown'}]}
        with pytest.raises(HTTPException):engine.backups.request(request(engine,'restore',snapshot=identifier))
        assert (engine.source/'config.yaml').read_text()=='current: true\n'
        assert engine.events==['backup']
    else:
        preview=engine.backups.preview('app',identifier)
        assert preview['files'][0]['type']=='file'
        result=engine.backups.request(request(engine,'restore',snapshot=identifier))
        assert result['safety_snapshot_id']!=identifier
        assert engine.events==['backup','safety','restore']
        assert (engine.source/'config.yaml').read_text()=='old: true\n'
        assert (engine.source/'extra.txt').read_text()=='preserve'
        assert engine.metadata==['copy','replace']


def test_backup_uncertain_intent_blocks_replay_until_inspection(engine):
    body=request(engine)
    engine.backups.execute=lambda *args,**kwargs:(_ for _ in ()).throw(HTTPException(503,'synthetic tool timeout'))
    with pytest.raises(HTTPException):engine.backups.request(body)
    with pytest.raises(HTTPException):engine.backups.request(body)
    reloaded=Backups(engine.config,engine.replay,engine.backups.execute)
    assert reloaded.acknowledge(BackupInspection(operation_id=body.operation_id,confirmed=True))['outcome_verified'] is False
    with pytest.raises(HTTPException):reloaded.request(body)


def test_unreceived_backup_acknowledgement_tombstones_late_dispatch(engine):
    body=request(engine)
    assert engine.backups.acknowledge(BackupInspection(operation_id=body.operation_id,confirmed=True))['outcome_verified'] is False
    with pytest.raises(HTTPException):engine.backups.request(body)
    assert not any(row[4]=='backup' for row in engine.calls)


def test_inflight_backup_cannot_be_acknowledged_and_completed_result_can(engine):
    body=request(engine);original=engine.backups.execute
    def execute(*args,**kwargs):
        with pytest.raises(HTTPException):engine.backups.acknowledge(BackupInspection(operation_id=body.operation_id,confirmed=True))
        return original(*args,**kwargs)
    engine.backups.execute=execute
    engine.backups.request(body)
    assert engine.backups.acknowledge(BackupInspection(operation_id=body.operation_id,confirmed=True))['status']=='acknowledged'


@pytest.mark.parametrize('case',['valid','invalid','edge'])
def test_retention_is_scoped_reviewed_and_never_prunes_safety_snapshots(engine,case):
    profile=engine.backups.profile('app')
    selected=engine.backups.retention_plan(profile,7,4)
    body=request(engine,'retention',retention_fingerprint=selected['fingerprint'] if case!='invalid' else '0'*64)
    if case=='edge':engine.config['backup_profiles']['app']['allow_retention']=False
    if case=='valid':
        result=engine.backups.request(body)
        assert result['safety_snapshots_preserved'] and result['pruned'] is False
        assert all('prune' not in command for command in engine.calls)
        assert any('hearth:app,hearth-data' in command for command in engine.calls)
    else:
        with pytest.raises(HTTPException):engine.backups.request(body)
        assert all('--dry-run' in command for command in engine.calls if command[4]=='forget')


def enable(client,mode='live'):
    sid='/api/v1/services/minecraft'
    service=client.get(sid).json()
    result=client.put(sid+'/backups/policy',json={'revision':service['revision'],'policy':{'profile':'minecraft','enabled':True,'mode':mode}})
    assert result.status_code==200,result.text
    return sid+'/backups'


@pytest.mark.parametrize('case',['valid','invalid','null-edge'])
def test_backup_api_plan_revision_guards_null_and_durable_audit(tmp_path,case):
    with TestClient(create_app(tmp_path,demo=True,token='',background=False)) as client:
        base=enable(client)
        plan=client.get(base+'/plan').json()
        body={'fingerprint':plan['fingerprint'],'confirmed':True}
        if case=='invalid':body['fingerprint']='0'*64
        if case=='null-edge':body['action']=None
        result=client.post(base,json=body)
        assert result.status_code=={'valid':200,'invalid':409,'null-edge':422}[case],result.text
        if case=='valid':
            state=client.get(base).json()
            assert state['last_success']['status']=='simulated' and len(state['runs'])==1
            assert client.get(base+'/'+state['runs'][0]['result']['snapshot_id']+'/preview').status_code==200
        assert client.get('/api/v1/audit/requests').json()[0]['http_status']==result.status_code


def test_consistent_backup_stops_copies_restarts_and_restore_requires_health(tmp_path):
    with TestClient(create_app(tmp_path,demo=True,token='',background=False)) as client:
        base=enable(client,'stop-copy-start')
        plan=client.get(base+'/plan').json()
        backup=client.post(base,json={'fingerprint':plan['fingerprint'],'confirmed':True})
        assert backup.status_code==200,backup.text
        assert client.get('/api/v1/services/minecraft').json()['status']=='running'
        snapshot=backup.json()['snapshot_id'];plan=client.get(base+'/plan').json()
        service=client.get('/api/v1/services/minecraft').json()
        configured=client.put('/api/v1/services/minecraft/health-check',json={'revision':service['revision'],'check':{'enabled':True,'type':'tcp','target':'demo.invalid','port':25565}})
        assert configured.status_code==200,configured.text
        plan=client.get(base+'/plan').json()
        result=client.post(base,json={'fingerprint':plan['fingerprint'],'confirmed':True,'action':'restore','snapshot':snapshot})
        assert result.status_code==200,result.text
        assert result.json()['health']['ok'] is True
        assert client.get('/api/v1/services/minecraft').json()['status']=='running'


@pytest.mark.parametrize('case',['valid','invalid','edge'])
def test_restore_preview_rejects_unsafe_archive_metadata_before_writes(engine,case):
    identifier=engine.backups.request(request(engine))['snapshot_id']
    original=engine.backups.execute
    def execute(argv,*args,**kwargs):
        if argv[4]=='ls':
            path='/'+engine.source.as_posix().replace(':','').lstrip('/')+'/config.yaml'
            return json.dumps({'struct_type':'node','path':path if case!='invalid' else '/../../outside','type':'symlink' if case=='edge' else 'file','size':10})
        return original(argv,*args,**kwargs)
    engine.backups.execute=execute
    if case=='valid':assert engine.backups.preview('app',identifier)['files'][0]['type']=='file'
    else:
        with pytest.raises(HTTPException):engine.backups.preview('app',identifier)
        assert engine.events==['backup']


def test_agent_result_is_whitelisted_before_any_storage(tmp_path):
    coordinator=create_app(tmp_path,demo=True,token='',background=False).state.backups
    response={'status':'success','operation_id':'a'*32,'snapshot_id':'b'*64,'secret':'never-store','documentation':'PASSWORD=private-value'}
    filtered=coordinator.filtered_result(response,'a'*32)
    assert 'secret' not in filtered and 'private-value' not in json.dumps(filtered)
    with pytest.raises(HTTPException):coordinator.filtered_result(response|{'snapshot_id':'b'*8},'a'*32)


def test_retention_deletes_only_reviewed_ids_even_if_repository_changes(engine):
    identifier=engine.backups.request(request(engine))['snapshot_id']
    original=engine.backups.execute
    def execute(argv,*args,**kwargs):
        if argv[4]=='forget':
            if '--dry-run' in argv:
                return json.dumps([{'remove':[{'id':identifier,'tags':['hearth:app','hearth-data']}]}])
            assert argv[5:]==['--',identifier]
            engine.snapshots[:]=[row for row in engine.snapshots if row['id']!=identifier]
            # A snapshot arriving after review must never join the removal set.
            engine.snapshots.append({'id':'f'*64,'tags':['hearth:app','hearth-data']})
            return '{}'
        return original(argv,*args,**kwargs)
    engine.backups.execute=execute
    selected=engine.backups.retention_plan(engine.backups.profile('app'),7,4)
    result=engine.backups.request(request(engine,'retention',retention_fingerprint=selected['fingerprint']))
    assert result['retention_applied'] and engine.snapshots[0]['id']=='f'*64


def test_backup_failure_alert_and_cross_action_hold_survive_restart(tmp_path,monkeypatch):
    from controller.app import Action
    from controller.store import now
    app=create_app(tmp_path,demo=True,token='',background=False)
    coordinator=app.state.backups;store=app.state.store
    alerts=[];monkeypatch.setattr('controller.backups.enqueue',lambda *args:alerts.append(args))
    async def scenario():
        revision=store.get('services','minecraft')['revision']
        await coordinator.save('minecraft',BackupPolicyEdit(revision=revision,policy={'profile':'app','enabled':True}))
        host=store.get('hosts','worker-node1');host.update(status='online',last_seen=now(),signing_env='PSC_TEST_SIGNING',physical_host_id='synthetic-host',active_os='Linux');store.put('hosts',host)
        coordinator.demo=False
        async def fake_agent(host,method,path,payload=None,**kwargs):
            if path.startswith('/backups/profile'):return {'profile':'app','fingerprint':'a'*64,'physical_host_id':'synthetic-host','os':'Linux','paths':['/synthetic/data'],'snapshots':[],'live_allowed':True,'allow_restore':True,'allow_retention':False}
            raise HTTPException(503,'Synthetic backup interruption')
        coordinator.agent_request=fake_agent
        selected=await coordinator.plan('minecraft')
        with pytest.raises(HTTPException):await coordinator.request('minecraft',BackupAction(fingerprint=selected['fingerprint'],confirmed=True))
        assert len(alerts)==1 and 'private' not in str(alerts)
        held=coordinator.listing('minecraft')['runs'][0]
        assert held['status']=='unknown' and held['active']==1
        control=next(route.endpoint for route in app.routes if route.path=='/api/v1/services/{sid}/control')
        with pytest.raises(HTTPException):await control('minecraft',Action(action='stop'))
        reloaded=create_app(tmp_path,demo=True,token='',background=False)
        assert reloaded.state.backups.listing('minecraft')['runs'][0]['active']==1
    asyncio.run(scenario())


def test_backup_schedule_skips_restart_gaps_and_does_not_block_polling(tmp_path,monkeypatch):
    app=create_app(tmp_path,demo=True,token='',background=False)
    coordinator=app.state.backups
    async def scenario():
        current=datetime(2026,10,16,3,0,tzinfo=timezone.utc)
        coordinator.clock=lambda:current-timedelta(minutes=2)
        revision=app.state.store.get('services','minecraft')['revision']
        await coordinator.save('minecraft',BackupPolicyEdit(revision=revision,policy={'profile':'app','enabled':True,'schedule':'daily'}))
        coordinator.demo=False;coordinator.clock=lambda:current
        calls=[]
        async def plan(sid):calls.append(sid);return {'fingerprint':'a'*64}
        async def run(sid,body):calls.append(body.action)
        monkeypatch.setattr(coordinator,'plan',plan);monkeypatch.setattr(coordinator,'request',run)
        await coordinator.tick();await asyncio.sleep(0)
        assert calls==[]
        with app.state.store.connection() as db:db.execute('UPDATE backup_policies SET cursor=?',((current-timedelta(minutes=1)).isoformat(),))
        await coordinator.tick();await asyncio.gather(*coordinator.tasks)
        assert calls==['minecraft','backup']
        await coordinator.tick();assert calls==['minecraft','backup']
    asyncio.run(scenario())
