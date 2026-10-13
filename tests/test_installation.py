import json
import os
import asyncio

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from agent.installation import file_snapshot, inventory
from agent.installation import docker_resources
from controller.app import create_app
from controller.installation import differences, history_commands, relevant
from agent.app import create_agent


def test_watch_roots_metadata_hashes_noise_secrets_and_changes(tmp_path):
    root = tmp_path / 'approved';root.mkdir()
    (root / 'compose.yaml').write_text('services: {}\n', encoding='utf-8')
    (root / '.env').write_text('PASSWORD=never-export', encoding='utf-8')
    (root / 'notes.txt').write_text('token=never-export', encoding='utf-8')
    (root / 'logs').mkdir();(root / 'logs' / 'example.txt').write_text('noisy', encoding='utf-8')
    config = {'file_roots': {'ref': [str(root)]}, 'installation_watch_roots': {'ref': [str(root)]}}
    first=file_snapshot(config,'ref')
    assert [row['name'] for row in first['rows']]==['compose.yaml']
    assert 'never-export' not in json.dumps(first) and 'services:' not in json.dumps(first)
    (root / 'compose.yaml').write_text('services: {app: {}}\n', encoding='utf-8')
    last=file_snapshot(config,'ref')
    changes,gaps=differences({'categories':{'files':first}},{'categories':{'files':last}})
    assert not gaps and changes[0]['kind']=='changed'
    outside=tmp_path/'outside';outside.mkdir()
    config['installation_watch_roots']['ref']=[str(outside)]
    with pytest.raises(HTTPException):file_snapshot(config,'ref')


def test_watched_file_budget_marks_scope_incomplete(tmp_path):
    (tmp_path/'large.txt').write_bytes(b'x'*65537)
    result=file_snapshot({'file_roots':{'ref':[str(tmp_path)]},'installation_watch_roots':{'ref':[str(tmp_path)]}},'ref')
    assert not result['complete'] and not result['rows']


def test_watched_symlink_and_hardlink_are_never_read(tmp_path, monkeypatch):
    original=tmp_path/'original.txt';original.write_text('example: 1',encoding='utf-8')
    alias=tmp_path/'alias.txt'
    try:os.link(original,alias)
    except OSError:pytest.skip('Temporary hardlink creation unavailable')
    result=file_snapshot({'file_roots':{'ref':[str(tmp_path)]},'installation_watch_roots':{'ref':[str(tmp_path)]}},'ref')
    assert not result['rows'] and not result['complete']
    monkeypatch.setattr('agent.installation.safe',lambda path:False)
    with pytest.raises(HTTPException):file_snapshot({'file_roots':{'ref':[str(tmp_path)]},'installation_watch_roots':{'ref':[str(tmp_path)]}},'ref')


def test_partial_or_different_scope_never_infers_removed_files():
    row={'id':'a','name':'a','value':'a'*64}
    before={'categories':{'files':{'rows':[row],'complete':True,'roots':['/one']}}}
    after={'categories':{'files':{'rows':[],'complete':False,'roots':['/one']}}}
    assert differences(before,after)[0]==[] and differences(before,after)[1]
    after['categories']['files'].update(complete=True,roots=['/other'])
    assert not differences(before,after)[0]


@pytest.mark.parametrize('shell,text,expected',[
    ('bash','#1700000000\ncd /opt/services/minecraft\ndocker compose up -d', ['cd /opt/services/minecraft','docker compose up -d']),
    ('zsh',': 1700000000:3;mkdir minecraft\n: 1700000001:2;echo example', ['mkdir minecraft','echo example']),
    ('fish','- cmd: mkdir minecraft\n  when: 1700000000\n- cmd: echo hello\\nworld', ['mkdir minecraft','echo hello\nworld']),
])
def test_history_formats(shell,text,expected):
    assert history_commands(shell,text)==expected


def test_history_filters_service_tokens_ports_and_secrets():
    rows=relevant({'id':'minecraft','name':'Minecraft','ports':['25565/tcp'],'paths':['/srv/minecraft']},['echo unrelated','mkdir minecraft','docker run -p 25565:25565 image','echo minecraft PASSWORD=private','echo minecraft-other'])
    assert len(rows)==3 and 'private' not in json.dumps(rows)
    assert all(not row['verified'] for row in rows)


def test_history_import_review_conflicts_export_and_service_scope(tmp_path):
    app=create_app(tmp_path,demo=True,background=False)
    with TestClient(app) as client:
        base='/api/v1/services/minecraft'
        assert client.post(base+'/installation-history',json={'shell':'bash','content':'mkdir minecraft'}).status_code==409
        result=client.post(base+'/installation-history',json={'shell':'bash','content':'mkdir minecraft\necho minecraft PASSWORD=private\necho unrelated','confirmed':True}).json()
        identifier=result['session']['id'];path=base+'/terminal/sessions/'+identifier+'/installation'
        assert result['reconstructed'] and len(result['commands'])==1
        assert client.get('/api/v1/services/ollama/terminal/sessions/'+identifier+'/installation').status_code==404
        export=client.get(base+'/terminal/sessions/'+identifier+'/instructions')
        assert 'Reconstructed' in export.text and 'unverified' in export.text and 'private' not in export.text
        assert client.get(base+'/terminal/sessions/'+identifier+'/cast').status_code==409
        assert not any(event['action']=='recording.export' and event['result']=='success' for event in app.state.store.events())
        body={'revision':0,'excluded':[result['commands'][0]['id']],'instructions':'Review prerequisites first','approved':True}
        saved=client.put(path,json=body)
        assert saved.status_code==200 and saved.json()['revision']==1
        assert client.put(path,json=body).status_code==409
        assert 'mkdir minecraft' not in client.get(base+'/terminal/sessions/'+identifier+'/instructions').text
        with app.state.store.connection() as db:
            assert 'private' not in str(db.execute('SELECT body FROM installation_history').fetchall()[0]['body'])
        assert 'private' not in str(app.state.store.events())


def test_snapshot_capture_demo_no_agent_and_review_pruning(tmp_path,monkeypatch):
    monkeypatch.setattr('controller.app.httpx.AsyncClient',lambda *a,**k:pytest.fail('Demo contacted agent'))
    app=create_app(tmp_path,demo=True,background=False)
    with TestClient(app) as client:
        base='/api/v1/services/minecraft'
        opened=client.post(base+'/terminal/open',json={'profile':'demo','fingerprint':'0'*64,'confirmed':True,'recording':True,'snapshots':True}).json()
        with client.websocket_connect(base+'/terminal/sessions/'+opened['id']+'/ws') as ws:
            ws.send_json({'ticket':opened['ticket']});assert ws.receive_json()['kind']=='ready';ws.receive_json()
            ws.send_json({'data':'mkdir minecraft\r'});ws.receive_json()
            assert client.put(base+'/terminal/sessions/'+opened['id']+'/installation',json={'revision':0}).status_code==409
            ws.send_json({'kind':'close'});ws.receive_json()
        evidence=client.get(base+'/terminal/sessions/'+opened['id']+'/installation').json()
        assert evidence['changes'][0]['name']=='compose.yaml' and not evidence['gaps']
        result=client.put(base+'/terminal/sessions/'+opened['id']+'/installation',json={'revision':0,'excluded':[evidence['changes'][0]['id']]}).json()
        assert result['revision']==1
        assert 'compose.yaml' not in client.get(base+'/terminal/sessions/'+opened['id']+'/instructions').text


def test_untrusted_snapshot_rejects_content_duplicates_and_secrets(tmp_path):
    app=create_app(tmp_path,demo=True,background=False)
    engine=app.state.terminals.installation
    for rows in ([{'id':'a','name':'a','value':'a'*64,'content':'private'}],[{'id':'a','name':'a','value':'a'*64}]*2,[{'id':'a','name':'PASSWORD=private','value':'a'*64}]):
        with pytest.raises(HTTPException):engine.save_snapshot('id','before',{'categories':{'files':{'complete':True,'rows':rows}}})


def test_installation_inventory_is_explicit_and_does_not_export_runtime_secrets(tmp_path):
    config={'installation_snapshot_refs':['ref'],'file_roots':{'ref':[str(tmp_path)]},'installation_watch_roots':{}}
    runtime={'services':[{'agent_ref':'unit','name':'example','runtime':'systemd','environment':{'PASSWORD':'private'}}],'completed_runtimes':['systemd'],'containers':[]}
    result=inventory(config,'ref',runtime,{'applications':[],'ports':[],'completed':['applications','ports']})
    assert 'private' not in json.dumps(result) and result['categories']['services']['complete']
    with pytest.raises(HTTPException):inventory(config,'other',runtime,{})


def test_demo_ai_drafts_are_explicit_and_do_not_save_or_contact_models(tmp_path,monkeypatch):
    monkeypatch.setattr('controller.app.httpx.AsyncClient',lambda *a,**k:pytest.fail('Demo contacted model'))
    app=create_app(tmp_path,demo=True,background=False)
    with TestClient(app) as client:
        base='/api/v1/services/minecraft'
        before=app.state.store.get('services','minecraft')
        summary=client.post(base+'/summary-draft',json={})
        assert summary.status_code==200 and '[DEMO]' in summary.json()['draft']
        assert app.state.store.get('services','minecraft')==before
        imported=client.post(base+'/installation-history',json={'shell':'bash','content':'mkdir minecraft','confirmed':True}).json()
        path=base+'/terminal/sessions/'+imported['session']['id']+'/installation'
        generated=client.post(path+'/draft',json={})
        assert generated.status_code==200 and not generated.json()['verified']
        assert client.get(path).json()['review']['instructions']==''
        with app.state.store.connection() as db:
            db.execute("INSERT OR REPLACE INTO settings VALUES('ai',?)",(json.dumps({'enabled':False,'endpoint':'','model':'','timeout_s':60,'context_lines':200}),))
        assert client.post(base+'/summary-draft',json={}).status_code==409
        assert client.post(path+'/draft',json={}).status_code==409


@pytest.mark.parametrize('system',['Linux','Darwin','Windows'])
def test_agent_snapshot_permission_and_native_boundaries_mocked(tmp_path,monkeypatch,system):
    monkeypatch.setattr('agent.app.platform.system',lambda:system)
    monkeypatch.setattr('agent.app.command',lambda *a,**k:pytest.fail('Unmocked native command'))
    software={'applications':[],'ports':[],'completed':['applications','ports'],'os':system}
    monkeypatch.setattr('agent.app.software_snapshot',lambda *a:software)
    monkeypatch.setattr('agent.app.windows_snapshot',lambda *a:software)
    config={'discover':[],'installation_snapshot_refs':['ref'],'file_roots':{'ref':[str(tmp_path)]},'installation_watch_roots':{'ref':[str(tmp_path)]}}
    with TestClient(create_agent(config,token='test')) as client:
        assert client.post('/installation/snapshot',json={'ref':'ref'}).status_code==401
        client.headers['Authorization']='Bearer test'
        assert client.post('/installation/snapshot',json={'ref':'other'}).status_code==403
        value=client.post('/installation/snapshot',json={'ref':'ref'})
        assert value.status_code==200 and value.json()['os']==system
        assert value.json()['categories']['files']['complete']


def test_changed_live_snapshot_identity_stays_an_evidence_gap(tmp_path):
    app=create_app(tmp_path,demo=True,background=False)
    terminal=app.state.terminals
    service=app.state.store.get('services','minecraft')
    host=app.state.store.get('hosts',service['host_id']);host['physical_host_id']='expected';app.state.store.put('hosts',host)
    item={'service':service,'host':host,'snapshots':True}
    terminal.demo=False
    async def wrong_identity(*args,**kwargs):return {'os':'Linux','physical_host_id':'other','categories':{}}
    terminal.agent=wrong_identity
    asyncio.run(terminal.installation.capture('test','before',item))
    with app.state.store.connection() as db:
        assert not db.execute('SELECT * FROM installation_snapshots').fetchone()
    assert app.state.store.events()[0]['result']=='failed'


def test_docker_resources_are_metadata_only_and_partial_errors_remain_gaps():
    calls=[]
    def command(argv,**kwargs):
        calls.append(argv)
        if argv[1]=='image':return json.dumps({'ID':'sha256:a','Repository':'example','Tag':'latest','Digest':'sha256:a'})
        if argv[1]=='network':return json.dumps({'ID':'network-a','Name':'example','Driver':'bridge'})
        return json.dumps({'Name':'data','Driver':'local'})
    result=docker_resources(command)
    assert result['complete'] and len(result['rows'])==3 and all('ls' in args for args in calls)
    def incomplete(argv,**kwargs):
        if argv[1]=='volume':raise HTTPException(403,'no permission')
        return command(argv,**kwargs)
    after=docker_resources(incomplete)
    changes,gaps=differences({'categories':{'docker_resources':result}},{'categories':{'docker_resources':after}})
    assert gaps and not any(row['kind']=='removed' for row in changes)
