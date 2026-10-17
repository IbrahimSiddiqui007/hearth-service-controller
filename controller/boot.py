"""Revision-bound boot plans using the existing per-host reservation domain."""
import hashlib
import json
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException
from controller.store import now
from controller.schedules import fresh
from shared.boot import BootReview,BootInspection


def register(app, store, demo, require, lock, busy, agent_request):
    with store.connection() as db:
        db.execute('CREATE TABLE IF NOT EXISTS boot_requests(id TEXT PRIMARY KEY,service_id TEXT NOT NULL,host_id TEXT NOT NULL,ts TEXT NOT NULL,status TEXT NOT NULL,active INTEGER NOT NULL)')
        db.execute("UPDATE boot_requests SET status='unknown' WHERE status='running'")
    def context(sid):
        service = require('services', sid)
        host = require('hosts', service['host_id'])
        if service.get('component_ids') or any(sid in row.get('component_ids', []) for row in store.all('services')):
            raise HTTPException(409, 'Edit boot policy on unlinked runtime services; split application links before changing persistence')
        if not demo and (host.get('status') != 'online' or not host.get('signing_env') or not host.get('physical_host_id') or not fresh(host.get('last_seen'), datetime.now(timezone.utc)) or not fresh(service.get('observed_at'),datetime.now(timezone.utc))):
            raise HTTPException(409, 'Boot editing requires a fresh online host and signed transport')
        return service, host

    def fingerprint(service, host, profile):
        value = {'service': {key: service.get(key) for key in ('id','revision','runtime','host_id','control_handle')},
                 'host': {key: host.get(key) for key in ('agent_url','token_env','signing_env','physical_host_id','active_os')}, 'profile': profile}
        return hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest()

    async def build(sid):
        service, host = context(sid)
        if busy(host['id']):
            raise HTTPException(409, 'Host is busy or has an unresolved power request')
        if demo:
            choices = ['enabled','disabled'] if service['runtime'] == 'systemd' else ['no','always','unless-stopped','on-failure'] if service['runtime'] in ('docker','compose') else []
            profile = {'current': service.get('boot_policy', choices[0] if choices else 'unsupported'), 'choices': choices, 'targets': [service['name']]}
        else:
            profile = await agent_request(host, 'POST', '/boot/plan', {'runtime': service['runtime'],'handle': service.get('control_handle', {})})
        if not isinstance(profile, dict) or not isinstance(profile.get('choices'), list) or set(profile['choices']) - {'enabled','disabled','no','always','unless-stopped','on-failure'}:
            raise HTTPException(502, 'Invalid boot profile')
        if not isinstance(profile.get('targets'),list) or len(profile['targets'])>100 or any(not isinstance(t,str) or len(t)>256 for t in profile['targets']) or profile.get('current') not in ('enabled','disabled','no','always','unless-stopped','on-failure','mixed','unsupported'):raise HTTPException(502,'Invalid boot target metadata')
        if not demo and (profile.get('physical_host_id')!=host['physical_host_id'] or profile.get('os')!=host.get('active_os')):
            raise HTTPException(409,'Boot profile physical host or active OS changed')
        profile={k:v for k,v in profile.items() if k in ('current','choices','targets','fingerprint','physical_host_id','os')}
        current, current_host = context(sid)
        if fingerprint(current,current_host,{}) != fingerprint(service,host,{}):
            raise HTTPException(409, 'Service changed during review')
        return profile | {'agent_fingerprint':profile.get('fingerprint',''), 'context_fingerprint':fingerprint(service,host,{}), 'fingerprint': fingerprint(service,host,profile), 'demo': demo,
                          'notice': 'Changes startup persistence only. Existing Compose containers may be reset by a later recreation; Compose source is unchanged.'}

    @app.get('/api/v1/services/{sid}/boot')
    async def get_boot(sid: str):
        return await build(sid)

    @app.post('/api/v1/services/{sid}/boot')
    async def set_boot(sid: str, body: BootReview):
        if not body.confirmed:
            raise HTTPException(409, 'Confirm the boot change')
        selected = await build(sid)
        identifier = uuid.uuid4().hex
        async with lock:
            service, host = context(sid)
            if busy(host['id']) or selected['fingerprint'] != body.fingerprint or selected['context_fingerprint'] != fingerprint(service,host,{}) or body.policy not in selected['choices']:
                raise HTTPException(409, 'Boot plan changed or host is busy')
            with store.connection() as db:
                db.execute('INSERT INTO operations VALUES(?,?,?,?,?,?)',(identifier,sid,'boot','running',now(),''))
                db.execute("INSERT INTO boot_requests VALUES(?,?,?,?,'running',1)",(identifier,sid,host['id'],now()))
        outcome = 'unknown'
        try:
            result = {'current':body.policy,'verified':True} if demo else await agent_request(host,'POST','/boot',{'runtime':service['runtime'],'handle':service.get('control_handle',{}),'policy':body.policy,'confirmed':True,'fingerprint':selected['agent_fingerprint'],'operation_id':identifier})
            if not isinstance(result,dict) or result.get('current') != body.policy or result.get('verified') is not True:
                raise HTTPException(409,'Boot setting could not be verified; inspect it before retrying')
            outcome = 'simulated' if demo else 'success'
            current = require('services',sid)
            current['boot_policy'] = body.policy
            store.put('services',current)
            return {'status':outcome,'policy':body.policy,'verified':not demo}
        finally:
            with store.connection() as db:
                db.execute('UPDATE operations SET status=?,detail=? WHERE id=?',(outcome,'Boot policy request; runtime state is unchanged',identifier))
                db.execute('UPDATE boot_requests SET status=?,active=? WHERE id=?',(outcome,int(outcome not in ('simulated','success')),identifier))
                store.audit('boot.update',outcome,'Reviewed boot policy request',sid,host['id'],db=db)

    @app.get('/api/v1/services/{sid}/boot/status')
    def status(sid:str):
        require('services',sid)
        with store.connection() as db:return [dict(r) for r in db.execute('SELECT id,status,ts,active FROM boot_requests WHERE service_id=? ORDER BY ts DESC LIMIT 20',(sid,))]

    @app.post('/api/v1/services/{sid}/boot/acknowledge')
    async def acknowledge(sid:str,body:BootInspection):
        if not body.confirmed:raise HTTPException(409,'Confirm inspection of startup persistence')
        service,host=context(sid)
        with store.connection() as db:row=db.execute("SELECT * FROM boot_requests WHERE id=? AND service_id=? AND status='unknown' AND active=1",(body.operation_id,sid)).fetchone()
        if not row:raise HTTPException(409,'Select an uncertain held boot request')
        if not demo:
            if host.get('last_seen','')<=row['ts'] or service.get('observed_at','')<=row['ts']:raise HTTPException(409,'Fresh post-operation observations are required')
            result=await agent_request(host,'POST','/boot/acknowledge',body.model_dump())
            if result!={'status':'acknowledged','outcome_verified':False}:raise HTTPException(502,'Unverified agent inspection acknowledgement')
        with store.connection() as db:
            db.execute('UPDATE boot_requests SET active=0 WHERE id=?',(body.operation_id,))
            store.audit('boot.acknowledge','success','Owner inspected startup persistence; historical outcome remains unknown',sid,host['id'],db=db)
        return {'status':'acknowledged','outcome_verified':False}
