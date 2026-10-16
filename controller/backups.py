"""Service-scoped backup orchestration, durable holds and non-replaying schedules."""
import hashlib
import json
import uuid
from datetime import datetime, timezone, timedelta

from fastapi import HTTPException
from controller.store import now
from controller.obsidian import service_note
from controller.notifications import enqueue
from controller.schedules import fresh
from shared.backups import BackupPolicy, BackupPolicyEdit, BackupAction, BackupInspection


def fingerprint(value):return hashlib.sha256(json.dumps(value,sort_keys=True,default=str).encode()).hexdigest()


class Coordinator:
    def __init__(self,app,store,demo,require,lock,busy,agent_request,control,health):
        self.store,self.demo,self.require,self.lock,self.busy,self.agent_request,self.control,self.health=store,demo,require,lock,busy,agent_request,control,health
        self.clock=lambda:datetime.now(timezone.utc)
        self.tasks=set()
        with store.connection() as db:
            db.execute('CREATE TABLE IF NOT EXISTS backup_policies(service_id TEXT PRIMARY KEY,body TEXT NOT NULL,cursor TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS backup_runs(id TEXT PRIMARY KEY,service_id TEXT NOT NULL,host_id TEXT NOT NULL,action TEXT NOT NULL,ts TEXT NOT NULL,status TEXT NOT NULL,active INTEGER NOT NULL,result TEXT NOT NULL)')
        app.add_api_route('/api/v1/services/{sid}/backups',self.listing,methods=['GET'])
        app.add_api_route('/api/v1/services/{sid}/backups/policy',self.save,methods=['PUT'])
        app.add_api_route('/api/v1/services/{sid}/backups/plan',self.plan,methods=['GET'])
        app.add_api_route('/api/v1/services/{sid}/backups/{snapshot}/preview',self.preview,methods=['GET'])
        app.add_api_route('/api/v1/services/{sid}/backups',self.request,methods=['POST'])
        app.add_api_route('/api/v1/services/{sid}/backups/acknowledge',self.acknowledge,methods=['POST'])
        app.add_api_route('/api/v1/services/{sid}/backups/{identifier}/inspection',self.inspect,methods=['GET'])

    def recover(self):
        with self.store.connection() as db:db.execute("UPDATE backup_runs SET status='unknown' WHERE status='running'")

    def policy(self,sid):
        with self.store.connection() as db:row=db.execute('SELECT body FROM backup_policies WHERE service_id=?',(sid,)).fetchone()
        return BackupPolicy.model_validate_json(row['body']) if row else BackupPolicy()

    def context(self,sid):
        service=self.require('services',sid);host=self.require('hosts',service['host_id'])
        if not self.demo and (host.get('status')!='online' or not host.get('signing_env') or not host.get('physical_host_id') or not fresh(host.get('last_seen'),self.clock()) or not fresh(service.get('observed_at'),self.clock())):
            raise HTTPException(409,'Backups require fresh service/host observations and signed agent transport')
        return service,host

    def binding(self,service,host,policy,include_state=True):
        return fingerprint({'state':service.get('status') if include_state else None,'service':{k:service.get(k) for k in ('id','revision','host_id','runtime','control_handle','component_ids','dependencies')},
                            'host':{k:host.get(k) for k in ('agent_url','signing_env','token_env','physical_host_id','active_os')},'policy':policy.model_dump()})

    def listing(self,sid:str):
        service=self.require('services',sid);policy=self.policy(sid)
        with self.store.connection() as db:runs=[dict(row) for row in db.execute('SELECT * FROM backup_runs WHERE service_id=? ORDER BY ts DESC LIMIT 50',(sid,))]
        for row in runs:row['result']=json.loads(row['result'])
        successful=next((row for row in runs if row['status'] in ('success','simulated') and row['action']=='backup'),None)
        current=self.clock();next_run=None
        if policy.enabled and policy.schedule!='manual':
            candidate=current.replace(hour=policy.hour_utc,minute=0,second=0,microsecond=0)
            for _ in range(8):
                if candidate>current and (policy.schedule=='daily' or candidate.weekday()==policy.weekday):next_run=candidate.isoformat();break
                candidate+=timedelta(days=1)
        return {'policy':policy.model_dump(),'revision':service['revision'],'runs':runs,'last_success':successful,'next_run':next_run,'demo':self.demo}

    async def save(self,sid:str,body:BackupPolicyEdit):
        async with self.lock:
            service=self.require('services',sid)
            if body.revision!=service['revision'] or self.busy(service['host_id']):raise HTTPException(409,'Service changed or host is busy')
            with self.store.connection() as db:
                db.execute('INSERT OR REPLACE INTO backup_policies VALUES(?,?,?)',(sid,body.policy.model_dump_json(),self.clock().replace(second=0,microsecond=0).isoformat()))
                service.update(revision=service['revision']+1,updated_at=now());self.store.put('services',service,db=db)
                self.store.audit('backup.policy','success','Owner saved backup profile/schedule/retention; no backup was run',sid,service['host_id'],db=db)
        return self.listing(sid)

    async def plan(self,sid:str):
        service,host=self.context(sid);policy=self.policy(sid)
        if not policy.enabled:raise HTTPException(409,'Enable an explicitly approved backup profile first')
        if self.busy(host['id']):raise HTTPException(409,'Host has an active or uninspected operation')
        binding=self.binding(service,host,policy)
        profile={'profile':policy.profile,'fingerprint':fingerprint({'demo':policy.profile}),'paths':service.get('paths',[]),'repository':'Demo repository; no storage touched','snapshots':self.demo_snapshots(sid),'allow_restore':True,'allow_retention':True,'live_allowed':True,'retention_preview':{'remove':[],'keep_daily':policy.keep_daily,'keep_weekly':policy.keep_weekly,'fingerprint':fingerprint({'demo-retention':True})}} if self.demo else await self.agent_request(host,'GET','/backups/profile?name='+policy.profile+'&keep_daily='+str(policy.keep_daily)+'&keep_weekly='+str(policy.keep_weekly),timeout=30)
        if not isinstance(profile,dict) or not isinstance(profile.get('snapshots'),list) or not isinstance(profile.get('fingerprint'),str):raise HTTPException(502,'Invalid backup profile response')
        if not self.demo and (profile.get('physical_host_id')!=host['physical_host_id'] or profile.get('os')!=host.get('active_os')):raise HTTPException(409,'Backup profile physical identity or active OS does not match the selected host')
        current,current_host=self.context(sid)
        if binding!=self.binding(current,current_host,self.policy(sid)):raise HTTPException(409,'Service or backup policy changed during review')
        return profile|{'agent_fingerprint':profile['fingerprint'],'fingerprint':fingerprint({'binding':binding,'profile':profile}),
                        'binding':binding,'policy':policy.model_dump(),'demo':self.demo,
                        'notice':'Restores require a stopped runtime, a current-data safety snapshot, a staged file preview and a configured post-restore health check. Interrupted results stay held for inspection. Extra current files are preserved.'}

    def demo_snapshots(self,sid):
        with self.store.connection() as db:rows=db.execute("SELECT result,ts FROM backup_runs WHERE service_id=? AND action='backup' AND status='simulated' ORDER BY ts DESC",(sid,)).fetchall()
        return [{'id':json.loads(row['result'])['snapshot_id'],'time':row['ts'],'tags':['synthetic'],'size_bytes':1024} for row in rows]

    async def preview(self,sid:str,snapshot:str):
        import re
        if not re.fullmatch(r'[a-f0-9]{64}',snapshot):raise HTTPException(422,'Select a full immutable snapshot ID')
        selected=await self.plan(sid)
        if snapshot not in {r['id'] for r in selected['snapshots']}:raise HTTPException(404,'Snapshot is outside this service profile')
        if self.demo:return {'snapshot':snapshot,'files':[{'path':'/demo/config.yaml','type':'file','size':64}],'demo':True,'fingerprint':selected['fingerprint']}
        _,host=self.context(sid)
        return await self.agent_request(host,'GET','/backups/preview?name='+self.policy(sid).profile+'&snapshot='+snapshot,timeout=30)

    def stop_context(self,service):
        if service.get('component_ids') or any(service['id'] in r.get('component_ids',[]) for r in self.store.all('services')):
            raise HTTPException(409,'Stop-copy-start and restore require an independent runtime service; live static-profile backups also support linked applications')
        if service.get('status') not in ('running','stopped') or not service.get('capabilities',{}).get('control'):
            raise HTTPException(409,'A known, controllable runtime is required for consistent backup/restore')
        impacted={service['id']}
        while True:
            more={r['id'] for r in self.store.all('services') if impacted.intersection(r.get('dependencies',[]))}-impacted
            if not more:break
            impacted.update(more)
        if any((self.require('services',sid).get('status')!='stopped') for sid in impacted-{service['id']}):
            raise HTTPException(409,'Stop dependent services before consistent backup or restore')

    async def request(self,sid:str,body:BackupAction):
        if not body.confirmed:raise HTTPException(409,'Confirm the reviewed backup/restore impact')
        selected=await self.plan(sid)
        if selected['fingerprint']!=body.fingerprint:raise HTTPException(409,'Backup plan changed; review it again')
        policy=self.policy(sid);service,host=self.context(sid)
        if body.action=='retention' and not selected.get('allow_retention') or body.action=='restore' and not selected.get('allow_restore'):raise HTTPException(403,'This operation requires separate local profile approval')
        needs_stop=body.action=='restore' or policy.mode=='stop-copy-start' and body.action=='backup'
        if needs_stop:self.stop_context(service)
        if body.action=='backup' and policy.mode=='live' and not selected.get('live_allowed'):raise HTTPException(409,'Choose stop-copy-start for this non-static profile')
        if body.action=='restore':
            if not (service.get('health_check') or {}).get('enabled'):raise HTTPException(409,'Configure a health check before guided restore')
            await self.preview(sid,body.snapshot)
        identifier=uuid.uuid4().hex;outcome='unknown';result={}
        async with self.lock:
            service,host=self.context(sid)
            if self.busy(host['id']) or selected['binding']!=self.binding(service,host,self.policy(sid)):raise HTTPException(409,'Host or service changed before reservation')
            if needs_stop:self.stop_context(service)
            initial=service.get('status')
            identity=self.binding(service,host,policy,False)
            with self.store.connection() as db:
                db.execute('INSERT INTO backup_runs VALUES(?,?,?,?,?,?,1,?)',(identifier,sid,host['id'],body.action,now(),'running','{}'))
                db.execute('INSERT INTO operations VALUES(?,?,?,?,?,?)',(identifier,sid,'backup.'+body.action,'running',now(),''))
        try:
            def guard():
                current,current_host=self.context(sid)
                if self.binding(current,current_host,self.policy(sid),False)!=identity:raise HTTPException(409,'Service identity or policy changed during the backup workflow')
            if needs_stop and initial=='running':
                stopped=await self.control(sid,'stop',identifier,guard)
                if stopped.get('status')!='success' or stopped.get('service',{}).get('status')!='stopped':raise HTTPException(409,'Runtime did not reach a verified stopped state; no data copy dispatched')
            documentation=service_note(self.require('services',sid),{h['id']:h for h in self.store.all('hosts')})
            if self.demo:
                result={'status':'success','operation_id':identifier,'snapshot_id':body.snapshot if body.action=='restore' else fingerprint({'operation':identifier}),'size_bytes':1024,'documentation_included':True,'demo':True}
                if body.action=='restore':result.update(safety_snapshot_id=fingerprint({'safety':identifier}),restored_files=1,extra_files_preserved=True)
            else:
                response=await self.agent_request(host,'POST','/backups',{'profile':policy.profile,'operation_id':identifier,'action':body.action,'fingerprint':selected['agent_fingerprint'],
                    'snapshot':body.snapshot,'documentation':documentation if body.action=='backup' else '', 'keep_daily':policy.keep_daily,'keep_weekly':policy.keep_weekly,'confirmed':True,'mode':policy.mode,
                    'retention_fingerprint':(selected.get('retention_preview') or {}).get('fingerprint','')},timeout=650)
                result=self.filtered_result(response,identifier)
                if body.action=='backup' and not result.get('snapshot_id'):raise HTTPException(502,'Backup did not provide a verified snapshot identity')
                if body.action=='restore' and (result.get('snapshot_id')!=body.snapshot or not result.get('safety_snapshot_id')):raise HTTPException(502,'Restore safety snapshot/result identity is unverified')
                if body.action=='retention' and result.get('retention_applied') is not True:raise HTTPException(502,'Retention outcome is unverified')
            if needs_stop and initial=='running':
                started=await self.control(sid,'start',identifier,guard)
                if started.get('status')!='success' or started.get('service',{}).get('status')!='running':raise HTTPException(409,'Data operation completed; runtime did not return to a verified running state')
            if body.action=='restore' and initial=='running':
                result['health']=await self.health(sid)
                if not result['health'].get('ok'):raise HTTPException(409,'Restore files were installed but health check failed; inspect the service and safety snapshot')
            elif body.action=='restore':result['health']={'ok':None,'detail':'Runtime was stopped before restore and remains stopped; application health is unverified'}
            outcome='simulated' if self.demo else 'success'
            return result|{'status':outcome,'run_id':identifier}
        finally:
            if outcome=='unknown':enqueue(self.store,'backup:'+identifier,'Backup/restore did not complete for '+service['name']+'. Inspect the service and repository before retrying.')
            with self.store.connection() as db:
                db.execute('UPDATE backup_runs SET status=?,active=?,result=? WHERE id=?',(outcome,0 if outcome in ('success','simulated') else 1,json.dumps(result),identifier))
                db.execute('UPDATE operations SET status=?,detail=? WHERE id=?',(outcome,'Backup operation finished; inspect scoped backup history',identifier))
                self.store.audit('backup.'+body.action,outcome,'Reviewed backup operation; uncertain results require inspection',sid,host['id'],db=db)

    def filtered_result(self,response,identifier):
        import re
        from shared.models import redact
        if not isinstance(response,dict) or response.get('status')!='success' or response.get('operation_id')!=identifier:raise HTTPException(502,'Backup result is unverified; inspect before retrying')
        result={'operation_id':identifier,'status':'success'}
        for key in ('snapshot_id','safety_snapshot_id'):
            if key in response:
                if not isinstance(response[key],str) or not re.fullmatch(r'[a-f0-9]{64}',response[key]):raise HTTPException(502,'Invalid snapshot identity')
                result[key]=response[key]
        for key in ('size_bytes','restored_files'):
            if response.get(key) is not None:
                if type(response[key])!=int or not 0<=response[key]<2**63:raise HTTPException(502,'Invalid backup counters')
                result[key]=response[key]
        for key in ('extra_files_preserved','documentation_included','retention_applied','safety_snapshots_preserved','pruned'):
            if key in response:
                if type(response[key])!=bool:raise HTTPException(502,'Invalid backup flags')
                result[key]=response[key]
        if response.get('documentation') is not None:
            text=response['documentation']
            if not isinstance(text,str) or len(text)>100000:raise HTTPException(502,'Invalid restored notebook')
            result['documentation']=redact(text)
        return result

    async def acknowledge(self,sid:str,body:BackupInspection):
        service,host=self.context(sid)
        if not body.confirmed:raise HTTPException(409,'Confirm inspection of the runtime, repository and any partially restored files')
        with self.store.connection() as db:row=db.execute("SELECT * FROM backup_runs WHERE id=? AND service_id=? AND status='unknown' AND active=1",(body.operation_id,sid)).fetchone()
        if not row:raise HTTPException(409,'Only an interrupted held run can be acknowledged')
        if not self.demo:
            if host.get('last_seen','')<=row['ts'] or service.get('observed_at','')<=row['ts']:raise HTTPException(409,'Fresh post-operation observations are required')
            acknowledged=await self.agent_request(host,'POST','/backups/acknowledge',body.model_dump())
            if not isinstance(acknowledged,dict) or acknowledged.get('status')!='acknowledged' or acknowledged.get('outcome_verified') is not False:raise HTTPException(502,'Agent inspection acknowledgement is unverified; hold retained')
        with self.store.connection() as db:
            db.execute('UPDATE backup_runs SET active=0 WHERE id=?',(body.operation_id,))
            self.store.audit('backup.acknowledge','success','Owner inspected uncertain outcome; no automatic replay or runtime recovery',sid,host['id'],db=db)
        return {'status':'acknowledged','outcome_verified':False}

    async def inspect(self,sid:str,identifier:str):
        import re
        if not re.fullmatch(r'[a-f0-9]{32}',identifier):raise HTTPException(422,'Invalid operation identity')
        _,host=self.context(sid)
        with self.store.connection() as db:row=db.execute('SELECT * FROM backup_runs WHERE id=? AND service_id=?',(identifier,sid)).fetchone()
        if not row:raise HTTPException(404,'Operation does not belong to this service')
        if self.demo:return {'operation_id':identifier,'status':row['status'],'result':json.loads(row['result']),'demo':True}
        response=await self.agent_request(host,'GET','/backups/inspection?operation_id='+identifier)
        if not isinstance(response,dict) or response.get('operation_id')!=identifier or response.get('profile') not in (None,'unreceived',self.policy(sid).profile):raise HTTPException(502,'Invalid operation inspection response')
        result=response.get('result',{})
        filtered={}
        for key in ('snapshot_id','safety_snapshot_id'):
            value=result.get(key)
            if isinstance(value,str) and re.fullmatch(r'[a-f0-9]{64}',value):filtered[key]=value
        return {'operation_id':identifier,'status':response.get('status') if response.get('status') in ('running','success','unknown','acknowledged','unreceived') else 'unknown','result':filtered,'outcome_verified':False}

    async def tick(self):
        if self.demo:return
        current=self.clock().replace(second=0,microsecond=0)
        with self.store.connection() as db:rows=[dict(r) for r in db.execute('SELECT * FROM backup_policies')]
        for row in rows:
            policy=BackupPolicy.model_validate_json(row['body']);previous=datetime.fromisoformat(row['cursor'])
            if current<=previous:continue
            with self.store.connection() as db:
                claimed=db.execute('UPDATE backup_policies SET cursor=? WHERE service_id=? AND cursor=?',(current.isoformat(),row['service_id'],row['cursor'])).rowcount
            # Restart gaps and stale windows are deliberately skipped, never replayed.
            if not claimed or current-previous>timedelta(seconds=90) or not policy.enabled or policy.schedule=='manual' or current.hour!=policy.hour_utc or current.minute!=0 or policy.schedule=='weekly' and current.weekday()!=policy.weekday:continue
            import asyncio
            async def dispatch(sid):
                try:
                    selected=await self.plan(sid)
                    await self.request(sid,BackupAction(fingerprint=selected['fingerprint'],confirmed=True))
                except HTTPException:
                    self.store.audit('backup.schedule','skipped','Scheduled backup was blocked or failed; no automatic retry',sid)
            task=asyncio.create_task(dispatch(row['service_id']))
            self.tasks.add(task);task.add_done_callback(self.tasks.discard)

    async def close(self):
        import asyncio
        tasks=list(self.tasks)
        for task in tasks:task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
