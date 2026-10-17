"""Explicit Kuma data review/import; no login, monitor mutation or live probing."""
import hashlib
import json
import os
from datetime import datetime,timezone,timedelta
from urllib.parse import urlsplit
import httpx
from fastapi import HTTPException
from pydantic import Field
from shared.models import StrictModel,redact


class Selection(StrictModel):
    source:str=Field(default='',max_length=80,pattern=r'^[a-zA-Z0-9_.-]*$')
    slug:str=Field(default='',max_length=80,pattern=r'^[a-zA-Z0-9_-]*$')
    payload:str=Field(default='',max_length=2_000_000)
    monitor_id:int=Field(ge=1,le=2**31-1)


class Import(Selection):
    fingerprint:str=Field(pattern=r'^[a-f0-9]{64}$')
    revision:int=Field(ge=1)
    confirmed:bool=False


def sources():
    try:
        rows=json.loads(os.environ.get('PSC_KUMA_SOURCES','{}'))
        if not isinstance(rows,dict) or len(rows)>8:raise ValueError()
        result={}
        import re
        for name,origin in rows.items():
            p=urlsplit(origin)
            if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,80}',name) or p.scheme not in ('http','https') or not p.hostname or p.username or p.password or p.query or p.fragment or p.path not in ('','/'):raise ValueError()
            result[name]=origin.rstrip('/')
        return result
    except (ValueError,TypeError,AttributeError):raise HTTPException(409,'Review controller-local PSC_KUMA_SOURCES origins')


async def fetch_json(url):
    try:
        async with httpx.AsyncClient(timeout=15,follow_redirects=False,trust_env=False) as client:
            async with client.stream('GET',url) as response:
                if response.status_code!=200:raise HTTPException(502,'Kuma published data unavailable; no credentials or redirects are followed')
                raw=bytearray()
                async for chunk in response.aiter_bytes():
                    raw.extend(chunk)
                    if len(raw)>2_000_000:raise HTTPException(413,'Kuma response exceeds review budget')
        return json.loads(raw)
    except (httpx.HTTPError,ValueError):raise HTTPException(502,'Kuma data is unavailable or not valid JSON')


def normalize(value,identifier):
    if not isinstance(value,dict):raise HTTPException(422,'Use a Kuma monitor/heartbeat JSON object')
    monitors=value.get('monitorList',[])
    if isinstance(monitors,dict):monitors=list(monitors.values())
    if not isinstance(monitors,list):raise HTTPException(422,'Invalid monitor list')
    groups=value.get('publicGroupList',[])
    if not isinstance(groups,list):raise HTTPException(422,'Invalid published groups')
    for group in groups:
        if not isinstance(group,dict) or not isinstance(group.get('monitorList',[]),list):raise HTTPException(422,'Invalid published monitor list')
        monitors+=group.get('monitorList',[])
    selected=[m for m in monitors if isinstance(m,dict) and m.get('id')==identifier]
    if len(selected)!=1:raise HTTPException(422,'Select one unique monitor present in the supplied data')
    monitor=selected[0]
    name=monitor.get('name')
    if not isinstance(name,str) or not 1<=len(name)<=100 or redact(name)!=name:raise HTTPException(422,'Invalid or secret-bearing monitor name')
    kind=monitor.get('type','unknown')
    if not isinstance(kind,str) or len(kind)>40:raise HTTPException(422,'Invalid monitor type')
    if kind not in ('http','keyword','json-query','port','tcp','ping','dns','docker','push','steam','mqtt','redis','postgres','mysql','mongodb','grpc-keyword'):kind='other'
    interval=monitor.get('interval',60)
    if type(interval)!=int or not 1<=interval<=86400:raise HTTPException(422,'Invalid monitor interval')
    mapping=value.get('heartbeatList',{})
    if not isinstance(mapping,dict):raise HTTPException(422,'Invalid heartbeat list')
    rows=mapping.get(str(identifier),[])
    if not isinstance(rows,list) or len(rows)>10000:raise HTTPException(413,'Heartbeat history exceeds supported review scope')
    samples={}
    for row in rows:
        try:
            if not isinstance(row,dict) or type(row.get('status'))!=int or row['status'] not in (0,1,2,3):raise ValueError()
            timestamp=datetime.fromisoformat(row['time'].replace('Z','+00:00'))
            if timestamp.tzinfo is None:timestamp=timestamp.replace(tzinfo=timezone.utc)
            timestamp=timestamp.astimezone(timezone.utc)
            if timestamp>datetime.now(timezone.utc)+timedelta(minutes=5) or timestamp.year<1970:raise ValueError()
            ping=row.get('ping')
            if ping is not None and (type(ping) not in (float,int) or not 0<=ping<=86400000):raise ValueError()
            sample={'ts':timestamp.isoformat(),'status':row['status'],'ping':ping}
            if sample['ts'] in samples and samples[sample['ts']]!=sample:raise ValueError()
            samples[sample['ts']]=sample
        except (ValueError,TypeError,AttributeError,KeyError):raise HTTPException(422,'Invalid or conflicting heartbeat metadata')
    return {'monitor':{'id':identifier,'name':name,'type':kind,'interval':interval},'samples':sorted(samples.values(),key=lambda r:r['ts'])}


def register(app,store,demo,require,lock,busy):
    with store.connection() as db:
        db.execute('CREATE TABLE IF NOT EXISTS kuma_previews(token TEXT PRIMARY KEY,service_id TEXT NOT NULL,ts TEXT NOT NULL,body TEXT NOT NULL)')
        db.execute('CREATE TABLE IF NOT EXISTS kuma_imports(service_id TEXT PRIMARY KEY,source TEXT NOT NULL,monitor TEXT NOT NULL)')
        db.execute('CREATE TABLE IF NOT EXISTS kuma_samples(service_id TEXT NOT NULL,source TEXT NOT NULL,monitor_id INTEGER NOT NULL,ts TEXT NOT NULL,status INTEGER NOT NULL,ping REAL,PRIMARY KEY(service_id,source,monitor_id,ts))')

    async def prepare(sid,body):
        service=require('services',sid)
        if body.source:
            origins={'demo':'https://demo.invalid'} if demo else sources()
            if body.source not in origins or not body.slug or body.payload:raise HTTPException(403,'Choose one controller-approved Kuma source and published slug')
            origin=origins[body.source]
            if demo:value={'monitorList':[{'id':1,'name':'Synthetic Minecraft','type':'tcp'}],'heartbeatList':{'1':[{'status':1,'time':'2026-10-01T00:00:00Z','ping':5}]}}
            else:
                value=await fetch_json(origin+'/api/status-page/'+body.slug)
                hearts=await fetch_json(origin+'/api/status-page/heartbeat/'+body.slug)
                if not isinstance(value,dict) or not isinstance(hearts,dict):raise HTTPException(502,'Invalid Kuma published response')
                value=value|{'heartbeatList':hearts.get('heartbeatList',{})}
            source=origin+'/status/'+body.slug
        else:
            if body.slug:raise HTTPException(422,'A slug needs an approved source')
            try:value=json.loads(body.payload)
            except ValueError:raise HTTPException(422,'Paste a Kuma monitor/heartbeat JSON capture')
            source='owner-import'
        normalized=normalize(value,body.monitor_id)
        fingerprint=hashlib.sha256(json.dumps({'service':sid,'revision':service['revision'],'source':source,'data':normalized},sort_keys=True).encode()).hexdigest()
        return normalized|{'source':source,'fingerprint':fingerprint,'revision':service['revision'],'notice':'Imported/published Kuma evidence only. Available history is preserved separately; no Hearth check or runtime state is changed. Public endpoints may expose only recent history.'}

    @app.get('/api/v1/services/{sid}/kuma')
    def listing(sid:str):
        require('services',sid)
        with store.connection() as db:
            row=db.execute('SELECT * FROM kuma_imports WHERE service_id=?',(sid,)).fetchone()
            data=dict(row) if row else None
            if data:
                data['monitor']=json.loads(data['monitor'])
                data['samples']=[dict(r) for r in db.execute('SELECT ts,status,ping FROM kuma_samples WHERE service_id=? AND source=? AND monitor_id=? ORDER BY ts DESC LIMIT 120',(sid,data['source'],data['monitor']['id']))]
        return {'sources':['demo'] if demo else list(sources()),'imported':data,'demo':demo}

    @app.post('/api/v1/services/{sid}/kuma/preview')
    async def preview(sid:str,body:Selection):
        selected=await prepare(sid,body)
        selected['selection']={'source':body.source,'slug':body.slug,'monitor_id':body.monitor_id}
        with store.connection() as db:
            db.execute('DELETE FROM kuma_previews WHERE ts<?',((datetime.now(timezone.utc)-timedelta(minutes=10)).isoformat(),))
            db.execute('INSERT OR REPLACE INTO kuma_previews VALUES(?,?,?,?)',(selected['fingerprint'],sid,datetime.now(timezone.utc).isoformat(),json.dumps(selected)))
        return selected

    @app.post('/api/v1/services/{sid}/kuma/import')
    async def apply(sid:str,body:Import):
        if not body.confirmed:raise HTTPException(409,'Confirm the reviewed Kuma monitor/history mapping')
        with store.connection() as db:row=db.execute('SELECT * FROM kuma_previews WHERE token=? AND service_id=?',(body.fingerprint,sid)).fetchone()
        if not row or datetime.fromisoformat(row['ts'])<datetime.now(timezone.utc)-timedelta(minutes=10):raise HTTPException(409,'Kuma preview expired; review again')
        selected=json.loads(row['body'])
        if selected['selection']!={'source':body.source,'slug':body.slug,'monitor_id':body.monitor_id}:raise HTTPException(409,'Selected monitor/source changed')
        if body.source:
            origin=({'demo':'https://demo.invalid'} if demo else sources()).get(body.source)
            if selected['source']!=str(origin)+'/status/'+body.slug:raise HTTPException(409,'Approved Kuma source changed')
        if body.fingerprint!=selected['fingerprint'] or body.revision!=selected['revision']:raise HTTPException(409,'Kuma data or service changed; review again')
        async with lock:
            service=require('services',sid)
            if service['revision']!=body.revision or busy(service['host_id']):raise HTTPException(409,'Service changed or host is busy')
            with store.connection() as db:
                for r in selected['samples']:
                    old=db.execute('SELECT status,ping FROM kuma_samples WHERE service_id=? AND source=? AND monitor_id=? AND ts=?',(sid,selected['source'],body.monitor_id,r['ts'])).fetchone()
                    if old and (old['status'],old['ping'])!=(r['status'],r['ping']):raise HTTPException(409,'Existing imported history conflicts; original samples preserved')
                    db.execute('INSERT OR IGNORE INTO kuma_samples VALUES(?,?,?,?,?,?)',(sid,selected['source'],body.monitor_id,r['ts'],r['status'],r['ping']))
                db.execute('INSERT OR REPLACE INTO kuma_imports VALUES(?,?,?)',(sid,selected['source'],json.dumps(selected['monitor'])))
                store.audit('kuma.import','simulated' if demo else 'success','Owner reviewed monitor identity and available history; native health series unchanged',sid,service['host_id'],db=db)
        return listing(sid)
