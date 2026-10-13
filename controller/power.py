"""Reviewed host power plans; unknown results hold writes until owner inspection."""
import hashlib
import json
import os
import secrets
from datetime import datetime, timezone

from fastapi import HTTPException
from controller.schedules import fresh
from controller.store import now
from shared.power import PowerReview, PowerAcknowledge


def register(app, store, demo, require, lock, busy, agent_request):
    def approved(hid):
        raw = os.environ.get('PSC_POWER_HOSTS', '[]')
        try:
            hosts = json.loads(raw)
            if not isinstance(hosts, list) or len(hosts) > 50 or hid not in hosts:
                raise ValueError()
        except (ValueError, TypeError):
            raise HTTPException(403, 'Host power controls need explicit controller-local approval')

    def context(hid):
        host = require('hosts', hid)
        if not demo:
            approved(hid)
            if not host.get('physical_host_id') or not host.get('signing_env') or host.get('status') != 'online' or not fresh(host.get('last_seen'), datetime.now(timezone.utc)):
                raise HTTPException(409, 'Power requires a configured physical-host identity, fresh online observations and independently signed agent transport')
        services = sorted([row for row in store.all('services') if row['host_id'] == hid], key=lambda row: row['id'])
        if not demo and any(row.get('status') not in ('running', 'stopped') or not fresh(row.get('observed_at'), datetime.now(timezone.utc)) for row in services):
            raise HTTPException(409, 'Observe every registered service before reviewing host power')
        return host, services

    def binding(host, services, profile):
        registered = {row['id'] for row in services}
        registry = store.all('services')
        impacted = set(registered)
        while True:
            extra = {row['id'] for row in registry if impacted.intersection(row.get('dependencies', []))} - impacted
            if not extra:
                break
            impacted.update(extra)
        dependents = sorted(row['id'] for row in registry if row['host_id'] != host['id'] and row['id'] in impacted)
        value = {'host': {key: host.get(key) for key in ('id', 'name', 'agent_url', 'token_env', 'signing_env', 'physical_host_id', 'os', 'active_os')},
                 'services': [{key: row.get(key) for key in ('id', 'name', 'revision', 'status', 'runtime', 'control_handle', 'component_ids')} for row in services],
                 'dependents': dependents, 'profile': profile}
        return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest(), dependents

    async def build(hid):
        host, services = context(hid)
        profile = {'fingerprint': 'demo', 'actions': {'suspend': [], 'shutdown': []}, 'os': host.get('active_os') or 'demo', 'physical_host_id': host.get('physical_host_id', ''), 'pending': None} if demo else await agent_request(host, 'GET', '/power/profile')
        if not isinstance(profile, dict) or not isinstance(profile.get('actions'), dict) or set(profile['actions']) - {'suspend', 'shutdown'} or not isinstance(profile.get('fingerprint'), str):
            raise HTTPException(502, 'Agent returned an invalid power profile')
        if profile.get('pending'):
            raise HTTPException(409, 'Agent has an unresolved power intent; inspect and reconcile it first')
        if not demo and (profile.get('physical_host_id', '') != host.get('physical_host_id', '') or profile.get('os') != host.get('active_os')):
            raise HTTPException(409, 'Power profile physical identity or active OS does not match this host')
        latest, observed = context(hid)
        fingerprint, dependents = binding(latest, observed, profile)
        if binding(host, services, profile)[0] != fingerprint:
            raise HTTPException(409, 'Host or services changed during the plan read')
        return {'host_id': hid, 'host_name': latest['name'], 'fingerprint': fingerprint, 'profile_fingerprint': profile['fingerprint'],
                'context_fingerprint': binding(latest, observed, {})[0],
                'actions': sorted(profile['actions']), 'affected': [{'id': row['id'], 'name': row['name'], 'status': row['status']} for row in observed],
                'external_dependents': dependents, 'demo': demo,
                'notice': 'Power affects every process and user session on this host, including unregistered applications. This list covers registered services only. Permission and physical sleep/shutdown behavior are unverified. No force-close or inhibitor bypass is used.'}

    @app.get('/api/v1/hosts/{hid}/power-plan')
    async def power_plan(hid: str):
        if busy(hid):
            raise HTTPException(409, 'Host has an active or unresolved operation')
        return await build(hid)

    @app.get('/api/v1/hosts/{hid}/power-status')
    def power_status(hid: str):
        require('hosts', hid)
        with store.connection() as db:
            return {'requests': [dict(row) for row in db.execute('SELECT * FROM power_requests WHERE host_id=? ORDER BY ts DESC LIMIT 20', (hid,))]}

    @app.post('/api/v1/hosts/{hid}/power')
    async def power_request(hid: str, body: PowerReview):
        if not body.confirmed:
            raise HTTPException(409, 'Confirm the host, registered services and impact on unregistered processes')
        selected = await build(hid)
        async with lock:
            current, services = context(hid)
            if busy(hid) or body.fingerprint != selected['fingerprint'] or body.action not in selected['actions'] or binding(current, services, {})[0] != selected['context_fingerprint']:
                raise HTTPException(409, 'Plan changed or the host is busy; review a fresh power plan')
            identifier = secrets.token_hex(16)
            with store.connection() as db:
                db.execute('INSERT INTO power_requests VALUES(?,?,?,?,?,?,?)', (identifier, hid, body.action, now(), 'unknown', 1, 'Intent recorded before dispatch; inspect host outcome'))
                db.execute('INSERT INTO operations VALUES(?,?,?,?,?,?)', (identifier, 'host:' + hid, 'host.' + body.action, 'running', now(), 'Confirmed host power plan'))
                store.audit('host.' + body.action, 'running', 'Confirmed affected-service plan; outcome unverified', host_id=hid, db=db)
        status, detail = 'unknown', 'Power outcome unverified; refresh observations and acknowledge inspection before any further writes'
        try:
            if not demo:
                result = await agent_request(current, 'POST', '/power', {'action': body.action, 'operation_id': identifier, 'fingerprint': selected['profile_fingerprint'], 'confirmed': True}, timeout=15)
                if not isinstance(result, dict) or result.get('operation_id') != identifier or result.get('status') != 'dispatched' or result.get('verified') is not False:
                    raise HTTPException(502, detail)
            status = 'simulated' if demo else 'dispatched'
            detail = 'Demo power action; no native command sent' if demo else detail
            return {'operation_id': identifier, 'status': status, 'verified': False, 'detail': detail, 'demo': demo}
        finally:
            # Neither an accepted command nor disconnect proves host power state.
            with store.connection() as db:
                db.execute('UPDATE power_requests SET status=?,active=?,detail=? WHERE id=?', (status, 0 if demo else 1, detail, identifier))
                db.execute('UPDATE operations SET status=?,detail=? WHERE id=?', (status, detail, identifier))
                if not demo:
                    host = require('hosts', hid); host.update(status='stale', error='Power request outcome unverified; awaiting fresh observations'); store.put('hosts', host, db=db)
                    for service in store.all('services'):
                        if service['host_id'] == hid:
                            service['status'] = 'unknown'; store.put('services', service, db=db)
                store.audit('host.' + body.action, status, detail, host_id=hid, db=db)

    @app.post('/api/v1/hosts/{hid}/power/acknowledge')
    async def acknowledge(hid: str, body: PowerAcknowledge):
        if not body.confirmed:
            raise HTTPException(409, 'Confirm you inspected this host and its services')
        host, services = context(hid)
        with store.connection() as db:
            row = db.execute('SELECT * FROM power_requests WHERE id=? AND host_id=? AND active=1', (body.operation_id, hid)).fetchone()
            in_flight = db.execute("SELECT 1 FROM operations WHERE id=? AND status='running'", (body.operation_id,)).fetchone()
        if in_flight:
            raise HTTPException(409, 'Power dispatch is still in flight; inspection acknowledgement must wait for its result')
        if not row or not demo and (host.get('last_seen', '') <= row['ts'] or any(service.get('observed_at', '') <= row['ts'] for service in services)):
            raise HTTPException(409, 'Fresh post-request host and service observations are required before acknowledgement')
        if not demo:
            result = await agent_request(host, 'POST', '/power/acknowledge', body.model_dump())
            if not isinstance(result, dict) or result.get('status') != 'acknowledged' or result.get('power_state_verified') is not False:
                raise HTTPException(502, 'Agent acknowledgement was not verified; the controller hold remains')
        async with lock:
            current, current_services = context(hid)
            if binding(host, services, {})[0] != binding(current, current_services, {})[0]:
                raise HTTPException(409, 'Host changed during acknowledgement; inspect again')
            with store.connection() as db:
                if db.execute('UPDATE power_requests SET active=0 WHERE id=? AND host_id=? AND active=1', (body.operation_id, hid)).rowcount != 1:
                    raise HTTPException(409, 'Power inspection was already acknowledged; reload its history')
                store.audit('host.power.acknowledged', 'success', 'Owner inspected fresh observations; historical power outcome remains unverified', host_id=hid, db=db)
        return {'status': 'acknowledged', 'power_state_verified': False}
