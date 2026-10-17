"""Separate local approval for persistent boot configuration; no elevation."""
import json
import hashlib
import platform
import sqlite3
import threading
import re
from pathlib import Path

from fastapi import HTTPException


def _plan(config, body, command):
    handle = body.handle
    if body.runtime == 'systemd':
        unit = handle.get('unit', '')
        if unit not in config.get('allow_boot_units', []) or unit.startswith('-') or not unit.endswith('.service'):
            raise HTTPException(403, 'Boot changes require exact local unit approval')
        current = command(['systemctl', 'show', '--property=UnitFileState', '--value', unit]).strip()
        if current not in ('enabled', 'disabled'):
            raise HTTPException(409, 'Only ordinary enabled/disabled units support this boot editor')
        return {'current': current, 'choices': ['enabled', 'disabled'], 'targets': [unit]}
    if body.runtime not in ('docker', 'compose'):
        raise HTTPException(409, 'Boot editing supports systemd and existing Docker/Compose containers')
    if body.runtime == 'docker':
        name = handle.get('container', '')
        if name not in config.get('allow_boot_containers', []) or not name or name.startswith('-'):
            raise HTTPException(403, 'Container boot changes require separate local approval')
        names = [name]
    else:
        project = handle.get('project', '')
        root = config.get('allow_boot_projects', {}).get(project)
        if not root or project.startswith('-') or Path(root).resolve() != Path(handle.get('path', '')).resolve():
            raise HTTPException(403, 'Compose boot changes require exact local project approval')
        names = command(['docker', 'compose', '--project-directory', str(Path(root).resolve()), '--project-name', project, 'ps', '-aq']).split()
        if not names or len(names) > 100 or any(not name.isalnum() for name in names):
            raise HTTPException(409, 'Inspect the existing Compose containers before boot changes')
    records = json.loads(command(['docker', 'inspect', *names]))
    if len(records) != len(names):
        raise HTTPException(409, 'Container inventory changed')
    if body.runtime == 'compose' and any((row.get('Config', {}).get('Labels') or {}).get('com.docker.compose.project') != project for row in records):
        raise HTTPException(409, 'Container no longer belongs to the approved project')
    identities = [row.get('Id', '') for row in records]
    if any(not isinstance(identifier, str) or not re.fullmatch(r'[a-f0-9]{64}', identifier) for identifier in identities) or len(set(identities)) != len(names):
        raise HTTPException(409, 'Container identity could not be verified')
    policies = {row['HostConfig']['RestartPolicy']['Name'] for row in records}
    return {'current': next(iter(policies)) if len(policies) == 1 else 'mixed',
            'choices': ['no', 'always', 'unless-stopped', 'on-failure'], 'targets': sorted(identities),
            'notice': 'Existing container restart policies only. Compose source is unchanged; recreation may replace this policy.'}


def plan(config, body, command):
    selected = _plan(config, body, command)
    selected['fingerprint'] = hashlib.sha256(json.dumps({'runtime':body.runtime,'handle':body.handle,'profile':selected},sort_keys=True).encode()).hexdigest()
    return selected


def change(config, body, command):
    selected = plan(config, body, command)
    if not body.confirmed or body.policy not in selected['choices'] or body.fingerprint != selected['fingerprint']:
        raise HTTPException(409, 'Confirm a supported boot policy')
    if body.runtime == 'systemd':
        command(['systemctl', '--no-ask-password', 'enable' if body.policy == 'enabled' else 'disable', selected['targets'][0]])
    else:
        command(['docker', 'update', '--restart=' + body.policy, *selected['targets']])
    observed = plan(config, body, command)
    return observed | {'verified': observed['current'] == body.policy and observed['targets'] == selected['targets']}


class Boot:
    def __init__(self,config,replay,command):
        self.config,self.replay,self.command=config,replay,command
        self.lock=threading.Lock()
        if replay:
            with self.db() as db:
                db.execute('CREATE TABLE IF NOT EXISTS boot_intents(id TEXT PRIMARY KEY,status TEXT NOT NULL,active INTEGER NOT NULL)')
                db.execute("UPDATE boot_intents SET status='unknown' WHERE status='running'")

    def db(self):
        if not self.replay:raise HTTPException(403,'Boot controls require signed transport and private durable state')
        return sqlite3.connect(self.replay.path,timeout=5)

    def plan(self,body):
        with self.db() as db:
            if db.execute('SELECT 1 FROM boot_intents WHERE active=1').fetchone():raise HTTPException(409,'Inspect the previous boot operation before another change')
        return plan(self.config,body,self.command)|{'physical_host_id':self.config.get('physical_host_id',''),'os':platform.system()}

    def change(self,body):
        selected=self.plan(body)
        if not body.confirmed or selected['fingerprint']!=body.fingerprint or body.policy not in selected['choices']:raise HTTPException(409,'Confirm the current boot plan')
        with self.lock,self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT 1 FROM boot_intents WHERE active=1').fetchone():raise HTTPException(409,'A boot intent is already active')
            try:db.execute("INSERT INTO boot_intents VALUES(?,'running',1)",(body.operation_id,))
            except sqlite3.IntegrityError:raise HTTPException(409,'Boot intent was already used; replay refused')
        outcome='unknown'
        try:
            result=change(self.config,body,self.command)
            if not result['verified']:raise HTTPException(409,'Inspect unverified boot policy before retrying')
            outcome='success'
            return result
        finally:
            with self.db() as db:db.execute('UPDATE boot_intents SET status=?,active=? WHERE id=?',(outcome,int(outcome!='success'),body.operation_id))

    def acknowledge(self,body):
        if not body.confirmed:raise HTTPException(409,'Inspect startup persistence before releasing its hold')
        with self.lock,self.db() as db:
            row=db.execute('SELECT status FROM boot_intents WHERE id=?',(body.operation_id,)).fetchone()
            if row and row[0]=='running':raise HTTPException(409,'Boot dispatch is still in flight')
            if row:db.execute('UPDATE boot_intents SET active=0 WHERE id=?',(body.operation_id,))
            else:db.execute("INSERT INTO boot_intents VALUES(?,'acknowledged',0)",(body.operation_id,))
        return {'status':'acknowledged','outcome_verified':False}
