"""Fixed, explicitly opted-in OS power requests with durable uncertainty holds."""
import hashlib
import json
import platform
import sqlite3
import os
import threading
from pathlib import Path

from fastapi import HTTPException
from agent.terminal import ordinary_account


def windows_suspend():
    import ctypes
    library = ctypes.WinDLL(r'C:\Windows\System32\powrprof.dll', use_last_error=True)
    function = library.SetSuspendState
    function.argtypes = [ctypes.c_ubyte, ctypes.c_ubyte, ctypes.c_ubyte]
    function.restype = ctypes.c_ubyte
    if not function(0, 0, 0):  # sleep; no force; preserve wake events
        raise OSError('Windows refused the non-forced suspend request')


def profile(config):
    system = platform.system()
    # No forced application closure, privilege escalation or inhibitor bypass.
    choices = {'Linux': {'suspend': ['/usr/bin/systemctl', '--no-ask-password', 'suspend'],
                         'shutdown': ['/usr/bin/systemctl', '--no-ask-password', 'poweroff']},
               'Darwin': {'suspend': ['/usr/bin/pmset', 'sleepnow'],
                          'shutdown': ['/usr/bin/osascript', '-e', 'tell application "System Events" to shut down']},
               'Windows': {'shutdown': ['C:\\Windows\\System32\\shutdown.exe', '/s', '/t', '0'],
                           'suspend': ['C:\\Windows\\System32\\powrprof.dll', 'SetSuspendState(0,0,0)']}}
    approved = config.get('power_actions', [])
    if not isinstance(approved, list) or any(action not in ('suspend', 'shutdown') for action in approved):
        raise HTTPException(409, 'Invalid local power action approval')
    actions = {action: choices.get(system, {})[action] for action in approved if action in choices.get(system, {})}
    if not ordinary_account():
        raise HTTPException(403, 'Power requests refuse root or elevated administrator agents')
    scope = 'host'
    if system == 'Darwin' and 'shutdown' in actions:
        scope = config.get('macos_power_domain', '')
        if not hasattr(os, 'getuid') or scope != 'gui/' + str(os.getuid()):
            raise HTTPException(403, 'macOS shutdown requires an explicitly approved current-user GUI domain')
    value = {'os': system, 'physical_host_id': config.get('physical_host_id', ''), 'actions': actions, 'scope': scope}
    return value | {'fingerprint': hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()}


class Power:
    def __init__(self, config, replay, command):
        self.config, self.replay, self.command = config, replay, command
        self.lock, self.in_flight = threading.Lock(), set()
        if replay:
            with sqlite3.connect(replay.path) as db:
                db.execute('CREATE TABLE IF NOT EXISTS power_intents(id TEXT PRIMARY KEY,action TEXT NOT NULL,status TEXT NOT NULL)')

    def db(self):
        if not self.replay or self.replay.path.is_symlink() or not self.replay.path.is_file():
            raise HTTPException(403, 'Power controls require signed requests and safe durable replay state')
        return sqlite3.connect(self.replay.path, timeout=2)

    def plan(self):
        with self.lock, self.db() as db:
            pending = db.execute("SELECT id FROM power_intents WHERE status!='acknowledged'").fetchone()
        return profile(self.config) | {'pending': pending[0] if pending else None, 'permissions_verified': False}

    def request(self, body):
        plan = self.plan()
        if not body.confirmed or body.fingerprint != plan['fingerprint'] or body.action not in plan['actions']:
            raise HTTPException(409, 'Power profile changed, is not approved or needs confirmation')
        if plan['pending']:
            raise HTTPException(409, 'Previous power outcome is unresolved; never retry automatically')
        if not Path(plan['actions'][body.action][0]).is_file():
            raise HTTPException(409, 'Fixed native power executable is unavailable')
        with self.lock, self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute("SELECT 1 FROM power_intents WHERE status!='acknowledged'").fetchone():
                raise HTTPException(409, 'Another power request is unresolved')
            try:
                db.execute('INSERT INTO power_intents VALUES(?,?,?)', (body.operation_id, body.action, 'unknown'))
            except sqlite3.IntegrityError:
                raise HTTPException(409, 'Power operation IDs cannot be reused')
            self.in_flight.add(body.operation_id)
        # Intent commits before dispatch. A crash, timeout or host disappearance
        # retains the hold and cannot cause automatic replay.
        try:
            if profile(self.config)['fingerprint'] != plan['fingerprint']:
                raise HTTPException(409, 'Local power profile changed before dispatch')
            if plan['os'] == 'Windows' and body.action == 'suspend':
                windows_suspend()
            else:
                self.command(plan['actions'][body.action], timeout=10)
        except (HTTPException, OSError):
            raise HTTPException(503, 'Power request did not return a verified result; inspect the host before any retry')
        finally:
            with self.lock:
                self.in_flight.discard(body.operation_id)
        return {'status': 'dispatched', 'verified': False, 'operation_id': body.operation_id}

    def acknowledge(self, body):
        if not body.confirmed:
            raise HTTPException(409, 'Explicit inspection acknowledgement is required')
        with self.lock, self.db() as db:
            if self.in_flight:
                raise HTTPException(409, 'Power dispatch is in flight; inspection acknowledgement must wait')
            if not db.execute('SELECT 1 FROM power_intents WHERE id=?', (body.operation_id,)).fetchone():
                # Tombstone an unreceived request so a delayed original cannot
                # execute after the owner's inspection clears controller holds.
                db.execute('INSERT INTO power_intents VALUES(?,?,?)', (body.operation_id, 'unreceived', 'acknowledged'))
            else:
                db.execute("UPDATE power_intents SET status='acknowledged' WHERE id=?", (body.operation_id,))
        return {'status': 'acknowledged', 'power_state_verified': False}
