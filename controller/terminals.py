"""Controller-owned terminal tickets, service reservations and opt-in masked recordings."""
import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import tempfile
from pathlib import Path
from collections import deque
from datetime import datetime
from urllib.parse import urlencode

from fastapi import HTTPException, Request, WebSocket, WebSocketDisconnect
from pydantic import Field
from controller.login import COOKIE
from controller.store import now
from shared.streams import LineMask
from shared.models import StrictModel, redact, TerminalInput


class Open(StrictModel):
    profile: str = Field(pattern=r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$')
    fingerprint: str = Field(pattern=r'^[a-f0-9]{64}$')
    confirmed: bool = False
    recording: bool = False
    snapshots: bool = False
    name: str = Field(default='Installation session', min_length=1, max_length=100)


class Recording:
    def __init__(self, save):
        self.save, self.pending, self.mask = save, {'input': '', 'output': ''}, LineMask()
        self.sensitive, self.bytes, self.entries = False, 0, 0

    def feed(self, direction, content, final=False):
        if direction == 'output' and re.search(r'(?i)(password|passphrase|token|secret)\s*[:?]\s*$', (self.pending[direction] + content)[-250:]):
            self.sensitive = True
        text = self.pending[direction] + content
        if len(text) > 65536:
            self.pending[direction] = ''
            if self.entries < 5000:
                self.save(direction, '[Oversized recording line omitted]\n')
                self.entries += 1
            return
        pieces = text.splitlines(keepends=True)
        self.pending[direction] = ''
        for index, piece in enumerate(pieces):
            complete = piece.endswith(('\n', '\r')) or final
            if not complete and index == len(pieces) - 1:
                self.pending[direction] = piece
                continue
            # Remove OSC/CSI/control sequences before masking and persistent use.
            clean = re.sub(r'\x1b\][^\x07]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]', '', piece)
            clean = re.sub(r'[\x00-\x08\x0b-\x1f\x7f\u202a-\u202e\u2066-\u2069]', '', clean)
            if direction == 'input' and self.sensitive:
                clean, self.sensitive = '[Sensitive prompt input omitted]\n', False
            clean = self.mask.apply(clean)
            size = len(clean.encode())
            if self.bytes + size <= 500000 and self.entries < 5000:
                self.save(direction, clean)
                self.bytes += size
                self.entries += 1

    def finish(self):
        for direction in self.pending:
            self.feed(direction, '', final=True)

    def resize(self, rows, cols):
        if self.entries < 5000:
            self.save('resize', str(cols) + 'x' + str(rows))
            self.entries += 1


class Terminals:
    def __init__(self, app, store, demo, require, lock, busy, request_agent, origins, hosts, login, token):
        self.store, self.demo, self.require, self.lock, self.busy, self.agent = store, demo, require, lock, busy, request_agent
        self.origins, self.hosts, self.login, self.token = origins, hosts, login, token
        self.sessions = {}
        from controller.installation import InstallationReview
        with store.connection() as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS terminal_sessions(id TEXT PRIMARY KEY,service_id TEXT NOT NULL,host_id TEXT NOT NULL,started_at TEXT NOT NULL,ended_at TEXT,status TEXT NOT NULL,profile TEXT NOT NULL,recording INTEGER NOT NULL,detail TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS terminal_recording(id INTEGER PRIMARY KEY,session_id TEXT NOT NULL,ts TEXT NOT NULL,direction TEXT NOT NULL,content TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS terminal_recording_session ON terminal_recording(session_id,id);''')
            if 'name' not in {row['name'] for row in db.execute('PRAGMA table_info(terminal_sessions)')}:
                db.execute("ALTER TABLE terminal_sessions ADD COLUMN name TEXT NOT NULL DEFAULT 'Installation session'")
            db.execute("UPDATE terminal_sessions SET ended_at=?,status='unknown',detail='Controller restarted; remote lease cleanup is unverified until expiry' WHERE status IN ('pending','running')", (now(),))
        self.installation = InstallationReview(app, self)
        self.register(app)

    async def profiles(self, sid):
        service = self.require('services', sid)
        host = self.require('hosts', service['host_id'])
        if host.get('status') != 'online':
            raise HTTPException(409, 'Terminal requires a currently online host')
        if self.demo:
            return {'profiles': [{'id': 'demo', 'label': 'Synthetic terminal', 'cwd': (service.get('paths') or ['/demo'])[0], 'fingerprint': '0' * 64}], 'demo': True}
        if not host.get('signing_env'):
            raise HTTPException(403, 'Interactive terminals require signed agent requests')
        reference = service.get('agent_ref') or service.get('control_handle', {}).get('agent_ref', '')
        result = await self.agent(host, 'GET', '/terminal/profiles?' + urlencode({'ref': reference}))
        if not isinstance(result, dict) or result.get('os') not in ('Linux', 'Darwin', 'Windows') or host.get('active_os') and host['active_os'] != result.get('os') or host.get('physical_host_id') and result.get('physical_host_id') != host['physical_host_id']:
            raise HTTPException(409, 'Terminal agent identity or OS differs from this host')
        rows = result.get('profiles')
        if not isinstance(rows, list) or len(rows) > 10:
            raise HTTPException(502, 'Invalid terminal profile inventory')
        clean = []
        for row in rows:
            if not isinstance(row, dict) or any(not isinstance(row.get(key), str) for key in ('id', 'label', 'cwd', 'fingerprint')) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}', row['id']) or not re.fullmatch(r'[a-f0-9]{64}', row['fingerprint']) or len(row['cwd']) > 1024:
                raise HTTPException(502, 'Invalid terminal profile metadata')
            clean.append({key: redact(row[key]) for key in ('id', 'label', 'cwd', 'fingerprint')})
        return {'profiles': clean, 'demo': False}

    def owner(self, request):
        cookie = request.cookies.get(COOKIE)
        if self.login.authorized(cookie):
            return ('cookie', cookie)
        bearer = request.headers.get('authorization', '').removeprefix('Bearer ')
        if self.token and hmac.compare_digest(bearer.encode(), self.token.encode()):
            return ('token', hashlib.sha256(self.token.encode()).hexdigest())
        return ('local', request.client.host if request.client else '')

    def valid_owner(self, item, socket):
        kind, value = item['owner']
        if kind == 'cookie':
            return socket.cookies.get(COOKIE) == value and self.login.authorized(value)
        if kind == 'token':
            return bool(self.token and hmac.compare_digest(value, hashlib.sha256(self.token.encode()).hexdigest()))
        return bool(socket.client and socket.client.host == value and value in ('127.0.0.1', '::1', 'testclient'))

    def bound(self, item):
        service, host = self.require('services', item['service']['id']), self.require('hosts', item['host']['id'])
        if host.get('status') != 'online' or any(service.get(key) != item['service'].get(key) for key in ('host_id', 'revision', 'control_handle', 'agent_ref')) or any(host.get(key) != item['host'].get(key) for key in ('agent_url', 'token_env', 'signing_env', 'active_os', 'physical_host_id')):
            raise HTTPException(409, 'Terminal service, identity or host connection changed; session closed')

    def cast_text(self, sid, identifier):
        with self.store.connection() as db:
            session = db.execute('SELECT * FROM terminal_sessions WHERE service_id=? AND id=?', (sid, identifier)).fetchone()
            if not session:
                raise HTTPException(404, 'Terminal session does not belong to this service')
            entries = db.execute('SELECT ts,direction,content FROM terminal_recording WHERE session_id=? ORDER BY id LIMIT 5000', (identifier,)).fetchall()
        if not session['recording']:
            raise HTTPException(409, 'Content was not recorded for this session')
        if session['status'] == 'reconstructed':
            raise HTTPException(409, 'Imported history has no terminal output recording; export unverified instructions instead')
        started = datetime.fromisoformat(session['started_at'])
        header = {'version': 2, 'width': 80, 'height': 24, 'timestamp': int(started.timestamp()), 'title': ('[DEMO] ' if self.demo else '') + redact(session['name']) + ' (masked, normalized recording)', 'idle_time_limit': 2, 'env': {'TERM': 'xterm-256color'}}
        lines, previous = [json.dumps(header)], 0.0
        for entry in entries:
            if entry['direction'] not in ('output', 'resize'):
                continue
            offset = max(previous, (datetime.fromisoformat(entry['ts']) - started).total_seconds(), 0)
            lines.append(json.dumps([round(offset, 6), 'r' if entry['direction'] == 'resize' else 'o', entry['content']], ensure_ascii=True))
            previous = offset
        return '\n'.join(lines) + '\n'

    def store_cast(self, sid, identifier):
        if not re.fullmatch(r'[a-f0-9]{32}', identifier):
            raise OSError('Invalid recording artifact identity')
        root = self.store.root / 'recordings'
        if any(part.is_symlink() for part in (root, *root.parents)):
            raise OSError('Recording storage cannot traverse symlinks')
        root.mkdir(mode=0o700, exist_ok=True)
        destination = root / (identifier + '.cast')
        if destination.exists() or destination.is_symlink():
            raise OSError('Recording artifact already exists; it was not overwritten')
        content = self.cast_text(sid, identifier).encode()
        if len(content) > 4_000_000:
            raise OSError('Recording artifact exceeds supported size')
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=root, prefix='.cast-', delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, destination)
            temporary = None
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    async def close(self, identifier, reason='Terminal closed'):
        item = self.sessions.get(identifier)
        if not item or item.get('closing'):
            return
        item['closing'] = True
        uncertain = False
        try:
            if item.get('agent_id') and not self.demo:
                try:
                    await self.agent(item['host'], 'POST', '/terminal/' + item['agent_id'] + '/close', {}, timeout=5)
                except (HTTPException, OSError):
                    uncertain = True
            if item.get('recorder'):
                item['recorder'].finish()
                if not uncertain:
                    await self.installation.capture(identifier, 'after', item)
                try:
                    self.store_cast(item['service']['id'], identifier)
                    self.store.audit('recording.saved', 'success', 'Stored bounded masked asciicast v2 recording', item['service']['id'], item['host']['id'])
                except OSError:
                    self.store.audit('recording.saved', 'failed', 'Cast artifact could not be stored; masked JSON transcript remains available', item['service']['id'], item['host']['id'])
            with self.store.connection() as db:
                status = 'unknown' if uncertain else 'closed'
                db.execute('UPDATE operations SET status=?,detail=? WHERE id=?', (status, reason, identifier))
                db.execute('UPDATE terminal_sessions SET ended_at=?,status=?,detail=? WHERE id=?', (now(), status, reason, identifier))
                self.store.audit('terminal.end', status, reason + ('; remote lease cleanup is unverified and expires after missed polling' if uncertain else ''), item['service']['id'], item['host']['id'], db=db)
            if not self.demo and item.get('agent_id'):
                async with self.lock:
                    for service in self.store.all('services'):
                        if service['host_id'] == item['host']['id']:
                            service.update(status='unknown', capabilities={'control': False, 'logs': False, 'files': False})
                            self.store.put('services', service)
        finally:
            self.sessions.pop(identifier, None)

    async def sweep(self):
        for identifier, item in list(self.sessions.items()):
            if not item['attached'] and time.monotonic() - item['created'] > 30:
                await self.close(identifier, 'Unused terminal ticket expired')

    async def close_all(self):
        for identifier in list(self.sessions):
            await self.close(identifier, 'Controller shutting down')

    def register(self, app):
        @app.get('/api/v1/services/{sid}/terminal/profiles')
        async def profiles(sid: str):
            return await self.profiles(sid)

        @app.post('/api/v1/services/{sid}/terminal/open')
        async def open_terminal(sid: str, body: Open, request: Request):
            if not body.confirmed:
                raise HTTPException(409, 'Confirm the terminal account, working directory and recording choice first')
            if redact(body.name) != body.name:
                raise HTTPException(422, 'Installation session names cannot contain secret values')
            before = self.require('services', sid)
            before_host = self.require('hosts', before['host_id'])
            if not self.demo and os.environ.get('PSC_TERMINAL_REAUTH', '') == '1' and not self.login.recent(request.cookies.get(COOKIE), 300):
                raise HTTPException(401, 'Terminal policy requires a password/TOTP login within the last five minutes')
            profiles = await self.profiles(sid)
            selected = next((row for row in profiles['profiles'] if row['id'] == body.profile and row['fingerprint'] == body.fingerprint), None)
            if not selected:
                raise HTTPException(409, 'Terminal profile changed; refresh and review it again')
            async with self.lock:
                self.bound({'service': before, 'host': before_host})
                service = self.require('services', sid)
                host = self.require('hosts', service['host_id'])
                if host.get('status') != 'online' or self.busy(host['id']) or len(self.sessions) >= 4:
                    raise HTTPException(409, 'Terminal host must be online/free; controller permits at most four sessions')
                identifier, ticket = secrets.token_hex(16), secrets.token_urlsafe(32)
                item = {'service': service, 'host': host, 'profile': selected, 'owner': self.owner(request), 'ticket': hashlib.sha256(ticket.encode()).hexdigest(), 'created': time.monotonic(), 'attached': False, 'recording': body.recording, 'snapshots': body.recording and body.snapshots}
                self.sessions[identifier] = item
                with self.store.connection() as db:
                    db.execute('INSERT INTO operations VALUES(?,?,?,?,?,?)', (identifier, sid, 'terminal.session', 'running', now(), 'Awaiting single-use terminal ticket'))
                    db.execute('INSERT INTO terminal_sessions(id,service_id,host_id,started_at,ended_at,status,profile,recording,detail,name) VALUES(?,?,?,?,?,?,?,?,?,?)', (identifier, sid, host['id'], now(), None, 'pending', selected['id'], int(body.recording), '', body.name))
                return {'id': identifier, 'ticket': ticket, 'profile': selected, 'recording': body.recording, 'demo': self.demo}

        @app.get('/api/v1/services/{sid}/terminal/sessions')
        def history(sid: str):
            self.require('services', sid)
            with self.store.connection() as db:
                return [dict(row) for row in db.execute('SELECT * FROM terminal_sessions WHERE service_id=? ORDER BY started_at DESC LIMIT 100', (sid,))]

        @app.get('/api/v1/services/{sid}/terminal/sessions/{identifier}')
        def recording(sid: str, identifier: str):
            self.require('services', sid)
            with self.store.connection() as db:
                row = db.execute('SELECT * FROM terminal_sessions WHERE service_id=? AND id=?', (sid, identifier)).fetchone()
                if not row:
                    raise HTTPException(404, 'Terminal session does not belong to this service')
                rows = [dict(row) for row in db.execute('SELECT ts,direction,content FROM terminal_recording WHERE session_id=? ORDER BY id LIMIT 10000', (identifier,))]
            return {'session': dict(row), 'entries': rows, 'notice': 'Opt-in masked transcript; incomplete installation evidence, not verified reinstall instructions'}

        @app.post('/api/v1/services/{sid}/terminal/sessions/{identifier}/close')
        async def close(sid: str, identifier: str, request: Request):
            item = self.sessions.get(identifier)
            if not item or item['service']['id'] != sid or self.owner(request) != item['owner']:
                raise HTTPException(404, 'No active terminal session owned by this caller')
            await self.close(identifier, 'Owner closed terminal')
            return {'closed': True}

        @app.get('/api/v1/services/{sid}/terminal/sessions/{identifier}/cast')
        def cast(sid: str, identifier: str):
            from fastapi.responses import Response
            value = recording(sid, identifier)
            session = value['session']
            if not session['recording']:
                raise HTTPException(409, 'Content was not recorded for this session')
            content = self.cast_text(sid, identifier)
            self.store.audit('recording.export', 'success', 'Exported masked normalized asciicast v2 output', sid, session['host_id'])
            return Response(content, media_type='application/x-asciicast', headers={'Content-Disposition': 'attachment; filename="' + sid + '-installation.cast"'})

        @app.websocket('/api/v1/services/{sid}/terminal/sessions/{identifier}/ws')
        async def socket(socket: WebSocket, sid: str, identifier: str):
            item = self.sessions.get(identifier)
            if not item or item['service']['id'] != sid or item['attached'] or time.monotonic() - item['created'] > 30 or socket.url.hostname not in self.hosts or socket.headers.get('origin') and socket.headers['origin'] not in self.origins or not self.valid_owner(item, socket) or socket.scope.get('query_string'):
                await socket.close(code=1008)
                return
            reason, receiver = 'Terminal disconnected', None
            try:
                await socket.accept()
                raw = await asyncio.wait_for(socket.receive_text(), timeout=5)
                if len(raw) > 512:
                    raise HTTPException(403, 'Invalid terminal ticket')
                proof = json.loads(raw)
                if not isinstance(proof, dict) or not isinstance(proof.get('ticket'), str) or not hmac.compare_digest(hashlib.sha256(proof['ticket'].encode()).hexdigest(), item['ticket']):
                    raise HTTPException(403, 'Invalid terminal ticket')
                self.bound(item)
                item['attached'], item['ticket'] = True, ''
                await self.installation.capture(identifier, 'before', item)
                self.bound(item)
                if not self.demo:
                    opened = await self.agent(item['host'], 'POST', '/terminal/open', {'ref': item['service'].get('agent_ref') or item['service'].get('control_handle', {}).get('agent_ref', ''), 'profile': item['profile']['id'], 'fingerprint': item['profile']['fingerprint'], 'confirmed': True})
                    if not isinstance(opened, dict) or not isinstance(opened.get('id'), str) or not re.fullmatch(r'[a-f0-9]{32}', opened['id']):
                        raise HTTPException(502, 'Invalid agent terminal lease')
                    item['agent_id'] = opened['id']
                def save(direction, content):
                    with self.store.connection() as db:
                        db.execute('INSERT INTO terminal_recording(session_id,ts,direction,content) VALUES(?,?,?,?)', (identifier, now(), direction, content))
                item['recorder'] = Recording(save) if item['recording'] else None
                with self.store.connection() as db:
                    db.execute("UPDATE terminal_sessions SET status='running' WHERE id=?", (identifier,))
                    self.store.audit('terminal.start', 'success', ('Synthetic terminal' if self.demo else 'Confirmed ordinary agent account terminal') + ('; masked recording enabled' if item['recording'] else '; content recording disabled'), sid, item['host']['id'], db=db)
                await socket.send_json({'kind': 'ready', 'demo': self.demo, 'recording': item['recording']})
                if self.demo:
                    await socket.send_json({'kind': 'output', 'content': 'Synthetic terminal: typed commands are displayed but never executed.\r\n$ '})
                receiver = asyncio.create_task(socket.receive_text())
                last_input, deadline, frames = time.monotonic(), time.monotonic() + 3600, deque()
                input_bytes, output_bytes = 0, 0
                while identifier in self.sessions and time.monotonic() < deadline and time.monotonic() - last_input < 900:
                    self.bound(item)
                    if not self.valid_owner(item, socket):
                        reason = 'Owner authentication expired or revoked'
                        break
                    done, _ = await asyncio.wait([receiver], timeout=.25)
                    if receiver in done:
                        raw = receiver.result()
                        if len(raw.encode()) > 20000:
                            raise HTTPException(413, 'Terminal frame is too large')
                        frame = json.loads(raw)
                        if isinstance(frame, dict) and frame.get('kind') == 'close':
                            reason = 'Owner closed terminal'
                            break
                        body = TerminalInput.model_validate(frame)
                        input_bytes += len(body.data.encode())
                        if len(body.data.encode()) > 8192 or input_bytes > 256000:
                            raise HTTPException(413, 'Terminal input limit reached')
                        stamp = time.monotonic()
                        while frames and frames[0] < stamp - 1:
                            frames.popleft()
                        if len(frames) >= 60:
                            raise HTTPException(429, 'Terminal input rate limit reached')
                        frames.append(stamp)
                        if body.data:
                            last_input = stamp
                            if item['recorder']:
                                item['recorder'].feed('input', body.data)
                        if not self.demo:
                            await self.agent(item['host'], 'POST', '/terminal/' + item['agent_id'] + '/input', body.model_dump(exclude_none=True))
                        elif body.data:
                            output = body.data + ('\r\n[DEMO] Command not executed.\r\n$ ' if '\r' in body.data or '\n' in body.data else '')
                            output_bytes += len(output.encode())
                            if output_bytes > 2_000_000:
                                raise HTTPException(413, 'Terminal output limit reached')
                            await socket.send_json({'kind': 'output', 'content': output})
                            if item['recorder']:
                                item['recorder'].feed('output', output)
                        if body.rows is not None and item['recorder']:
                            item['recorder'].resize(body.rows, body.cols)
                        receiver = asyncio.create_task(socket.receive_text())
                    if not self.demo:
                        result = await self.agent(item['host'], 'GET', '/terminal/' + item['agent_id'] + '/output', timeout=5)
                        if not isinstance(result, dict) or not isinstance(result.get('content'), str) or len(result['content'].encode()) > 65536:
                            raise HTTPException(502, 'Invalid terminal output frame')
                        if result['content']:
                            output_bytes += len(result['content'].encode())
                            if output_bytes > 2_000_000:
                                raise HTTPException(413, 'Terminal output limit reached')
                            await socket.send_json({'kind': 'output', 'content': result['content']})
                            if item['recorder']:
                                item['recorder'].feed('output', result['content'])
                        if result.get('ended'):
                            reason = str(result.get('reason') or 'Agent terminal ended')[:200]
                            break
                else:
                    reason = 'Terminal timeout or lease ended'
            except (HTTPException, ValueError, OSError, WebSocketDisconnect, asyncio.TimeoutError):
                reason = 'Terminal disconnected or safety check failed; inspect state before retrying'
            finally:
                if receiver:
                    receiver.cancel()
                    await asyncio.gather(receiver, return_exceptions=True)
                await self.close(identifier, reason)
                try:
                    await socket.send_json({'kind': 'end', 'detail': reason})
                    await socket.close()
                except (RuntimeError, WebSocketDisconnect):
                    pass
