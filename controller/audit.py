"""Durable authenticated write intents without bodies, query strings or secrets."""
import uuid

from starlette.routing import Match
from controller.store import now


class AuditJournal:
    def __init__(self, app, store):
        self.app, self.store = app, store
        with store.connection() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS request_audit(
                id TEXT PRIMARY KEY,started_at TEXT NOT NULL,finished_at TEXT,method TEXT NOT NULL,
                route TEXT NOT NULL,service_id TEXT,host_id TEXT,status TEXT NOT NULL,http_status INTEGER)''')

    def recover(self):
        with self.store.connection() as db:
            db.execute("UPDATE request_audit SET status='unknown',finished_at=? WHERE status='running'", (now(),))

    def rows(self, sid=None):
        with self.store.connection() as db:
            if sid:
                return [dict(row) for row in db.execute('SELECT * FROM request_audit WHERE service_id=? ORDER BY started_at DESC LIMIT 200', (sid,))]
            return [dict(row) for row in db.execute('SELECT * FROM request_audit ORDER BY started_at DESC LIMIT 200')]

    async def run(self, request, call_next):
        if request.method not in ('POST', 'PUT', 'PATCH', 'DELETE') or not request.url.path.startswith('/api/v1/'):
            return await call_next(request)
        selected, parameters = None, {}
        for route in self.app.routes:
            match, child = route.matches(request.scope)
            if match == Match.FULL:
                selected, parameters = route, child.get('path_params', {})
                break
        if selected is None:
            return await call_next(request)
        sid, hid = parameters.get('sid'), parameters.get('hid')
        service = self.store.get('services', sid) if isinstance(sid, str) else None
        host = self.store.get('hosts', hid) if isinstance(hid, str) else None
        sid = service['id'] if service else None
        hid = host['id'] if host else service['host_id'] if service else None
        identifier = uuid.uuid4().hex
        # Persist before body validation and action. Never store caller paths,
        # query strings, body fields, authentication or exception text.
        with self.store.connection() as db:
            db.execute('INSERT INTO request_audit VALUES(?,?,?,?,?,?,?,?,?)',
                       (identifier, now(), None, request.method, selected.path, sid, hid, 'running', None))
        result, response = 'unknown', None
        try:
            response = await call_next(request)
            result = 'accepted' if response.status_code < 400 else 'refused' if response.status_code < 500 else 'unknown'
            response.headers['X-PSC-Request-ID'] = identifier
            return response
        finally:
            with self.store.connection() as db:
                db.execute('UPDATE request_audit SET status=?,finished_at=?,http_status=? WHERE id=?',
                           (result, now(), response.status_code if response else None, identifier))
