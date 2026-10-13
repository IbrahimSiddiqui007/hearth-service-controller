"""Reviewed installation evidence and history import; never executes commands."""
import hashlib
import json
import re
from typing import Literal

from fastapi import HTTPException
from fastapi.responses import Response
from pydantic import Field, ConfigDict
from shared.models import StrictModel, redact
from shared.configuration import secret_reasons
from controller.store import now


class HistoryImport(StrictModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=False)
    shell: Literal['bash', 'zsh', 'fish']
    content: str = Field(max_length=500000)
    name: str = Field(default='Reconstructed installation', min_length=1, max_length=100)
    confirmed: bool = False


class Review(StrictModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=False)
    revision: int = Field(ge=0)
    excluded: list[str] = Field(default_factory=list, max_length=500)
    instructions: str = Field(default='', max_length=100000)
    approved: bool = False


def history_commands(shell, text):
    if len(text.encode()) > 500000 or '\0' in text:
        raise HTTPException(413, 'History import requires bounded UTF-8 text')
    commands = []
    pending = ''
    for line in text.splitlines()[:10000]:
        if shell == 'fish':
            if not line.startswith('- cmd: '):
                continue
            command = line[7:].replace('\\n', '\n').replace('\\\\', '\\')
        else:
            if shell == 'bash' and re.fullmatch(r'#\d{9,}', line):
                continue
            command = re.sub(r'^: \d+:\d+;', '', line) if shell == 'zsh' else line
            pending += command
            if pending.endswith('\\'):
                pending = pending[:-1] + '\n'
                if len(pending) > 8192:
                    pending = ''
                continue
            command, pending = pending, ''
        if command.strip() and len(command) <= 8192:
            commands.append(command)
    return commands


def relevant(service, commands):
    terms = [service.get('name', ''), service.get('id', ''), service.get('image', '')]
    terms += service.get('paths', [])
    terms += [str(port).split('/')[0] for port in service.get('ports', [])]
    locations = service.get('locations') or {}
    terms += locations.get('configuration', []) + locations.get('data', [])
    if locations.get('working_directory'):
        terms.append(locations['working_directory'])
    terms = [term.casefold() for term in terms if isinstance(term, str) and len(term) >= 3 and len(term) <= 1024 and not secret_reasons(term)]
    found = []
    for index, command in enumerate(commands):
        matches = [term for term in terms if re.search(r'(?<![\w])' + re.escape(term) + r'(?![\w])', command.casefold())]
        if not matches:
            continue
        # Omit suspected secret-bearing commands entirely, before persistent use.
        if secret_reasons(command) or redact(command) != command:
            continue
        clean = re.sub(r'[\x00-\x08\x0b-\x1f\x7f\u202a-\u202e\u2066-\u2069]', '', command)
        found.append({'id': str(index), 'command': clean, 'matches': matches[:10], 'verified': False})
        if len(found) == 500:
            break
    return found


def differences(before, after):
    changes, gaps = [], []
    for name in sorted(set(before.get('categories', {})) | set(after.get('categories', {}))):
        first, last = before.get('categories', {}).get(name, {}), after.get('categories', {}).get(name, {})
        complete = bool(first.get('complete') and last.get('complete') and first.get('scope') == last.get('scope') and first.get('roots') == last.get('roots'))
        if not complete:
            gaps.append(name + ': incomplete or different scope; missing entries are not removals')
        old, new = {row['id']: row for row in first.get('rows', [])}, {row['id']: row for row in last.get('rows', [])}
        for key in sorted(set(old) | set(new)):
            kind = 'added' if key not in old else 'removed' if key not in new else 'changed'
            if kind == 'removed' and not complete or key in old and key in new and old[key].get('value') == new[key].get('value'):
                continue
            row = new.get(key, old.get(key))
            identity = hashlib.sha256((name + '\0' + kind + '\0' + key).encode()).hexdigest()
            changes.append({'id': identity, 'category': name, 'kind': kind, 'name': row.get('name', key), 'verified_scope': complete, 'before': old.get(key), 'after': new.get(key)})
            if len(changes) >= 500:
                gaps.append('Change limit reached')
                return changes, gaps
    return changes, gaps


class InstallationReview:
    def __init__(self, app, terminals):
        self.terminal, self.store = terminals, terminals.store
        with self.store.connection() as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS installation_snapshots(session_id TEXT NOT NULL,phase TEXT NOT NULL,ts TEXT NOT NULL,body TEXT NOT NULL,PRIMARY KEY(session_id,phase));
                CREATE TABLE IF NOT EXISTS installation_reviews(session_id TEXT PRIMARY KEY,revision INTEGER NOT NULL,body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS installation_history(session_id TEXT PRIMARY KEY,body TEXT NOT NULL);''')
        self.register(app)

    def session(self, sid, identifier):
        self.terminal.require('services', sid)
        with self.store.connection() as db:
            row = db.execute('SELECT * FROM terminal_sessions WHERE service_id=? AND id=?', (sid, identifier)).fetchone()
        if not row or not row['recording']:
            raise HTTPException(404, 'No recorded installation belongs to this service')
        return dict(row)

    def save_snapshot(self, identifier, phase, body):
        # Treat agent responses as untrusted: bounded structure and secret-free metadata only.
        raw = json.dumps(body, ensure_ascii=True)
        if len(raw) > 2_000_000 or secret_reasons(raw) or not isinstance(body, dict) or not isinstance(body.get('categories'), dict):
            raise HTTPException(502, 'Invalid installation snapshot metadata')
        categories = body['categories']
        if set(categories) - {'applications', 'ports', 'services', 'containers', 'files', 'docker_resources'}:
            raise HTTPException(502, 'Invalid snapshot categories')
        for value in categories.values():
            if not isinstance(value, dict) or set(value) - {'rows', 'complete', 'roots', 'scope', 'notice'} or type(value.get('complete')) is not bool or not isinstance(value.get('rows'), list) or len(value['rows']) > 500:
                raise HTTPException(502, 'Invalid snapshot rows')
            for field in ('roots', 'scope'):
                if field in value and (not isinstance(value[field], list) or len(value[field]) > 20 or any(not isinstance(item, str) or len(item) > 1024 for item in value[field])):
                    raise HTTPException(502, 'Invalid snapshot scope')
            keys = []
            for row in value['rows']:
                if not isinstance(row, dict) or set(row) - {'id', 'name', 'value', 'metadata', 'root_index', 'bytes'} or not isinstance(row.get('id'), str) or not isinstance(row.get('value'), str) or len(row['id']) > 1024 or not re.fullmatch(r'[a-f0-9]{64}', row['value']) or not isinstance(row.get('name'), str) or len(row['name']) > 1024:
                    raise HTTPException(502, 'Invalid snapshot identity')
                metadata = row.get('metadata', {})
                if not isinstance(metadata, dict) or set(metadata) - {'id', 'name', 'version', 'source', 'protocol', 'address', 'port', 'pid', 'agent_ref', 'runtime', 'image', 'project'} or any(not isinstance(item, str) or len(item) > 1024 for item in metadata.values()):
                    raise HTTPException(502, 'Invalid snapshot metadata')
                keys.append(row['id'])
            if len(keys) != len(set(keys)):
                raise HTTPException(502, 'Duplicate snapshot identity')
        with self.store.connection() as db:
            clean = {'categories': categories, 'notice': 'Metadata/hash evidence only; content was not captured'}
            db.execute('INSERT INTO installation_snapshots VALUES(?,?,?,?)', (identifier, phase, now(), json.dumps(clean)))

    async def capture(self, identifier, phase, item):
        if not item.get('snapshots'):
            return
        try:
            self.terminal.bound(item)
            if self.terminal.demo:
                body = {'categories': {'files': {'complete': True, 'rows': [] if phase == 'before' else [{'id': '0:compose.yaml', 'name': 'compose.yaml', 'value': 'd' * 64}], 'roots': ['/demo']}}, 'notice': 'Synthetic demonstration only'}
            else:
                ref = item['service'].get('agent_ref') or item['service'].get('control_handle', {}).get('agent_ref', '')
                body = await self.terminal.agent(item['host'], 'POST', '/installation/snapshot', {'ref': ref}, timeout=40)
                if not isinstance(body, dict) or body.get('os') not in ('Linux', 'Darwin', 'Windows') or item['host'].get('active_os') and item['host']['active_os'] != body.get('os') or item['host'].get('physical_host_id') and item['host']['physical_host_id'] != body.get('physical_host_id'):
                    raise HTTPException(409, 'Installation snapshot agent identity changed')
            self.terminal.bound(item)
            self.save_snapshot(identifier, phase, body)
            self.store.audit('installation.snapshot', 'success', phase + ' metadata captured', item['service']['id'], item['host']['id'])
        except (HTTPException, OSError, ValueError, TypeError):
            self.store.audit('installation.snapshot', 'failed', phase + ' capture unavailable; comparison remains incomplete', item['service']['id'], item['host']['id'])

    def evidence(self, sid, identifier):
        session = self.session(sid, identifier)
        with self.store.connection() as db:
            snapshots = {row['phase']: json.loads(row['body']) for row in db.execute('SELECT phase,body FROM installation_snapshots WHERE session_id=?', (identifier,))}
            review = db.execute('SELECT revision,body FROM installation_reviews WHERE session_id=?', (identifier,)).fetchone()
            history = db.execute('SELECT body FROM installation_history WHERE session_id=?', (identifier,)).fetchone()
            inputs = db.execute("SELECT id,content FROM terminal_recording WHERE session_id=? AND direction='input' ORDER BY id LIMIT 5000", (identifier,)).fetchall()
        changes, gaps = differences(snapshots.get('before', {}), snapshots.get('after', {}))
        if set(snapshots) != {'before', 'after'}:
            gaps.append('Before/after capture is absent; changes cannot prove installation steps')
        commands = json.loads(history['body']) if history else [{'id': 'input-' + str(row['id']), 'command': row['content'], 'verified': False} for row in inputs]
        if len(commands) > 500 or len(inputs) >= 5000:
            gaps.append('Command review is bounded; some recorded input may be omitted')
        body = json.loads(review['body']) if review else {'excluded': [], 'instructions': '', 'approved': False}
        return {'session': session, 'changes': changes, 'gaps': gaps, 'commands': commands[:500], 'revision': review['revision'] if review else 0, 'review': body, 'reconstructed': bool(history), 'demo': self.terminal.demo, 'notice': 'Observed or reconstructed evidence. Commands may have failed or been edited; instructions remain unverified even after owner approval.'}

    def draft(self, evidence):
        excluded = set(evidence['review']['excluded'])
        lines = ['# ' + ('[DEMO] ' if evidence['demo'] else '') + ('Reconstructed' if evidence['reconstructed'] else 'Recorded') + ' installation — unverified', '', 'Review host, OS, prerequisites, permissions and credentials before running anything. No command is executed by this document.', '', '## Candidate commands (original order)', '']
        for index, row in enumerate(evidence['commands'], 1):
            if row['id'] in excluded or secret_reasons(row['command']) or redact(row['command']) != row['command']:
                continue
            # Indented blocks cannot break out through pasted Markdown fences.
            lines.extend([str(index) + '. Review this captured command:', '', *('       ' + line for line in row['command'].splitlines()), ''])
        lines += ['## Observed changes', '']
        for change in evidence['changes']:
            if change['id'] not in excluded:
                lines.append('- ' + change['category'] + ' ' + change['kind'] + ': ' + change['name'].replace('\n', ' ')[:255] + (' (scope incomplete)' if not change['verified_scope'] else ''))
        lines += ['', '## Evidence gaps', '', *('- ' + item for item in evidence['gaps']), '', 'Owner review does not verify reproducibility or successful execution.']
        return '\n'.join(lines)[:100000]

    def register(self, app):
        @app.get('/api/v1/services/{sid}/terminal/sessions/{identifier}/installation')
        def evidence(sid: str, identifier: str):
            return self.evidence(sid, identifier)

        @app.put('/api/v1/services/{sid}/terminal/sessions/{identifier}/installation')
        def review(sid: str, identifier: str, body: Review):
            current = self.evidence(sid, identifier)
            if current['session']['status'] in ('pending', 'running'):
                raise HTTPException(409, 'Close the session before reviewing installation evidence')
            valid = {row['id'] for row in current['commands'] + current['changes']}
            if set(body.excluded) - valid or secret_reasons(body.instructions) or redact(body.instructions) != body.instructions:
                raise HTTPException(422, 'Review contains invalid exclusions or possible credentials')
            with self.store.connection() as db:
                row = db.execute('SELECT revision FROM installation_reviews WHERE session_id=?', (identifier,)).fetchone()
                revision = row['revision'] if row else 0
                if revision != body.revision:
                    raise HTTPException(409, 'Installation review changed; reload before saving')
                db.execute('INSERT OR REPLACE INTO installation_reviews VALUES(?,?,?)', (identifier, revision + 1, json.dumps(body.model_dump(exclude={'revision'}))))
                self.store.audit('installation.review', 'success', 'Saved reviewed exclusions/instructions; execution remains unverified', sid, current['session']['host_id'], db=db)
            return self.evidence(sid, identifier)

        @app.get('/api/v1/services/{sid}/terminal/sessions/{identifier}/instructions')
        def instructions(sid: str, identifier: str):
            value = self.evidence(sid, identifier)
            content = self.draft(value)
            if value['review']['instructions']:
                content += '\n\n## Owner-edited instructions (unverified)\n\n' + value['review']['instructions']
            self.store.audit('installation.export', 'success', 'Exported unverified installation instructions', sid, value['session']['host_id'])
            return Response(content, media_type='text/markdown', headers={'Content-Disposition': 'attachment; filename="installation-unverified.md"'})

        @app.post('/api/v1/services/{sid}/terminal/sessions/{identifier}/installation/draft')
        async def ai_draft(sid: str, identifier: str):
            from controller.ai import configuration, draft
            value = self.evidence(sid, identifier)
            config = configuration(self.store)
            if not config['enabled']:
                raise HTTPException(409, 'Local AI is disabled in Settings')
            result = {'draft': '[DEMO] Unverified installation instructions. Review the captured commands and evidence gaps; no model request was made.', 'model':'demo', 'verified':False, 'advice_only':True} if self.terminal.demo else await draft('installation', {'evidence':self.draft(value)}, config)
            self.store.audit('installation.ai_draft', 'success', 'Generated advice-only installation draft; not saved or executed', sid, value['session']['host_id'])
            return result

        @app.post('/api/v1/services/{sid}/installation-history')
        def import_history(sid: str, body: HistoryImport):
            import secrets
            service = self.terminal.require('services', sid)
            if not body.confirmed:
                raise HTTPException(409, 'Confirm explicit import; history may contain credentials')
            if secret_reasons(body.name):
                raise HTTPException(422, 'Choose a name without credentials')
            commands = relevant(service, history_commands(body.shell, body.content))
            if not commands:
                raise HTTPException(422, 'No secret-free commands match this service name, path, image or port')
            identifier = secrets.token_hex(16)
            with self.store.connection() as db:
                db.execute('INSERT INTO terminal_sessions(id,service_id,host_id,started_at,ended_at,status,profile,recording,detail,name) VALUES(?,?,?,?,?,?,?,?,?,?)', (identifier, sid, service['host_id'], now(), now(), 'reconstructed', body.shell, 1, 'Explicit history import; inferred, unverified', body.name))
                db.execute('INSERT INTO installation_history VALUES(?,?)', (identifier, json.dumps(commands)))
                self.store.audit('installation.history', 'success', 'Imported bounded matched commands; reconstructed and unverified', sid, service['host_id'], db=db)
            return self.evidence(sid, identifier)
