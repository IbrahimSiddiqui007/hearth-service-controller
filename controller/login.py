"""Single-owner password plus TOTP login with revocable HttpOnly sessions."""
import base64
import hashlib
import hmac
import os
import re
import secrets
import struct
import time
import threading

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

COOKIE = 'psc-session'
LIFETIME = 12 * 3600
PASSWORD_WORK = threading.BoundedSemaphore(1)


def password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    result = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    return 'scrypt-v1$' + salt.hex() + '$' + result.hex()


def totp(secret, step):
    key = base64.b32decode(secret.upper() + '=' * (-len(secret) % 8))
    result = hmac.new(key, struct.pack('>Q', step), hashlib.sha1).digest()
    offset = result[-1] & 15
    return str((struct.unpack('>I', result[offset:offset + 4])[0] & 0x7fffffff) % 1_000_000).zfill(6)


class Credentials(BaseModel):
    model_config = ConfigDict(extra='forbid')
    password: str = Field(min_length=1, max_length=1024)
    code: str = Field(pattern=r'^[0-9]{6}$')


class OwnerLogin:
    def __init__(self, store, enabled=True):
        self.store = store
        self.hash = os.environ.get('PSC_PASSWORD_HASH', '') if enabled else ''
        self.secret = os.environ.get('PSC_TOTP_SECRET', '').upper() if enabled else ''
        self.enabled = bool(self.hash or self.secret)
        if self.enabled and (not re.fullmatch(r'scrypt-v1\$[a-f0-9]{32}\$[a-f0-9]{64}', self.hash) or not re.fullmatch(r'[A-Z2-7]{32,64}', self.secret)):
            raise ValueError('Password/TOTP login requires valid PSC_PASSWORD_HASH and PSC_TOTP_SECRET')
        with store.connection() as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS login_sessions(id TEXT PRIMARY KEY,expires REAL NOT NULL,configuration TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS login_attempts(id INTEGER PRIMARY KEY,ts REAL NOT NULL,peer TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS login_totp(configuration TEXT PRIMARY KEY,step INTEGER NOT NULL);''')
        self.configuration = hashlib.sha256((self.hash + ':' + self.secret).encode()).hexdigest()

    def authorized(self, session):
        if not self.enabled or not session or not re.fullmatch(r'[A-Za-z0-9_-]{43}', session):
            return False
        identifier = hashlib.sha256(session.encode()).hexdigest()
        with self.store.connection() as db:
            row = db.execute('SELECT expires,configuration FROM login_sessions WHERE id=?', (identifier,)).fetchone()
        return bool(row and row['expires'] > time.time() and hmac.compare_digest(row['configuration'], self.configuration))

    def login(self, credentials, peer):
        current = time.time()
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM login_attempts WHERE ts < ?', (current - 300,))
            global_count = db.execute('SELECT count(*) FROM login_attempts').fetchone()[0]
            peer_count = db.execute('SELECT count(*) FROM login_attempts WHERE peer=?', (peer,)).fetchone()[0]
            if global_count >= 30 or peer_count >= 5:
                raise HTTPException(429, 'Too many login attempts; wait five minutes')
            db.execute('INSERT INTO login_attempts(ts,peer) VALUES(?,?)', (current, peer))
        salt = bytes.fromhex(self.hash.split('$')[1])
        with PASSWORD_WORK:
            password_ok = hmac.compare_digest(password_hash(credentials.password, salt), self.hash)
        step = int(current // 30)
        matching = [candidate for candidate in (step - 1, step, step + 1) if hmac.compare_digest(totp(self.secret, candidate), credentials.code)]
        if not password_ok or not matching:
            self.store.audit('auth.login', 'failed', 'Invalid owner credentials')
            raise HTTPException(401, 'Invalid password or verification code')
        with self.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            previous = db.execute('SELECT step FROM login_totp WHERE configuration=?', (self.configuration,)).fetchone()
            selected = max(matching)
            if previous and previous['step'] >= selected:
                raise HTTPException(401, 'Verification code already used; wait for a new code')
            db.execute('INSERT OR REPLACE INTO login_totp VALUES(?,?)', (self.configuration, selected))
            db.execute('DELETE FROM login_sessions WHERE expires < ? OR configuration <> ?', (current, self.configuration))
            if db.execute('SELECT count(*) FROM login_sessions').fetchone()[0] >= 20:
                oldest = db.execute('SELECT id FROM login_sessions ORDER BY expires LIMIT 1').fetchone()['id']
                db.execute('DELETE FROM login_sessions WHERE id=?', (oldest,))
            session = secrets.token_urlsafe(32)
            db.execute('INSERT INTO login_sessions VALUES(?,?,?)', (hashlib.sha256(session.encode()).hexdigest(), current + LIFETIME, self.configuration))
            self.store.audit('auth.login', 'success', 'Owner password/TOTP session opened', db=db)
        return session

    def recent(self, session, maximum_age):
        if not self.authorized(session):
            return False
        with self.store.connection() as db:
            row = db.execute('SELECT expires FROM login_sessions WHERE id=?', (hashlib.sha256(session.encode()).hexdigest(),)).fetchone()
        return bool(row and time.time() - (row['expires'] - LIFETIME) <= maximum_age)

    def routes(self, app):
        @app.get('/api/v1/auth/status')
        def status(request: Request):
            return {'password_totp': self.enabled, 'session': self.authorized(request.cookies.get(COOKIE))}

        @app.post('/api/v1/auth/login')
        def login(request: Request, credentials: Credentials):
            if not self.enabled:
                raise HTTPException(409, 'Password/TOTP login is not configured')
            local = request.client and request.client.host in ('127.0.0.1', '::1', 'testclient')
            if request.url.scheme != 'https' and not local:
                raise HTTPException(403, 'Remote password login requires HTTPS')
            session = self.login(credentials, request.client.host if request.client else 'unknown')
            result = JSONResponse({'status': 'authenticated'})
            result.set_cookie(COOKIE, session, max_age=LIFETIME, httponly=True, secure=request.url.scheme == 'https', samesite='strict', path='/api/')
            return result

        @app.post('/api/v1/auth/logout')
        def logout(request: Request):
            session = request.cookies.get(COOKIE, '')
            with self.store.connection() as db:
                db.execute('DELETE FROM login_sessions WHERE id=?', (hashlib.sha256(session.encode()).hexdigest(),))
                self.store.audit('auth.logout', 'success', 'Owner session revoked', db=db)
            result = JSONResponse({'status': 'signed_out'})
            result.delete_cookie(COOKIE, path='/api/')
            return result
