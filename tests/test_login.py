import hashlib
import base64
import time

import pytest
from fastapi.testclient import TestClient

from controller.app import create_app
from controller.login import COOKIE, password_hash, totp

SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
PASSWORD = 'test-only-owner-password'


@pytest.mark.parametrize('seconds,code', [(59, '287082'), (1111111109, '081804'), (1111111111, '050471'), (1234567890, '005924'), (2000000000, '279037'), (20000000000, '353130')])
def test_rfc6238_sha1_vectors_truncated_to_six_digits(seconds, code):
    secret = base64.b32encode(b'12345678901234567890').decode()
    assert totp(secret, seconds // 30) == code


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv('PSC_PASSWORD_HASH', password_hash(PASSWORD))
    monkeypatch.setenv('PSC_TOTP_SECRET', SECRET)
    return create_app(tmp_path, token='', background=False)


def credentials(password=PASSWORD):
    return {'password': password, 'code': totp(SECRET, int(time.time() // 30))}


def test_login_session_logout_and_totp_replay(app):
    with TestClient(app) as client:
        assert client.get('/api/v1/hosts').status_code == 401
        assert client.get('/api/v1/auth/status').json()['password_totp']
        result = client.post('/api/v1/auth/login', json=credentials())
        assert result.status_code == 200
        assert 'HttpOnly' in result.headers['set-cookie'] and 'SameSite=strict' in result.headers['set-cookie']
        cookie = client.cookies.get(COOKIE)
        assert client.get('/api/v1/hosts').status_code == 200
        with app.state.store.connection() as db:
            assert db.execute('SELECT id FROM login_sessions').fetchone()['id'] == hashlib.sha256(cookie.encode()).hexdigest()
        assert client.post('/api/v1/auth/login', json=credentials()).status_code == 401
        assert client.post('/api/v1/auth/logout', json={}).status_code == 200
        assert client.get('/api/v1/hosts').status_code == 401
        assert PASSWORD not in str(app.state.store.events())


def test_invalid_credentials_rate_limit_and_origin(app):
    with TestClient(app) as client:
        assert client.post('/api/v1/auth/login', json=credentials(), headers={'Origin': 'https://evil.invalid'}).status_code == 403
        for _ in range(5):
            assert client.post('/api/v1/auth/login', json=credentials('wrong')).status_code == 401
        assert client.post('/api/v1/auth/login', json=credentials()).status_code == 429
        assert client.get('/api/v1/hosts').status_code == 401


def test_secure_cookie_expiry_remote_http_and_configuration_change(app, monkeypatch):
    with TestClient(app, base_url='https://testserver', client=('remote', 50000)) as client:
        result = client.post('/api/v1/auth/login', json=credentials())
        assert result.status_code == 200 and 'Secure' in result.headers['set-cookie']
        cookie = client.cookies.get(COOKIE)
        with app.state.store.connection() as db:
            db.execute('UPDATE login_sessions SET expires=?', (time.time() - 1,))
        assert client.get('/api/v1/hosts').status_code == 401
    with TestClient(app, client=('remote', 50000)) as client:
        assert client.post('/api/v1/auth/login', json=credentials()).status_code == 403
    monkeypatch.setenv('PSC_PASSWORD_HASH', password_hash('new-owner-password'))
    changed = create_app(app.state.store.root, token='', background=False)
    with TestClient(changed) as client:
        client.cookies.set(COOKIE, cookie, path='/api/')
        assert client.get('/api/v1/hosts').status_code == 401


def test_demo_ignores_live_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv('PSC_PASSWORD_HASH', 'invalid')
    monkeypatch.setenv('PSC_TOTP_SECRET', 'invalid')
    with TestClient(create_app(tmp_path, demo=True, token='', background=False)) as client:
        assert not client.get('/api/v1/auth/status').json()['password_totp']
        assert client.get('/api/v1/hosts').status_code == 200
