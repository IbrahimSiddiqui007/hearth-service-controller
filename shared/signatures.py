"""Versioned request signatures; keys are environment references, never registry values."""
import hashlib
import hmac
import re
import secrets
import time

WINDOW = 120


def digest(key, method, target, body, timestamp, nonce):
    message = '\n'.join(['psc-v1', timestamp, nonce, method.upper(), target, hashlib.sha256(body).hexdigest()])
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()


def headers(key, method, target, body, timestamp=None, nonce=None):
    if len(key.encode()) < 32:
        raise ValueError('Request signing requires at least 32 bytes of key material')
    timestamp = str(int(time.time()) if timestamp is None else timestamp)
    nonce = nonce or secrets.token_hex(24)
    return {'X-PSC-Time': timestamp, 'X-PSC-Nonce': nonce,
            'X-PSC-Signature': digest(key, method, target, body, timestamp, nonce)}


def valid(key, method, target, body, supplied, clock=None):
    timestamp, nonce, signature = (supplied.get(name, '') for name in ('x-psc-time', 'x-psc-nonce', 'x-psc-signature'))
    if len(key.encode()) < 32 or not re.fullmatch(r'[0-9]{10,12}', timestamp) or not re.fullmatch(r'[a-f0-9]{48}', nonce) or not re.fullmatch(r'[a-f0-9]{64}', signature):
        return False
    if abs((time.time() if clock is None else clock) - int(timestamp)) > WINDOW:
        return False
    return hmac.compare_digest(signature, digest(key, method, target, body, timestamp, nonce))


def frame_signature(key, nonce, sequence, payload):
    return digest(key, 'HEARTBEAT', str(sequence), payload, '0', nonce)
