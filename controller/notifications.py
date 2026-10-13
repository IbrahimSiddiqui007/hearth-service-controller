"""Opt-in notification outbox. Demo delivery is always simulated."""
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone

import httpx

from controller.store import now
from shared.models import NotificationSettings, redact
from shared.configuration import secret_reasons


def settings(store):
    with store.connection() as db:
        saved = db.execute("SELECT body FROM settings WHERE key='notifications'").fetchone()
    config = NotificationSettings.model_validate_json(saved['body']).model_dump() if saved else NotificationSettings().model_dump()
    secret = os.environ.get(config['token_env'], '') if config['token_env'] else ''
    configured = bool(config['enabled'] and ((config['endpoint'] and config['topic'] and (not config['token_env'] or secret)) if config['channel'] == 'ntfy' else (secret and config['chat_id'])))
    return config | {'configured': configured, 'reason': '' if configured else 'Enable a channel and configure its destination and any required environment token'}


def config_key(config):
    return hashlib.sha256(json.dumps({key: config.get(key) for key in NotificationSettings.model_fields}, sort_keys=True).encode()).hexdigest()


def enqueue(store, event_key, message):
    config = settings(store)
    if not config['configured']:
        return None
    text = redact(message)[:2000]
    if secret_reasons(text):
        text = 'Homelab state changed; sensitive detail omitted. Inspect the local Activity page.'
    with store.connection() as db:
        cursor = db.execute('INSERT OR IGNORE INTO notification_outbox(event_key,ts,message,config_key,next_at) VALUES(?,?,?,?,?)', (event_key, now(), text, config_key(config), now()))
        return cursor.lastrowid if cursor.rowcount else None


async def deliver(config, message):
    secret = os.environ.get(config['token_env'], '') if config['token_env'] else ''
    try:
        async with httpx.AsyncClient(timeout=5, follow_redirects=False, trust_env=False) as client:
            if config['channel'] == 'ntfy':
                response = await client.post(config['endpoint'] + '/' + config['topic'], content=message.encode('utf-8'), headers={'Authorization': 'Bearer ' + secret} if secret else {})
                accepted = 200 <= response.status_code < 300
            else:
                response = await client.post('https://api.telegram.org/bot' + secret + '/sendMessage', json={'chat_id': config['chat_id'], 'text': message})
                accepted = response.status_code == 200 and response.json().get('ok') is True
            return accepted, 'Delivered' if accepted else 'Notification server rejected the request (HTTP ' + str(response.status_code) + ')'
    except (httpx.HTTPError, ValueError, AttributeError):
        # Never include exception URLs: Telegram URLs contain the environment token.
        return False, 'Notification server unavailable or returned an invalid response'


async def flush(store, demo=False):
    config = settings(store)
    if not config['configured']:
        return []
    with store.connection() as db:
        rows = [dict(row) for row in db.execute("SELECT * FROM notification_outbox WHERE status='pending' AND next_at<=? ORDER BY id LIMIT 5", (now(),))]
    outcomes = []
    for row in rows:
        # Preferences may change while a preceding delivery awaits the server.
        config = settings(store)
        if row['config_key'] != config_key(config):
            with store.connection() as db:
                db.execute("UPDATE notification_outbox SET status='cancelled',detail='Settings changed before delivery' WHERE id=? AND status='pending'", (row['id'],))
            continue
        if not config['configured']:
            continue
        with store.connection() as db:
            claimed = db.execute("UPDATE notification_outbox SET status='sending' WHERE id=? AND status='pending'", (row['id'],)).rowcount
        if not claimed:
            continue
        ok, detail = (True, 'Simulated demo delivery; no network request') if demo else await deliver(config, row['message'])
        attempts = row['attempts'] + 1
        status = ('simulated' if demo else 'delivered') if ok else 'failed' if attempts >= 3 else 'pending'
        next_at = (datetime.now(timezone.utc) + timedelta(seconds=30 * 3 ** attempts)).isoformat()
        with store.connection() as db:
            db.execute('UPDATE notification_outbox SET status=?,attempts=?,next_at=?,detail=? WHERE id=?', (status, attempts, next_at, detail, row['id']))
            store.audit('notification.delivery', 'success' if ok else 'warning', detail, db=db)
        outcomes.append({'id': row['id'], 'status': status, 'detail': detail})
    return outcomes
