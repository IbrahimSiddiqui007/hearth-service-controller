"""Value-free, bounded credential review evidence. Never hash secret values."""
import hashlib

from shared.secret_findings import categories, CATEGORIES
from controller.store import now


def record(store, sid, source, reasons):
    # Sources are fixed labels chosen by the caller, never client paths/content.
    with store.connection() as db:
        for reason in CATEGORIES:
            if reason not in reasons:
                continue
            key = hashlib.sha256((sid + ':' + source + ':' + reason).encode()).hexdigest()
            db.execute('''INSERT INTO secret_findings(id,service_id,source,category,first_seen,last_seen,revision,vault_ref)
                          VALUES(?,?,?,?,?,?,1,'') ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen''',
                       (key, sid, source, reason, now(), now()))


def listing(store, sid):
    with store.connection() as db:
        return [dict(row) | {'verification': 'unverified'} for row in db.execute(
            'SELECT * FROM secret_findings WHERE service_id=? ORDER BY first_seen,id', (sid,))]
