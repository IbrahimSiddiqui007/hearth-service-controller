from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from shared.models import redact


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, root: Path):
        root.mkdir(parents=True, exist_ok=True)
        self.root = root
        self.path = root / "controller.sqlite3"
        with self.connection() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS hosts (id TEXT PRIMARY KEY, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS container_inventory (host_id TEXT PRIMARY KEY, ts TEXT NOT NULL, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS host_inventory (host_id TEXT NOT NULL,provider TEXT NOT NULL,ts TEXT NOT NULL,body TEXT NOT NULL,PRIMARY KEY(host_id,provider));
                CREATE TABLE IF NOT EXISTS services (id TEXT PRIMARY KEY, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS secret_findings(
                    id TEXT PRIMARY KEY,service_id TEXT NOT NULL,source TEXT NOT NULL,category TEXT NOT NULL,
                    first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,revision INTEGER NOT NULL,vault_ref TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS schedule_cursors(service_id TEXT PRIMARY KEY,policy_key TEXT NOT NULL,minute TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS schedule_runs(service_id TEXT NOT NULL,policy_key TEXT NOT NULL,minute TEXT NOT NULL,
                    action TEXT NOT NULL,status TEXT NOT NULL,ts TEXT NOT NULL,detail TEXT NOT NULL,PRIMARY KEY(service_id,policy_key,minute));
                CREATE TABLE IF NOT EXISTS power_requests(id TEXT PRIMARY KEY,host_id TEXT NOT NULL,action TEXT NOT NULL,
                    ts TEXT NOT NULL,status TEXT NOT NULL,active INTEGER NOT NULL,detail TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
                    service_id TEXT, host_id TEXT, action TEXT NOT NULL, result TEXT NOT NULL, detail TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS note_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, service_id TEXT NOT NULL,
                    ts TEXT NOT NULL, revision INTEGER NOT NULL, notes TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS documentation_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, service_id TEXT NOT NULL,
                    ts TEXT NOT NULL, revision INTEGER NOT NULL, body TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS heartbeat_nonces(host_id TEXT NOT NULL,nonce TEXT NOT NULL,expires REAL NOT NULL,PRIMARY KEY(host_id,nonce));
                CREATE TABLE IF NOT EXISTS telemetry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, host_id TEXT NOT NULL, ts TEXT NOT NULL, body TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS telemetry_host_ts ON telemetry(host_id, ts);
                CREATE TABLE IF NOT EXISTS operations (
                    id TEXT PRIMARY KEY, service_id TEXT NOT NULL, action TEXT NOT NULL,
                    status TEXT NOT NULL, ts TEXT NOT NULL, detail TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS health_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, service_id TEXT NOT NULL, ts TEXT NOT NULL,
                    ok INTEGER NOT NULL, latency_ms REAL, detail TEXT NOT NULL, check_key TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS health_service_ts ON health_results(service_id, ts);
                CREATE TABLE IF NOT EXISTS discovery_scans(id TEXT PRIMARY KEY, host_id TEXT NOT NULL, ts TEXT NOT NULL, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, service_id TEXT NOT NULL, check_key TEXT NOT NULL,
                    started_at TEXT NOT NULL, ended_at TEXT, detail TEXT NOT NULL, cause TEXT NOT NULL DEFAULT '', resolution TEXT
                );
                CREATE TABLE IF NOT EXISTS incident_notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, service_id TEXT NOT NULL, incident_id INTEGER,
                    ts TEXT NOT NULL, note TEXT NOT NULL, source TEXT NOT NULL, model TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS config_versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, service_id TEXT NOT NULL, file_key TEXT NOT NULL,
                    path TEXT NOT NULL, root_index INTEGER NOT NULL, ts TEXT NOT NULL, git_commit TEXT NOT NULL,
                    etag TEXT NOT NULL, message TEXT NOT NULL, status TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS config_file_versions ON config_versions(service_id,file_key,id);
                CREATE TABLE IF NOT EXISTS demo_files(service_id TEXT NOT NULL,path TEXT NOT NULL,body TEXT NOT NULL,PRIMARY KEY(service_id,path));
                CREATE TABLE IF NOT EXISTS notification_outbox(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,event_key TEXT NOT NULL UNIQUE,ts TEXT NOT NULL,
                    message TEXT NOT NULL,config_key TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0,next_at TEXT NOT NULL,detail TEXT NOT NULL DEFAULT ''
                );
            """)
            columns = {row["name"] for row in db.execute("PRAGMA table_info(health_results)")}
            if "check_key" not in columns:
                db.execute("ALTER TABLE health_results ADD COLUMN check_key TEXT NOT NULL DEFAULT ''")
            if "interval_s" not in columns:
                db.execute("ALTER TABLE health_results ADD COLUMN interval_s INTEGER NOT NULL DEFAULT 60")
            db.execute("CREATE INDEX IF NOT EXISTS health_series_ts ON health_results(service_id,check_key,ts)")

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def all(self, table: str):
        assert table in ("hosts", "services")
        with self.connection() as db:
            return [json.loads(row["body"]) for row in db.execute(f"SELECT body FROM {table} ORDER BY id")]

    def get(self, table: str, key: str):
        assert table in ("hosts", "services")
        with self.connection() as db:
            row = db.execute(f"SELECT body FROM {table} WHERE id=?", (key,)).fetchone()
        return json.loads(row["body"]) if row else None

    def put(self, table: str, body: dict, db=None):
        assert table in ("hosts", "services")
        if db is None:
            with self.connection() as db:
                self.put(table, body, db)
        else:
            db.execute(f"INSERT INTO {table}(id,body) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body",
                       (body["id"], json.dumps(body)))

    def audit(self, action: str, result: str, detail: str = "", service_id=None, host_id=None, db=None):
        detail = redact(detail)
        if db is None:
            with self.connection() as db:
                self.audit(action, result, detail, service_id, host_id, db)
        else:
            db.execute("INSERT INTO audit(ts,service_id,host_id,action,result,detail) VALUES(?,?,?,?,?,?)",
                       (now(), service_id, host_id, action, result, detail))

    def events(self, service_id=None, limit=100):
        with self.connection() as db:
            if service_id:
                rows = db.execute("SELECT * FROM audit WHERE service_id=? ORDER BY id DESC LIMIT ?", (service_id, limit))
            else:
                rows = db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(row) for row in rows]
