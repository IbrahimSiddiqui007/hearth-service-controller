"""Durable nonce claims survive agent restart and reject concurrent replays."""
import os
import sqlite3
import time
from pathlib import Path

from shared.signatures import WINDOW


class ReplayGuard:
    def __init__(self, directory):
        root = Path(directory)
        if not directory or not root.is_absolute() or not root.is_dir() or root.is_symlink():
            raise ValueError('Signing requires an existing absolute private state_dir')
        if any(parent.is_symlink() for parent in root.parents):
            raise ValueError('Signing state directory cannot traverse symlinks')
        if os.name != 'nt':
            info = root.stat()
            if info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ValueError('Signing state_dir must be owned by the agent with mode 0700')
        self.path = root / 'request-nonces.sqlite3'
        if self.path.is_symlink() or self.path.exists() and not self.path.is_file():
            raise ValueError('Unsafe signing replay store')
        with sqlite3.connect(self.path) as db:
            db.execute('CREATE TABLE IF NOT EXISTS nonces(nonce TEXT PRIMARY KEY,expires REAL NOT NULL)')
        if os.name != 'nt':
            self.path.chmod(0o600)

    def claim(self, nonce, timestamp, clock=None):
        current = time.time() if clock is None else clock
        if self.path.is_symlink():
            return False
        try:
            with sqlite3.connect(self.path, timeout=2) as db:
                db.execute('DELETE FROM nonces WHERE expires < ?', (current,))
                if db.execute('SELECT count(*) FROM nonces').fetchone()[0] >= 10000:
                    return False
                db.execute('INSERT INTO nonces VALUES(?,?)', (nonce, int(timestamp) + WINDOW + 1))
            return True
        except (sqlite3.Error, OSError, ValueError):
            return False
