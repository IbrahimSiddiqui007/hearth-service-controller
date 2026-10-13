"""Opt-in fixed shell profiles, owned PTYs and bounded, expiring terminal leases."""
import codecs
import hashlib
import json
import os
import platform
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from fastapi import HTTPException
from pydantic import Field
from shared.models import StrictModel, redact, TerminalInput


class TerminalOpen(StrictModel):
    ref: str = Field(min_length=1, max_length=100)
    profile: str = Field(pattern=r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$')
    fingerprint: str = Field(pattern=r'^[a-f0-9]{64}$')
    confirmed: bool = False


def ordinary_account():
    system = platform.system()
    if system in ('Linux', 'Darwin'):
        return hasattr(os, 'getuid') and os.getuid() > 0
    if system == 'Windows':
        import ctypes
        return not bool(ctypes.windll.shell32.IsUserAnAdmin())
    return False


def profile(config, ref, identifier):
    item = config.get('terminal_profiles', {}).get(ref, {}).get(identifier)
    if not isinstance(item, dict) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}', identifier):
        raise HTTPException(403, 'Terminal profile is not explicitly approved on this agent')
    argv, cwd = item.get('argv'), item.get('cwd')
    if not isinstance(argv, list) or not 1 <= len(argv) <= 20 or any(not isinstance(arg, str) or '\x00' in arg or len(arg) > 1024 for arg in argv) or not Path(argv[0]).is_absolute():
        raise HTTPException(409, 'Terminal profiles require fixed argv and an absolute shell executable')
    if not isinstance(cwd, str) or not Path(cwd).is_absolute() or not Path(cwd).is_dir() or any(part.is_symlink() or getattr(part, 'is_junction', lambda: False)() for part in (Path(cwd), *Path(cwd).parents)):
        raise HTTPException(409, 'Terminal working directory must be an existing absolute path without links')
    if not ordinary_account():
        raise HTTPException(403, 'Interactive terminals refuse root or elevated administrator agents')
    fingerprint = hashlib.sha256(json.dumps([argv, str(Path(cwd).resolve())], ensure_ascii=True).encode()).hexdigest()
    return {'argv': argv, 'cwd': str(Path(cwd).resolve()), 'fingerprint': fingerprint, 'id': identifier, 'label': redact(str(item.get('label', identifier)))[:100]}


def environment():
    allowed = ('HOME', 'USER', 'LOGNAME', 'PATH', 'LANG', 'LC_ALL', 'SystemRoot', 'WINDIR', 'USERPROFILE', 'TEMP', 'TMP', 'COMSPEC')
    result = {key: os.environ[key] for key in allowed if key in os.environ}
    result.update(TERM='xterm-256color', HISTFILE=os.devnull, HISTSIZE='0', SAVEHIST='0')
    return result


class PosixPTY:
    def __init__(self, item):
        import pty
        master, slave = pty.openpty()
        self.master, self.child = master, None
        try:
            self.child = subprocess.Popen([sys.executable, str(Path(__file__).with_name('terminal_child.py')), str(slave), *item['argv']],
                cwd=item['cwd'], env=environment(), pass_fds=(slave,), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False)
            os.set_blocking(master, False)
        except BaseException:
            os.close(master)
            if self.child is not None:
                self.child.terminate()
                self.child.wait(timeout=3)
            raise
        finally:
            os.close(slave)

    def read(self):
        try:
            return os.read(self.master, 16384)
        except BlockingIOError:
            return None
        except OSError as exc:
            if exc.errno == 5:  # POSIX PTY EOF often reports EIO.
                return b''
            raise

    def write(self, data):
        written = os.write(self.master, data.encode())
        if written != len(data.encode()):
            raise OSError('Terminal input was incomplete; do not blindly resend it')

    def resize(self, rows, cols):
        import fcntl
        import struct
        import termios
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))

    def close(self):
        if self.child.poll() is None:
            def send(sig):
                try:
                    if os.getpgid(self.child.pid) == self.child.pid:
                        os.killpg(self.child.pid, sig)
                    else:
                        self.child.send_signal(sig)
                except ProcessLookupError:
                    pass
            send(signal.SIGTERM)
            try:
                self.child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                send(signal.SIGKILL)
                self.child.wait(timeout=3)
        os.close(self.master)


class WindowsPTY:
    def __init__(self, item):
        try:
            from winpty import PtyProcess
            from winpty.enums import Backend
        except ImportError as exc:
            raise HTTPException(409, 'Windows terminal needs the optional pywinpty agent dependency') from exc
        # pywinpty treats integer zero as an environment fallback; a truthy
        # string selects ConPTY explicitly without consulting global overrides.
        self.child = PtyProcess.spawn(item['argv'], cwd=item['cwd'], env=environment(), dimensions=(24, 80), backend=str(Backend.ConPTY))
        self.child.fileobj.setblocking(False)

    def read(self):
        try:
            return self.child.fileobj.recv(16384)
        except BlockingIOError:
            return None

    def write(self, data):
        if self.child.write(data) != len(data.encode()):
            raise OSError('Terminal input was incomplete; do not blindly resend it')

    def resize(self, rows, cols):
        self.child.setwinsize(rows, cols)

    def close(self):
        self.child.close(force=True)


def native(item):
    return WindowsPTY(item) if platform.system() == 'Windows' else PosixPTY(item)


class TerminalManager:
    def __init__(self, config, factory=None, clock=None):
        self.config, self.factory, self.clock = config, factory or native, clock or time.monotonic
        self.sessions, self.lock = {}, threading.RLock()

    def profiles(self, ref):
        rows = []
        for identifier in list(self.config.get('terminal_profiles', {}).get(ref, {}))[:10]:
            item = profile(self.config, ref, identifier)
            rows.append({key: item[key] for key in ('id', 'label', 'cwd', 'fingerprint')})
        return rows

    def sweep(self):
        with self.lock:
            current = self.clock()
            for identifier, item in list(self.sessions.items()):
                if current - item['input_at'] >= 900 or current - item['started'] >= 3600 or current - item['polled'] >= 15:
                    self.close(identifier)

    def open(self, body):
        if not body.confirmed:
            raise HTTPException(409, 'Explicit terminal confirmation is required')
        with self.lock:
            self.sweep()
            if len(self.sessions) >= 2:
                raise HTTPException(429, 'Agent terminal limit reached')
            item = profile(self.config, body.ref, body.profile)
            if item['fingerprint'] != body.fingerprint:
                raise HTTPException(409, 'Terminal profile changed; review it again')
            identifier = secrets.token_hex(16)
            child = self.factory(item)
            stamp = self.clock()
            self.sessions[identifier] = {'pty': child, 'ref': body.ref, 'profile': body.profile, 'fingerprint': item['fingerprint'], 'started': stamp, 'input_at': stamp, 'polled': stamp, 'input_bytes': 0, 'output_bytes': 0, 'decoder': codecs.getincrementaldecoder('utf-8')(errors='replace')}
            return {'id': identifier, 'idle_timeout_s': 900, 'maximum_duration_s': 3600}

    def require(self, identifier):
        self.sweep()
        item = self.sessions.get(identifier)
        if not item or item.get('closing'):
            raise HTTPException(410, 'Terminal lease ended')
        try:
            current = profile(self.config, item['ref'], item['profile'])
            if current['fingerprint'] != item['fingerprint']:
                raise HTTPException(409, 'Terminal profile changed; session closed')
        except HTTPException:
            self.close(identifier)
            raise
        return item

    def read(self, identifier):
        with self.lock:
            item = self.require(identifier)
            item['polled'] = self.clock()
            raw = item['pty'].read()
            if raw == b'':
                self.close(identifier)
                return {'content': '', 'ended': True}
            raw = raw or b''
            item['output_bytes'] += len(raw)
            if item['output_bytes'] > 2_000_000:
                self.close(identifier)
                return {'content': '', 'ended': True, 'reason': 'Terminal output limit reached'}
            return {'content': item['decoder'].decode(raw), 'ended': False}

    def input(self, identifier, body):
        with self.lock:
            item = self.require(identifier)
            size = len(body.data.encode())
            if size > 8192 or item['input_bytes'] + size > 256000:
                self.close(identifier)
                raise HTTPException(413, 'Terminal input limit reached; session closed')
            if (body.rows is None) != (body.cols is None):
                raise HTTPException(422, 'Terminal resizing needs both dimensions')
            if body.data:
                item['pty'].write(body.data)
                item['input_at'], item['input_bytes'] = self.clock(), item['input_bytes'] + size
            if body.rows is not None:
                item['pty'].resize(body.rows, body.cols)
            return {'accepted': True}

    def close(self, identifier):
        with self.lock:
            item = self.sessions.get(identifier)
            if item:
                item['closing'] = True
                item['pty'].close()
                self.sessions.pop(identifier, None)
            return {'closed': True}

    def close_all(self):
        with self.lock:
            for identifier in list(self.sessions):
                self.close(identifier)
