"""Opt-in read-only cron/startup metadata and listening sockets; no commands exported."""
import hashlib
import platform
import re
from pathlib import Path

import psutil
from fastapi import HTTPException
from shared.models import redact


def entry(kind, source, name, material):
    identity = hashlib.sha256((kind + '\0' + source + '\0' + name).encode()).hexdigest()
    return {'id': identity, 'kind': kind, 'source': redact(source)[:1024], 'name': redact(name)[:255],
            'fingerprint': hashlib.sha256(material).hexdigest()}


def cron_files():
    paths = [Path('/etc/crontab')]
    for directory in ('/etc/cron.d', '/etc/cron.hourly', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.monthly'):
        root = Path(directory)
        if root.is_dir() and not root.is_symlink():
            entries = []
            for item in root.iterdir():
                entries.append(item)
                if len(entries) > 100:
                    raise OSError('Cron directory inventory limit reached')
            paths.extend(sorted(entries))
    return paths


def linux_rows():
    rows = []
    for path in cron_files():
        if not path.exists():
            continue
        if not path.is_file() or path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
            raise OSError('Unsafe cron source')
        with path.open('rb') as stream:
            raw = stream.read(262145)
        if len(raw) > 262144:
            raise OSError('Oversized cron source')
        rows.append(entry('cron', str(path.parent), path.name, raw))
        if path.name == 'crontab' or path.parent.name == 'cron.d':
            for index, line in enumerate(raw.decode('utf-8', errors='replace').splitlines(), 1):
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                fields = stripped.split()
                schedule = fields[0] if fields[0] in ('@reboot', '@yearly', '@annually', '@monthly', '@weekly', '@daily', '@midnight', '@hourly') else ' '.join(fields[:5]) if len(fields) >= 7 and all(re.fullmatch(r'[0-9A-Za-z*/?,#-]+', item) for item in fields[:5]) else ''
                if schedule:
                    rows.append(entry('cron', str(path), 'entry ' + str(index) + ' · ' + schedule, stripped.encode()))
                if len(rows) >= 1000:
                    raise OSError('Cron entry inventory limit reached')
    return rows


def windows_rows():
    import winreg
    rows = []
    for hive, scope in ((winreg.HKEY_LOCAL_MACHINE, 'machine'), (winreg.HKEY_CURRENT_USER, 'agent user')):
        for suffix in ('Run', 'RunOnce'):
            source = r'Software\Microsoft\Windows\CurrentVersion' + '\\' + suffix
            for view in (winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY):
                try:
                    with winreg.OpenKey(hive, source, 0, winreg.KEY_READ | view) as key:
                        count = winreg.QueryInfoKey(key)[1]
                        if count > 500:
                            raise OSError('Startup entry limit reached')
                        for index in range(count):
                            name, value, _ = winreg.EnumValue(key, index)
                            rows.append(entry('startup', scope + '/' + suffix + '/' + str(view), str(name), str(value).encode()))
                except FileNotFoundError:
                    continue
    return rows


def socket_rows():
    rows = {}
    connections = psutil.net_connections(kind='inet')
    if len(connections) > 10000:
        raise OSError('Socket inventory limit reached')
    for connection in connections:
        if connection.status != psutil.CONN_LISTEN or not connection.laddr:
            continue
        address, port = connection.laddr.ip, connection.laddr.port
        name = str(address) + ':' + str(port)
        rows[name] = entry('listener', 'TCP listening sockets', name, name.encode())
        if len(rows) >= 500:
            raise OSError('Listener inventory limit reached')
    return list(rows.values())


def snapshot(config):
    if not config.get('persistence_inventory', False):
        raise HTTPException(403, 'Enable the read-only persistence inventory locally on this agent first')
    rows, complete, warnings = [], [], []
    providers = [('listener', socket_rows)]
    if platform.system() == 'Linux':
        providers.append(('cron', linux_rows))
    elif platform.system() == 'Windows':
        providers.append(('startup', windows_rows))
    elif platform.system() == 'Darwin':
        from agent.macos import startup_rows
        providers.append(('startup', startup_rows))
    for kind, provider in providers:
        try:
            rows.extend(provider())
            complete.append(kind)
        except (OSError, psutil.Error):
            warnings.append(kind + ' inventory incomplete; no removal conclusions for this provider')
    return {'rows': rows, 'complete': complete, 'warnings': warnings,
            'gaps': ['Read-only metadata; commands and values are deliberately omitted.', 'Private user crontabs, scheduled tasks, macOS background-item databases, Apple system launchd folders and other users\u2019 startup entries are not scanned.']}
