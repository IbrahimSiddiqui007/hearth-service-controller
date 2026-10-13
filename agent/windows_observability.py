"""Read-only Windows metadata; no product repair, uninstall, process or service control."""
import hashlib
import json
import platform
import socket
from datetime import datetime, timezone

import psutil
from fastapi import HTTPException

from shared.models import redact
from shared.software_guides import guides

UNINSTALL = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'


def text(value, limit=500):
    return redact(str(value or '').replace('\x00', ''))[:limit]


def registry_apps(registry=None):
    if registry is None:
        import winreg as registry
    rows, warnings, seen = [], [], set()
    for hive, scope in ((registry.HKEY_LOCAL_MACHINE, 'machine'), (registry.HKEY_CURRENT_USER, 'agent user')):
        for view in (registry.KEY_WOW64_64KEY, registry.KEY_WOW64_32KEY):
            try:
                with registry.OpenKey(hive, UNINSTALL, 0, registry.KEY_READ | view) as parent:
                    for index in range(min(registry.QueryInfoKey(parent)[0], 2000)):
                        if len(rows) >= 2000:
                            break
                        try:
                            key_name = registry.EnumKey(parent, index)
                            with registry.OpenKey(parent, key_name, 0, registry.KEY_READ | view) as key:
                                def value(field):
                                    try:
                                        return registry.QueryValueEx(key, field)[0]
                                    except OSError:
                                        return ''
                                name = text(value('DisplayName'), 255)
                                if not name or value('SystemComponent') == 1:
                                    continue
                                publisher, version = text(value('Publisher'), 255), text(value('DisplayVersion'), 100)
                                identity = (scope, name.casefold(), version, publisher.casefold())
                                if identity in seen:
                                    continue
                                seen.add(identity)
                                rows.append({'id': hashlib.sha256(repr(identity).encode()).hexdigest()[:20], 'name': name,
                                             'publisher': publisher, 'version': version, 'scope': scope, 'source': 'uninstall registry',
                                             'install_location': text(value('InstallLocation'), 1024), **guides(name, publisher)})
                        except OSError:
                            continue
            except FileNotFoundError:
                continue
            except OSError:
                warnings.append('An uninstall registry view could not be read; other users and protected entries may be absent.')
    return sorted(rows, key=lambda row: row['name'].casefold()), list(dict.fromkeys(warnings))


def package_apps(command):
    # Current agent-user packages only. All-user inventory would require elevation.
    script = "Get-AppxPackage | Select-Object -First 500 Name,Version,Publisher,InstallLocation,NonRemovable | ConvertTo-Json -Compress"
    result = json.loads(command(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script], timeout=15) or '[]')
    if isinstance(result, dict):
        result = [result]
    if not isinstance(result, list):
        raise ValueError('Invalid package inventory')
    rows = []
    for item in result[:500]:
        if not isinstance(item, dict) or not isinstance(item.get('Name'), str):
            continue
        name, publisher = text(item['Name'], 255), text(item.get('Publisher'), 255)
        rows.append({'id': hashlib.sha256(('package:' + name).encode()).hexdigest()[:20], 'name': name,
                     'version': text(item.get('Version'), 100), 'publisher': publisher, 'scope': 'agent user',
                     'source': 'Windows package', 'install_location': text(item.get('InstallLocation'), 1024),
                     'non_removable': item.get('NonRemovable') is True, **guides(name, publisher)})
    return rows


def process_inventory():
    rows = []
    for process in psutil.process_iter(['pid', 'name', 'exe', 'create_time']):
        if len(rows) >= 500:
            break
        try:
            item = process.info
            rows.append({'pid': item['pid'], 'name': text(item.get('name'), 255), 'executable': text(item.get('exe'), 1024),
                         'started_at': datetime.fromtimestamp(item['create_time'], timezone.utc).isoformat() if item.get('create_time') else None})
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError, ValueError):
            continue
    return rows


def port_inventory():
    rows = []
    for item in psutil.net_connections(kind='inet'):
        if len(rows) >= 500:
            break
        udp = item.type == socket.SOCK_DGRAM
        if not item.laddr or (not udp and item.status != psutil.CONN_LISTEN):
            continue
        rows.append({'pid': item.pid, 'address': text(item.laddr.ip, 100), 'port': item.laddr.port, 'protocol': 'udp' if udp else 'tcp'})
    return rows


def event_inventory(command):
    script = "$ErrorActionPreference='Stop'; Get-WinEvent -FilterHashtable @{LogName=@('System','Application');Level=@(1,2,3)} -MaxEvents 40 | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,LogName,Message | ConvertTo-Json -Compress -Depth 3"
    result = json.loads(command(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script], timeout=15) or '[]')
    if isinstance(result, dict):
        result = [result]
    if not isinstance(result, list):
        raise ValueError('Invalid Event Log inventory')
    return [{'timestamp': text(item.get('TimeCreated'), 100), 'event_id': item.get('Id'), 'level': text(item.get('LevelDisplayName'), 50),
             'provider': text(item.get('ProviderName'), 255), 'log': text(item.get('LogName'), 50), 'message': text(item.get('Message'), 1000)}
            for item in result[:40] if isinstance(item, dict)]


def snapshot(config, command):
    if platform.system() != 'Windows':
        raise HTTPException(409, 'Windows inventory requires an active Windows agent')
    result = {'os': 'Windows', 'physical_host_id': text(config.get('physical_host_id'), 80),
              'applications': [], 'processes': [], 'ports': [], 'events': [], 'warnings': [], 'completed': []}
    for name, provider in [('applications', registry_apps), ('processes', process_inventory), ('ports', port_inventory)]:
        try:
            rows = provider()
            if name == 'applications':
                rows, warnings = rows
                result['warnings'].extend(warnings)
            result[name] = rows
            result['completed'].append(name)
        except (OSError, ValueError, ImportError, psutil.Error, HTTPException):
            # Access limitations are evidence gaps, never proof of empty inventory.
            result['warnings'].append(name + ' inventory unavailable to the agent user')
    for name, enabled, provider in [('packages', config.get('windows_packages', True), package_apps),
                                     ('events', config.get('windows_events', False), event_inventory)]:
        if not enabled:
            result['warnings'].append(name + ' inventory disabled in agent configuration')
            continue
        try:
            rows = provider(command)
            if name == 'packages':
                result['applications'].extend(rows)
            else:
                result['events'] = rows
            result['completed'].append(name)
        except (OSError, ValueError, psutil.Error, HTTPException):
            result['warnings'].append(name + ' inventory unavailable to the agent user')
    result['coverage'] = 'Machine registrations and the agent user only; protected entries and other users may be absent.'
    result['truncated'] = []
    while len(json.dumps(result).encode()) > 3_000_000:
        name = max(('applications', 'processes', 'ports', 'events'), key=lambda key: len(result[key]))
        if name not in result['truncated']:
            result['truncated'].append(name)
        del result[name][-100:]
    return result
