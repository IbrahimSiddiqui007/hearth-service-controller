"""Read-only Linux package/desktop and macOS bundle inventory; never launch apps."""
import configparser
import hashlib
import platform
import plistlib
from pathlib import Path
import psutil

from fastapi import HTTPException
from shared.models import redact
from agent.windows_observability import process_inventory, port_inventory

LIMIT = 2000


def application(name, version, source, location='', publisher='', scope='machine'):
    return {'id': hashlib.sha256((source + '\0' + location + '\0' + name).encode()).hexdigest(),
            'name': redact(str(name))[:255], 'version': redact(str(version))[:100], 'publisher': redact(str(publisher))[:255],
            'source': source, 'scope': scope, 'install_location': redact(str(location))[:1024]}


def bounded_output(command, argv, maximum=2_000_000):
    raw = command(argv, timeout=15)
    if len(raw.encode()) > maximum:
        raise HTTPException(502, 'Software provider output exceeds the supported size limit')
    return raw


def linux_packages(config, command, distro):
    family = set((distro.get('ID', '') + ' ' + distro.get('ID_LIKE', '')).lower().split())
    if family.intersection(('debian', 'ubuntu')):
        raw = bounded_output(command, ['dpkg-query', '-W', '-f=${db:Status-Status}\t${binary:Package}\t${Version}\n'])
        rows = []
        for line in raw.splitlines():
            parts = line.split('\t')
            if len(parts) == 3 and parts[0] == 'installed':
                rows.append(application(parts[1], parts[2], 'dpkg'))
    elif family.intersection(('arch', 'cachyos', 'manjaro')):
        rows = [application(parts[0], parts[1], 'pacman') for line in bounded_output(command, ['pacman', '-Q']).splitlines() if len(parts := line.split()) == 2]
    elif family.intersection(('fedora', 'rhel', 'centos', 'opensuse', 'suse')):
        rows = [application(parts[0], parts[1], 'rpm') for line in bounded_output(command, ['rpm', '-qa', '--qf', '%{NAME}\t%{VERSION}-%{RELEASE}\n']).splitlines() if len(parts := line.split('\t')) == 2]
    else:
        raise HTTPException(409, 'Native package inventory currently supports Debian/Ubuntu, Arch/CachyOS and RPM families')
    truncated = len(rows) > LIMIT
    return rows[:LIMIT], truncated


def safe_metadata(path, maximum=262144):
    if any(part.is_symlink() for part in (path, *path.parents)) or not path.is_file():
        raise OSError('Metadata must be a regular file without symlink paths')
    with path.open('rb') as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise OSError('Metadata exceeds the supported size')
    return raw


def entries(root, warnings):
    try:
        yield from root.iterdir()
    except OSError:
        warnings.append('An application metadata folder was unavailable to this agent account')


def desktop_apps(roots=None):
    roots = roots if roots is not None else [Path('/usr/share/applications'), Path.home() / '.local/share/applications']
    rows, warnings, truncated = [], [], False
    for root in roots:
        if len(rows) >= LIMIT:
            truncated = True
            break
        if root.is_symlink() or not root.is_dir():
            continue
        count = 0
        for path in entries(root, warnings):
            count += 1
            if count > 3000:
                truncated = True
                break
            if path.suffix != '.desktop':
                continue
            try:
                parsed = configparser.ConfigParser(interpolation=None, strict=False)
                parsed.read_string(safe_metadata(path).decode('utf-8'))
                entry = parsed['Desktop Entry']
                if entry.get('Type') != 'Application' or entry.get('Hidden', '').lower() == 'true' or entry.get('NoDisplay', '').lower() == 'true':
                    continue
                name = entry.get('Name', '')
                if name:
                    rows.append(application(name, '', 'desktop entry', str(path), scope='agent user' if root != Path('/usr/share/applications') else 'machine'))
                # Exec, TryExec and arbitrary URLs are never selected or executed.
            except (OSError, UnicodeError, configparser.Error, KeyError):
                warnings.append('Some desktop application metadata was unavailable or invalid')
            if len(rows) >= LIMIT:
                truncated = True
                break
    return rows, list(dict.fromkeys(warnings)), truncated


def mac_apps(config, roots=None):
    roots = roots if roots is not None else [Path('/Applications'), Path.home() / 'Applications'] + ([Path('/System/Applications')] if config.get('macos_system_apps', False) else [])
    rows, warnings, truncated, seen = [], [], False, set()
    for root in roots:
        if len(rows) >= LIMIT:
            truncated = True
            break
        if root.is_symlink() or not root.is_dir():
            continue
        candidates = []
        for index, path in enumerate(entries(root, warnings)):
            if index >= 3000:
                truncated = True
                break
            if path.suffix == '.app':
                candidates.append(path)
            elif path.name == 'Utilities' and path.is_dir() and not path.is_symlink():
                for nested_index, nested in enumerate(entries(path, warnings)):
                    if nested_index >= 500:
                        truncated = True
                        break
                    if nested.suffix == '.app':
                        candidates.append(nested)
        for bundle in candidates:
            if str(bundle) in seen:
                continue
            seen.add(str(bundle))
            try:
                info = plistlib.loads(safe_metadata(bundle / 'Contents/Info.plist'))
                if not isinstance(info, dict):
                    raise ValueError('Invalid app metadata')
                name = info.get('CFBundleDisplayName') or info.get('CFBundleName') or bundle.stem
                version = info.get('CFBundleShortVersionString') or info.get('CFBundleVersion') or ''
                publisher = info.get('CFBundleIdentifier', '')
                if any(not isinstance(value, str) for value in (name, version, publisher)):
                    raise ValueError('Invalid app metadata fields')
                rows.append(application(name, version, 'macOS app bundle', str(bundle), publisher, 'agent user' if root == Path.home() / 'Applications' else 'machine'))
                # Do not launch/codesign applications or export bundle executable/env.
            except (OSError, ValueError, plistlib.InvalidFileException):
                warnings.append('Some application bundle metadata was unavailable or invalid')
            if len(rows) >= LIMIT:
                truncated = True
                break
    return rows, list(dict.fromkeys(warnings)), truncated


def snapshot(config, command):
    system = platform.system()
    if system not in ('Linux', 'Darwin'):
        raise HTTPException(409, 'This software provider requires Linux or macOS')
    result = {'os': system, 'physical_host_id': redact(str(config.get('physical_host_id', '')))[:80], 'applications': [], 'processes': [], 'ports': [], 'events': [], 'completed': [], 'warnings': [], 'truncated': [],
              'coverage': 'Read-only local package/app and agent-account process/socket metadata. No commands, uninstall strings or remote-supplied help links are exported.'}
    if system == 'Linux':
        try:
            distro = platform.freedesktop_os_release()
        except OSError:
            distro = {}
        result['distribution'] = redact(distro.get('ID', 'unknown'))[:80]
        if config.get('software_packages', True):
            try:
                rows, truncated = linux_packages(config, command, distro)
                result['applications'].extend(rows)
                result['completed'].append('packages')
                if truncated:
                    result['truncated'].append('packages')
            except (HTTPException, OSError, ValueError):
                result['warnings'].append('Native package inventory is unavailable; existing packages were not changed')
        rows, warnings, truncated = desktop_apps()
        result['applications'] = rows + result['applications']
        result['warnings'].extend(warnings)
        result['completed'].append('applications')
    else:
        rows, warnings, truncated = mac_apps(config)
        result['applications'] = rows
        result['warnings'].extend(warnings)
        result['completed'].append('applications')
        result['warnings'].append('macOS application inventory is limited to standard Applications folders; other users and installer receipts are not scanned')
    if truncated or len(result['applications']) > LIMIT:
        result['truncated'].append('applications')
    result['applications'] = result['applications'][:LIMIT]
    for name, provider in (('processes', process_inventory), ('ports', port_inventory)):
        try:
            rows = provider()
            result[name] = rows
            result['completed'].append(name)
            if len(rows) >= 500:
                result['truncated'].append(name)
        except (OSError, psutil.Error, ValueError):
            # psutil platform/provider errors never turn absent data into empty
            # verified inventory. Details may contain private process arguments.
            result['warnings'].append(name + ' inventory unavailable to this agent account')
    return result
