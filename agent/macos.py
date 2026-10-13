"""launchd discovery and explicitly approved current-user GUI LaunchAgent controls."""
import hashlib
import os
import platform
import plistlib
import re
from pathlib import Path

from fastapi import HTTPException
from agent.software_inventory import safe_metadata
from shared.models import redact


def launchd_profile(config, label):
    if platform.system() != 'Darwin' or not hasattr(os, 'getuid') or os.getuid() <= 0:
        raise HTTPException(403, 'LaunchAgent controls require an ordinary macOS agent account')
    if not isinstance(label, str) or label.startswith('com.apple.') or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,254}', label):
        raise HTTPException(403, 'Only explicitly approved non-Apple LaunchAgent labels can be controlled')
    path = config.get('allow_launchd', {}).get(label)
    if not isinstance(path, str) or not Path(path).is_absolute():
        raise HTTPException(403, 'LaunchAgent is not explicitly approved on this agent')
    source = Path(path)
    root = Path.home() / 'Library/LaunchAgents'
    if not source.is_relative_to(root) or source.suffix != '.plist':
        raise HTTPException(403, 'Approved LaunchAgents must be in this agent account Library/LaunchAgents folder')
    try:
        for part in (source, *source.parents):
            info = part.stat()
            if part.is_symlink() or info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
                raise OSError('Untrusted LaunchAgent metadata path')
        if source.stat().st_uid != os.getuid():
            raise OSError('The agent account must own its approved plist')
        raw = safe_metadata(source)
        metadata = plistlib.loads(raw)
        if not isinstance(metadata, dict) or metadata.get('Label') != label or metadata.get('UserName') or metadata.get('GroupName') or metadata.get('RootDirectory'):
            raise ValueError('LaunchAgent identity or scope is invalid')
    except (OSError, ValueError, plistlib.InvalidFileException) as exc:
        raise HTTPException(409, 'Approved LaunchAgent metadata must retain its label, ordinary account scope and trusted ownership/permissions') from exc
    return source, hashlib.sha256(raw).hexdigest(), metadata, 'gui/' + str(os.getuid())


def gui_job(source, label, domain, command):
    output = command(['/bin/launchctl', 'print', domain], timeout=10)
    if len(output) > 2_000_000 or not output.lstrip().startswith(domain + ' = {'):
        raise HTTPException(409, 'The agent account GUI launchd domain could not be verified')
    target = domain + '/' + label
    try:
        output = command(['/bin/launchctl', 'print', target], timeout=10)
    except HTTPException as exc:
        detail = str(exc.detail)
        if exc.status_code == 502 and detail.lstrip().startswith('Could not find service') and label in detail:
            return {'loaded': False, 'status': 'stopped', 'pid': None}
        raise
    if len(output) > 262144 or not output.lstrip().startswith(target + ' = {'):
        raise HTTPException(409, 'LaunchAgent observation is invalid; no control was sent')
    paths = re.findall(r'(?m)^\s*path = (.+)$', output)
    if len(paths) != 1 or Path(paths[0].strip()) != source:
        raise HTTPException(409, 'Loaded LaunchAgent plist identity differs; no control was sent')
    pids = re.findall(r'(?m)^\s*pid = ([0-9]+)\s*$', output)
    states = re.findall(r'(?m)^\s*state = (.+)$', output)
    state = states[0].strip() if len(states) == 1 else 'unknown'
    return {'loaded': True, 'status': 'running' if state == 'running' and len(pids) == 1 else 'stopped' if state in ('not running', 'waiting') else 'unknown', 'pid': int(pids[0]) if len(pids) == 1 else None}


def launchd_control(config, handle, action, command):
    label = handle.get('name', '')
    source, fingerprint, metadata, domain = launchd_profile(config, label)
    if handle.get('domain') != domain or handle.get('plist_hash') != fingerprint:
        raise HTTPException(409, 'LaunchAgent account or plist changed since discovery; review it again')
    observed = gui_job(source, label, domain, command)
    if observed['status'] == 'unknown':
        raise HTTPException(409, 'LaunchAgent state is unknown; inspect it locally before controlling it')
    target = domain + '/' + label
    def send(argv):
        current_source, current_hash, _, current_domain = launchd_profile(config, label)
        if (current_source, current_hash, current_domain) != (source, fingerprint, domain):
            raise HTTPException(409, 'Approved LaunchAgent changed while preparing control; inspect before retrying')
        return command(argv, timeout=30)
    if action == 'stop':
        if observed['loaded']:
            send(['/bin/launchctl', 'bootout', target])
    elif action in ('start', 'restart'):
        if action == 'start' and observed['status'] == 'running':
            return 'Approved LaunchAgent is already running'
        if not observed['loaded']:
            send(['/bin/launchctl', 'bootstrap', domain, str(source)])
        send(['/bin/launchctl', 'kickstart', *(['-k'] if action == 'restart' and observed['loaded'] else []), target])
    else:
        raise HTTPException(422, 'Unsupported LaunchAgent action')
    return 'Approved LaunchAgent action completed; resulting state requires a fresh observation. Boot preferences were not changed.'


def launchd_inventory(config, command, include_system=False):
    if platform.system() != 'Darwin':
        raise HTTPException(409, 'launchd inventory requires macOS')
    output = command(['/bin/launchctl', 'list'], timeout=15)
    if len(output.encode()) > 2_000_000:
        raise HTTPException(502, 'launchd inventory exceeds the supported limit')
    rows = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) != 3 or not re.fullmatch(r'-|[0-9]+', parts[0]) or not re.fullmatch(r'-?[0-9]+', parts[1]):
            continue
        label = parts[2]
        if len(label) > 255 or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', label):
            continue
        if label.startswith('com.apple.') and not include_system:
            continue
        if len(rows) >= 1000:
            raise HTTPException(502, 'launchd job count exceeds the supported limit')
        # list describes only the calling account's current launchd context.
        # A successful exit is stopped; nonzero is failed; '-' PID never means running.
        rows.append({'agent_ref': 'launchd-' + hashlib.sha256(label.encode()).hexdigest()[:12],
            'name': label[:100], 'runtime': 'launchd', 'status': 'running' if parts[0] != '-' else 'failed' if parts[1] != '0' else 'stopped',
            'description': 'Read-only job in the agent account launchd context', 'tags': ['macOS', 'discovered'],
            'ports': [], 'urls': [], 'paths': [], 'dependencies': [], 'control_handle': {'name': label},
            'capabilities': {'control': False, 'logs': False, 'files': False}, 'system_unit': label.startswith('com.apple.'),
            'runtime_details': {'scope': 'agent launchd context', 'pid': int(parts[0]) if parts[0] != '-' else None,
                                'last_exit_status': int(parts[1]), 'enabled_state': 'unknown'}})
    for label in list(config.get('allow_launchd', {}))[:100]:
        source, fingerprint, metadata, domain = launchd_profile(config, label)
        observed = gui_job(source, label, domain, command)
        rows = [row for row in rows if row['control_handle'].get('name') != label]
        rows.append({'agent_ref': 'launchd-' + hashlib.sha256(label.encode()).hexdigest()[:12], 'name': label[:100],
            'runtime': 'launchd', 'status': observed['status'], 'description': 'Explicitly approved GUI LaunchAgent owned by the agent account',
            'tags': ['macOS', 'discovered'], 'ports': [], 'urls': [], 'paths': [str(source)], 'dependencies': [],
            'control_handle': {'name': label, 'domain': domain, 'plist_hash': fingerprint},
            'capabilities': {'control': observed['status'] != 'unknown', 'logs': False, 'files': False},
            'runtime_details': {'scope': domain, 'loaded': observed['loaded'], 'pid': observed['pid'], 'enabled_state': 'not modified'},
            'locations': {'working_directory': redact(metadata.get('WorkingDirectory', ''))[:1024] if isinstance(metadata.get('WorkingDirectory', ''), str) else '', 'configuration': [str(source)], 'data': [], 'volumes': [], 'logs': []}})
    if len(rows) > 1000:
        raise HTTPException(502, 'LaunchAgent inventory exceeds the supported limit')
    return rows


def startup_rows(roots=None):
    from agent.persistence import entry
    roots = roots if roots is not None else [Path.home() / 'Library/LaunchAgents', Path('/Library/LaunchAgents'), Path('/Library/LaunchDaemons')]
    rows = []
    for root in roots:
        if root.is_symlink():
            raise OSError('Unsafe launchd metadata root')
        if not root.exists():
            continue
        for index, path in enumerate(root.iterdir()):
            if index >= 500:
                raise OSError('Launchd metadata inventory limit reached')
            if path.suffix != '.plist':
                continue
            raw = safe_metadata(path)
            try:
                metadata = plistlib.loads(raw)
            except (ValueError, plistlib.InvalidFileException) as exc:
                raise OSError('Invalid launchd metadata') from exc
            label = metadata.get('Label') if isinstance(metadata, dict) else None
            if not isinstance(label, str) or not label or len(label) > 255:
                raise OSError('Invalid launchd identity')
            # Fingerprint full content for change detection; never export Program,
            # ProgramArguments, EnvironmentVariables or command-bearing values.
            rows.append(entry('startup', str(root), redact(label), raw))
            if len(rows) >= 1000:
                raise OSError('Launchd metadata inventory limit reached')
    return rows
