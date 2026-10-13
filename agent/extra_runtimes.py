"""Fixed pm2 profiles, identity-bound foreground processes and approved file log tails."""
import hashlib
import json
import os
import platform
import re
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

import psutil
from fastapi import HTTPException

from agent.observability import process_sample
from shared.models import redact

_process_lock = threading.Lock()


def reference(runtime, name):
    return runtime + '-' + hashlib.sha256(name.encode()).hexdigest()[:12]


def pm2_records(config, command):
    # pm2 can start a daemon on an ordinary CLI query. Only query an already
    # running, agent-owned daemon with its existing IPC socket.
    if not config.get('pm2_home'):
        raise HTTPException(409, 'Configure pm2_home for an existing agent-user pm2 daemon')
    home = Path(config['pm2_home'])
    try:
        pid_path = home / 'pm2.pid'
        if home.is_symlink() or pid_path.is_symlink() or not (home / 'rpc.sock').is_socket():
            raise ValueError('Invalid daemon path')
        daemon = psutil.Process(int(pid_path.read_text(encoding='utf-8').strip()))
        if not daemon.is_running() or not any('GodDaemon' in part for part in daemon.cmdline()):
            raise ValueError('Daemon identity unavailable')
        if hasattr(os, 'getuid') and (pid_path.stat().st_uid != os.getuid() or daemon.uids().real != os.getuid()):
            raise ValueError('Daemon is not agent-owned')
    except (OSError, ValueError, psutil.Error):
        raise HTTPException(409, 'An existing agent-owned pm2 daemon is required; discovery never creates one')
    raw = command(['pm2', 'jlist'], timeout=12)
    if len(raw.encode()) > 4_000_000:
        raise HTTPException(502, 'pm2 inventory exceeds the supported size')
    rows = json.loads(raw)
    if not isinstance(rows, list) or len(rows) > 1000:
        raise HTTPException(502, 'Invalid pm2 inventory')
    if any(not isinstance(row, dict) or not isinstance(row.get('pm2_env', {}), dict) or not isinstance(row.get('monit', {}), dict) for row in rows):
        raise HTTPException(502, 'Invalid pm2 process metadata')
    return rows


def pm2_inventory(config, command):
    rows = []
    for item in pm2_records(config, command):
        env = item.get('pm2_env', {})
        name, identifier = item.get('name'), item.get('pm_id')
        if not isinstance(name, str) or not name or len(name) > 100 or redact(name) != name or not isinstance(identifier, int) or identifier < 0:
            continue
        ref = reference('pm2', name + ':' + str(identifier))
        state = {'online': 'running', 'stopped': 'stopped', 'errored': 'failed', 'launching': 'restarting'}.get(env.get('status'), 'unknown')
        metrics = item.get('monit', {}) if config.get('resource_samples', True) else {}
        cpu, memory = metrics.get('cpu'), metrics.get('memory')
        paths = [env['pm_cwd']] if isinstance(env.get('pm_cwd'), str) else []
        rows.append({'agent_ref': ref, 'name': redact(name)[:100], 'runtime': 'pm2', 'status': state, 'tags': ['discovered', 'pm2'],
                     'description': 'pm2 application instance ' + str(identifier), 'ports': [], 'urls': [], 'paths': paths, 'dependencies': [],
                     'control_handle': {'name': name, 'pm_id': str(identifier)},
                     'capabilities': {'control': name in config.get('allow_pm2', []), 'logs': name in config.get('allow_pm2', []), 'files': False},
                     'metrics': {'cpu_percent': cpu if isinstance(cpu, (int, float)) else None, 'memory_mb': round(memory / 1024 ** 2, 2) if isinstance(memory, (int, float)) else None, 'scope': 'pm2 process'},
                     'runtime_details': {'restart_count': env.get('restart_time'), 'started_at': datetime.fromtimestamp(env['pm_uptime'] / 1000, timezone.utc).isoformat() if isinstance(env.get('pm_uptime'), (int, float)) and 0 < env['pm_uptime'] < 32_503_680_000_000 else None},
                     'locations': {'working_directory': paths[0] if paths else '', 'configuration': [], 'data': [], 'volumes': [], 'logs': [redact(env[key])[:1024] for key in ('pm_out_log_path', 'pm_err_log_path') if isinstance(env.get(key), str)]}})
    return rows


def pm2_args(config, handle, action, command, lines=None, stream=False):
    name, identifier = handle.get('name'), handle.get('pm_id', '')
    if not name or name not in config.get('allow_pm2', []) or not re.fullmatch(r'[0-9]{1,10}', identifier):
        raise HTTPException(403, 'pm2 application and instance must be explicitly allow-listed')
    # Numeric instance IDs prevent pm2 name/namespace/regex expansion.
    matches = [row for row in pm2_records(config, command) if row.get('name') == name and str(row.get('pm_id')) == identifier]
    if len(matches) != 1:
        raise HTTPException(409, 'pm2 instance changed since discovery; rescan before controlling it')
    if lines is not None:
        return ['pm2', 'logs', identifier, '--raw', '--lines', str(lines)] + ([] if stream else ['--nostream'])
    if action == 'start' and matches[0].get('pm2_env', {}).get('status') == 'online':
        return []
    return ['pm2', 'restart' if action == 'start' else action, identifier]


def process_profile(config, name):
    profiles = config.get('process_commands', {})
    profile = profiles.get(name)
    if not isinstance(profile, dict) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}', name or ''):
        raise HTTPException(403, 'Process profile is not configured on this agent')
    argv = profile.get('argv')
    if not isinstance(argv, list) or not argv or len(argv) > 30 or any(not isinstance(arg, str) or '\x00' in arg or len(arg) > 1024 for arg in argv) or not PurePosixPath(argv[0]).is_absolute():
        raise HTTPException(409, 'Process profiles require trusted fixed argv with an absolute executable')
    cwd = Path(profile.get('cwd', ''))
    if not profile.get('cwd') or not cwd.is_dir() or cwd.is_symlink():
        raise HTTPException(409, 'Process profiles require an existing approved working directory')
    return profile, hashlib.sha256(json.dumps([argv, str(cwd.resolve()), profile.get('expected_executable', argv[0])]).encode()).hexdigest()


def state_file(config, name):
    if not config.get('state_dir'):
        raise HTTPException(409, 'Configure a private agent state_dir for process identities')
    root = Path(config['state_dir'])
    if root.is_symlink() or any(parent.is_symlink() for parent in root.parents):
        raise HTTPException(403, 'Agent state directory cannot be a symlink')
    root.mkdir(parents=True, exist_ok=True)
    path = root / (reference('process', name) + '.json')
    if path.is_symlink():
        raise HTTPException(403, 'Process identity state cannot be a symlink')
    return path


def managed_process(config, name):
    profile, key = process_profile(config, name)
    path = state_file(config, name)
    if not path.exists():
        return None
    try:
        record = json.loads(path.read_text(encoding='utf-8'))
        if record.get('profile_key') != key:
            raise HTTPException(409, 'Process profile changed; review its previous running process locally')
        if record.get('status') == 'stopped':
            return None
        if record.get('status') != 'running':
            raise HTTPException(409, 'A prior process launch has an uncertain outcome; inspect it locally before retrying')
        process = psutil.Process(record['pid'])
        if process.create_time() != record['created_at'] or process.exe() != record['executable']:
            raise HTTPException(409, 'Saved PID identity changed; no process signal was sent')
        if process.status() == psutil.STATUS_ZOMBIE or not process.is_running():
            return None
        return process
    except psutil.NoSuchProcess:
        return None
    except (OSError, ValueError, KeyError, psutil.AccessDenied):
        raise HTTPException(409, 'Process identity cannot be safely verified')


def save_state(path, record):
    temporary = path.with_suffix('.tmp')
    if temporary.is_symlink():
        raise HTTPException(403, 'Process state temporary file cannot be a symlink')
    try:
        with temporary.open('w', encoding='utf-8') as stream:
            json.dump(record, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def process_control(config, name, action):
    if platform.system() not in ('Linux', 'Darwin'):
        raise HTTPException(409, 'Configured process controls require Linux or macOS')
    if name not in config.get('allow_processes', []):
        raise HTTPException(403, 'Process profile is not allow-listed for controls')
    with _process_lock:
        profile, key = process_profile(config, name)
        process = managed_process(config, name)
        if process and action == 'start':
            return 'Configured process is already running'
        if process and action in ('stop', 'restart'):
            try:
                process.terminate()  # psutil also prechecks PID reuse before signalling.
                process.wait(timeout=10)
            except psutil.NoSuchProcess:
                pass
            except psutil.TimeoutExpired:
                raise HTTPException(504, 'Process did not stop in time; no automatic force-kill or replacement was attempted')
            except psutil.AccessDenied:
                raise HTTPException(403, 'Agent cannot signal this configured process')
        if action == 'stop':
            return 'Configured process is stopped'
        path = state_file(config, name)
        save_state(path, {'profile_key': key, 'status': 'starting'})
        env = {key: value for key, value in os.environ.items() if not key.startswith('PSC_')}
        try:
            child = subprocess.Popen(profile['argv'], cwd=profile['cwd'], env=env, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True, shell=False)
        except OSError:
            save_state(path, {'profile_key': key, 'status': 'stopped'})
            raise HTTPException(503, 'Configured executable could not be started')
        try:
            started = psutil.Process(child.pid)
            executable = started.exe()
            if executable != profile.get('expected_executable', profile['argv'][0]):
                raise HTTPException(503, 'Started process identity could not be verified; inspect the configured process locally')
            record = {'pid': child.pid, 'created_at': started.create_time(), 'executable': executable, 'profile_key': key, 'status': 'running'}
            save_state(path, record)
        except (OSError, psutil.Error):
            raise HTTPException(503, 'Started process outcome could not be verified; inspect the process locally')
        return 'Configured process started; runtime observation is required to verify its state'


def process_inventory(config):
    rows = []
    for name in list(config.get('process_commands', {}))[:100]:
        profile, _ = process_profile(config, name)
        try:
            process = managed_process(config, name)
            state = 'running' if process else 'stopped'
        except HTTPException:
            process, state = None, 'unknown'
        ref = reference('process', name)
        metrics = process_sample(process.pid)['metrics'] if process and config.get('resource_samples', True) else {'cpu_percent': None, 'memory_mb': None, 'scope': 'configured process unavailable'}
        rows.append({'agent_ref': ref, 'name': name, 'runtime': 'process', 'status': state, 'description': 'Configured foreground process', 'tags': ['configured'],
                     'ports': [], 'urls': [], 'paths': [profile['cwd']], 'dependencies': [], 'control_handle': {'name': name},
                     'capabilities': {'control': name in config.get('allow_processes', []) and state != 'unknown', 'logs': ref in config.get('log_files', {}), 'files': False},
                     'metrics': metrics, 'locations': {'working_directory': profile['cwd'], 'configuration': [], 'data': [], 'volumes': [], 'logs': [config['log_files'][ref]] if ref in config.get('log_files', {}) else []}})
    return rows


def approved_log(config, ref, safe_path):
    value = config.get('log_files', {}).get(ref)
    if not isinstance(value, str):
        raise HTTPException(403, 'No approved file-log profile for this service')
    target = Path(value)
    for root in config.get('file_roots', {}).get(ref, []):
        try:
            relative = target.relative_to(Path(root))
            resolved = safe_path(Path(root), str(relative))
            if not resolved.is_file() or any(part.is_symlink() for part in (target, *target.parents)):
                raise HTTPException(403, 'File log must be an existing regular file without symlink paths')
            return resolved
        except ValueError:
            continue
    raise HTTPException(403, 'Configured log is outside the approved file roots')


def file_log(config, ref, lines, safe_path):
    target = approved_log(config, ref, safe_path)
    with target.open('rb') as stream:
        stream.seek(0, os.SEEK_END)
        size = stream.tell()
        stream.seek(max(0, size - 2_000_000))
        raw = stream.read(2_000_000)
    if b'\x00' in raw:
        raise HTTPException(415, 'Binary file logs cannot be displayed')
    text = raw.decode('utf-8', errors='replace')
    if size > 2_000_000:
        text = text.partition('\n')[2]
    return redact('\n'.join(text.splitlines()[-lines:]))[-100_000:]
