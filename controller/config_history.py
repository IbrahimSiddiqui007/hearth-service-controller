"""Per-service local Git snapshots. No remote operations, hooks or global Git changes."""
import hashlib
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from fastapi import HTTPException

from controller.store import now
from shared.configuration import secret_filename, secret_reasons


async def capture_due(store, capture, lock, maximum=3):
    """Bound each live polling pass without changing notes or service revisions."""
    attempts = 0
    for service in store.all('services'):
        if attempts >= maximum:
            break
        async with lock:
            current = store.get('services', service['id'])
            previous = current.get('config_capture_at')
            due = not previous or (datetime.now(timezone.utc) - datetime.fromisoformat(previous)).total_seconds() >= current.get('config_capture_interval_s', 300)
            if not current.get('track_configuration') or not due:
                continue
            current['config_capture_at'] = now()
            store.put('services', current)
        try:
            await capture(service['id'])
        except HTTPException:
            pass
        attempts += 1
    return attempts


def file_key(service, info):
    return hashlib.sha256((service['host_id'] + '\0' + info.get('resolved_path', info['path'])).encode()).hexdigest()


def repository(store, sid):
    folder = store.root / 'config-history' / hashlib.sha256(sid.encode()).hexdigest()[:32]
    if not folder.resolve().is_relative_to(store.root.resolve()) or folder.is_symlink() or (folder / '.git').is_symlink():
        raise HTTPException(409, 'Configuration history must remain within the controller workspace')
    folder.mkdir(parents=True, exist_ok=True)
    if (folder / '.gitattributes').exists() or (folder / '.git' / 'info' / 'attributes').exists():
        raise HTTPException(409, 'Custom Git attributes are not supported in managed configuration history')
    (folder / 'disabled-hooks').mkdir(exist_ok=True)
    return folder


def git(folder, *args):
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT='0')
    # A commit:path argument can exceed Windows MAX_PATH during Git's path
    # disambiguation even when every real worktree file has a shorter path.
    fixed = ['git', '-c', 'core.hooksPath=' + str(folder / 'disabled-hooks'), '-c', 'core.fsmonitor=false', '-c', 'core.autocrlf=false', '-c', 'core.longpaths=true', '-c', 'commit.gpgsign=false', '-c', 'user.name=Hearth owner', '-c', 'user.email=hearth@localhost']
    try:
        result = subprocess.run(fixed + list(args), cwd=folder, env=env, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=15)
        if result.returncode:
            raise HTTPException(409, 'Local configuration history could not complete its Git operation')
        return result.stdout if args and args[0] == 'show' else result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        raise HTTPException(409, 'Git is required for configuration history; install it on the controller')


def snapshot(store, service, info, content, message, status='checkpoint'):
    if secret_filename(info['path']) or secret_reasons(content) or secret_reasons(message):
        raise HTTPException(422, 'Secret-bearing content and messages are excluded from configuration history')
    key = file_key(service, info)
    folder = repository(store, service['id'])
    if not (folder / '.git').is_dir():
        git(folder, 'init', '-q', '--initial-branch=main')
    filename = key + '.txt'
    target = folder / filename
    if target.is_symlink():
        raise HTTPException(409, 'Snapshot files cannot be symlinks')
    target.write_bytes(content.encode('utf-8'))
    git(folder, 'add', '--', filename)
    # --allow-empty records explicit restores even when content matches a past version.
    git(folder, 'commit', '-q', '--allow-empty', '-m', message)
    commit = git(folder, 'rev-parse', 'HEAD')
    with store.connection() as db:
        cursor = db.execute('INSERT INTO config_versions(service_id,file_key,path,root_index,ts,git_commit,etag,message,status) VALUES(?,?,?,?,?,?,?,?,?)',
                            (service['id'], key, info['path'], info.get('root_index', 0), now(), commit, info.get('etag', ''), message, status))
        return cursor.lastrowid


def version(store, sid, key, version_id):
    with store.connection() as db:
        row = db.execute("SELECT * FROM config_versions WHERE id=? AND service_id=? AND file_key=? AND status IN ('checkpoint','applied')", (version_id, sid, key)).fetchone()
    if not row:
        raise HTTPException(404, 'Configuration version does not belong to this service and file')
    result = dict(row)
    if not re.fullmatch(r'[a-f0-9]{40,64}', result['git_commit']) or not re.fullmatch(r'[a-f0-9]{64}', key):
        raise HTTPException(409, 'Invalid managed snapshot reference')
    result['content'] = git(repository(store, sid), 'show', result['git_commit'] + ':' + key + '.txt')
    if secret_reasons(result['content']) or secret_filename(result['path']):
        raise HTTPException(403, 'This version is excluded by the current secret policy')
    return result
