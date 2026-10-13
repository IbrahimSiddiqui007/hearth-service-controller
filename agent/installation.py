"""Opt-in bounded installation metadata; no contents or executable commands exported."""
import hashlib
import json
import os
import stat
import time
from pathlib import Path

from fastapi import HTTPException
from shared.configuration import secret_filename, secret_reasons
from shared.models import redact

NOISE = {'.git', '.cache', '__pycache__', 'node_modules', 'cache', 'logs', 'log', 'tmp', 'temp'}


def safe(path):
    return not any(part.is_symlink() or getattr(part, 'is_junction', lambda: False)() for part in (path, *path.parents))


def watched(config, ref):
    configured = config.get('installation_watch_roots', {}).get(ref, [])
    approved = config.get('file_roots', {}).get(ref, [])
    if not isinstance(configured, list) or len(configured) > 5:
        raise HTTPException(409, 'Installation watching permits at most five locally configured roots')
    roots = []
    for raw in configured:
        path = Path(raw)
        if not path.is_absolute() or not safe(path) or not path.is_dir():
            raise HTTPException(403, 'Watch roots must be existing directories without symlink or junction paths')
        resolved = path.resolve()
        if not any(Path(root).is_absolute() and safe(Path(root)) and resolved.is_relative_to(Path(root).resolve()) for root in approved):
            raise HTTPException(403, 'Installation watch roots must stay within approved service file roots')
        roots.append(resolved)
    return roots


def file_snapshot(config, ref):
    roots = watched(config, ref)
    rows, incomplete, visited, budget = [], False, 0, 0
    started = time.monotonic()
    def inaccessible(error):
        nonlocal incomplete
        incomplete = True
    for index, root in enumerate(roots):
        for folder, dirs, files in os.walk(root, followlinks=False, onerror=inaccessible):
            directory = Path(folder)
            if len(directory.relative_to(root).parts) >= 8:
                dirs[:] = []
                incomplete = True
            dirs[:] = sorted(name for name in dirs if name.lower() not in NOISE and not secret_filename(directory / name) and safe(directory / name))
            for name in sorted(files):
                visited += 1
                if visited > 2000 or len(rows) >= 500 or time.monotonic() - started > 3:
                    return {'rows': rows, 'complete': False, 'roots': [redact(str(p)) for p in roots], 'notice': 'Watch budget reached; missing files cannot imply deletion'}
                target = directory / name
                relative = target.relative_to(root).as_posix()
                if secret_filename(target) or redact(relative) != relative or not safe(target) or name.lower().endswith(('.log', '.tmp', '.swp', '.pyc')):
                    continue
                try:
                    metadata = target.stat()
                    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > 65536:
                        incomplete = True
                        continue
                    budget += metadata.st_size
                    if budget > 2_000_000:
                        return {'rows': rows, 'complete': False, 'roots': [redact(str(p)) for p in roots], 'notice': 'Watch byte budget reached'}
                    descriptor = os.open(target, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0))
                    with os.fdopen(descriptor, 'rb') as stream:
                        opened = os.fstat(stream.fileno())
                        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                            incomplete = True
                            continue
                        content = stream.read(65537)
                    after = target.stat()
                    if not safe(target) or (after.st_ino, after.st_size, after.st_mtime_ns) != (metadata.st_ino, metadata.st_size, metadata.st_mtime_ns):
                        incomplete = True
                        continue
                    text = content.decode('utf-8')
                    if '\0' in text or secret_reasons(text):
                        continue
                    rows.append({'id': str(index) + ':' + relative, 'name': relative, 'root_index': index, 'value': hashlib.sha256(content).hexdigest(), 'bytes': len(content)})
                except (OSError, UnicodeError):
                    incomplete = True
    return {'rows': rows, 'complete': not incomplete, 'roots': [redact(str(p)) for p in roots], 'notice': 'Metadata/hash only; secret, binary, large and noisy files excluded'}


def docker_resources(command):
    rows, completed = [], []
    complete = True
    for kind, argv, fields in (
        ('images', ['docker','image','ls','--no-trunc','--format','{{json .}}'], ('ID','Repository','Tag','Digest')),
        ('networks', ['docker','network','ls','--no-trunc','--format','{{json .}}'], ('ID','Name','Driver')),
        ('volumes', ['docker','volume','ls','--format','{{json .}}'], ('Name','Driver')),
    ):
        try:
            raw = command(argv, timeout=10)
            if len(raw.encode()) > 1_000_000:
                raise ValueError()
            for line in raw.splitlines():
                item = json.loads(line)
                if not isinstance(item, dict) or not isinstance(item.get('Name',item.get('ID')), str):
                    raise ValueError()
                selected = {key:redact(str(item.get(key,'')))[:1024] for key in fields}
                identity = kind + ':' + (selected.get('Name') or selected.get('ID',''))
                # One image can have multiple tags; retain each repository/tag identity.
                if kind == 'images':
                    identity += ':' + selected['Repository'] + ':' + selected['Tag']
                rows.append({'id':identity[:1024],'name':(selected.get('Name') or selected.get('Repository','') + ':' + selected.get('Tag',''))[:255], 'value':hashlib.sha256(str(sorted(selected.items())).encode()).hexdigest(), 'metadata':{'source':kind}})
                if len(rows) > 500:
                    return {'rows':rows[:500],'complete':False,'scope':completed,'notice':'Docker resource limit reached'}
            completed.append(kind)
        except (HTTPException, OSError, ValueError, TypeError):
            complete = False
    return {'rows':rows,'complete':complete,'scope':completed}


def inventory(config, ref, runtime, software, resources=None):
    if ref not in config.get('installation_snapshot_refs', []):
        raise HTTPException(403, 'Installation snapshots require an explicit local reference allow-list')
    result = {'categories': {}, 'notice': 'Observed metadata, not proof of installation ownership or success'}
    for category, source, rows, fields, complete in (
        ('applications', software, software.get('applications', []), ('id', 'name', 'version', 'source'), any(n in software.get('completed', []) for n in ('applications', 'packages')) and not software.get('truncated') and not software.get('warnings')),
        ('ports', software, software.get('ports', []), ('protocol', 'address', 'port', 'pid'), 'ports' in software.get('completed', []) and 'ports' not in software.get('truncated', [])),
        ('services', runtime, runtime.get('services', []), ('agent_ref', 'name', 'runtime', 'image', 'project'), bool(runtime.get('completed_runtimes')) and not runtime.get('warnings')),
        ('containers', runtime, runtime.get('containers', []), ('agent_ref', 'name', 'image', 'project'), 'docker' in runtime.get('completed_runtimes', []) and not runtime.get('warnings')),
    ):
        clean = []
        for row in rows[:500]:
            selected = {key: redact(str(row[key]))[:1024] for key in fields if key in row and row[key] is not None}
            identity = str(row.get('id') or row.get('agent_ref') or '')
            if category == 'ports':
                identity = '|'.join(str(row.get(key, '')) for key in ('protocol', 'address', 'port', 'pid'))
            if not identity or redact(identity) != identity:
                continue
            clean.append({'id': identity[:1024], 'name': selected.get('name', identity)[:255], 'value': hashlib.sha256(str(sorted(selected.items())).encode()).hexdigest(), 'metadata': selected})
        result['categories'][category] = {'rows': clean, 'complete': bool(complete and len(rows) <= 500), 'scope': sorted(runtime.get('completed_runtimes', [])) if category in ('services', 'containers') else sorted(software.get('completed', []))}
    result['categories']['files'] = file_snapshot(config, ref)
    result['categories']['docker_resources'] = resources or {'rows':[],'complete':False,'scope':[], 'notice':'Docker resource metadata unavailable or disabled'}
    return result
