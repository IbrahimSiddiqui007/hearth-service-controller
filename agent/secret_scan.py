"""Opt-in exact configuration files, without crawling or exporting secret content."""
import stat
from pathlib import Path

from fastapi import HTTPException

from shared.configuration import secret_filename
from shared.secret_findings import categories, CATEGORIES


def scan(config, ref, safe_path):
    profiles = config.get('secret_scan_files', {}).get(ref, [])
    if not isinstance(profiles, list) or len(profiles) > 20:
        return {'categories': [], 'scope': 'unavailable'}
    reasons, remaining = set(), 256_000
    complete = True
    for profile in profiles:
        try:
            if not isinstance(profile, dict) or set(profile) != {'root_index', 'path'} or type(profile['root_index']) is not int or profile['root_index'] < 0:
                raise ValueError()
            roots = config.get('file_roots', {}).get(ref, [])
            root = Path(roots[profile['root_index']])
            original = root / profile['path']
            if any(part.is_symlink() or getattr(part, 'is_junction', lambda: False)() for part in (original, *original.parents)):
                raise ValueError()
            target = safe_path(root, profile['path'])
            metadata = target.stat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError()
            if secret_filename(target):
                reasons.add(CATEGORIES[3])  # Filename only; existing exclusion remains intact.
                continue
            if metadata.st_size > 64_000 or remaining < metadata.st_size:
                raise ValueError()
            with target.open('rb') as stream:
                raw = stream.read(min(64_001, remaining + 1))
            if len(raw) > 64_000 or len(raw) > remaining or b'\x00' in raw:
                raise ValueError()
            remaining -= len(raw)
            reasons.update(categories(raw.decode('utf-8')))
        except (HTTPException, OSError, UnicodeError, ValueError, TypeError, KeyError, IndexError):
            complete = False
    return {'categories': [reason for reason in CATEGORIES if reason in reasons],
            'scope': 'complete' if complete and profiles else 'incomplete' if profiles else 'disabled'}
