"""Configuration validation and conservative exclusion from version history."""
import json
import math
import re
import tomllib
from collections import Counter
from pathlib import Path

import yaml
from fastapi import HTTPException

from shared.models import redact


def secret_filename(path):
    name = Path(path).name.lower()
    return name.startswith('.env') or Path(name).suffix in ('.pem', '.key', '.pfx', '.p12') or name in ('id_rsa', 'id_ed25519', 'authorized_keys') or bool(re.search(r'(^|[_.-])(secrets?|credentials?)([_.-]|$)', name))


def secret_reasons(content):
    reasons = []
    if redact(content) != content:
        reasons.append('Recognized secret assignment or credential URL')
    if re.search(r'-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----|\b(?:ghp_|github_pat_|sk-proj-)[a-zA-Z0-9_-]{16,}', content):
        reasons.append('Private key or recognized credential token')
    for token in re.findall(r'(?<![\w/-])[a-zA-Z0-9+/=_-]{40,}(?![\w/-])', content):
        if re.fullmatch(r'[a-fA-F0-9]+', token) or '${' in token:
            continue
        frequencies = Counter(token)
        entropy = -sum(count / len(token) * math.log2(count / len(token)) for count in frequencies.values())
        if entropy >= 4.6 and any(c.isupper() for c in token) and any(c.islower() for c in token) and any(c.isdigit() for c in token):
            reasons.append('High-entropy value; keep possible credentials out of history')
            break
    return reasons


def validate_configuration(path, content):
    if secret_filename(path) or secret_reasons(content):
        raise HTTPException(422, 'Secret-bearing files cannot be edited or included in configuration history; use vault references')
    if '\x00' in content or len(content.encode('utf-8')) > 2_000_000:
        raise HTTPException(413, 'Configuration edits require UTF-8 text of at most 2 MB')
    suffix = Path(path).suffix.lower()
    try:
        if suffix in ('.yaml', '.yml'):
            for count, _ in enumerate(yaml.parse(content)):
                if count > 50000:
                    raise HTTPException(413, 'YAML contains too many elements')
            validator = 'YAML syntax'
        elif suffix == '.json':
            json.loads(content)
            validator = 'JSON syntax'
        elif suffix == '.toml':
            tomllib.loads(content)
            validator = 'TOML syntax'
        else:
            validator = 'UTF-8 text; application-specific validation is not automatic'
    except (yaml.YAMLError, ValueError, RecursionError):
        raise HTTPException(422, 'Invalid configuration syntax; check the file before saving')
    return {'valid': True, 'validator': validator, 'bytes': len(content.encode('utf-8'))}
