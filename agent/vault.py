"""Exact-item existence checks using a locally unlocked Bitwarden CLI session."""
import os
import re
import subprocess
import tempfile

from fastapi import HTTPException
from pydantic import Field
from shared.models import StrictModel


class VaultCheck(StrictModel):
    item_id: str = Field(pattern=r'^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')


def check(config, body):
    if body.item_id not in config.get('vault_check_items', []):
        raise HTTPException(403, 'Vault checks require exact local item approval')
    environment = config.get('vault_session_env', '')
    if not re.fullmatch(r'PSC_[A-Z0-9_]+', environment) or not os.environ.get(environment):
        raise HTTPException(409, 'An existing unlocked vault session is required; no login or sync runs automatically')
    env = {key:value for key,value in os.environ.items() if not key.startswith('BW_')}
    env['BW_SESSION']=os.environ[environment]
    try:
        with tempfile.TemporaryFile() as output:
            result = subprocess.run(['bw', 'get', 'item', body.item_id], env=env, stdout=output,stderr=subprocess.DEVNULL, timeout=10)
            if result.returncode or output.tell()>1_000_000:return {'status':'unverified','exists':None}
            output.seek(0)
            raw=output.read()
    except (OSError, subprocess.TimeoutExpired):
        return {'status': 'unavailable', 'exists': None}
    # A nonzero result can mean locked/offline/denied as well as absent. Never
    # report a missing credential or retain returned secret-bearing JSON.
    import json
    try:
        record = json.loads(raw)
        found = record.get('id') == body.item_id and not record.get('deletedDate')
    except (ValueError, AttributeError):
        found = False
    return {'status': 'exists' if found else 'unverified', 'exists': True if found else None}
