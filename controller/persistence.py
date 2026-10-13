import hashlib
import json
import re
from fastapi import HTTPException
from shared.models import redact


def verified(value):
    if not isinstance(value, dict) or not isinstance(value.get('rows'), list) or len(value['rows']) > 1500:
        raise HTTPException(502, 'Invalid persistence inventory')
    rows = []
    for item in value['rows']:
        if not isinstance(item, dict) or item.get('kind') not in ('listener', 'cron', 'startup') or any(not isinstance(item.get(field), str) for field in ('id', 'name', 'source', 'fingerprint')) or not re.fullmatch('[a-f0-9]{64}', item['id']) or not re.fullmatch('[a-f0-9]{64}', item['fingerprint']):
            raise HTTPException(502, 'Invalid persistence metadata')
        rows.append({field: redact(item[field])[:1024] for field in ('id', 'kind', 'name', 'source', 'fingerprint')})
    if len({row['id'] for row in rows}) != len(rows):
        raise HTTPException(502, 'Duplicate persistence references')
    complete = value.get('complete', [])
    if not isinstance(complete, list) or any(kind not in ('listener', 'cron', 'startup') for kind in complete):
        raise HTTPException(502, 'Invalid persistence provider coverage')
    return {'rows': rows, 'complete': complete, 'warnings': [redact(str(item))[:1000] for item in value.get('warnings', [])[:20]],
            'gaps': [redact(str(item))[:1000] for item in value.get('gaps', [])[:20]]}


def view(current, baseline):
    before = {row['id']: row for row in baseline}
    present = {row['id']: row for row in current['rows']}
    changes = [{**row, 'change': 'new' if key not in before else 'changed'} for key, row in present.items() if key not in before or row['fingerprint'] != before[key]['fingerprint']]
    changes += [{**row, 'change': 'gone'} for key, row in before.items() if key not in present and row['kind'] in current['complete']]
    fingerprint = hashlib.sha256(json.dumps(current, sort_keys=True).encode()).hexdigest()
    return {**current, 'changes': changes, 'fingerprint': fingerprint, 'baseline_rows': baseline}


def demo_snapshot():
    return {'rows': [{'id': '1' * 64, 'kind': 'listener', 'source': 'DEMO TCP listeners', 'name': '127.0.0.1:8788', 'fingerprint': '2' * 64}], 'complete': ['listener'],
            'warnings': [], 'gaps': ['Synthetic example; no machine was scanned.']}
