"""Validate and decorate remote read-only Windows snapshots with curated guide links."""
from fastapi import HTTPException
from shared.models import redact
from shared.software_guides import guides


def verified(payload, os_name='Windows'):
    if os_name not in ('Windows', 'Linux', 'Darwin') or not isinstance(payload, dict) or payload.get('os') != os_name:
        raise HTTPException(502, 'Agent returned invalid Windows inventory')
    result = {key: payload.get(key, []) for key in ('completed', 'warnings', 'truncated')}
    if any(not isinstance(value, list) or len(value) > 30 or any(not isinstance(item, str) or len(item) > 500 for item in value) for value in result.values()):
        raise HTTPException(502, 'Agent returned invalid Windows inventory status')
    result = {key: [redact(item) for item in values] for key, values in result.items()}
    result.update(os=os_name, coverage=redact(str(payload.get('coverage', 'Agent-user scoped read-only inventory')))[:1000])
    for section, maximum, fields in [
        ('applications', 2500, ('id', 'name', 'version', 'publisher', 'scope', 'source', 'install_location', 'non_removable')),
        ('processes', 500, ('pid', 'name', 'executable', 'started_at')),
        ('ports', 500, ('pid', 'address', 'port', 'protocol')),
        ('events', 40, ('timestamp', 'event_id', 'level', 'provider', 'log', 'message')),
    ]:
        rows = payload.get(section)
        if not isinstance(rows, list) or len(rows) > maximum or any(not isinstance(row, dict) for row in rows):
            raise HTTPException(502, 'Agent returned invalid Windows ' + section)
        result[section] = []
        for row in rows:
            clean = {}
            for key in fields:
                value = row.get(key)
                if isinstance(value, str):
                    clean[key] = redact(value.replace('\x00', ''))[:1024]
                elif value is None or isinstance(value, (int, float, bool)):
                    clean[key] = value
                else:
                    raise HTTPException(502, 'Agent returned invalid Windows metadata')
            if section == 'applications':
                if not isinstance(clean.get('name'), str) or not clean['name'] or not isinstance(clean.get('id'), str):
                    raise HTTPException(502, 'Agent returned invalid application identity')
                # Ignore remote/vendor registry URLs and uninstall command strings.
                clean.update(guides(clean['name'], clean.get('publisher') or '', os_name=os_name, source=clean.get('source') or ''))
            result[section].append(clean)
    return result


def demo_snapshot():
    return verified({'os': 'Windows', 'completed': ['applications', 'packages', 'processes', 'ports', 'events'],
        'warnings': [], 'coverage': 'Synthetic Windows example; no real machine was read.',
        'applications': [
            {'id': 'demo-autocad', 'name': 'Autodesk AutoCAD 2026', 'version': '2026', 'publisher': 'Autodesk', 'scope': 'machine', 'source': 'synthetic sample'},
            {'id': 'demo-office', 'name': 'Microsoft 365', 'version': 'sample', 'publisher': 'Microsoft', 'scope': 'machine', 'source': 'synthetic sample'},
            {'id': 'demo-edge', 'name': 'Microsoft Edge', 'version': 'sample', 'publisher': 'Microsoft', 'scope': 'machine', 'source': 'synthetic sample'},
        ], 'processes': [{'pid': 1001, 'name': 'acad.exe', 'executable': r'C:\Program Files\Autodesk\AutoCAD 2026\acad.exe'}],
        'ports': [{'pid': 1002, 'address': '127.0.0.1', 'port': 8788, 'protocol': 'tcp'}],
        'events': [{'timestamp': 'Synthetic example', 'event_id': 1000, 'level': 'Warning', 'provider': 'Demo application', 'log': 'Application', 'message': 'Synthetic event; no Windows Event Log was read.'}]})
