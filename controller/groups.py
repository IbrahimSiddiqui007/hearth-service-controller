"""Explicit component relationships preserve every notebook and runtime permission."""
from pathlib import PurePosixPath, PureWindowsPath

from fastapi import HTTPException

from controller.dependencies import startup_order, validate_dependencies


def validate_groups(registry):
    parents = {}
    graph = {sid: dict(row) for sid, row in registry.items()}
    for sid, service in registry.items():
        members = service.get('component_ids', [])
        for member in members:
            if member not in registry or member == sid:
                raise HTTPException(422, 'Components must reference other existing services')
            item = registry[member]
            if item['host_id'] != service['host_id']:
                raise HTTPException(422, 'Runtime components must share their application host; use dependencies across hosts')
            if member in parents or item.get('component_ids'):
                raise HTTPException(422, 'Components cannot belong to multiple or nested application groups')
            if service['runtime'] == 'compose' and item['runtime'] == 'docker' and item.get('control_handle', {}).get('container') in service.get('components', []):
                raise HTTPException(422, 'A Compose project already includes this container; do not control it twice as a linked component')
            parents[member] = sid
        graph[sid]['dependencies'] = list(dict.fromkeys(service.get('dependencies', []) + members))
    validate_dependencies(graph)
    for sid, service in registry.items():
        schedule = service.get('schedule_policy', {})
        if schedule.get('enabled') and (sid in parents or service.get('component_ids') and not schedule.get('acknowledge_components')):
            raise HTTPException(422, 'Schedules belong to an approved application parent; explicitly approve every linked component')
        policy = service.get('idle_policy', {})
        if not policy.get('enabled'):
            continue
        if sid in parents:
            raise HTTPException(422, 'Configure automatic inactivity on the application parent, not a linked component')
        if set(policy.get('component_profiles', {})) != set(service.get('component_ids', [])):
            raise HTTPException(422, 'Automatic inactivity needs an explicit activity profile for every linked component')
    return parents, graph


def group_plan(registry, sid, action):
    _, graph = validate_groups(registry)
    members = {sid, *registry[sid].get('component_ids', [])}
    order = startup_order(graph, sid)
    targets = [item for item in order if item in members]
    if action == 'stop':
        targets.reverse()
    external = [item for item in order if item not in members]
    return targets, external


def component_suggestions(service, registry, parents=None):
    def directory(row):
        if row['runtime'] == 'docker':
            return ''  # Container-internal /app is not a host grouping key.
        value = (row.get('locations') or {}).get('working_directory') or row.get('control_handle', {}).get('path', '')
        if not value:
            return ''
        kind = PurePosixPath if value.startswith('/') else PureWindowsPath
        return str(kind(value)).rstrip('/\\').casefold() if kind is PureWindowsPath else str(kind(value)).rstrip('/')
    root = directory(service)
    if not root:
        return []
    if parents is None:
        parents, _ = validate_groups(registry)
    return [sid for sid, row in registry.items() if sid != service['id'] and row['host_id'] == service['host_id']
            and not row.get('component_ids') and sid not in parents and directory(row) == root]
