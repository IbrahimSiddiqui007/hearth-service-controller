"""Persisted at-most-once schedule decisions. Expired windows never replay."""
import hashlib
import json
from datetime import datetime, timezone

from fastapi import HTTPException

from controller.dependencies import startup_order
from controller.groups import validate_groups, group_plan
from controller.store import now
from shared.models import SchedulePolicy
from shared.schedules import matches, parse, local_minute


def fingerprint(service):
    return hashlib.sha256(json.dumps({key: service.get(key) for key in (
        'revision', 'host_id', 'runtime', 'control_handle', 'dependencies', 'component_ids', 'schedule_policy')}, sort_keys=True).encode()).hexdigest()


def fresh(stamp, current):
    try:
        return 0 <= (current - datetime.fromisoformat(stamp)).total_seconds() <= 90
    except (TypeError, ValueError):
        return False


def preflight(store, sid, action, current):
    registry = {row['id']: row for row in store.all('services')}
    service = registry[sid]
    parents, _ = validate_groups(registry)
    if sid in parents:
        raise HTTPException(409, 'Schedule linked components through their application parent')
    targets, external = group_plan(registry, sid, action)
    if service.get('component_ids') and not service.get('schedule_policy', {}).get('acknowledge_components'):
        raise HTTPException(409, 'Group scheduling requires explicit owner approval for all linked components')
    if any(registry[target].get('status') not in ('running', 'stopped') for target in targets):
        raise HTTPException(409, 'Service or component state is unknown or transitional')
    related = set(targets + external)
    if action == 'stop':
        impacted = set(targets)
        while True:
            extra = {row['id'] for row in registry.values() if impacted.intersection(row.get('dependencies', []))} - impacted
            if not extra:
                break
            impacted.update(extra)
        related = impacted
    context = {}
    for target in sorted(related):
        row = registry[target]
        host = store.get('hosts', row['host_id']) or {}
        if host.get('status') != 'online' or not fresh(host.get('last_seen'), current) or not fresh(row.get('observed_at'), current):
            raise HTTPException(409, 'Fresh service and host observations are required for every dependency')
        if target not in targets and row.get('status') != ('running' if action == 'start' else 'stopped'):
            raise HTTPException(409, 'Dependencies or dependents inhibit the scheduled action')
        context[target] = {'service': fingerprint(row), 'state': row.get('status'), 'host': {key: host.get(key) for key in (
            'status', 'agent_url', 'token_env', 'signing_env', 'physical_host_id', 'os', 'active_os')}}
    if any(not registry[target].get('capabilities', {}).get('control') for target in targets):
        raise HTTPException(403, 'Agent control permission is required')
    return context


def at_desired_state(store, service, action):
    desired = 'running' if action == 'start' else 'stopped'
    return all((store.get('services', sid) or {}).get('status') == desired for sid in [service['id'], *service.get('component_ids', [])])


class Scheduler:
    def __init__(self, store, dispatch):
        self.store, self.dispatch = store, dispatch
        self.clock = lambda: datetime.now(timezone.utc)

    def arm(self, service):
        with self.store.connection() as db:
            db.execute('INSERT OR REPLACE INTO schedule_cursors VALUES(?,?,?)',
                       (service['id'], fingerprint(service), self.clock().replace(second=0, microsecond=0).isoformat()))

    def recover(self):
        with self.store.connection() as db:
            db.execute("UPDATE schedule_runs SET status='unknown',detail='Controller restarted before outcome was recorded' WHERE status='running'")
        for service in self.store.all('services'):
            if service.get('schedule_policy', {}).get('enabled'):
                self.arm(service)  # Restart never executes the current or missed minutes.

    async def tick(self):
        minute = self.clock().replace(second=0, microsecond=0)
        for service in self.store.all('services'):
            if not service.get('schedule_policy', {}).get('enabled'):
                continue
            policy = SchedulePolicy.model_validate(service['schedule_policy']).model_dump()
            key = fingerprint(service)
            with self.store.connection() as db:
                cursor = db.execute('SELECT * FROM schedule_cursors WHERE service_id=?', (service['id'],)).fetchone()
                if not cursor or cursor['policy_key'] != key:
                    self.arm(service)
                    continue
                if minute.isoformat() <= cursor['minute']:
                    continue  # Backward clock movement and repeated ticks cannot replay.
                db.execute('UPDATE schedule_cursors SET minute=? WHERE service_id=?', (minute.isoformat(), service['id']))
            local = local_minute(minute, policy['timezone'])
            rules = [row for row in policy['rules'] if local is not None and matches(parse(row['cron']), local)]
            if not rules:
                continue
            # Different expressions may collide at a minute; never choose a winner.
            action = rules[0]['action'] if len({row['action'] for row in rules}) == 1 else 'conflict'
            with self.store.connection() as db:
                inserted = db.execute('INSERT OR IGNORE INTO schedule_runs VALUES(?,?,?,?,?,?,?)',
                                      (service['id'], key, minute.isoformat(), action, 'running', now(), '')).rowcount
            if not inserted:
                continue
            outcome, detail = 'unknown', 'Schedule interrupted; inspect observed state before retrying manually'
            try:
                if action == 'conflict':
                    raise HTTPException(409, 'Conflicting start and stop rules match this minute')
                context = preflight(self.store, service['id'], action, self.clock())
                if at_desired_state(self.store, service, action):
                    outcome, detail = 'skipped', 'Desired state already observed; no command sent'
                else:
                    result = await self.dispatch(service, action, context, minute)
                    desired = 'running' if action == 'start' else 'stopped'
                    outcome = result['status'] if result['status'] != 'success' or result['service'].get('status') == desired else 'unknown'
                    detail = 'Scheduled action finished; review observed outcome'
            except HTTPException as exc:
                outcome, detail = 'skipped', str(exc.detail)
            except Exception:
                outcome, detail = 'unknown', 'Scheduled operation failed without a verified result; no automatic retry'
            finally:
                with self.store.connection() as db:
                    db.execute('UPDATE schedule_runs SET status=?,detail=? WHERE service_id=? AND policy_key=? AND minute=?',
                               (outcome, detail, service['id'], key, minute.isoformat()))
                    self.store.audit('schedule.' + action, outcome, detail, service['id'], service['host_id'], db=db)
