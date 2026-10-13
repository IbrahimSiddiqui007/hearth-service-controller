import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError

from controller.app import Action, create_app
from controller.schedules import Scheduler
from shared.models import SchedulePolicy, ScheduleEdit
from shared.schedules import parse, matches, preview, local_minute
from test_config_operations import endpoint, fake_agent, live_app


STAMP = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)


def setup(app, state='running', stamp=STAMP):
    store = app.state.store
    service = store.get('services', 'minecraft')
    service.update(status=state, observed_at=stamp.isoformat(), dependencies=[],
                   schedule_policy={'enabled': True, 'timezone': 'UTC', 'rules': [{'action': 'stop', 'cron': '* * * * *'}]})
    store.put('services', service)
    host = store.get('hosts', service['host_id'])
    host.update(status='online', last_seen=stamp.isoformat())
    store.put('hosts', host)
    for other in store.all('services'):
        if service['id'] in other.get('dependencies', []):
            other['dependencies'] = []
            store.put('services', other)
    return service


def test_cron_contract_ranges_steps_or_days_and_preview():
    assert matches(parse('*/15 12 * * 2'), STAMP)
    assert matches(parse('0 12 1 * 2'), STAMP)  # Tuesday OR day 1
    assert not matches(parse('0 12 * * 3'), STAMP)
    assert not matches(parse('0 12 */1 * 3'), STAMP)
    assert matches(parse('5/10 * * * *'), STAMP.replace(minute=15))
    assert preview([{'action': 'start', 'cron': '1 12 * * *'}], STAMP)[0]['ts'] == (STAMP + timedelta(minutes=1)).isoformat()
    for invalid in ('@reboot', '60 * * * *', '0 0 * * 7', '* * * * */0', '0 0 0 * *', '*/99 * * * *', '0 0 * * mon'):
        with pytest.raises(ValueError):
            parse(invalid)
    with pytest.raises(ValidationError):
        SchedulePolicy(enabled=True)


def test_save_revision_optin_and_independent_scope(tmp_path):
    with TestClient(create_app(tmp_path, demo=True, token='', background=False)) as client:
        base = '/api/v1/services/minecraft/schedule'
        old = client.get(base).json()
        assert not old['policy']['enabled']
        body = {'revision': old['revision'], 'policy': {'enabled': True, 'rules': [{'action': 'stop', 'cron': '0 23 * * *'}]}}
        result = client.put(base, json=body)
        assert result.status_code == 200 and result.json()['next_windows']
        assert client.put(base, json=body).status_code == 409
        assert client.put(base, json={'revision': result.json()['revision'], 'policy': {'enabled': True, 'rules': [{'action': 'stop', 'cron': '@reboot'}]}}).status_code == 422
        assert client.get('/api/v1/services/missing/schedule').status_code == 404


def test_at_most_once_and_manual_idle_schedule_stop_sources(tmp_path, monkeypatch):
    app = live_app(tmp_path, monkeypatch)
    service = setup(app)
    current = [STAMP]
    scheduler = app.state.scheduler
    scheduler.clock = lambda: current[0]
    scheduler.arm(service)
    calls = []
    async def request(method, url, **kwargs):
        if url.endswith('/control'):
            calls.append(kwargs['json']['action'])
            return httpx.Response(200, json={'output': 'accepted'})
        return httpx.Response(200, json={'services': [{**service, 'agent_ref': 'compose-minecraft', 'status': 'stopped'}], 'completed_runtimes': ['compose']})
    fake_agent(monkeypatch, request)
    current[0] += timedelta(minutes=1)
    asyncio.run(scheduler.tick())
    asyncio.run(scheduler.tick())
    assert calls == ['stop']
    stopped = app.state.store.get('services', 'minecraft')
    assert stopped['last_control']['source'] == 'schedule' and stopped['last_control']['verified']
    details = endpoint(app, '/api/v1/services/{sid}/schedule', 'GET')('minecraft')
    assert len(details['runs']) == 1 and details['runs'][0]['status'] == 'success'
    # Manual control uses the same machinery, with a distinct source.
    asyncio.run(endpoint(app, '/api/v1/services/{sid}/control', 'POST')('minecraft', Action(action='stop')))
    assert app.state.store.get('services', 'minecraft')['last_control']['source'] == 'manual'


@pytest.mark.parametrize('gap', ['offline', 'unknown', 'dependent', 'reservation', 'group', 'stale'])
def test_blocked_window_consumed_without_network_or_backlog(tmp_path, monkeypatch, gap):
    app = live_app(tmp_path, monkeypatch)
    service = setup(app)
    store, scheduler = app.state.store, app.state.scheduler
    current = [STAMP]
    scheduler.clock = lambda: current[0]
    scheduler.arm(service)
    if gap in ('unknown', 'group', 'stale'):
        service.update(status='unknown' if gap == 'unknown' else 'running',
                       component_ids=['ollama'] if gap == 'group' else [],
                       observed_at=(STAMP - timedelta(minutes=10)).isoformat() if gap == 'stale' else STAMP.isoformat())
        store.put('services', service)
        scheduler.arm(service)
    elif gap == 'offline':
        host = store.get('hosts', service['host_id']); host['status'] = 'offline'; store.put('hosts', host)
    elif gap == 'dependent':
        row = store.get('services', 'ollama'); row.update(dependencies=['minecraft'], status='running', observed_at=STAMP.isoformat()); store.put('services', row)
    elif gap == 'reservation':
        with store.connection() as db:
            db.execute('INSERT INTO operations VALUES(?,?,?,?,?,?)', ('busy', 'minecraft', 'test', 'running', STAMP.isoformat(), ''))
    calls = []
    async def request(*args, **kwargs):
        calls.append(args)
        raise AssertionError('No network allowed')
    fake_agent(monkeypatch, request)
    current[0] += timedelta(minutes=1)
    asyncio.run(scheduler.tick())
    asyncio.run(scheduler.tick())
    assert not calls
    runs = endpoint(app, '/api/v1/services/{sid}/schedule', 'GET')('minecraft')['runs']
    assert len(runs) == 1 and runs[0]['status'] == 'skipped'


def test_restart_clock_rollback_conflicting_rules_and_crash_never_retry(tmp_path, monkeypatch):
    app = live_app(tmp_path, monkeypatch)
    service = setup(app)
    stamp = [STAMP]
    calls = []
    async def dispatch(*args):
        calls.append(args)
        raise asyncio.CancelledError()
    scheduler = Scheduler(app.state.store, dispatch)
    scheduler.clock = lambda: stamp[0]
    scheduler.arm(service)
    stamp[0] += timedelta(minutes=1)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(scheduler.tick())
    asyncio.run(scheduler.tick())
    assert len(calls) == 1
    with app.state.store.connection() as db:
        assert db.execute('SELECT status FROM schedule_runs').fetchone()['status'] == 'unknown'
    stamp[0] -= timedelta(minutes=1)
    asyncio.run(scheduler.tick())
    scheduler.recover()
    asyncio.run(scheduler.tick())
    assert len(calls) == 1
    # Conflicting expressions consume the future window without choosing an action.
    service['schedule_policy']['rules'].append({'action': 'start', 'cron': '*/1 * * * *'})
    app.state.store.put('services', service)
    scheduler.arm(service)
    stamp[0] += timedelta(minutes=1)
    asyncio.run(scheduler.tick())
    assert len(calls) == 1


def test_changed_context_guard_blocks_before_dispatch(tmp_path, monkeypatch):
    app = live_app(tmp_path, monkeypatch)
    service = setup(app)
    scheduler = app.state.scheduler
    scheduler.clock = lambda: STAMP
    scheduler.arm(service)
    original = scheduler.dispatch
    async def change_then_dispatch(expected, action, context, minute):
        changed = app.state.store.get('services', 'minecraft')
        changed['revision'] += 1
        app.state.store.put('services', changed)
        return await original(expected, action, context, minute)
    scheduler.dispatch = change_then_dispatch
    scheduler.clock = lambda: STAMP + timedelta(minutes=1)
    asyncio.run(scheduler.tick())
    with app.state.store.connection() as db:
        assert db.execute('SELECT status FROM schedule_runs').fetchone()['status'] == 'skipped'
        assert not db.execute('SELECT 1 FROM operations').fetchone()


def test_timezone_valid_invalid_null_and_dst_edges():
    assert SchedulePolicy(timezone='Asia/Dubai').timezone == 'Asia/Dubai'
    for value in ('../../private', 'Unknown/Zone', None):
        with pytest.raises(ValidationError):
            SchedulePolicy(timezone=value)
    # New York spring 02:30 never occurs; fall 01:30 has only one eligible instant.
    spring = datetime(2026, 3, 8, 6, 59, tzinfo=timezone.utc)
    windows = preview([{'action': 'start', 'cron': '30 2 * * *'}], spring, 'America/New_York')
    assert windows[0]['local_ts'].startswith('2026-03-09T02:30')
    assert local_minute(datetime(2026, 11, 1, 5, 30, tzinfo=timezone.utc), 'America/New_York') is not None
    assert local_minute(datetime(2026, 11, 1, 6, 30, tzinfo=timezone.utc), 'America/New_York') is None


def test_group_schedule_valid_preflight_order_and_component_rejection(tmp_path, monkeypatch):
    app = live_app(tmp_path, monkeypatch)
    store = app.state.store
    service = setup(app)
    service.update(component_ids=['ollama'], schedule_policy={'enabled':True,'timezone':'UTC','acknowledge_components':True,'rules':[{'action':'stop','cron':'* * * * *'}]})
    member = store.get('services','ollama'); member.update(host_id=service['host_id'], dependencies=[],status='running',observed_at=STAMP.isoformat(),capabilities={'control':True})
    store.put('services',service);store.put('services',member)
    current = [STAMP]
    monkeypatch.setattr('controller.app.now',lambda:current[0].isoformat())
    app.state.scheduler.clock=lambda:current[0]
    app.state.scheduler.arm(service)
    calls=[]
    async def request(method,url,**kwargs):
        if url.endswith('/control'):
            calls.append(kwargs['json']['runtime'])
            return httpx.Response(200,json={'output':'accepted'})
        rows=[]
        for sid,ref in [('minecraft','compose-minecraft'),('ollama','systemd-ollama')]:
            row=store.get('services',sid)
            row['agent_ref']=ref
            row['status']='stopped' if (sid=='minecraft' and calls or len(calls)==2) else 'running'
            rows.append(row)
        return httpx.Response(200,json={'services':rows,'completed_runtimes':['compose','systemd']})
    fake_agent(monkeypatch,request)
    current[0]+=timedelta(minutes=1)
    asyncio.run(app.state.scheduler.tick())
    assert calls==['compose','systemd']
    assert store.get('services','minecraft')['last_control']['source']=='schedule'
    assert store.get('services','ollama')['last_control']['source']=='schedule'
    # A component cannot enroll its own independent policy.
    with pytest.raises(HTTPException):
        asyncio.run(endpoint(app,'/api/v1/services/{sid}/schedule','PUT')('ollama',ScheduleEdit(revision=member['revision'],policy=SchedulePolicy(enabled=True,rules=[{'action':'start','cron':'* * * * *'}]))))
