import asyncio
import json

import pytest
from fastapi import HTTPException

from agent.app import create_agent, safe_path
from agent.log_stream import command_lines, file_lines
from controller.app import create_app
from shared.models import LogsRequest
from test_config_operations import endpoint


def test_follower_child_cleanup_masking_and_fixed_args(monkeypatch):
    calls = []
    class Child:
        returncode = None
        def __init__(self):
            self.stdout = asyncio.StreamReader()
            self.stdout.feed_data(b'API_TOKEN=test-secret\n-----BEGIN PRIVATE KEY-----\nprivate bytes\n-----END PRIVATE KEY-----\n')
        def terminate(self):
            calls.append('terminate')
            self.returncode = 0
        async def wait(self):
            calls.append('wait')
            return 0
    async def spawn(*args, **kwargs):
        calls.append(args)
        assert 'shell' not in kwargs
        return Child()
    monkeypatch.setattr('agent.log_stream.asyncio.create_subprocess_exec', spawn)
    async def scenario():
        stream = command_lines(['journalctl', '--unit', 'approved.service', '--follow'])
        first = json.loads(await anext(stream))
        assert 'test-secret' not in first['content']
        assert '[REDACTED]' in first['content']
        for _ in range(3):
            assert 'private key material' in json.loads(await anext(stream))['content']
        await stream.aclose()
    asyncio.run(scenario())
    assert calls == [('journalctl', '--unit', 'approved.service', '--follow'), 'terminate', 'wait']


def test_file_stream_holds_split_secret_and_stops_rotation(tmp_path):
    path = tmp_path / 'worker.log'
    path.write_text('ready\n')
    config = {'log_files': {'ref': str(path)}, 'file_roots': {'ref': [str(tmp_path)]}}
    async def scenario():
        stream = file_lines(config, 'ref', safe_path, duration=2)
        assert 'ready' in await anext(stream)
        with path.open('a') as output:
            output.write('PASSWORD=test')
        assert json.loads(await anext(stream))['kind'] == 'heartbeat'
        with path.open('a') as output:
            output.write('-secret\n')
        row = await anext(stream)
        assert 'test-secret' not in row and 'REDACTED' in row
        path.write_text('new\n')
        assert json.loads(await anext(stream))['kind'] == 'end'
        await stream.aclose()
    asyncio.run(scenario())


def test_agent_stream_allowlist_and_follow_vector(monkeypatch):
    app = create_agent({'allow_units': ['approved.service']}, token='test')
    observed = []
    async def source(argv, **kwargs):
        observed.append(argv)
        yield '{"kind":"log","content":"ok"}\n'
    monkeypatch.setattr('agent.app.command_lines', source)
    async def scenario():
        handler = endpoint(app, '/logs/stream', 'POST')
        with pytest.raises(HTTPException) as rejected:
            await handler(LogsRequest(runtime='systemd', handle={'unit': 'denied.service'}))
        assert rejected.value.status_code == 403
        reply = await handler(LogsRequest(runtime='systemd', handle={'unit': 'approved.service'}))
        assert [row async for row in reply.body_iterator]
    asyncio.run(scenario())
    assert observed == [['journalctl', '--follow', '--unit', 'approved.service', '--lines', '300', '--no-pager', '--output', 'short-iso']]


def test_controller_stream_auth_permission_and_event_cursor(tmp_path):
    app = create_app(tmp_path, demo=True, token='test-token', background=False)
    async def scenario():
        logs = endpoint(app, '/api/v1/services/{sid}/logs/stream', 'GET')
        with pytest.raises(HTTPException):
            await logs('playground', 10)
        reply = await logs('minecraft', 10)
        assert '[DEMO]' in await anext(reply.body_iterator)
        await reply.body_iterator.aclose()
        store = app.state.store
        store.audit('test.event', 'success', 'PASSWORD=secret')
        cursor = store.events()[0]['id'] - 1
        events = await endpoint(app, '/api/v1/events/stream', 'GET')(cursor)
        row = await anext(events.body_iterator)
        assert 'test.event' in row and 'PASSWORD=secret' not in row and 'REDACTED' in row
        await events.body_iterator.aclose()
    asyncio.run(scenario())
