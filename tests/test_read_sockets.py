import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from controller.app import create_app


def test_read_websockets_require_auth_and_origin_and_close_cleanly(tmp_path):
    app = create_app(tmp_path, demo=True, token='dummy', background=False)
    with TestClient(app) as client:
        for path in ['/api/v1/events/ws', '/api/v1/services/minecraft/logs/ws', '/api/v1/state/ws']:
            with pytest.raises(WebSocketDisconnect):
                with client.websocket_connect(path):
                    pass
            with pytest.raises(WebSocketDisconnect):
                with client.websocket_connect(path, headers={'Authorization': 'Bearer dummy', 'Origin': 'https://evil.invalid'}):
                    pass
        app.state.store.audit('test.socket', 'success', 'PASSWORD=secret')
        cursor = app.state.store.events()[0]['id'] - 1
        with client.websocket_connect('/api/v1/events/ws?after=' + str(cursor), headers={'Authorization': 'Bearer dummy'}) as socket:
            event = socket.receive_json()
            assert event['kind'] == 'event' and event['event']['action'] == 'test.socket'
            assert 'secret' not in event['event']['detail']
        with client.websocket_connect('/api/v1/services/minecraft/logs/ws', headers={'Authorization': 'Bearer dummy'}) as socket:
            assert socket.receive_json()['kind'] == 'log'
        with client.websocket_connect('/api/v1/state/ws', headers={'Authorization': 'Bearer dummy'}) as socket:
            state = socket.receive_json()
            assert state['kind'] == 'state' and len(state['hosts']) == 3
            assert all('notes' not in row and 'credentials' not in row for row in state['services'])
        assert any(row['action'] == 'logs.follow' and row['result'] == 'finished' for row in app.state.store.events())
