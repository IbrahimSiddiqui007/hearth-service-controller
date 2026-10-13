"""Optional outbound heartbeats to a pre-registered private controller."""
import asyncio
import json
import os
import hmac
import re
import psutil
from urllib.parse import urlsplit

from shared.binding import private_listener
from shared.signatures import headers as signed_headers, frame_signature


def target(config):
    origin = config.get('heartbeat_controller', '')
    if not origin:
        return ''
    parsed = urlsplit(origin)
    host_id = config.get('controller_host_id', '')
    if parsed.scheme not in ('ws', 'wss') or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('', '/') or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}', host_id):
        raise ValueError('Heartbeat controller must be a private WS(S) origin with a pre-registered host ID')
    if not (private_listener(parsed.hostname) or parsed.hostname.endswith('.ts.net')):
        raise ValueError('Heartbeats require loopback, an explicit tailnet IP, or a .ts.net controller name')
    if not config.get('signing_key_env'):
        raise ValueError('Persistent heartbeats require an independent request signing key')
    return origin.rstrip('/') + '/api/v1/agents/' + host_id + '/heartbeat'


async def run(config, token, collect, connect=None):
    url = target(config)
    if not url:
        return
    if connect is None:
        from websockets.asyncio.client import connect
    from websockets.exceptions import WebSocketException
    retry = 5
    while True:
        try:
            path = urlsplit(url).path
            key = os.environ.get(config['signing_key_env'], '')
            headers = {'Authorization': 'Bearer ' + token, **signed_headers(key, 'GET', path, b'')}
            nonce = headers['X-PSC-Nonce']
            async with connect(url, additional_headers=headers, proxy=None, compression=None, max_size=4096, max_queue=2, open_timeout=8, close_timeout=3) as socket:
                retry = 5
                ready = json.loads(await asyncio.wait_for(socket.recv(), timeout=10))
                if ready.get('status') != 'ready' or not isinstance(ready.get('signature'), str) or not hmac.compare_digest(ready['signature'].encode(), frame_signature(key, nonce, -1, b'ready').encode()):
                    raise ValueError('Controller identity could not be verified')
                sequence = 0
                while True:
                    payload = await asyncio.to_thread(collect, sequence % 4 == 0)
                    body = json.dumps(payload, allow_nan=False, separators=(',', ':'), sort_keys=True)
                    if len(body.encode()) > 4_000_000:
                        raise ValueError('Heartbeat inventory exceeded size limit')
                    await socket.send(json.dumps({'sequence': sequence, 'payload': payload, 'signature': frame_signature(key, nonce, sequence, body.encode())}, separators=(',', ':')))
                    acknowledgment = json.loads(await asyncio.wait_for(socket.recv(), timeout=10))
                    if acknowledgment.get('status') != 'accepted' or acknowledgment.get('sequence') != sequence or not isinstance(acknowledgment.get('signature'), str) or not hmac.compare_digest(acknowledgment['signature'].encode(), frame_signature(key, nonce, sequence, b'accepted').encode()):
                        raise ValueError('Heartbeat refused')
                    sequence += 1
                    await asyncio.sleep(15)
        except (OSError, TimeoutError, ValueError, TypeError, AttributeError, psutil.Error, WebSocketException):
            # No URLs, tokens, profile output or returned data in retry logs.
            await asyncio.sleep(retry)
            retry = min(60, retry * 2)
