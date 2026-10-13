import argparse
import os

import uvicorn

from controller.app import create_app
from shared.binding import verified_listener


def main():
    parser = argparse.ArgumentParser(description="Pi Service Controller")
    parser.add_argument("--demo", action="store_true", help="Use isolated sample data; never connect to agents")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument('--container-listener', action='store_true', help='Explicit container-only wildcard listener; requires private port publication and PSC_CONTAINER_PRIVATE_INGRESS=1')
    args = parser.parse_args()
    container = args.container_listener and args.host == '0.0.0.0' and os.environ.get('PSC_CONTAINER_PRIVATE_INGRESS') == '1'
    if not container and not verified_listener(args.host):
        parser.error('Bind to loopback or an explicit Tailscale IP; wildcard, LAN and public listeners are refused')
    if args.host not in ("127.0.0.1", "::1", "localhost") and len(os.environ.get("PSC_TOKEN", "")) < 24:
        parser.error("Remote binding requires PSC_TOKEN with at least 24 random characters and PSC_ORIGINS for your URL")
    uvicorn.run(create_app(demo=args.demo, port=args.port), host=args.host, port=args.port, ws_max_size=4_000_000, ws_max_queue=2)


if __name__ == "__main__":
    main()
