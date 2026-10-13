"""CLI listener policy: loopback or an explicit private tailnet IP."""
import ipaddress
import json
import subprocess


def private_listener(value):
    if value == 'localhost':
        return True
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_loopback or address in ipaddress.ip_network('100.64.0.0/10') or address in ipaddress.ip_network('fd7a:115c:a1e0::/48')


def verified_listener(value):
    if value == 'localhost':
        return True
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if address.is_loopback:
        return True
    if not private_listener(value):
        return False
    try:
        result = subprocess.run(['tailscale', 'status', '--json'], capture_output=True, timeout=5, text=True, encoding='utf-8', errors='replace')
        if result.returncode or len(result.stdout) > 1_000_000:
            return False
        status = json.loads(result.stdout)
        own = status.get('Self') or {}
        return status.get('BackendState') == 'Running' and own.get('Online') is True and any(ipaddress.ip_address(item) == address for item in own.get('TailscaleIPs', []))
    except (OSError, subprocess.TimeoutExpired, ValueError, AttributeError, TypeError):
        return False
