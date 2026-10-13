from datetime import datetime, timezone


def liveness(host, clock=None):
    host = dict(host)
    if host.get('transport') != 'heartbeat':
        return host
    try:
        age = ((clock or datetime.now(timezone.utc)) - datetime.fromisoformat(host['last_seen'])).total_seconds()
    except (KeyError, ValueError, TypeError):
        age = 150
    if age >= 150:
        host['status'] = 'offline'
    elif age >= 45 and host.get('status') == 'online':
        host['status'] = 'stale'
    return host
