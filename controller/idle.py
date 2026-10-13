"""Conservative idle timer: only explicit, fresh, consecutive idle observations count."""
from datetime import datetime, timezone


def observe(previous, signal, minutes, timestamp=None):
    current = timestamp or datetime.now(timezone.utc)
    previous = previous or {}
    last = previous.get('checked_at')
    gap = (current - datetime.fromisoformat(last)).total_seconds() if last else None
    uninterrupted = gap is not None and 0 < gap <= 90
    since = previous.get('idle_since') if uninterrupted else None
    if signal is not True:
        since = None
    elif not since:
        since = current.isoformat()
    seconds = max(0, (current - datetime.fromisoformat(since)).total_seconds()) if since else 0
    return {'checked_at': current.isoformat(), 'idle_since': since, 'signal': 'idle' if signal is True else 'active' if signal is False else 'unknown',
            'ready': signal is True and seconds >= minutes * 60, 'idle_seconds': seconds, 'asleep': previous.get('asleep', False)}
