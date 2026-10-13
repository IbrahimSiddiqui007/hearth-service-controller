from datetime import datetime
from math import isfinite


def rates(current, previous, timestamp, previous_timestamp):
    result = dict(current)
    keys = {'network_sent_bps': 'network_sent_bytes', 'network_recv_bps': 'network_recv_bytes',
            'disk_read_bps': 'disk_read_bytes', 'disk_write_bps': 'disk_write_bytes'}
    elapsed = (datetime.fromisoformat(timestamp) - datetime.fromisoformat(previous_timestamp)).total_seconds() if previous and previous_timestamp else 0
    comparable = previous and current.get('boot_time') == previous.get('boot_time') and 0 < elapsed <= 300
    def rate(new, old):
        return round((new - old) / elapsed, 1) if comparable and isinstance(new, (int, float)) and isinstance(old, (int, float)) and new >= old else None
    for field, counter in keys.items():
        result[field] = rate(current.get(counter), (previous or {}).get(counter))
    result['rate_interval_s'] = round(elapsed, 2) if comparable else None
    result['interface_rates'] = {name: {'sent_bps': rate(row.get('sent_bytes'), (previous or {}).get('interfaces', {}).get(name, {}).get('sent_bytes')),
                                      'received_bps': rate(row.get('received_bytes'), (previous or {}).get('interfaces', {}).get(name, {}).get('received_bytes'))}
                                  for name, row in current.get('interfaces', {}).items()}
    return result

def thresholds(host, metrics):
    from shared.models import TelemetryPolicy
    policy = TelemetryPolicy.model_validate(host.get('telemetry_policy') or {}).model_dump()
    if not policy['enabled']:
        host['telemetry_alerts'], host['telemetry_streaks'] = {}, {}
        return []
    alerts, streaks = dict(host.get('telemetry_alerts', {})), dict(host.get('telemetry_streaks', {}))
    events = []
    def known(value):
        return isinstance(value, (int, float)) and not isinstance(value, bool) and isfinite(value)
    for metric in ('cpu_percent', 'memory_percent', 'disk_percent', 'temperature_c'):
        value = metrics.get(metric)
        if metric == 'disk_percent' and metrics.get('volumes'):
            readings = [volume.get('percent') for volume in metrics['volumes'] if isinstance(volume, dict) and known(volume.get('percent'))]
            if known(value):
                readings.append(value)
            value = max(readings) if readings else None
        if not known(value):
            streaks[metric] = 0
            continue
        high = value >= policy[metric]
        streaks[metric] = streaks.get(metric, 0) + 1 if high else 0
        previous = alerts.get(metric, False)
        active = (previous or streaks[metric] >= policy['sustained_samples']) if high else False
        if active != previous:
            events.append({'metric': metric, 'active': active, 'value': value, 'threshold': policy[metric]})
        alerts[metric] = active
    host['telemetry_alerts'], host['telemetry_streaks'] = alerts, streaks
    return events
