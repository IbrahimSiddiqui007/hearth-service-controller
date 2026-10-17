"""Bounded, read-only suggestions from agent-account listening processes."""
import hashlib
import os

import psutil


def inventory(known, maximum=300):
    covered = {port for row in known for port in row.get('ports', [])}
    owned_pids = {row.get('runtime_details', {}).get('pid') for row in known}
    sockets = psutil.net_connections(kind='inet')
    by_pid = {}
    for connection in sockets[:10000]:
        if not connection.pid or not connection.laddr or connection.pid in owned_pids:
            continue
        protocol = 'tcp' if connection.type == 1 else 'udp'
        if protocol == 'tcp' and connection.status != psutil.CONN_LISTEN:
            continue
        port = str(connection.laddr.port) + '/' + protocol
        if port not in covered:
            by_pid.setdefault(connection.pid, set()).add(port)
    rows = []
    for pid, ports in list(by_pid.items())[:maximum]:
        try:
            process = psutil.Process(pid)
            if hasattr(os, 'getuid'):
                if process.uids().real != os.getuid():
                    continue
            elif process.username() != psutil.Process().username():
                continue
            executable, started = process.exe(), process.create_time()
            # No command line, environment or socket peer addresses are read.
            identity = hashlib.sha256(f'{pid}\0{started}\0{executable}'.encode()).hexdigest()[:16]
            rows.append({'agent_ref': 'listener-' + identity, 'name': process.name()[:100], 'runtime': 'process',
                         'description': 'Unmanaged listening process suggestion; review before registration',
                         'status': 'running', 'tags': ['suggestion', 'read-only'], 'ports': sorted(ports),
                         'paths': [executable] if executable else [], 'urls': [], 'dependencies': [],
                         'control_handle': {'name': 'listener-' + identity},
                         'capabilities': {'control': False, 'logs': False, 'files': False},
                         'runtime_details': {'pid': pid, 'created_at': started}})
        except (psutil.Error, OSError):
            continue
    return rows
