"""Explicit read-only activity profiles. No activity is inferred from low CPU."""
import os
import re
from pathlib import Path

import psutil
from fastapi import HTTPException


def check(profile, command, timeout=5):
    if not isinstance(profile, dict):
        raise HTTPException(403, 'Activity profile is not configured on this agent')
    kind = profile.get('type', 'command')
    if kind == 'tcp_connections':
        ports = profile.get('ports')
        if not isinstance(ports, list) or not 1 <= len(ports) <= 30 or any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
            raise HTTPException(409, 'TCP activity profiles require explicit local TCP ports')
        try:
            connections = psutil.net_connections(kind='tcp')
        except (psutil.Error, OSError):
            return None
        if len(connections) > 10000:
            return None
        listeners = {row.laddr.port for row in connections if row.laddr and row.status == psutil.CONN_LISTEN}
        if not set(ports).issubset(listeners):
            return None  # An absent listener is not proof of an idle application.
        return not any(row.laddr and row.laddr.port in ports and row.status != psutil.CONN_LISTEN for row in connections)
    if kind == 'minecraft_players':
        executable, port, reference = profile.get('executable', ''), profile.get('port', 25575), profile.get('password_env', '')
        if not isinstance(executable, str) or not Path(executable).is_absolute() or Path(executable).name.lower() not in ('mcrcon', 'mcrcon.exe') or type(port) is not int or not 1 <= port <= 65535 or not isinstance(reference, str) or not re.fullmatch(r'PSC_IDLE_[A-Z0-9_]+', reference):
            raise HTTPException(409, 'Minecraft activity requires an absolute mcrcon executable, local RCON port and credential environment reference')
        password = os.environ.get(reference, '')
        if not password:
            return None
        environment = {key: value for key, value in os.environ.items() if not key.startswith(('PSC_', 'MCRCON_'))}
        environment['MCRCON_PASS'] = password
        try:
            output = command([executable, '-c', '-H', '127.0.0.1', '-P', str(port), 'list'], env=environment, timeout=min(timeout, 5))
        except HTTPException:
            return None
        if len(output) > 100000:
            return None
        counts = re.findall(r'(?m)^There are ([0-9]{1,6}) of a max of [0-9]{1,6} players online:', output)
        return int(counts[0]) == 0 if len(counts) == 1 else None
    if kind != 'command':
        raise HTTPException(409, 'Unknown activity profile type')
    argv = profile.get('argv')
    if not isinstance(argv, list) or not argv or len(argv) > 30 or any(not isinstance(arg, str) or '\x00' in arg or len(arg) > 1024 for arg in argv) or not Path(argv[0]).is_absolute():
        raise HTTPException(403, 'Activity checks require explicit fixed argv and an absolute executable')
    try:
        result = command(argv, timeout=min(timeout, 5)).strip()
    except HTTPException:
        return None
    return result == 'idle' if result in ('idle', 'active') else None
