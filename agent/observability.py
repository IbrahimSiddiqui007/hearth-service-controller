"""Bounded resource observations. Missing permissions produce unknown values, never invented zeros."""
import json
import math
import re
import time
from pathlib import PurePosixPath, PureWindowsPath
from datetime import datetime, timezone

import psutil
from fastapi import HTTPException

_samples = {}


def metadata_path(root, value):
    path_type = PurePosixPath if root.startswith('/') else PureWindowsPath
    path = path_type(value)
    return str(path if path.is_absolute() else path_type(root) / path)


def counter_cpu(key, counter):
    current = time.monotonic()
    previous = _samples.get(key)
    _samples[key] = (current, counter)
    if len(_samples) > 2000:
        _samples.clear()
    if not previous or current <= previous[0] or counter < previous[1]:
        return None
    return round((counter - previous[1]) / (current - previous[0]) * 100, 2)


def process_sample(pid):
    try:
        process = psutil.Process(int(pid))
        with process.oneshot():
            started = process.create_time()
            cpu = process.cpu_times()
            memory = process.memory_info().rss
        return {"metrics": {"cpu_percent": counter_cpu(('process', int(pid), started), cpu.user + cpu.system),
                            "memory_mb": round(memory / 1024 ** 2, 2), "scope": "main process", "sampled_at": datetime.now(timezone.utc).isoformat()},
                "started_at": datetime.fromtimestamp(started, timezone.utc).isoformat()}
    except (psutil.Error, OSError, ValueError, TypeError, OverflowError):
        return {"metrics": {"cpu_percent": None, "memory_mb": None, "scope": "main process unavailable"}}


def memory_mb(value):
    match = re.fullmatch(r'\s*([0-9]+(?:\.[0-9]+)?)\s*(B|[KMGT]i?B)\s*', value.split('/')[0])
    if not match:
        return None
    amount, unit = match.groups()
    exponent = {'B': 0, 'KB': 1, 'MB': 2, 'GB': 3, 'TB': 4, 'KiB': 1, 'MiB': 2, 'GiB': 3, 'TiB': 4}[unit]
    return round(float(amount) * (1024 if 'i' in unit or unit == 'B' else 1000) ** exponent / 1024 ** 2, 2)


def docker_samples(command):
    try:
        result = {}
        for line in command(['docker', 'stats', '--all', '--no-stream', '--format', '{{json .}}'], timeout=12).splitlines()[:1000]:
            row = json.loads(line)
            if not isinstance(row, dict):
                continue
            cpu = float(row.get('CPUPerc', '').rstrip('%'))
            result[row.get('Name', '')] = {"cpu_percent": cpu if math.isfinite(cpu) and cpu >= 0 else None,
                     "memory_mb": memory_mb(row.get('MemUsage', '')), "scope": "container", "sampled_at": datetime.now(timezone.utc).isoformat()}
        return result
    except (HTTPException, ValueError, TypeError, AttributeError):
        return {}


def systemd_details(command, names):
    result = {}
    properties = 'Id,FragmentPath,DropInPaths,WorkingDirectory,MainPID,NRestarts,ActiveEnterTimestampMonotonic,Restart,UnitFileState,CPUUsageNSec,MemoryCurrent,StandardOutput,StandardError'
    for index in range(0, len(names), 100):
        try:
            output = command(['systemctl', 'show', '--no-pager', '--all', '--property=' + properties, '--', *names[index:index + 100]])
            for block in output.strip().split('\n\n'):
                values = dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
                if values.get('Id') in names:
                    result[values['Id']] = values
        except (HTTPException, ValueError):
            continue
    return result
