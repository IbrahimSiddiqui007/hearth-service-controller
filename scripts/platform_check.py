"""Read-only compatibility inventory; Python 3.8+; no project dependencies.

Prints selected public version/capability metadata only. Does not load agent
configuration, inspect services, execute a shell, contact hosts or install tools.
"""
import importlib.metadata
import json
import os
import platform
import shutil
import sys
from pathlib import Path


def report():
    system = platform.system()
    result = {
        'system': system,
        'release': platform.release(),
        'architecture': platform.machine(),
        'python': platform.python_version(),
        'ordinary_account': os.getuid() != 0 if hasattr(os, 'getuid') else 'not checked',
        'tools_present': {name: bool(shutil.which(name)) for name in (
            'systemctl', 'launchctl', 'docker', 'git', 'dpkg-query', 'pacman',
            'rpm', 'bash', 'zsh', 'node', 'npm')},
        'python_packages': {},
        'checks_not_run': ['native controls', 'file metadata replacement',
                           'PTY execution', 'Docker builds', 'host enrollment'],
    }
    for name in ('fastapi', 'uvicorn', 'PyYAML', 'psutil', 'httpx', 'websockets', 'pytest'):
        try:
            result['python_packages'][name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            result['python_packages'][name] = 'not installed in this interpreter'
    if system == 'Linux':
        try:
            values = {}
            for line in Path('/etc/os-release').read_text(encoding='utf-8').splitlines():
                key, separator, value = line.partition('=')
                if separator and key in ('ID', 'ID_LIKE', 'VERSION_ID', 'PRETTY_NAME'):
                    values[key] = value.strip('"')[:200]
            result['distribution'] = values
        except OSError:
            result['distribution'] = 'unavailable'
    if system == 'Darwin':
        result['macos_version'] = platform.mac_ver()[0] or 'unavailable'
        result['login_tty_available'] = hasattr(os, 'login_tty')
    return result


if __name__ == '__main__':
    if len(sys.argv) != 1:
        raise SystemExit('Usage: python3 scripts/platform_check.py (no arguments)')
    print(json.dumps(report(), indent=2, ensure_ascii=True))
