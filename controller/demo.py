from datetime import datetime, timedelta, timezone
import json
import math

from controller.store import Store, now
from shared.models import HostDefinition, ServiceDefinition


def illustrative_telemetry(store: Store):
    """Append a labelled synthetic series once; never rewrite existing observations."""
    with store.connection() as db:
        if db.execute("SELECT 1 FROM settings WHERE key='demo.telemetry.v2'").fetchone():
            return
        hosts = [host for host in store.all('hosts') if host.get('demo') and host['id'] in ('controller1', 'worker-node1')]
        for host in hosts:
            hid = host['id']
            sent, received, read, written = 123456789, 987654321, 100000000, 50000000
            previous, previous_ts = None, None
            for index in range(30):
                ts = (datetime.now(timezone.utc) - timedelta(seconds=(29 - index) * 30)).isoformat()
                variation = 1 + .4 * math.sin(index / 3)
                sent += int(30 * 45000 * variation)
                received += int(30 * 180000 * variation)
                read += int(30 * 320000 * variation)
                written += int(30 * 90000 * variation)
                body = {'cpu_percent': round(12 + 8 * math.sin(index / 3) + (7 if hid == 'worker-node1' else 0), 1),
                        'memory_percent': 48 if hid == 'worker-node1' else 22, 'memory_total_gb': 32 if hid == 'worker-node1' else 8,
                        'disk_percent': 37, 'disk_total_gb': 512, 'temperature_c': 46 if hid == 'worker-node1' else 41,
                        'network_sent_bytes': sent, 'network_recv_bytes': received, 'disk_read_bytes': read, 'disk_write_bytes': written,
                        'boot_time': 1, 'interfaces': {'eth0': {'sent_bytes': sent, 'received_bytes': received}}, 'demo': True,
                        'volumes': [{'mount': '/', 'device': 'demo-root', 'filesystem': 'ext4', 'total_bytes': 512 * 1024 ** 3, 'used_bytes': int(.37 * 512 * 1024 ** 3), 'free_bytes': int(.63 * 512 * 1024 ** 3), 'percent': 37},
                                    {'mount': '/srv/data', 'device': 'demo-data', 'filesystem': 'ext4', 'total_bytes': 256 * 1024 ** 3, 'used_bytes': 128 * 1024 ** 3, 'free_bytes': 128 * 1024 ** 3, 'percent': 50}]}
                from controller.telemetry import rates
                sample = rates(body, previous, ts, previous_ts)
                db.execute('INSERT INTO telemetry(host_id,ts,body) VALUES(?,?,?)', (hid, ts, json.dumps(sample)))
                previous, previous_ts = body, ts
        db.execute("INSERT INTO settings VALUES('demo.telemetry.v2','true')")


def seed(store: Store):
    if store.all("hosts"):
        return
    hosts = [
        ("controller1", "controller1", "Example ARM64 controller · 8 GB", "Ubuntu", "arm64", "100.64.0.10", "online"),
        ("worker-node1", "worker-node1", "Example AMD64 worker · 32 GB", "Ubuntu Server", "amd64", "100.64.0.20", "online"),
        ("laptop", "laptop", "Example portable host · 32 GB", "Linux / Windows", "amd64", "100.64.0.30", "offline"),
    ]
    for hid, name, hardware, os_name, arch, address, status in hosts:
        host = HostDefinition(id=hid, name=name, address=address, os=os_name, architecture=arch).model_dump()
        host.update(hardware=hardware, status=status, demo=True, last_seen=now() if status == "online" else None)
        store.put("hosts", host)

    rows = [
        ("minecraft", "Minecraft", "worker-node1", "compose", "running", "Your little corner of the overworld. Fabric server for friends.", ["games", "friends"], ["25565/tcp"], [], "/opt/services/minecraft", 27, 6144),
        ("ollama", "Ollama", "worker-node1", "systemd", "running", "Local models for private experiments and service explanations.", ["ai", "local"], ["11434/tcp"], ["http://worker-node1:11434"], "/opt/ollama", 4, 3840),
        ("uptime-kuma", "Uptime Kuma", "worker-node1", "docker", "running", "A second pair of eyes on the services that matter.", ["monitoring"], ["3001/tcp"], ["http://worker-node1:3001"], "/opt/services/uptime-kuma", 1, 148),
        ("portainer", "Portainer", "worker-node1", "docker", "running", "Container administration for the main worker.", ["infrastructure"], ["9443/tcp"], ["https://worker-node1:9443"], "/opt/services/portainer", 1, 92),
        ("vaultwarden", "Vaultwarden", "controller1", "compose", "running", "The vault. Credentials live here; service notes point to them.", ["security", "essential"], ["8080/tcp"], ["http://controller1:8080"], "/opt/services/vaultwarden", 2, 68),
        ("tailscale", "Tailscale", "controller1", "systemd", "running", "Private access to the lab, wherever you happen to be.", ["network", "essential"], [], [], "/etc/tailscale", 1, 42),
        ("playground", "Model playground", "laptop", "compose", "unknown", "A place to try ideas. Available when the laptop is on Linux.", ["ai", "experiments"], ["7860/tcp"], [], "/home/user/services/playground", 0, 0),
        ("paperless", "Paperless", "worker-node1", "compose", "stopped", "Documents, sorted. Waiting for the next batch of scans.", ["documents"], ["8000/tcp"], ["http://worker-node1:8000"], "/opt/services/paperless", 0, 0),
    ]
    for sid, name, hid, runtime, status, description, tags, ports, urls, path, cpu, memory in rows:
        handle = {"unit": "tailscaled.service" if sid == "tailscale" else sid + ".service"} if runtime == "systemd" else {"container": sid} if runtime == "docker" else {"project": sid, "path": path}
        notes = ("## Why it lives here\n\n" + description + "\n\n## Recovery notes\n\nThis is sample documentation. Replace it with your actual install and restore instructions.\n\n## Related\n\n[[Host--" + hid + "]]\n")
        row = ServiceDefinition(id=sid, name=name, host_id=hid, runtime=runtime, description=description,
                                tags=tags, ports=ports, urls=urls, paths=[path], control_handle=handle, notes=notes).model_dump()
        row.update(status=status, demo=True, source="demo", revision=1, created_at=now(), updated_at=now(),
                   observed_at=now(), metrics={"cpu_percent": cpu, "memory_mb": memory},
                   capabilities={"control": sid != "tailscale" and hid != "laptop", "logs": True, "files": True})
        store.put("services", row)
        store.audit("service.registered", "success", "Sample service added to demo workspace", sid, hid)

    with store.connection() as db:
        for hid in ("controller1", "worker-node1"):
            for index in range(30):
                ts = (datetime.now(timezone.utc) - timedelta(minutes=(29 - index) * 2)).isoformat()
                body = {"cpu_percent": round(12 + 8 * math.sin(index / 3) + (7 if hid == "worker-node1" else 0), 1),
                        "memory_percent": 48 if hid == "worker-node1" else 22, "memory_total_gb": 32 if hid == "worker-node1" else 8,
                        "disk_percent": 37, "disk_total_gb": 512, "temperature_c": 46 if hid == "worker-node1" else 41,
                        "network_sent_bytes": 123456789, "network_recv_bytes": 987654321, "boot_time": 0, "demo": True}
                db.execute("INSERT INTO telemetry(host_id,ts,body) VALUES(?,?,?)", (hid, ts, json.dumps(body)))
