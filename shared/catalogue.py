"""Small, deterministic fingerprints; no internet lookup or installation."""
CATALOGUE = [
    ("minecraft", ("minecraft-server", "minecraft.service"), "Minecraft", "game", ["games"], None),
    ("ollama", ("ollama", "ollama.service"), "Ollama", "ai", ["ai", "local"], (11434, "http")),
    ("uptime-kuma", ("uptime-kuma", "uptime-kuma.service"), "Uptime Kuma", "monitoring", ["monitoring"], (3001, "http")),
    ("portainer", ("portainer", "portainer-ce", "portainer.service"), "Portainer", "box", ["infrastructure"], (9443, "https")),
    ("vaultwarden", ("vaultwarden", "vaultwarden.service"), "Vaultwarden", "security", ["security"], (8080, "http")),
    ("tailscale", ("tailscale", "tailscaled.service"), "Tailscale", "network", ["network"], None),
    ("samba", ("samba", "smbd.service"), "Samba", "network", ["network", "storage"], None),
]


def enrich(row: dict, host_address: str):
    row = dict(row)
    hints = [row.get("image", ""), row.get("name", ""), row.get("control_handle", {}).get("unit", "")]
    images = row.get("images", [])
    hints.extend(images)
    normalized = {hint.lower().split(":")[0].split("/")[-1] for hint in hints if isinstance(hint, str)}
    for key, patterns, name, icon, tags, access in CATALOGUE:
        if not normalized.intersection(patterns):
            continue
        row["name"], row["icon"] = name, icon
        row["tags"] = list(dict.fromkeys(tags + row.get("tags", [])))
        row["fingerprint"] = key
        if access and not row.get("urls") and host_address and not any(char in host_address for char in ("/", "@", "?", "#", " ")):
            preferred, scheme = access
            ports = [int(port.split("/")[0]) for port in row.get("ports", []) if port.split("/")[0].isdigit()]
            # Use a published host port, never assume an internal port is reachable.
            port = preferred if preferred in ports else ports[0] if len(ports) == 1 else preferred if row.get("runtime") == "systemd" else None
            if port:
                address = f"[{host_address}]" if ":" in host_address and not host_address.startswith("[") else host_address
                row["urls"] = [f"{scheme}://{address}:{port}"]
        break
    return row
