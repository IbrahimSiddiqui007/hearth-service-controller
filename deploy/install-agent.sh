#!/usr/bin/env bash
# Review locally. Default is a plan; --apply installs files but never starts or
# enables the agent, opens a firewall, changes Tailscale, or grants runtime groups.
set -euo pipefail
mode="${1:---plan}"
if [[ "$mode" != "--plan" && "$mode" != "--apply" ]]; then
  printf 'Usage: bash deploy/install-agent.sh [--plan|--apply]\n' >&2
  exit 2
fi
source_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
target=/opt/pi-service-controller
[[ -f "$source_root/requirements.txt" && -d "$source_root/agent" && -d "$source_root/shared" ]] || { printf 'Source tree is incomplete\n' >&2; exit 1; }
[[ -f /etc/os-release ]] && . /etc/os-release
case "${ID:-unknown}" in
  ubuntu|debian) packages='python3 python3-venv python3-pip (apt)' ;;
  cachyos|arch) packages='python python-pip (pacman)' ;;
  *) printf 'Review support for this distribution before installing\n' >&2; exit 1 ;;
esac
printf 'Agent installation plan\nSource: %s\nTarget: %s\nRequired packages: %s\nDedicated non-root account: psc-agent\nConfig: /etc/psc/agent.yaml and agent.env\nPrivate state: /var/lib/psc-agent\n' "$source_root" "$target" "$packages"
printf 'Existing installation/config/service files are never overwritten. Runtime permissions remain opt-in.\n'
[[ "$mode" == "--apply" ]] || exit 0
[[ "$(id -u)" == 0 ]] || { printf '--apply requires root on the target Linux host\n' >&2; exit 1; }
[[ ! -e "$target" && ! -L "$target" && ! -e /etc/psc/agent.yaml && ! -e /etc/psc/agent.env && ! -e /etc/systemd/system/psc-agent.service ]] || { printf 'Existing files found; preserve/review them before an upgrade\n' >&2; exit 1; }
[[ ! -L /etc/psc && ! -L /var/lib/psc-agent ]] || { printf 'Config and state directories cannot be symlinks\n' >&2; exit 1; }
for tool in python3 install systemctl useradd; do command -v "$tool" >/dev/null || { printf 'Missing prerequisite: %s\n' "$tool" >&2; exit 1; }; done
if id psc-agent >/dev/null 2>&1; then
  [[ "$(id -u psc-agent)" != 0 ]] || { printf 'Agent account cannot be root\n' >&2; exit 1; }
else
  login_shell="$(command -v nologin)"
  useradd --system --user-group --home-dir /var/lib/psc-agent --shell "$login_shell" psc-agent
fi
install -d -m 0755 "$target"
install -d -m 0755 "$target/agent" "$target/shared"
install -m 0644 "$source_root"/agent/*.py "$target/agent/"
install -m 0644 "$source_root"/shared/*.py "$target/shared/"
install -m 0644 "$source_root/requirements.txt" "$target/requirements.txt"
python3 -m venv "$target/.venv"
"$target/.venv/bin/python" -m pip install -r "$target/requirements.txt"
install -d -m 0750 -o root -g psc-agent /etc/psc
install -d -m 0700 -o psc-agent -g psc-agent /var/lib/psc-agent
install -m 0640 -o root -g psc-agent "$source_root/deploy/agent.example.yaml" /etc/psc/agent.yaml
(umask 077; printf 'PSC_AGENT_TOKEN=\n' > /etc/psc/agent.env)
chown root:psc-agent /etc/psc/agent.env
chmod 0640 /etc/psc/agent.env
install -m 0644 "$source_root/deploy/psc-agent.service.example" /etc/systemd/system/psc-agent.service
systemctl daemon-reload
printf 'Files installed; agent remains stopped and disabled.\nSet a random token (24+ characters) privately in agent.env. Review allow-lists, state_dir and bind address. Then explicitly enable/start psc-agent.service when ready.\n'
