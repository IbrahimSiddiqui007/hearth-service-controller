# Pi Service Controller v2 — Spec

Public design specification · maintained by project contributors

## 1. Overview

Pi Service Controller v2 is a homelab memory: one dashboard, hosted on the ARM64 controller, that knows every service on every box, how it was installed, where its files and credentials live, how to back it up, and why it broke.

**Pitch:** *Every service, how you installed it, where its files are, where its password lives, and why it broke.*

**The problem it solves.** Homelab owners forget how they set things up. Passwords get lost, install steps are gone, config paths are a mystery, and "what do you use to document your homelab?" gets asked on r/selfhosted again and again with no single-tool answer. Existing tools manage containers (Portainer, Dockge, Komodo) or the OS (Cockpit), and dashboards (Trove, DeQ, Homepage) show status. None of them remember.

**Positioning.** Not "another Docker UI." The unit is the *service*, whatever runs it, and every service carries its own living documentation that the tool writes and keeps current.

**Release model.** Public source is available for review. This is an experimental project, not a validated v1 release. A public launch or production-readiness claim requires real deployment acceptance. No community post is authorized by this specification.

## 2. Goals and non-goals

v1 succeeds when every service across the Pi, mini PC and laptop is discovered, controllable with one click, and has a service card that answers "how did I set this up?" without SSH.

**Goals**

1. Service-first model: one object per service regardless of runtime (Docker, Compose, systemd, pm2, raw binary).
2. Auto-discovery: scan a host and propose services, with minimal hand-written config.
3. One-click start / stop / restart per service, across hosts.
4. Living documentation: a service card per service, auto-drafted and kept current.
5. Install recorder: capture how a service was installed and turn it into reinstall steps.
6. Built-in log terminal and file browser per service.
7. Config history: every edit made through the tool is versioned and reversible.
8. Local-AI log explainer using the user's own Ollama.
9. Credential pointers into Vaultwarden, never stored secrets.
10. Per-service backup and restore to the NAS.
11. Wake/sleep: Wake-on-LAN for hosts, idle auto-stop for services.
12. Runs comfortably on a low-power ARM64 computer.
13. Broad host telemetry: CPU, memory, disk, network, temperatures, and historical system monitoring.
14. Standalone container management and logging, alongside the service-first view.
15. Manually maintained JSON/YAML service manifests alongside reviewed auto-discovery.
16. An app catalogue with one-click installation of supported applications.
17. Kubernetes, Proxmox, and VM management through platform adapters.
18. Windows-side monitoring while the dual-boot laptop runs Windows 11.
19. Obsidian-compatible linked notes, portable Markdown export, and conflict-aware synchronization of owner notes.

**Non-goals (v1)**

- Not a password manager. Secrets live in Vaultwarden.
- No public internet exposure. Access is Tailscale-only.
- No multi-user roles or RBAC. Single owner.
- No Zero 2W as the controller host.

**Scope update — October 12, 2026.** The six capabilities in goals 13–18 are included in the planned product scope. Their feature definitions are F12–F17 below. Their release and phase assignments remain to be scheduled; they are no longer exclusions or merely external-tool alternatives.

## 3. Illustrative deployment environment

This is a generic reference topology, not an inventory of a contributor's network. Keep actual hostnames, device models, addresses, OS versions and storage details in ignored local configuration.

**Example network path:** private router/firewall → managed switch → hosts. Remote access uses a private tailnet; no public application listener is required.

| Example host | Hardware class | OS family | Role | Availability |
| --- | --- | --- | --- | --- |
| controller.example | Low-power ARM64 computer | Linux | Controller and optional local agent | Usually on |
| worker.example | AMD64 server | Linux | Approved container/application workloads | Usually on |
| portable.example | Portable AMD64 computer | Linux or Windows | Optional agent; active OS identified separately | Intermittent |
| storage.example | Network storage | NAS appliance | Existing SMB/NFS mount; no agent assumed | Owner configured |

**Design constraints**

- Offline hosts must remain usable as stale inventory; commands are refused rather than queued.
- ARM64 and AMD64 portability and the approximately 250 MB combined low-power resource goal require measured evidence.
- Storage is owner-provisioned; the controller never configures NAS permissions or mounts automatically.
- Bash, Zsh and Fish histories need distinct parsers; a shell choice is not an owner-network detail.
- Native permissions and active-OS behavior need platform acceptance. Optional orchestration platforms must not be assumed to exist.

## 4. Core concept: the service

A service is one thing you care about ("Minecraft", "Ollama", "Uptime Kuma"), not a container or a unit. It bundles everything needed to run, understand and recover it.

**What a service bundles**

| Part | What it holds | Example (Minecraft) |
| --- | --- | --- |
| Identity | Name, icon, host, tags, description | Minecraft, worker.example, tags: game |
| Runtime | How it runs: `docker`, `compose`, `systemd`, `pm2`, `process` | compose |
| Control handle | What start/stop acts on | compose project at `~/services/minecraft` |
| Components | Underlying containers, units or PIDs | 1 container: itzg/minecraft-server |
| Ports | Listening ports + protocol | 25565/tcp |
| URLs | Web UI links if any | none |
| Paths | Working dir, config files, data dirs, volumes | `~/services/minecraft/`, `data/` |
| Logs | Log source | `docker compose logs` |
| Health | Checks to run | TCP 25565 |
| Dependencies | Other services it needs | none |
| Credentials | Vaultwarden pointers + non-secret hints | RCON password → vault item |
| Install record | Recorded install steps | recorder session #3 |
| Backup policy | What to back up, where, how often | `data/` → NAS weekly |
| Notes | Free-form owner notes | "Fabric mods, 6 GB, 6 players" |

**Supported runtimes**

| Runtime | Start / stop via | Logs via | Discovered from |
| --- | --- | --- | --- |
| compose | `docker compose up -d` / `stop` in project dir | compose logs | `com.docker.compose.project` labels |
| docker | Docker API start / stop | container logs | Docker API, standalone containers |
| systemd | D-Bus `StartUnit` / `StopUnit` | `journalctl -u` | enabled/running units, filtered |
| pm2 | `pm2 start` / `stop` | pm2 logs | `pm2 jlist` |
| process | kill / launch command from manifest | log file path from manifest | listening sockets with no other owner |

**Grouping rule.** Discovery merges components into one service when they share a compose project, a systemd unit that wraps compose, or the same working directory. The user can split or merge services in the UI.

## 5. System architecture

Hub-and-agent: one controller on the ARM64 controller holds state and serves the UI; a small agent on every managed host (the Pi included) does the local work.

&#91;embedded content: system architecture · controller, 3 agents, 3 integrations\]

The browser only ever talks to the controller; the controller only ever talks to agents and integrations, never raw SSH.

**Components**

| Component | Runs on | Responsibility |
| --- | --- | --- |
| Controller | controller.example (ARM64 controller) | REST + WebSocket API, service registry, SQLite, scheduler (health checks, backups, idle timers), AI calls, serves the UI |
| Agent | every managed host | Discovery scans, runtime control, log/terminal streaming, file read/write, git snapshots of config, backup execution |
| Web UI | browser / phone (PWA) | Service grid, service cards, terminal, file browser, recorder, settings |
| Datastore | controller.example | SQLite: services, hosts, health history, recorder sessions, docs, audit log |

**Key flows**

1. **Status.** Each agent pushes a heartbeat + service states every 15 s over a persistent WebSocket. Three missed beats mark the host stale; ten mark it offline.
2. **Control.** UI → `POST /services/{id}/start` → controller checks the service's runtime → sends a signed command to that host's agent → agent executes → result + new state flow back.
3. **Logs and terminal.** UI opens a WebSocket to the controller, which proxies it to the agent's PTY or log stream. Bytes are relayed, not stored, except during a recording.
4. **Discovery.** Controller asks an agent to scan → agent returns candidate services → controller diffs against the registry → UI shows "new / changed / gone" for the user to accept.
5. **Offline host.** Commands to an offline host are refused with a clear state, never queued silently. Wake-on-LAN is offered if configured.

**Why agents instead of SSH.** No sudo-capable SSH keys stored on the Pi, a narrow allow-listed command surface per host, and push-based status that works when the controller restarts.

## 6. Feature specifications

F1–F11 form the original v1 plan; F1, F2, F4 and F5 are the core. F12–F17 extend the planned scope, with release and phase assignments still to be scheduled. F18 adds the requested Obsidian connection alongside service documentation.

| ID | Feature | Priority | Phase |
| --- | --- | --- | --- |
| F1 | Auto-discovery | Core | 1 |
| F2 | Service control | Core | 1 |
| F3 | Status and health | Core | 1 |
| F4 | Service card (living docs) | Core | 2 |
| F5 | Install recorder | Core | 3 |
| F6 | File browser + config history | High | 3 |
| F7 | Log viewer + terminal | High | 2 |
| F8 | AI log explainer | High | 4 |
| F9 | Credential pointers | High | 4 |
| F10 | Backup and restore | Medium | 5 |
| F11 | Wake / sleep | Medium | 5 |
| F12 | Broad host telemetry | To prioritize | To schedule |
| F13 | Standalone container management + logging | To prioritize | To schedule |
| F14 | Manual service manifests | To prioritize | To schedule |
| F15 | App catalogue + one-click installation | To prioritize | To schedule |
| F16 | Kubernetes, Proxmox + VM management | To prioritize | To schedule |
| F17 | Windows-side monitoring | To prioritize | To schedule |
| F18 | Obsidian linked notes + owner-note sync | High | Alongside F4 |

### F1. Auto-discovery

The agent scans its host and proposes services so the user never hand-writes a manifest.

**Scan sources**

- Docker API: containers, compose project labels, published ports, mounts, working dir label.
- systemd over D-Bus: loaded units, filtered to exclude OS noise (see filter list below).
- pm2: `pm2 jlist` if installed.
- Listening sockets (`ss -tlnp`): ports not owned by any of the above become `process` candidates.
- Known-app fingerprints: image names and unit names matched against a small built-in catalogue (Ollama, Samba, Tailscale, Uptime Kuma, Portainer, Minecraft…) to prefill name, icon and URL.

**Behaviour**

- Default systemd filter hides units from base OS packages (`systemd-*`, `dbus`, `getty@`, `snapd*`, `NetworkManager`, etc.). The user can unhide.
- Candidates are grouped per the grouping rule in section 4.
- Results appear as a review list: **New**, **Changed** (ports, image, paths differ), **Gone**. Nothing is added without the user accepting it.
- Rescan runs on demand and every 6 h by default.

**Acceptance criteria**

- [ ] Scanning worker.example finds the Minecraft compose project as one service with port 25565 and path `~/services/minecraft`.
- [ ] Portainer, Uptime Kuma and Ollama are found and named correctly from the catalogue.
- [ ] Base OS units do not appear unless unhidden.
- [ ] A scan completes in under 10 s on the Pi.

### F2. Service control

One click starts, stops or restarts a service, whatever its runtime.

**Behaviour**

- Actions: start, stop, restart. Plus enable/disable at boot for systemd and compose (`restart:` policy).
- The agent maps the action to the runtime (table in section 4) and only runs allow-listed operations.
- Dependencies: starting a service offers to start its declared dependencies first; stopping one warns if another running service depends on it.
- Bulk actions: select several services, act once.
- Every action lands in the audit log with time, service, action and result.

**Acceptance criteria**

- [ ] Toggle Minecraft off and on from the phone; state updates in under 3 s.
- [ ] A systemd service on the Pi can be stopped without the controller holding root.
- [ ] Acting on a service on an offline laptop shows "host offline", with a Wake option if configured.

### F3. Status and health

Every service shows live state and a health history, covering the Uptime Kuma use case per service.

**Behaviour**

- Runtime state from the agent: running, stopped, restarting, failed, unknown.
- Health checks per service: HTTP(S) status, TCP port, or a custom command. Interval default 60 s.
- History stored in SQLite: uptime % for 24 h / 7 d / 30 d, response time, last incidents.
- Resource snapshot: CPU %, memory, restart count, uptime since last start.
- Optional import of existing Uptime Kuma monitors via its API so history is not lost.
- Alerts: service down, host offline, repeated restarts. Delivered via ntfy or a Telegram bot (user picks one).

**Acceptance criteria**

- [ ] Stopping Minecraft marks it down within one check interval and records an incident.
- [ ] 30-day uptime is visible on the service card.

### F4. Service card (living documentation)

Each service has one page that answers "what is this and how is it set up?" without SSH. This is the product's centre.

**Card sections**

1. **Summary**: what the service is, in one or two sentences (AI-drafted, user-editable).
2. **Access**: URLs, ports, host.
3. **Where things live**: working dir, config files, data dirs, volumes, log location.
4. **How it runs**: runtime, compose file or unit file (read-only view), restart policy, boot behaviour.
5. **Credentials**: vault pointers and hints (F9).
6. **How it was installed**: recorded or reconstructed steps (F5).
7. **Backup**: policy, last backup, restore button (F10).
8. **Dependencies**: what it needs, what needs it.
9. **History**: config changes (F6), incidents (F3), control actions.
10. **Notes**: free-form markdown.

**Behaviour**

- The card auto-fills from discovery. The AI drafts the summary from the compose/unit file and known-app catalogue.
- Fields the tool knows stay live (ports, paths, state). A change detected on rescan shows as "changed since last review".
- Export: a single service or the whole lab as markdown files, so the docs survive even if the tool dies.
- Search across all cards: "which service uses port 8084?", "where is the Samba config?"

**Acceptance criteria**

- [ ] Opening the Minecraft card shows path, port, mods note, compose file and last backup without any SSH.
- [ ] "Export lab" produces one markdown file per service.
- [ ] Search by port, path or name returns the right service.

### F5. Install recorder

Captures how a service was installed and turns it into reinstall steps.

**Mode A: live recording.** Built on the F7 terminal.

1. User opens a terminal on a host and presses **Record setup**, naming the service (new or existing).
2. The agent records the PTY session (commands + output, asciinema-style) and takes a *before* snapshot.
3. User installs as normal.
4. On **Stop**, the agent takes an *after* snapshot and diffs them.
5. The AI turns commands + diff into clean, ordered reinstall steps. The user reviews and saves them to the card.

**Snapshot contents (before vs after)**

- Installed packages (`dpkg -l` / `pacman -Q`).
- systemd unit files and enabled state.
- Docker containers, images, compose projects, volumes.
- Listening ports.
- Files created or changed under watched dirs: `/etc`, `/opt`, `~/services`, the service working dir, plus user-added dirs.

**Mode B: backfill from shell history.** For services installed before the tool existed.

- Import Bash, Zsh and Fish history (Fish history includes timestamps).
- Filter by the service's name, paths, image and ports to find related commands.
- AI reconstructs a best-guess install sequence, clearly marked "reconstructed, unverified".

**Secret handling.** Before storing or sending to the AI, the recorder masks likely secrets: values after `-p`/`--password`, `*_PASSWORD=`/`*_TOKEN=`/`*_KEY=` assignments, `Authorization:` headers, and long high-entropy strings. Masked values become `‹secret›` with a prompt to vault them (F9).

**Acceptance criteria**

- [ ] Recording a fresh install of a small Compose app yields steps that reinstall it on a clean host.
- [ ] A password typed on the command line never appears in stored recordings or AI prompts.
- [ ] Backfill on the laptop reads Fish history and proposes steps for at least one existing service.

### F6. File browser + config history

Browse and edit a service's files, with every edit versioned and reversible.

**Behaviour**

- Tree scoped to the service's declared paths only. No browsing outside them without an explicit "open host root" toggle.
- Monaco editor for text files; syntax highlighting for YAML, JSON, TOML, INI, `.env`, shell.
- Size guard: files over 2 MB open read-only; binaries are download-only.
- **Config history**: the agent keeps a git repo per service tracking its config files (not data dirs).
  - Every save through the UI is a commit with a message.
  - A periodic check commits external edits as "changed outside tool".
  - Diff view between any two versions; one-click revert.
  - Files flagged as holding secrets (`.env`, anything the scanner flags) are excluded from history by default.
- Optional validate-before-save: YAML/JSON lint; `docker compose config` for compose files.

**Acceptance criteria**

- [ ] Edit Minecraft's `server.properties`, save, see the commit, revert it, and see the old value restored.
- [ ] An invalid compose file is blocked at save with the error shown.

### F7. Log viewer + terminal

Live logs and an optional shell per service, in the browser.

**Behaviour**

- **Logs mode (default, read-only):** follows `docker compose logs -f`, `journalctl -u -f`, pm2 logs or a log file. Filter, pause, search, jump to errors, download last N lines.
- **Shell mode:** a real PTY on the host, opened in the service's working dir, as the agent's configured non-root user. Requires an explicit click plus confirmation each session.
- xterm.js on the frontend, WebSocket relay through the controller.
- Sessions time out after 15 min idle.
- Shell sessions are logged to the audit log (start, end, host), not their content, unless recording (F5).

**Acceptance criteria**

- [ ] Minecraft logs stream live with under 1 s lag.
- [ ] Shell mode opens in `~/services/minecraft` and `docker compose ps` works there.

### F8. AI log explainer

One button, "Why did this break?", explains a failure in plain English using the user's own Ollama.

**Behaviour**

1. User clicks **Explain** on a failed service or a selected log range.
2. Controller gathers context: last 200 log lines (or the selection), the service card summary, runtime, recent config changes and recent incidents.
3. Secrets are masked (same rules as F5).
4. Prompt goes to the configured Ollama endpoint and model.
5. Response shows: **what happened**, **likely cause**, **suggested fix** (commands shown, never auto-run), **confidence**.
6. The explanation can be saved to the card's history as an incident note.

**Config**

- Endpoint (an explicitly configured local Ollama endpoint), model name, timeout (default 60 s), max context lines.
- If Ollama is unreachable, the button shows as unavailable with the reason.
- Other AI uses share this setup: card summaries (F4) and recorder step cleanup (F5).

**Acceptance criteria**

- [ ] Breaking a compose file port mapping and clicking Explain names the port conflict as the cause.
- [ ] No log line with an unmasked secret reaches Ollama.

### F9. Credential pointers

The tool remembers *where* a credential lives, never the credential itself.

**Behaviour**

- Per service, a list of credential entries: label, username (optional), Vaultwarden item link or ID, and hints ("stored as `RCON_PASSWORD` in `.env`", "set in web UI on first login").
- **Secret scanner**: during discovery and on file save, flag files containing likely secrets. The card shows "2 secrets found in `.env`, not vaulted" with a one-click "I've vaulted it" link-up.
- "Open in Vaultwarden" deep link; "copy username" button.
- No secret values in SQLite, logs, exports, AI prompts or git history.
- Later (post-v1): Bitwarden CLI integration to show whether the linked item still exists.

**Acceptance criteria**

- [ ] The Minecraft card shows the RCON credential as a Vaultwarden link, and the DB contains no password.
- [ ] Scanner flags a new `.env` with a `PASSWORD=` line within one scan.

### F10. Backup and restore

One-click backup of a service's config and data to the NAS, and a guided restore.

**Behaviour**

- Per-service policy: which paths and volumes, schedule (manual / daily / weekly), retention (e.g. keep 7 daily, 4 weekly), and consistency mode.
- Consistency modes: **stop-copy-start** (safe for databases, brief downtime) or **live** (for static config).
- Engine: restic to a repo on the NAS (SMB/NFS mount), giving dedup and encryption. Repo password stored in Vaultwarden and supplied to the agent at run time.
- Backup includes the service card export and compose/unit files, so a restore also restores the docs.
- **Restore flow:** pick snapshot → preview files → stop service → restore → start → run health check → report.
- Backup status on the card and dashboard: last success, size, next run, failures alert via F3.

**Acceptance criteria**

- [ ] Back up Minecraft `data/` to the NAS, delete a file, restore, and the world loads.
- [ ] A failed backup raises an alert.

### F11. Wake / sleep

Power control for hosts and idle control for services, built for a low-power lab.

**Behaviour**

- **Host wake:** Wake-on-LAN by MAC, sent from the Pi's agent on the LAN. Target: mini PC and laptop.
- **Host sleep:** suspend or shutdown via agent, with a warning listing running services.
- **Service schedules:** cron-style start/stop windows (e.g. Minecraft 18:00–02:00 only).
- **Idle stop:** stop a service after N minutes with no connections on its port. Start it again from the UI on demand.
- The dashboard shows which services are asleep by schedule versus stopped by hand.

**Acceptance criteria**

- [ ] Wake the mini PC from the phone and see its agent come online.
- [ ] Minecraft stops after 30 min with no players and starts again on one click.

### F12. Broad host telemetry

Provide host-level system monitoring alongside service health.

**Behaviour**

- Show CPU, memory, disk capacity and I/O, network traffic, and temperatures where available.
- Provide live readings and historical charts on each host page; display unavailable sensors explicitly.
- Support configurable resource thresholds and route alerts through the existing notification system.
- Netdata or Glances may supply telemetry through an adapter; the choice between native collection and integration remains open.
- Define collection intervals, retention, and resource budgets before implementation so telemetry remains practical on the Pi.

**Acceptance criteria**

- [ ] A host page shows current CPU, memory, disk, and network readings with historical charts.
- [ ] Missing temperature sensors do not fail the host page.
- [ ] A configured resource threshold can trigger an alert.

### F13. Standalone container management + logging

Offer a container-level view in addition to grouped service cards, covering the management/logging use cases discussed around Portainer and Dozzle.

**Behaviour**

- List running and stopped containers by host, including containers not yet accepted as a service.
- Show image, state, ports, mounts, restart policy, resource usage, and associated service where known.
- Start, stop, and restart authorized containers individually; warn when an action affects a component of a grouped service.
- Reuse the live log viewer, filtering, search, pause, and download features at container level.
- Discovery alone does not authorize control. Apply the same allow-lists and auditing as service actions.
- Portainer/Dozzle integrations are optional implementation choices, not prerequisites for this capability.

**Acceptance criteria**

- [ ] An ungrouped container is visible with details and live logs.
- [ ] An authorized individual container can be started, stopped, and restarted with an audit entry.
- [ ] A grouped container links back to its service card.

### F14. Manual service manifests

Allow owner-maintained JSON/YAML definitions alongside auto-discovery.

**Behaviour**

- Define identity, host, runtime, control handle, working/config/data paths, log source, health checks, and dependencies in a versioned schema.
- Import and export manifests; validate references and required runtime fields before applying changes.
- Preview changes and reconcile existing services rather than creating duplicates on repeated import.
- Mark manually managed fields and surface conflicts with discovered values for review rather than silently overwriting them.
- Use credential references instead of secret values. Manifests cannot bypass agent operation or filesystem restrictions.
- Keep the JSON/YAML service format compatible with the existing `lab.yaml` registry export/import model.

**Acceptance criteria**

- [ ] A service missed by discovery can be added from a valid manifest.
- [ ] Re-import updates the same service without duplicating it.
- [ ] Invalid definitions and conflicts are shown before applying changes.

### F15. App catalogue + one-click installation

Install supported applications from the dashboard and automatically create their service documentation.

**Behaviour**

- Browse supported application templates with descriptions, runtime requirements, supported architectures, ports, storage needs, and configuration inputs.
- Choose a target host and supply required configuration, then initiate installation from the UI.
- Check host compatibility and conflicting resources before changing the host.
- Show installation progress, logs, and actionable failure details.
- Register installed components as a service, preserve the installation record, and populate its card, paths, and health checks.
- Define template provenance, versioning, secret handling, and partial-install cleanup before enabling catalogue execution.

**Acceptance criteria**

- [ ] A supported application installs on a compatible host and appears as a documented service.
- [ ] An incompatible host or conflicting port is reported before installation.
- [ ] A failed installation reports its outcome and any remaining resources.

### F16. Kubernetes, Proxmox + VM management

Extend inventory and control beyond services on agent-managed physical hosts.

**Behaviour**

- Connect configured Kubernetes clusters and Proxmox installations through authenticated platform adapters.
- Inventory Kubernetes namespaces, workloads, pods, and services; show workload health, events, and available logs.
- Provide platform-appropriate workload controls such as scaling and rollout restart, with their scope shown before execution.
- Inventory Proxmox nodes, VMs, and containers; expose status, resource details, and supported start/shutdown/stop/reboot actions.
- Link applications to the workloads or guests that host them, keeping guest power actions distinct from application service controls.
- Define supported VM providers and actions explicitly; Proxmox is the initial named provider, not an assumption of universal hypervisor support.
- Specify platform permissions, credential provisioning, action allow-lists, and audit records before implementation.

**Acceptance criteria**

- [ ] A configured Kubernetes workload appears with health, logs where available, and authorized lifecycle controls.
- [ ] A configured Proxmox guest appears with status and authorized power controls.
- [ ] The UI distinguishes a guest shutdown from stopping an application inside it.

### F17. Windows-side monitoring

Keep the laptop observable while it is booted into Windows 11.

**Behaviour**

- Add a Windows-compatible monitoring agent or adapter for host availability, Windows service state, processes, listening ports, and host telemetry.
- Surface relevant Windows Event Log records through the monitoring interface, subject to configured permissions.
- Associate Linux and Windows installations with the same physical laptop while retaining separate OS-specific inventories and agent identities.
- Show the active OS and last-seen state without claiming that inactive-OS services are currently observable.
- Specify Windows packaging, startup, permissions, and telemetry support independently of the Linux systemd agent.
- This feature covers monitoring; Windows lifecycle controls, installation, and shell access require separate feature definitions. It does not promise antivirus protection.

**Acceptance criteria**

- [ ] Booting the laptop into Windows makes its Windows status, service inventory, and supported telemetry visible.
- [ ] The UI identifies the active OS and preserves the inactive OS inventory as last observed.
- [ ] Missing permissions produce an explicit unavailable state for affected data.

### F18. Obsidian linked notes + owner-note sync

Connect service documentation to the owner's Obsidian notebook using ordinary Markdown files rather than requiring a plugin or cloud account.

**Behaviour**

- Export a vault-ready collection with a home index, one note per host, and one note per service.
- Include YAML properties, stable filenames, host/service wikilinks, declared dependency links, paths, access details, and credential pointers.
- Provide a dedicated local vault under the controller's data directory; the owner can open or share this directory with Obsidian separately.
- Keep a clearly marked Owner notes section editable in either the dashboard or Obsidian. Generated service metadata is refreshed from the registry.
- On explicit sync, import owner-note edits when only the vault changed; export dashboard edits when only the dashboard changed.
- When both sides changed differently, or sync markers are damaged, preserve the affected note and report a conflict.
- Preserve unrelated notes and Obsidian configuration. Store previous imported owner notes in the service's note history.
- Downloaded exports are portable copies; remote-device sharing and automatic filesystem watching are separate future decisions.

**Acceptance criteria**

- [ ] An exported folder opens as an Obsidian vault with host/service links and no community plugin.
- [ ] An owner-note edit in the managed vault imports into the service card on sync.
- [ ] Conflicting dashboard/vault edits do not overwrite either version.
- [ ] Unrelated Markdown files and `.obsidian` settings remain untouched.

### Later (post-v1)

- Mobile push notifications through the PWA.
- Built-in MCP server so Claude or a local LLM can query and control services.
- Dependency graph view ("what breaks if I stop this?").
- Safe updates: snapshot before image update, auto-rollback on failed health check.
- Bitwarden CLI check for linked vault items.

## 7. Data model

One SQLite database on the controller; structured fields are columns, open-ended parts are JSON columns. No secret values anywhere.

| Table | Key fields | Notes |
| --- | --- | --- |
| `hosts` | id, name, address (Tailscale), mac, os, arch, agent\_version, last\_seen, status | status: online / stale / offline |
| `services` | id, host\_id, name, slug, icon, runtime, control\_handle (JSON), description, tags, created\_at, reviewed\_at | control\_handle: compose dir, unit name, container id, pm2 name or command |
| `service_components` | id, service\_id, kind, ref, image | containers / units / processes that make up a service |
| `service_ports` | service\_id, port, proto, url |  |
| `service_paths` | service\_id, path, kind, tracked | kind: workdir / config / data / volume / log; tracked = in config history |
| `service_deps` | service\_id, depends\_on\_id |  |
| `health_checks` | id, service\_id, type, target, interval\_s, timeout\_s | type: http / tcp / command |
| `health_results` | check\_id, ts, ok, latency\_ms, detail | rolled up to hourly after 7 days |
| `incidents` | id, service\_id, started\_at, ended\_at, cause, ai\_note |  |
| `credentials` | id, service\_id, label, username, vault\_ref, hint | vault\_ref = Vaultwarden item ID/URL; never a value |
| `recordings` | id, service\_id, host\_id, started\_at, ended\_at, cast\_path, snapshot\_diff (JSON), steps\_md, status | status: draft / reviewed; cast file on disk, masked |
| `docs` | service\_id, summary\_md, notes\_md, updated\_at | card prose; exportable |
| `backup_policies` | service\_id, paths (JSON), schedule, retention, mode | mode: stop-copy-start / live |
| `backup_runs` | id, service\_id, started\_at, ended\_at, ok, snapshot\_id, size\_bytes, error |  |
| `schedules` | id, service\_id, kind, cron, idle\_minutes | kind: window / idle |
| `audit_log` | id, ts, actor, host\_id, service\_id, action, result | every control, shell session, restore |
| `settings` | key, value | Ollama endpoint/model, alert channel, scan interval |

**On-disk on each agent host:** `~/.psc/history/<service>/` (git repo for config history), `~/.psc/recordings/` (masked cast files), agent config + token.

**Manifest export.** The whole registry can be exported/imported as one `lab.yaml` plus a `docs/` folder of markdown, so the lab is portable and version-controllable outside the tool.

**Expanded-scope design work.** F12–F17 require schema and API additions for telemetry, manifest reconciliation, catalogue installation runs, platform resources, and physical-host/OS associations. The tables and endpoints here describe the original baseline; finalize those extensions before implementing the added features.

## 8. API surface

Two APIs: the controller's public API (UI and future MCP use it) and the agent API (only the controller calls it). All JSON over HTTPS; streams over WebSocket.

**Controller API (`/api/v1`)**

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/hosts` | List hosts + status |
| POST | `/hosts/{id}/wake` | Wake-on-LAN |
| POST | `/hosts/{id}/sleep` | Suspend / shutdown |
| POST | `/hosts/{id}/scan` | Run discovery, return review list |
| POST | `/discovery/accept` | Accept / reject candidates |
| GET | `/services` | List services (filter by host, tag, state) |
| GET | `/services/{id}` | Full service card |
| PATCH | `/services/{id}` | Edit card fields, notes, deps, checks |
| POST | `/services/{id}/{start\|stop\|restart}` | Control |
| GET | `/services/{id}/health` | Uptime + history |
| GET | `/services/{id}/files?path=` | List / read file |
| PUT | `/services/{id}/files?path=` | Write file (commits to history) |
| GET | `/services/{id}/history` | Config commits |
| POST | `/services/{id}/history/{commit}/revert` | Revert |
| POST | `/services/{id}/explain` | AI log explanation |
| POST | `/services/{id}/backups` | Run backup now |
| GET | `/services/{id}/backups` | List snapshots |
| POST | `/services/{id}/backups/{snap}/restore` | Restore |
| POST | `/recordings` | Start recording (host, service) |
| POST | `/recordings/{id}/stop` | Stop, diff, draft steps |
| POST | `/recordings/backfill` | Shell-history reconstruction |
| GET | `/search?q=` | Search across cards |
| GET | `/export` | `lab.yaml` + docs zip |

**Controller WebSockets**

- `/ws/events`: live state changes, health, alerts for the dashboard.
- `/ws/services/{id}/logs`: log follow.
- `/ws/hosts/{id}/pty?cwd=`: shell session (also carries recording).

**Agent API (controller-only)**

| Method | Path | Purpose |
| --- | --- | --- |
| WS | `/agent/stream` | Heartbeat + state push, command channel |
| POST | `/scan` | Discovery on this host |
| POST | `/control` | `{handle, runtime, action}` — allow-listed only |
| GET/PUT | `/fs` | Read / write within declared paths |
| POST | `/git/commit`, `/git/revert` | Config history |
| WS | `/logs`, `/pty` | Streams |
| POST | `/snapshot` | Recorder before/after snapshot |
| POST | `/backup`, `/restore` | Run restic |
| POST | `/power` | Suspend / shutdown this host |

Wake-on-LAN is sent by the Pi's own agent, since a sleeping host cannot receive commands.

## 9. Security model

This tool has a shell, file write and service control on every host, so a breach of it is a breach of the lab. Security is designed in from phase 1, not added later.

**Threats and controls**

| Threat | Control |
| --- | --- |
| Someone on the internet reaches the UI | Bind to Tailscale interface only; no port forward on the private firewall; refuse non-tailnet source IPs |
| Someone on the LAN reaches the UI or an agent | Controller login (passkey or password + TOTP); agents accept only the controller's mTLS cert or signed token |
| Stolen controller = root on every host | Agents run as a dedicated non-root user; systemd control via a polkit rule scoped to allow-listed units; Docker via the `docker` group on hosts where that is accepted |
| Arbitrary command execution through the control API | Agent only runs allow-listed actions per runtime; no "run this string" endpoint outside the PTY |
| File browser used to read `/etc/shadow` or SSH keys | FS API restricted to declared service paths; `..` and symlink escapes rejected |
| Secrets leak into DB, logs, git, exports or AI | Masking layer on every write path and every AI prompt; secret files excluded from history; vault pointers only |
| Shell session abused | Explicit confirm per session, 15 min idle timeout, audit log entry, optional re-auth |
| Restore overwrites good data | Restore previews files and takes a safety snapshot first |

**Rules the code must follow**

- The controller never stores an SSH private key.
- The agent never runs as root. Anything needing root goes through polkit or a narrow sudoers entry for a specific command.
- Every destructive action (stop, restore, revert, shutdown) is audited.
- AI output is advice only; suggested commands are never executed automatically.

## 10. Tech stack

Python everywhere on the backend and React on the front, so there are only two languages to hold in your head.

| Layer | Choice | Why |
| --- | --- | --- |
| Controller | Python 3.13, FastAPI, Uvicorn | Async, WebSockets built in, fast to write |
| Agent | Python 3.13, FastAPI (same codebase, separate entrypoint) | Shared models and masking code; revisit Go single binary only if Pi RAM becomes a problem |
| DB | SQLite via SQLModel | Zero ops, fine for one user |
| Scheduler | APScheduler | Health checks, backups, idle timers, rescans |
| Docker | `docker` Python SDK + `docker compose` CLI | SDK for state, CLI for compose actions |
| systemd | D-Bus via `dbus-next` + polkit rule | Start/stop without root |
| PTY | `ptyprocess` | Terminal + recorder |
| Recording format | asciinema v2 cast | Replayable, standard |
| Config history | git CLI | Nothing to invent |
| Backups | restic binary | Dedup, encryption, snapshots |
| AI | Ollama HTTP API via `httpx` | Local, already running on worker.example |
| Alerts | ntfy or Telegram bot | Pick one in settings |
| Frontend | React + Vite + TypeScript + Tailwind | Known stack |
| Terminal UI | xterm.js | Standard web terminal |
| Editor | Monaco | Same editor as VS Code |
| Networking | Tailscale | Already the preferred remote access |
| Packaging | Controller: Docker Compose on the Pi. Agent: install script + systemd unit | Agent must run on the host, not in a container, to see systemd and the filesystem |

The packaging row describes Linux agents. F17 needs Windows-specific packaging and startup. F12 may use telemetry adapters, and F16 introduces authenticated platform API connections alongside host agents; neither requires a controller-side SSH key.

**Repo layout (one repo, few folders)**

```
pi-service-controller/
  controller/   # FastAPI app, DB, scheduler, AI
  agent/        # FastAPI agent, runtimes, fs, pty, backup
  shared/       # models, masking, allow-lists
  web/          # React UI
  deploy/       # compose file, agent installer, polkit rule
  README.md
```

## 11. Build phases

Six phases, each ending in something you use daily, so progress is visible after every one. Don't start a phase until the previous one's "done when" is true.

These six phases are the original delivery plan. F12–F17 are now in product scope, but have not yet been assigned to these phases or additional milestones; the plan must be extended before treating it as the complete release schedule.

| Phase | Delivers | Features | Done when |
| --- | --- | --- | --- |
| 1. Control | Agent on worker.example + Pi, controller, service grid, start/stop, status, basic health | F1 (Docker/compose only), F2, F3 | You toggle Minecraft from your phone and stop using Portainer for it |
| 2. Know | Service cards, systemd + pm2 discovery, log viewer | F1 (full), F4, F7 logs | Every service on both boxes has a card and you can read its logs in the UI |
| 3. Remember | Shell mode, install recorder, shell-history backfill, file browser, config history | F5, F6, F7 shell | You record one real install and can reinstall from the card alone |
| 4. Understand | AI explainer, AI card summaries, credential pointers, secret scanner | F8, F9 | A broken service gets a correct plain-English cause; no secrets in the DB |
| 5. Protect | Backups to NAS, restore, schedules, idle stop, Wake-on-LAN, laptop agent | F10, F11 | You restore a service from the NAS and wake the mini PC from your phone |
| 6. Ship | README, installer, demo GIF, `lab.yaml` export, r/selfhosted post | — | A stranger installs it from the README without asking you anything |

**Phase 1 task list**

- [ ] Repo skeleton with the five folders from section 10
- [ ] Agent: heartbeat WebSocket + Docker/compose scan on worker.example
- [ ] Agent: start / stop / restart for compose and docker runtimes
- [ ] Controller: hosts + services tables, accept-discovery endpoint
- [ ] Controller: `/ws/events` fan-out to the UI
- [ ] Web: service grid with state + toggle, host online/offline
- [ ] HTTP/TCP health check + 24 h uptime
- [ ] Bind to Tailscale, login, agent token
- [ ] Install controller on the Pi, agents on Pi + worker.example

**Scope guard.** If a phase is taking more than about three weeks of evenings, cut features from it rather than extending it. A working smaller phase beats a half-built bigger one.

## 12. Competitive landscape

Every existing tool covers one slice: status, containers or the OS. None records how a service was set up, where its credentials live, or explains failures, and the closest multi-host service catalogue (Trove) is read-only by design.

| Tool | What it does well | What it lacks vs. this spec |
| --- | --- | --- |
| [Trove](https://pkg.go.dev/github.com/techdox/trove@v0.11.2) | Agents push containers, K8s, Proxmox and systemd units into one view grouped by host; heartbeats, alerts | Read-only by design: cannot start, stop, exec or edit. No docs, recorder, backups or AI |
| [DeQ](https://github.com/anvilcomputing/deq) | Tiny dashboard for low-power hosts; Wake-on-LAN, Docker start/stop, file manager | Docker only for control; no systemd, service cards, recorder, history or AI |
| Portainer | Mature Docker/Swarm/K8s management | Container-only; r/selfhosted users cite a stagnant mobile UI, a lagging API and no volume/stack backups in CE ([bitdoze roundup](https://www.bitdoze.com/portainer-alternatives/)) |
| Dockge / Komodo / Arcane / Dockhand | Compose-first container UIs | Containers only; Dockge's multi-host gets clumsy at scale ([bitdoze roundup](https://www.bitdoze.com/portainer-alternatives/)) |
| Cockpit | systemd, logs, terminal, files, multi-host | Docker plugin deprecated in favour of Podman ([daily.dev](https://daily.dev/posts/cockpit-gave-my-headless-server-a-face-without-giving-it-an-entire-desktop-environment-neiqb5wji)); host-centric, not service-centric; no docs or recorder |
| Homepage / Homarr / Dashy | Pretty link dashboards with status widgets | Launchers, not managers; config by hand |
| Uptime Kuma | Uptime history and alerts | Monitoring only |
| Netbox / wiki / markdown repos | Where people document labs today ([example](https://github.com/dhop90/homelab/wiki)) | Manual, goes stale, disconnected from the running system |

**Differentiators, in order of strength**

1. Install recorder + shell-history backfill: nothing found does this.
2. Living service card that stays in sync with the running system.
3. Control + docs + history for Docker *and* systemd in one service object.
4. Local-AI failure explanation.
5. Credential pointers with a secret scanner.

Research note: Reddit threads themselves did not index well in search; these gaps come from tool READMEs and roundups that summarise r/selfhosted discussion. Treat them as directional.

## 13. Risks and open questions

The biggest risk is scope, not tech: eighteen feature groups are now planned, so the phase gates in section 11 and explicit scheduling of the expanded scope are the main defence.

**Risks**

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Scope creep stalls the project mid-way | High | Ship phase by phase; each phase usable alone; cut rather than extend |
| Security hole gives access to every host | High | Section 9 controls built in phase 1; Tailscale-only; non-root agents |
| Secret masking misses a pattern | High | Conservative regex + entropy check; tests with real `.env` samples; never send full files to AI |
| Recorder diff is noisy (apt caches, logs, temp files) | Medium | Ignore list for `/var/cache`, `/var/log`, `/tmp`; user can prune before saving |
| AI gives wrong fixes | Medium | Advice only, confidence shown, never auto-runs |
| Pi RAM pressure with many WebSocket streams | Medium | Cap concurrent terminals/log streams; revisit Go agent if needed |
| Laptop agent on an Arch-family Linux distribution differs (pacman, Fish) | Low | Runtime and package adapters per distro family |

**Open questions**

- [ ] Priorities, release targets, and build phases for F12–F17.
- [ ] Native telemetry collection versus Netdata/Glances integration, with retention and resource budgets.
- [ ] Application catalogue source, template trust/versioning, and partial-install cleanup.
- [ ] Kubernetes/Proxmox permissions and supported resource/action matrix.
- [ ] Windows agent packaging, permissions, and physical-host/OS identity model.

- [ ] Controller login: passkey only, or password + TOTP as fallback?
- [ ] Alerts channel: ntfy (self-hosted) or Telegram bot?
- [ ] Should the Pi's Docker socket access be via the `docker` group (simpler) or rootless Docker (safer)?
- [ ] Which Ollama model for explanations: use an owner-selected compatible model, or a smaller general model for speed?
- [ ] Keep Uptime Kuma running alongside, or migrate its monitors in and retire it?
- [ ] Project name for the public release.
