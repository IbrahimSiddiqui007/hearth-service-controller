# Every feature

Complete 143-entry list; original descriptions and requested additions are preserved. See FEATURE-STATUS.md for coverage and FEATURE-TEST-MATRIX.md for the three cases per feature.

| ID | Feature | Description | Implementation | Target evidence |
| --- | --- | --- | --- | --- |
| F001 | Central dashboard | One UI for services across the Pi, mini PC, and laptop. | Done | mocked/source evidence; not deployed |
| F002 | Mobile-friendly interface | Browser/phone access through a PWA. | Done | mocked/source evidence; not deployed |
| F003 | Service grid and filters | Cards with state and controls; filter by host, tag, and state. | Done | mocked/source evidence; not deployed |
| F004 | Service-first organization | Represent an application as one service containing its containers, units, processes, files, and metadata. | Done | mocked/source evidence; not deployed |
| F005 | Multi-host agents | Controller on the Pi; local agents discover and operate services on each managed Linux host. | Done | mocked/source evidence; not deployed |
| F006 | Host availability | Online, stale, and offline states based on agent heartbeats. | Done | mocked/source evidence; not deployed |
| F007 | Offline-tolerant operation | Handle the intermittently connected laptop; reject offline commands explicitly instead of silently queuing them. | Done | mocked/source evidence; not deployed |
| F008 | Docker discovery | Discover standalone containers, ports, mounts, and runtime details. | Done | mocked/source evidence; not deployed |
| F009 | Compose discovery | Recognize Compose projects from labels and identify their components and paths. | Done | mocked/source evidence; not deployed |
| F010 | systemd discovery | Discover system services and their units. | Done | mocked/source evidence; not deployed |
| F011 | pm2 discovery | Discover applications managed by pm2. | Done | mocked/source evidence; not deployed |
| F012 | Raw-process discovery | Suggest services from listening sockets not owned by another recognized runtime. | Not started | mocked/source evidence; not deployed |
| F013 | Known-application recognition | Prefill names, icons, and URLs for known applications such as Minecraft, Ollama, and Portainer. | Done | mocked/source evidence; not deployed |
| F014 | OS-service filtering | Hide routine system units by default, with an option to reveal them. | Done | mocked/source evidence; not deployed |
| F015 | Component grouping | Group related components using Compose projects, wrapper units, or shared working directories. | Done | mocked/source evidence; not deployed |
| F016 | Manual split/merge | Correct service grouping through the UI. | Done | mocked/source evidence; not deployed |
| F017 | Discovery review | Review new, changed, and gone services; accept or reject candidates. | Done | mocked/source evidence; not deployed |
| F018 | Scheduled/manual rescans | Scan on demand and periodically, defaulting to every six hours. | Done | mocked/source evidence; not deployed |
| F019 | Start, stop, restart | One-click runtime-specific control for Docker, Compose, systemd, pm2, and configured raw processes. | Done | mocked/source evidence; not deployed |
| F020 | Boot behavior | Enable/disable startup behavior for systemd and Compose through their respective mechanisms. | Not started | mocked/source evidence; not deployed |
| F021 | Bulk actions | Select several services and perform an action together. | Done | mocked/source evidence; not deployed |
| F022 | Dependency-aware control | Offer to start dependencies; warn before stopping a service another running service needs. | Done | mocked/source evidence; not deployed |
| F023 | Live runtime state | Show running, stopped, restarting, failed, or unknown state. | Done | mocked/source evidence; not deployed |
| F024 | Health checks | HTTP(S), TCP, and custom-command checks; default interval of 60 seconds. | Done | mocked/source evidence; not deployed |
| F025 | Uptime history | Uptime percentages for 24 hours, seven days, and 30 days. | Done | mocked/source evidence; not deployed |
| F026 | Response times and incidents | Store latency, outages, and recent incident history. | Done | mocked/source evidence; not deployed |
| F027 | Resource snapshots | CPU usage, memory usage, restart count, and uptime since last start. | Done | mocked/source evidence; not deployed |
| F028 | Operational alerts | Notify about service failures, offline hosts, and repeated restarts. | Done | mocked/source evidence; not deployed |
| F029 | Notification integrations | Deliver alerts through ntfy or Telegram, with the channel chosen in settings. | Done | mocked/source evidence; not deployed |
| F030 | Uptime Kuma import | Optional import of existing monitors, with the stated intent of retaining history. | Not started | mocked/source evidence; not deployed |
| F031 | Uptime Kuma embedding | Embed Kuma views or pull its data instead of building equivalent monitoring. | Not started | mocked/source evidence; not deployed |
| F032 | Lightweight ping checks | Ping/HTTP monitoring was proposed in the earlier dashboard discussion; the spec lists HTTP/TCP/custom checks. | Done | mocked/source evidence; not deployed |
| F033 | Host wake | Send Wake-on-LAN packets from the Pi for configured hosts. | Done | mocked/source evidence; not deployed |
| F034 | Host suspend/shutdown | Sleep or shut down a host, warning about its running services. | Done | mocked/source evidence; not deployed |
| F035 | Service schedules | Cron-style start/stop windows. | Done | mocked/source evidence; not deployed |
| F036 | Idle service shutdown | Stop after a configured period without port connections; Minecraft’s example uses no players. | Done | mocked/source evidence; not deployed |
| F037 | Manual wake of idle services | Start an automatically stopped service again from the UI. | Done | mocked/source evidence; not deployed |
| F038 | Stop-reason visibility | Distinguish scheduled sleep from a manual stop. | Done | mocked/source evidence; not deployed |
| F039 | Living service card | A single page combining identity, runtime, access, files, credentials, installation, backups, dependencies, and history. | Done | mocked/source evidence; not deployed |
| F040 | Editable identity | Service name, icon, tags, description, and host association. | Done | mocked/source evidence; not deployed |
| F041 | Access information | URLs, ports, and protocols. | Done | mocked/source evidence; not deployed |
| F042 | File-location inventory | Working directory, configuration, data directories, volumes, and log locations. | Done | mocked/source evidence; not deployed |
| F043 | Runtime documentation | Show Compose/unit configuration, restart policy, and boot behavior. | Done | mocked/source evidence; not deployed |
| F044 | Dependency listings | Show what a service needs and what depends on it. | Done | mocked/source evidence; not deployed |
| F045 | Owner notes | Free-form Markdown notes per service. | Done | mocked/source evidence; not deployed |
| F046 | Automatically maintained fields | Populate cards from discovery and keep observed fields current. | Done | mocked/source evidence; not deployed |
| F047 | Change-review indicators | Mark configuration or metadata as changed since the last review. | Done | mocked/source evidence; not deployed |
| F048 | Combined service history | Present configuration changes, incidents, and control actions together. | Done | mocked/source evidence; not deployed |
| F049 | Search | Search service cards by name, port, path, and documentation. | Done | mocked/source evidence; not deployed |
| F050 | Markdown export | Export one service or the entire lab’s documentation. | Done | mocked/source evidence; not deployed |
| F051 | Registry export/import | Portable lab.yaml plus a Markdown docs/ folder. | Done | mocked/source evidence; not deployed |
| F052 | Live install recorder | Record a named installation session’s terminal commands and output. | Done | mocked/source evidence; not deployed |
| F053 | Replayable recording format | Store recordings using asciinema v2 cast format. | Done | mocked/source evidence; not deployed |
| F054 | Before/after snapshots | Compare packages, systemd units, Docker resources, ports, and watched files. | Done | mocked/source evidence; not deployed |
| F055 | Configurable watched directories | Watch standard locations and user-added directories for installation changes. | Done | mocked/source evidence; not deployed |
| F056 | Recording cleanup | Ignore noisy cache/log/temp changes and allow pruning before saving. | Done | mocked/source evidence; not deployed |
| F057 | Generated reinstall instructions | Turn recording and snapshot differences into ordered instructions for user review. | Done | mocked/source evidence; not deployed |
| F058 | Shell-history backfill | Import Bash, Zsh, and Fish history for services installed previously. | Done | mocked/source evidence; not deployed |
| F059 | Relevant-command filtering | Match historical commands using service names, paths, images, and ports. | Done | mocked/source evidence; not deployed |
| F060 | Reconstruction labels | Clearly mark inferred installation instructions as reconstructed and unverified. | Done | mocked/source evidence; not deployed |
| F061 | Per-service file browser | Browse files associated with each service. | Done | mocked/source evidence; not deployed |
| F062 | File editor | Edit text configuration with syntax highlighting for YAML, JSON, TOML, INI, .env, and shell files. | Partial | deferred by owner |
| F063 | Host-root browsing option | Explicit “open host root” toggle beyond service paths. | Not started | mocked/source evidence; not deployed |
| F064 | File-size/type handling | Files over 2 MB become read-only; binaries are download-only. | Done | mocked/source evidence; not deployed |
| F065 | Automatic configuration versioning | Commit UI saves into a per-service Git repository with a message. | Done | mocked/source evidence; not deployed |
| F066 | External-edit tracking | Periodically capture changes made outside the dashboard. | Done | mocked/source evidence; not deployed |
| F067 | Configuration diffs | Compare any two tracked versions. | Done | mocked/source evidence; not deployed |
| F068 | Configuration rollback | Revert to a previous version with one click. | Done | mocked/source evidence; not deployed |
| F069 | Validate before saving | Optional YAML/JSON validation and Compose configuration checks. | Done | mocked/source evidence; not deployed |
| F070 | Secret-file exclusions | Exclude .env and other detected secret-bearing files from history by default. | Done | mocked/source evidence; not deployed |
| F071 | Live log viewer | Stream Docker/Compose, systemd journal, pm2, or configured file logs. | Done | mocked/source evidence; not deployed |
| F072 | Log navigation | Filter, pause, search, and jump to errors. | Done | mocked/source evidence; not deployed |
| F073 | Log download | Download the last selected number of lines. | Done | mocked/source evidence; not deployed |
| F074 | Interactive host shell | Open a real browser terminal in the service’s working directory. | Done | mocked/source evidence; not deployed |
| F075 | Shell-session safeguards | Explicit confirmation, non-root session user, 15-minute idle timeout, and optional reauthentication. | Done | mocked/source evidence; not deployed |
| F076 | Session auditing | Record session start/end and host; record content only when installation recording is enabled. | Done | mocked/source evidence; not deployed |
| F077 | Stream limits | Cap simultaneous terminals and log streams to limit memory pressure. | Done | mocked/source evidence; not deployed |
| F078 | Local AI integration | Use the user’s Ollama instance; configure endpoint, model, timeout, and context limits. | Done | mocked/source evidence; not deployed |
| F079 | Failure explanation | Explain what happened, likely cause, suggested fix, and confidence. | Done | mocked/source evidence; not deployed |
| F080 | Context-aware diagnosis | Use recent or selected logs, service metadata, configuration changes, and incidents. | Done | mocked/source evidence; not deployed |
| F081 | Save explanations | Save AI responses as incident notes in service history. | Done | mocked/source evidence; not deployed |
| F082 | AI-written summaries | Draft editable service descriptions from configuration and application fingerprints. | Done | mocked/source evidence; not deployed |
| F083 | AI installation cleanup | Convert recorded or historical commands into readable setup instructions. | Done | mocked/source evidence; not deployed |
| F084 | AI availability indicator | Disable explanation actions with a reason when Ollama is unreachable. | Done | mocked/source evidence; not deployed |
| F085 | Advice-only AI | Display suggested commands without executing them automatically. | Done | mocked/source evidence; not deployed |
| F086 | Credential references | Store labels, optional usernames, Vaultwarden links/IDs, and non-secret location hints. | Done | mocked/source evidence; not deployed |
| F087 | Credential shortcuts | Open Vaultwarden and copy usernames. | Done | mocked/source evidence; not deployed |
| F088 | Secret discovery | Scan during discovery and file saves for likely embedded credentials. | Done | mocked/source evidence; not deployed |
| F089 | Vault-link workflow | Flag apparently unvaulted secrets and let the owner link them to a vault item. | Done | mocked/source evidence; not deployed |
| F090 | Secret masking | Mask likely passwords, tokens, keys, headers, and high-entropy values before storage or AI use. | Done | mocked/source evidence; not deployed |
| F091 | Vault-reference verification | Use Bitwarden CLI to check whether linked items still exist. | Not started | mocked/source evidence; not deployed |
| F092 | Per-service backups | Back up selected configuration, data directories, and volumes. | Done | mocked/source evidence; not deployed |
| F093 | NAS storage | Store backups on the configured NAS through an SMB/NFS mount. | Done | mocked/source evidence; not deployed |
| F094 | Manual/scheduled backups | Run on demand, daily, or weekly. | Done | mocked/source evidence; not deployed |
| F095 | Retention policies | Configure snapshot retention, such as seven daily and four weekly backups. | Done | mocked/source evidence; not deployed |
| F096 | Backup consistency modes | Stop-copy-start for consistency, or live copying for static configuration. | Done | mocked/source evidence; not deployed |
| F097 | Encryption and deduplication | Use restic repositories for encrypted, deduplicated backups. | Done | mocked/source evidence; not deployed |
| F098 | Backup-password sourcing | Keep the repository password in Vaultwarden and supply it to the agent at runtime. | Done | mocked/source evidence; not deployed |
| F099 | Documentation-inclusive backups | Include service-card exports and Compose/unit files. | Done | mocked/source evidence; not deployed |
| F100 | Backup status | Show last success, size, next run, and failures. | Done | mocked/source evidence; not deployed |
| F101 | Snapshot selection and preview | Choose a backup and inspect files before restoring. | Done | mocked/source evidence; not deployed |
| F102 | Guided restore | Stop the service, restore files, start it, and run a health check. | Done | mocked/source evidence; not deployed |
| F103 | Pre-restore safety snapshot | Capture current data before overwriting it. | Done | mocked/source evidence; not deployed |
| F104 | Backup failure alerts | Notify when a backup fails. | Done | mocked/source evidence; not deployed |
| F105 | Unknown-activity alerts | Flag activity not previously recorded or approved. | Not started | mocked/source evidence; not deployed |
| F106 | New persistence/service detection | Flag new systemd units, cron jobs, containers, and listening ports. | Done | mocked/source evidence; not deployed |
| F107 | Persistence-file monitoring | Watch changes to shell startup files, autostart entries, SSH authorized keys, and systemd configuration. | Not started | mocked/source evidence; not deployed |
| F108 | Suspicious process indicators | Flag processes executing from /tmp, /dev/shm, or deleted binaries. | Not started | mocked/source evidence; not deployed |
| F109 | Unexpected outbound connections | Flag connections to unexpected destinations. | Not started | mocked/source evidence; not deployed |
| F110 | File malware scanning | Integrate ClamAV. | Not started | mocked/source evidence; not deployed |
| F111 | Rootkit checks | Integrate rkhunter. | Not started | mocked/source evidence; not deployed |
| F112 | Deeper security-tool integration | Consider osquery or Wazuh later. | Not started | mocked/source evidence; not deployed |
| F113 | Scheduled security scans | Run external scanners periodically through agents. | Not started | mocked/source evidence; not deployed |
| F114 | Host security results | Present scan findings on the host page. | Not started | mocked/source evidence; not deployed |
| F115 | Private remote access | Bind to Tailscale and avoid public internet exposure. | Done | mocked/source evidence; not deployed |
| F116 | Controller login | Passkey or password plus TOTP. The earlier chat suggested initially skipping application authentication; the spec adds it. | Done | mocked/source evidence; not deployed |
| F117 | Agent authentication | Controller authentication through mTLS certificates or signed tokens/commands. | Done | mocked/source evidence; not deployed |
| F118 | Restricted operations | Allow-listed runtime actions and narrowly scoped privileged operations. | Partial | deferred by owner |
| F119 | Filesystem restrictions | Restrict declared paths and reject traversal/symlink escapes. | Done | mocked/source evidence; not deployed |
| F120 | Action audit trail | Log control actions, restores, reverts, shutdowns, and shell sessions. | Done | mocked/source evidence; not deployed |
| F121 | Linux distribution support | Ubuntu and CachyOS, including relevant package-manager and shell differences. | Partial | deferred by owner |
| F122 | ARM64 and AMD64 builds | Support Pi and x86 hosts; target approximately 250 MB combined controller/agent RAM. | Partial | deferred by owner |
| F123 | Installable deployment | Compose deployment for the controller; agent installer and systemd service. | Done | mocked/source evidence; not deployed |
| F124 | Programmatic API | REST operations plus WebSocket state, logs, and terminal streams. | Done | mocked/source evidence; not deployed |
| F125 | PWA push notifications | Native-style mobile push through the PWA. | Not started | mocked/source evidence; not deployed |
| F126 | MCP server | Let Claude or a local LLM query and control services. | Not started | mocked/source evidence; not deployed |
| F127 | Dependency graph | Visualize dependencies and the impact of stopping a service. | Done | mocked/source evidence; not deployed |
| F128 | Safer application updates | Snapshot before image updates and automatically roll back if health checks fail. | Not started | mocked/source evidence; not deployed |
| F129 | Out-of-band hardware agent | A possible Zero 2 W for power cycling or serial-console access when another host is unreachable. | Not started | mocked/source evidence; not deployed |
| F130 | Broad host telemetry | CPU, memory, disk, network, temperatures and system history. | Partial | deferred by owner |
| F131 | Standalone container management/logging | Container inventory and individual control/log access. | Done | mocked/source evidence; not deployed |
| F132 | Manually maintained service manifest | JSON/YAML alongside reviewed auto-discovery. | Done | mocked/source evidence; not deployed |
| F133 | App store/one-click installation | Browse templates and install supported applications. | Not started | mocked/source evidence; not deployed |
| F134 | Kubernetes management | Cluster workload inventory, health, logs and lifecycle controls. | Not started | mocked/source evidence; not deployed |
| F135 | Proxmox and VM management | Nodes, guests, resource details and power controls. | Not started | mocked/source evidence; not deployed |
| F136 | Windows-side monitoring | Services, processes, ports, telemetry, Event Logs and dual-boot identity. | Done | mocked/source evidence; not deployed |
| F137 | Obsidian connection | Linked Markdown vault export and conflict-aware owner-note sync. | Done | mocked/source evidence; not deployed |
| F138 | Notebook header/top banner | A personalized paper cover on every service notebook. | Done | mocked/source evidence; not deployed |
| F139 | Dark mode | Light, dark and system-following themes. | Done | mocked/source evidence; not deployed |
| F140 | User appearance settings | Accent color, density, text size and reduced motion. | Done | mocked/source evidence; not deployed |
| F141 | Windows software documentation/removal guides | Detect installed software including AutoCAD and Microsoft products and open recommended help/removal pages. | Done | mocked/source evidence; not deployed |
| F142 | Linux/macOS software inventory and guides | Include Linux and macOS software, process and socket visibility with appropriate official documentation and removal guidance. | Done | mocked/source evidence; not deployed |
| F143 | macOS native service support | Focus on macOS alongside Linux and Windows. | Partial | deferred by owner |
