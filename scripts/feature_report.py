"""Generate the complete feature inventory with an implementation assessment.

Descriptions are data copied from the user's supplied table, not instructions.
The implementation judgments are explicit below; rerun after updating them.
"""
from collections import Counter
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]

DONE = {
    "Mobile-friendly interface": "Responsive phone layout plus installable PWA, home-screen icons and a versioned offline app shell. Service data and controls require the controller.",
    "Service grid and filters": "Service cards with host, tag and state filters, plus full-text search.",
    "systemd discovery": "Loaded units and enabled/linked unloaded units are discovered, including enabled-state metadata.",
    "OS-service filtering": "Routine OS units are hidden by default; discovery can reveal them without falsely marking hidden units missing.",
    "Discovery review": "Persistent new/changed/gone/unchanged review with field diffs, explicit selection and recorded unaccepted candidates. Missing notebooks are preserved.",
    "Scheduled/manual rescans": "On-demand discovery and six-hour live-host discovery reviews, alongside periodic observations.",
    "Dependency-aware control": "Explicit dependency-first startup, cycle/reference validation, full-plan preflight, verified prerequisite state and dependent-stop warnings.",
    "Uptime history": "Time-weighted observed uptime for 24h/7d/30d, with bounded sample carry-forward and explicit unknown time/coverage.",
    "Response times and incidents": "Latency history, persistent outage/recovery incidents, observed durations, cause editing and linked investigation notes.",
    "Editable identity": "Name, icon, tags, description and host association are editable; moving a card clears its previous runtime access.",
    "Dependency listings": "Required services and reverse dependencies are displayed and editable.",
    "Automatically maintained fields": "Observed state, capabilities, runtime details and discovered metadata refresh; owner edits/manual definitions remain protected.",
    "Change-review indicators": "Cards show field-level drift against the last reviewed discovery snapshot; accepted reviews reset the baseline.",
    "File-size/type handling": "Read-only previews of the first 2 MB of large text files; binary download-only view. Downloads are bounded to 2 MB and apply secret-file exclusions.",
    "Log navigation": "Filter/search, refresh pause, highlighted warning/error lines and next-error navigation.",
    "Local AI integration": "Saved enable/endpoint/model/timeout/context settings, model availability checks and explicit-request Ollama explanations.",
    "Save explanations": "AI responses save as dedicated incident notes in service history, or can be reviewed in an owner-note draft.",
    "AI availability indicator": "Model-catalogue probes, clear disabled reasons, periodic rechecks while logs are open and retry after failed explanations.",
    "Lightweight ping checks": "HTTP(S), TCP and ICMP checks; ping arguments are fixed and targets validated. Demo probes remain simulated.",
    "Known-application recognition": "Deterministic Minecraft/Ollama/Kuma/Portainer/Vaultwarden/Tailscale/Samba fingerprints prefill identity and suitable access URLs.",
    "Log download": "Authenticated snapshot downloads with a selectable 100/300/1000/5000-line limit and masking.",
    "Central dashboard": "Dashboard and navigation are implemented.",
    "Multi-host agents": "Controller-to-agent HTTP transport and per-host registration are implemented; deployment is still to verify.",
    "Offline-tolerant operation": "Offline/unverified host controls are refused; last inventory remains visible.",
    "Docker discovery": "Standalone containers, published ports, mounts, image, state and runtime details are discovered.",
    "Compose discovery": "Project labels, working directories and grouped components are discovered.",
    "Bulk actions": "Selected services execute sequentially with confirmation and individual audit outcomes.",
    "Live runtime state": "Known states refresh through polling and after controls; offline services become unobserved.",
    "Access information": "URLs, ports and protocols are stored, displayed and exported.",
    "Owner notes": "Markdown editor, revision checks, previous notes and unsaved-draft protection are implemented.",
    "Search": "Names, descriptions, notes, tags, runtimes, hosts, paths and ports are searchable.",
    "Markdown export": "Individual notes and a complete linked Markdown collection can be downloaded.",
    "Registry export/import": "lab.yaml and docs export; reviewed, validated, repeatable import.",
    "Per-service file browser": "Read-only directory navigation and UTF-8 previews within an approved agent root.",
    "Failure explanation": "Ollama advice is generated on explicit request; real model accuracy is not verified.",
    "Advice-only AI": "Model output is displayed; commands are never executed automatically.",
    "Credential references": "Labels, usernames, item links/IDs and hints are stored and exported; no password field.",
    "Credential shortcuts": "Open vault links and copy usernames.",
    "Filesystem restrictions": "Approved-root checks, traversal rejection, resolved symlink escape checks and blocked secret-file previews.",
}
PARTIAL = {
    "Service-first organization": "Service objects and Compose groups exist; full cross-runtime grouping and recovery metadata remain.",
    "Host availability": "Online/stale/offline handling uses authenticated HTTP polling rather than persistent agent heartbeats.",
    "Component grouping": "Compose grouping works; wrapper-unit/shared-directory grouping does not.",
    "Start, stop, restart": "Docker/Compose/systemd controls work; pm2 and raw-process controls do not.",
    "Health checks": "HTTP(S)/TCP/ICMP with configurable intervals and timeouts; custom-command checks are not implemented.",
    "Resource snapshots": "Host telemetry and Docker restart/start metadata exist; per-service CPU/memory sampling is incomplete.",
    "Operational alerts": "Failures/transitions appear in the audit/UI; external delivery and repeated-restart alerts remain.",
    "Manual wake of idle services": "Manual starts exist; idle-stop/asleep service workflows are not implemented.",
    "Living service card": "Core metadata, notes, credentials, health, logs and history are present; installation/backup/config sections remain.",
    "File-location inventory": "Discovered paths/mounts and manual paths exist; typed config/data/log path mapping is incomplete.",
    "Runtime documentation": "Runtime and available file previews exist; unit/Compose configuration and boot-policy presentation are incomplete.",
    "Combined service history": "Control/health/note audit, previous notes and structured incident/explanation history exist; Git config history and future backup/restore history remain.",
    "Secret-file exclusions": "Common secret-file previews are blocked; configuration history and scanner-based exclusions are not implemented.",
    "Live log viewer": "Docker/Compose/journal snapshots with optional refresh exist; streaming, pm2 and file-log adapters remain.",
    "Context-aware diagnosis": "Filtered logs, service metadata, discovery field changes, incidents and audit context exist; Git-backed configuration-file diffs remain.",
    "Secret masking": "Known assignment/header/credential-URL patterns are masked; entropy scanning and comprehensive recorder handling remain. Masking is best-effort.",
    "New persistence/service detection": "Review discovery identifies new units/containers; cron, listening-port and persistence monitoring remain.",
    "Private remote access": "Loopback defaults, token protection and Tailscale deployment guidance; enforced tailnet-only binding is not complete.",
    "Controller login": "Single-owner bearer-token login; passkeys/password+TOTP remain.",
    "Agent authentication": "Required bearer token, constant-time comparison; mTLS and signed commands remain.",
    "Restricted operations": "Agent runtime allow-lists and non-root Linux startup guard; OS privilege rules still require manual setup.",
    "Action audit trail": "Implemented control, notes, credentials, health, discovery and sync actions are audited; future shell/restore/power operations remain.",
    "Linux distribution support": "Linux runtime adapters are implemented; actual Ubuntu/CachyOS deployment and shell/package adaptations remain to verify.",
    "ARM64 and AMD64 builds": "Portable source and deployment definitions exist; both-target builds and Pi memory budget remain to verify.",
    "Installable deployment": "Local startup/check scripts, Compose/Dockerfile and systemd example; automatic agent installer remains.",
    "Programmatic API": "REST API implemented; event/log/PTY WebSockets remain.",
}

# Session 3 coverage after mocked tests and synthetic browser acceptance.
DONE.update({
    "Health checks": "HTTP(S)/TCP/ICMP plus agent-owned fixed custom-check profiles, configurable intervals/timeouts, and synthetic demo checks; arbitrary caller commands are refused.",
    "Resource snapshots": "Docker/Compose, systemd cgroup/main-process and Windows service-process CPU/memory snapshots, observed scopes, restart/start metadata, and a consistent sampling opt-out. Unknown values stay unknown; live adapters remain deployment validation.",
    "File-location inventory": "Typed working/configuration/data/volume/log locations, discovery metadata and editable notebook fields; documentation does not grant filesystem permission.",
    "Runtime documentation": "Runtime/resources page shows start/restart/boot policy metadata and rooted, masked Compose/unit document previews. Boot editing remains separate.",
    "Operational alerts": "Health failure/recovery, offline-host, repeated-restart and sustained host-threshold events feed an opt-in masked outbox with deduplication, bounded retries and simulated demo delivery.",
    "Notification integrations": "ntfy/Telegram settings, environment-token references, save/test actions and delivery status; disabled by default. Real transports are mocked in tests; demo delivery is simulated.",
    "Automatic configuration versioning": "Controller-owned per-service Git baseline/prospective snapshots precede remote writes; validated outcomes, host-operation reservations and unknown crash recovery protect history. Git is required on the controller.",
    "External-edit tracking": "Opt-in approved configuration capture detects baseline/changes, excludes secret/large/binary files, honors intervals, caps five files/service and three service attempts/live poll, and preserves notebook fields.",
    "Configuration diffs": "Scoped comparison between verified tracked versions, bounded unified diffs, preserved whitespace and a frontend Before/After selector.",
    "Configuration rollback": "Review a scoped verified version and restore with current etag protection; records a new version and never restarts the service automatically.",
    "Validate before saving": "UTF-8/size/secret and YAML/JSON/TOML syntax checks; optional fixed agent argv validates a temporary candidate before atomic replacement. Failed validation preserves the original.",
    "Secret-file exclusions": "Secret filenames and conservatively detected secret content are excluded from managed editing/history/capture; plain environment references are accepted. Detection is not exhaustive.",
    "Context-aware diagnosis": "Bounded logs, metadata, discovery changes, incidents, audit history and scoped verified Git configuration diffs; unknown/prepared/other-service versions are excluded. Model requests remain explicit and advice-only.",
})
for feature in DONE:
    PARTIAL.pop(feature, None)
PARTIAL.update({
    "File editor": "Opt-in existing Linux UTF-8 configuration editing with basic syntax coloring, whitespace/CRLF/mode preservation, etags, atomic replace, dirty guards and reviewed history restore. Windows and secret files remain read-only; coloring stops above 50 KB.",
    "Living service card": "Identity, runtime/resources, typed locations, notes, credentials, health, logs and config history are present; installation recorder, AI summaries and backup/recovery sections remain.",
    "Combined service history": "Configuration versions, control/health/note audit, note revisions and incident/explanation records exist; future recorder, backup/restore and power/session history remain.",
    "Secret masking": "Known assignments/headers/credential URLs are masked and high-entropy candidates are conservatively excluded from configuration history. Comprehensive discovery/recorder scanning remains; masking is best-effort.",
    "Action audit trail": "Controls, config save/restore, notes, credentials, health, discovery, alerts and sync actions are audited; future backup restore, shell and power actions remain.",
})

# Session 4: tested local workflows. These labels describe code, never deployment.
DONE.update({
    'Service-first organization': 'Applications link same-host runtime components under one card while preserving every notebook, file policy and control permission; installation, backup-plan and recovery documentation are editable and exported.',
    'Host availability': 'Opt-in 15-second persistent authenticated heartbeats with mutual HMAC proof, sequence-bound signed frames, durable handshake replay refusal, 45-second stale/150-second offline limits and immediate disconnect refusal; polling supports older agents.',
    'pm2 discovery': 'Opt-in selected pm2 metadata from an existing agent-owned daemon and configured PM2_HOME; environment values are omitted and discovery refuses to bootstrap an absent daemon.',
    'Component grouping': 'Compose grouping plus explicit same-host cross-runtime relationships, exact native working-directory suggestions, dependency-order group controls and cycle/nesting/duplicate-control checks.',
    'Manual split/merge': 'Notebook checkboxes link/unlink application components without deleting or merging their notes; child notebooks remain accessible and relationships round-trip in manifests/Markdown.',
    'Start, stop, restart': 'Docker/Compose/systemd plus verified numeric pm2 instances and fixed Linux process profiles. Process signalling checks PID, creation time, executable and profile identity; uncertain launches/timeouts prevent blind retry or force-kill.',
    'Manual wake of idle services': 'Verified automatic stops mark standalone services asleep. Wake uses normal confirmed, allow-listed startup and clears the asleep marker only after observed running state.',
    'Living service card': 'Identity, runtime/components/resources, access, files/config history, credential pointers, dependencies, health, owner installation/backup/recovery documentation and history appear in one notebook. Plans are not proof of executed backups; recorder/backup engines are separate roadmap items.',
    'Combined service history': 'Configuration changes, incidents and control actions are presented together with prior owner notes, installation/recovery documentation revisions and linked investigation records.',
    'Live log viewer': 'Authenticated bounded Docker/Compose/journal/pm2 followers and approved file-log tailing, snapshot downloads, filtering/error navigation, pause/disconnect cleanup, rotation handling and per-agent/controller follower limits.',
    'Secret masking': 'Assignment/header/credential-URL, private-key/token and conservative entropy masking cover logs, audit, discovery metadata and AI context before storage/use. Sensitive runtime identities are refused; secret files/history remain excluded. Best-effort detection is not exhaustive.',
    'New persistence/service detection': 'Reviewed unit/container discovery plus opt-in cron file/job, Windows Run/RunOnce and TCP-listener metadata diffs with explicit baseline acknowledgment, stale fingerprints and incomplete-provider safeguards; no commands or permissions are changed.',
    'Private remote access': 'Standard CLI listeners require loopback or an IP verified against the running local Tailscale identity. Compose explicitly permits its internal listener while publishing the host port on loopback. Private ingress/ACL deployment remains owner setup; no network changes were applied.',
    'Controller login': 'Optional single-owner scrypt password plus six-digit TOTP, replay/rate limits, revocable 12-hour HttpOnly/SameSite sessions, HTTPS for remote login, logout and configuration-change revocation; API bearer access remains available.',
    'Agent authentication': 'Bearer tokens plus opt-in independent HMAC request signatures covering method/target/body/time/nonce; durable nonce claims reject replays across restart. Persistent channels additionally prove both endpoints and sign each sequence-bound frame. mTLS is an alternative, not implemented.',
    'Installable deployment': 'Controller Compose/Dockerfile and reviewed Ubuntu/Debian/CachyOS/Arch agent installer with a default plan and explicit apply, non-root account, private state, preserved existing files and hardened systemd unit. Installer syntax verified; no target installation, service activation or image build was executed.',
})
for feature in DONE:
    PARTIAL.pop(feature, None)
PARTIAL.update({
    'File editor': 'Approved existing Linux configuration editing/history/restore is implemented. Windows stays read-only until an ACL-preserving replacement adapter is verified; secret files intentionally remain excluded.',
    'Restricted operations': 'Runtime/profile/file allow-lists, non-root startup and a narrow exact-unit/action polkit template exist. Actual journal, Docker and unit privilege grants need reviewed target-host setup and verification; no broad runtime groups are granted by the installer.',
    'Action audit trail': 'Controls/groups/idle wake-stop, config restore, docs/history, discovery/persistence, auth, log followers, incidents, alerts and sync are audited. Backup restore, interactive shell/session and power subsystems still need implementation and their corresponding audit hooks.',
    'Linux distribution support': 'POSIX runtime adapters and distro-specific installer prerequisites cover Ubuntu/Debian/CachyOS/Arch in source. Actual installation and permission/CLI behavior on Ubuntu and CachyOS remain unverified.',
    'ARM64 and AMD64 builds': 'Portable source and build definitions exist; Docker is unavailable here. Both-target image builds and the approximately 250 MB Pi controller/agent memory target remain unverified.',
    'Programmatic API': 'REST plus authenticated bounded state/event/log WebSockets and SSE/NDJSON streams are implemented; interactive PTY/terminal streams and session safeguards remain.',
    'Idle service shutdown': 'Opt-in standalone auto-stop supports native TCP-connection and fixed local Minecraft player-list probes plus custom profiles, uninterrupted idle observations, unknown/gap resets, dependent protection and verified asleep state. A shared activity model for linked application groups remains; absent listeners/unreadable or unrecognized probes inhibit stopping.',
})

DONE.update({
    'Idle service shutdown': 'Standalone and linked-application auto-stop require continuous explicit activity signals for the application and every linked component, with up to eight component profiles. Unknown/active signals, revised components, offline hosts, external dependents and missing permissions inhibit stops. Group reservation, dependency order and observed stopped states protect manual wake; no CPU-only inactivity inference.',
    'Start, stop, restart': 'Docker/Compose/systemd, verified numeric pm2 instances and fixed Linux/macOS process profiles; PID/time/executable/profile checks, uncertain-outcome refusal and no force-kill. macOS launchd and Windows service controls remain read-only.',
    'Manual wake of idle services': 'Verified automatic stops mark standalone or entire linked applications asleep. Normal confirmed dependency-ordered startup clears sleep after verified running states.',
})
PARTIAL.pop('Idle service shutdown', None)
PARTIAL['File editor'] = 'Approved existing Linux editing/history/restore works. Windows and macOS remain read-only pending ACL-preserving replacement and macOS extended-attribute preservation; secret files intentionally stay excluded.'
PARTIAL['Linux distribution support'] = 'Ubuntu/Debian/CachyOS/Arch installer prerequisites, systemd/shared runtime adapters, dpkg/pacman/RPM and desktop inventory are implemented in source. Actual Ubuntu/CachyOS installation, permissions and CLI behavior remain unverified.'

# Session 6: native adapters are mocked; target validation stays Partial.
DONE.update({
    'Programmatic API': 'REST, authenticated state/event/log streams and interactive terminal WebSockets; one-use owner-bound attach tickets, signed agent requests, host reservations, bounded streams and disconnect cleanup.',
    'Live install recorder': 'Named opt-in terminal sessions record bounded, best-effort masked input/output; metadata-only auditing by default. Demo is synthetic and a transcript does not prove installation success.',
    'Replayable recording format': 'Opt-in recordings persist as private asciinema v2 cast artifacts with relative timing and output/resize events; authenticated scoped export omits input events.',
    'Interactive host shell': 'Browser xterm with fixed locally approved argv/cwd profiles, POSIX PTY and optional Windows ConPTY adapters. Live execution requires signed transport and ordinary account checks; native target behavior remains unverified.',
    'Shell-session safeguards': 'Explicit host/account/cwd confirmation, changed-profile refusal, owner-bound one-use tickets, optional recent login, host reservations, idle/absolute limits and disconnect cleanup. Cwd is not a filesystem sandbox.',
    'Session auditing': 'Session start/end, host/service/profile and outcome are durable metadata; terminal content is stored only with explicit installation recording. Transcript/cast exports are scoped and audited.',
    'Stream limits': 'Per-agent/controller terminal and log follower limits, bounded input/output/recordings, idle/absolute expiry, frame-rate caps and missing-poll cleanup.',
})
for feature in DONE:
    PARTIAL.pop(feature, None)
PARTIAL['File editor'] = 'Approved Linux editing/history/restore plus Windows owner/DACL checks and ReplaceFileW recovery, and macOS ACL/xattr-preserving metadata copy are implemented with mocked tests. Actual native replacement/permissions behavior remains unverified; secret files stay excluded.'
PARTIAL['Action audit trail'] = 'Existing actions plus terminal/session start/end and opt-in recording save/export are audited. Backup restore/revert and power engines and their audit hooks remain unimplemented.'

# Session 7: explicit recorder reviews, advice-only drafts and configured wake.
DONE.update({
    'Before/after snapshots': 'Opt-in installation sessions compare bounded native package/app, service/unit, container, Docker image/network/volume, listening-port and approved file-hash metadata. Incomplete/different scopes do not imply removals; capture failure remains an explicit evidence gap. Native providers are mocked.',
    'Configurable watched directories': 'Locally approved per-reference watch directories must stay inside approved service file roots. Five-root, depth/time/file/byte budgets, symlink/junction/hardlink refusal and metadata-only UTF-8 hashes protect Linux/macOS/Windows capture; large/binary/secret files remain excluded.',
    'Recording cleanup': 'Noisy cache/log/temp paths are excluded during file capture; owners can omit commands or changes from a revision-checked installation review before saving/exporting instructions. Original masked evidence is retained; cleanup never deletes it.',
    'Generated reinstall instructions': 'Ordered captured-command and snapshot-change drafts, editable owner instructions, explicit review state and scoped Markdown export. Evidence/reconstructed/demo labels and gaps persist; nothing runs automatically and reproducibility is not claimed.',
    'Shell-history backfill': 'Explicit bounded pasted Bash, Zsh extended-history and Fish history-file excerpts import only secret-free commands matching the selected service. Raw/unrelated history is discarded; no history files are fetched automatically.',
    'Relevant-command filtering': 'Service names/IDs, approved paths, images and numeric ports select candidate historical commands in source order; suspected credentials are omitted. Matching is heuristic and every inferred command remains unverified.',
    'Reconstruction labels': 'Imported histories, their review views, AI context and exported instructions are marked reconstructed/unverified. Demo evidence remains separately synthetic; owner approval never changes reproducibility to verified.',
    'AI-written summaries': 'Explicit-request local-model description drafts from stored observed metadata and up to two verified configuration-history files, with masking and credential refusal. Editable UI drafts require an explicit use action and notebook save; demo never contacts a model.',
    'AI installation cleanup': 'Explicit-request advice-only model drafts use the saved reviewed installation evidence/exclusions. Returned instructions require owner review and a separate save; no commands run and model accuracy remains unverified.',
    'Dependency graph': 'Notebook graph and full linked lists show recorded prerequisites and transitive dependents/stop impact, observed states, bounded diagram nodes and unknown references. It does not infer undeclared dependencies or execute controls.',
    'Host wake': 'Fixed locally configured MAC/private IPv4/UDP7-or-9 profiles, confirmed fingerprint-bound dispatch, host-operation reservation, persistent cooldown and audits. Demo and test sockets never send a real packet; dispatch does not imply observed wake. Hardware/network support remains unverified.',
})
for feature in DONE:
    PARTIAL.pop(feature, None)
PARTIAL['Action audit trail'] = 'Existing actions plus installation snapshots/import/review/draft/export and configured wake dispatch are audited. Backup restore/revert and suspend/shutdown engines and their audit hooks remain unimplemented.'

# Session 8: scoped credential review, UTC windows and guarded host power.
DONE.update({
    'Secret discovery': 'Best-effort fixed-category checks on discovery metadata, Docker environment assignments, locally approved exact configuration files and rejected configuration drafts. File roots, 20-file/64-KB/256-KB budgets and link/binary exclusions apply; secret filenames are flagged without reading contents. Findings contain no values, excerpts or value hashes. No root crawl; incomplete scope is explicit.',
    'Vault-link workflow': 'Persistent per-service findings show apparently unlinked credentials and let the owner save validated vault item links/IDs with finding revisions and audits. Linking never verifies item existence, secret removal or file safety; no vault login or credential export occurs.',
    'Stop-reason visibility': 'Last controller start/stop/restart requests retain manual, idle or schedule origin, timestamp, outcome and observed-result flag. Unrecorded stops remain unknown; an accepted command is not proof of state or of later external changes.',
})
PARTIAL['Service schedules'] = 'Opt-in five-field UTC cron start/stop windows for independent services, preview and durable at-most-once decisions, restart/clock-backward refusal, fresh observation/dependency/revision/host-reservation guards and no offline backlog or automatic retry. Grouped applications and local-time/DST schedules remain unavailable; demo automatic dispatch is disabled.'
PARTIAL['Host suspend/shutdown'] = 'Reviewed affected-service/registered-dependent plans, controller-local host approval, signed transport, fixed ordinary-account native commands, durable uncertain-outcome holds, inspection acknowledgement and delayed-request tombstones are implemented with mocks. Linux suspend/shutdown, macOS suspend and Windows shutdown adapters exist; macOS shutdown, Windows suspend and native permissions/behavior remain unavailable or unverified. No power command was executed.'
PARTIAL['Action audit trail'] = 'Existing controls, recordings, installation evidence and wake plus credential links, schedule decisions and confirmed suspend/shutdown/inspection hooks are audited. Backup restore/revert engine and its audit hooks remain unimplemented; native power outcomes remain unverified.'
for feature in DONE:
    PARTIAL.pop(feature, None)

# Session 9: finish the three source/workflow rows; owner defers six native checks.
DONE.update({
    'Service schedules': 'Opt-in individual and grouped application start/stop schedules with explicit component consent, IANA timezone previews, DST gap/fold handling, durable once-only decisions, fresh dependency/revision guards and no offline replay. Demo never dispatches automatically.',
    'Host suspend/shutdown': 'Reviewed host impact, signed fixed Linux/macOS/Windows suspend and shutdown adapters, ordinary-account approval, durable uncertain holds and inspection acknowledgements are implemented and mocked. macOS shutdown requires an explicitly approved current GUI domain. Native execution/permissions remain owner-deferred platform evidence; no real power command was executed.',
    'Action audit trail': 'Existing semantic action records plus durable authenticated write intents, fixed route templates, correlation IDs and accepted/refused/unknown outcomes. Crash/cancellation recovery never replays actions; bodies/secrets are excluded. Generic write hooks cover future restore routes when those engines are implemented; backup engines remain Not started.',
})
for feature in DONE:
    PARTIAL.pop(feature, None)

# Backup source workflows; actual NAS/application recovery remains unverified.
DONE.update({
    'Per-service backups': 'Locally approved restic profiles select one to eight config/data/mounted-volume directories; fixed argv, immutable snapshots and signed durable intents. No automatic volume export.',
    'NAS storage': 'Existing owner-mounted SMB/NFS storage and provisioned repository required; missing mount or changed mount identity refuses local fallback. Actual NAS permissions and restore remain unverified.',
    'Manual/scheduled backups': 'Confirmed manual and opt-in daily/weekly UTC backups with durable once-only windows, no restart backlog or automatic retries. Demo automatic dispatch is disabled.',
    'Retention policies': 'Bounded daily/weekly policy, dry-run removal review and separately approved exact-ID forget; safety snapshots excluded. No automatic prune or deletion.',
    'Backup consistency modes': 'Explicit static-file live profiles or observed stop-copy-start for independent runtimes with stopped dependents; linked applications support static backups only. Uncertain outcomes retain a host hold.',
    'Encryption and deduplication': 'Delegated to restic repositories; disposable real encrypted repository backup/restore/check verified locally. Native NAS and application acceptance remains pending.',
    'Backup-password sourcing': 'Owner supplies the vault-managed password through an approved PSC_ environment reference. Values never enter argv, registry or results; automatic vault login/unlock is excluded.',
    'Documentation-inclusive backups': 'Service-card Markdown shares the data snapshot; approved roots include Compose/unit files. Restored prose is returned for separate review without overwriting owner notes.',
    'Backup status': 'Per-service history includes last success, snapshot IDs, byte counts, next UTC window and failures/unknown holds; policy alone never implies backup availability.',
    'Snapshot selection and preview': 'Full immutable scoped snapshot selection, bounded file metadata preview, traversal/link/special-file refusal and separate overwrite confirmation.',
    'Guided restore': 'Independent runtime stop, staged verified restore, atomic file overlay, restart if originally running and configured health check. Previously stopped runtimes remain stopped with health unverified; extra current files are preserved.',
    'Pre-restore safety snapshot': 'Mandatory completed current-data snapshot before target overwrites, durable safety ID before overlay, native metadata checks and interrupted-operation inspection. No multi-file transaction or automatic rollback is claimed.',
    'Backup failure alerts': 'Backup/restore failures feed the existing masked notification outbox and persistent audit/history; real external delivery remains deployment verification.',
})
DONE['Action audit trail'] = 'Durable authenticated write intents plus semantic controls, backup/restore/retention, inspection and schedule records; interrupted results remain unknown and are never replayed. Bodies and secrets are excluded.'

EXTRA = [
    ("Broad host telemetry", "CPU, memory, disk, network, temperatures and system history.", "Spec F12", "Planned", "Partial", "Native telemetry, volume/interface views, reset-aware disk/network rates and charts, sustained threshold policy/state and monitoring links exist. Optional adapters and measured Pi collection/resource budget remain."),
    ("Standalone container management/logging", "Container inventory and individual control/log access.", "Spec F13", "Planned", "Done", "Dedicated persistent container screen, Compose components, current-state checks, confirmed allow-listed controls, filtered logs and snapshot downloads."),
    ("Manually maintained service manifest", "JSON/YAML alongside reviewed auto-discovery.", "Spec F14", "Planned", "Done", "Validated preview/import/export and repeat-import reconciliation are implemented."),
    ("App store/one-click installation", "Browse templates and install supported applications.", "Spec F15", "Planned", "Not started", ""),
    ("Kubernetes management", "Cluster workload inventory, health, logs and lifecycle controls.", "Spec F16", "Planned", "Not started", ""),
    ("Proxmox and VM management", "Nodes, guests, resource details and power controls.", "Spec F16", "Planned", "Not started", ""),
    ("Windows-side monitoring", "Services, processes, ports, telemetry, Event Logs and dual-boot identity.", "Spec F17", "Planned", "Done", "Read-only Windows services/apps/processes/TCP/UDP/Event Log inventory, section-level availability/staleness, optional physical-host identity and OS-switch access invalidation are implemented. Providers are mocked; real dual-boot deployment is unverified."),
    ("Obsidian connection", "Linked Markdown vault export and conflict-aware owner-note sync.", "Spec F18", "Planned", "Done", "Manual linked-vault export/sync works; automatic watching and remote sharing are future extensions."),
    ("Notebook header/top banner", "A personalized paper cover on every service notebook.", "Current request", "Requested", "Done", "Each banner uses its service name, host, runtime and note excerpt."),
    ("Dark mode", "Light, dark and system-following themes.", "Current request", "Requested", "Done", "Theme covers dashboard, notebook banners, forms and dialogs; preference persists across reloads."),
    ("User appearance settings", "Accent color, density, text size and reduced motion.", "Current request", "Requested", "Done", "Saved per browser, with reset and cross-tab preference synchronization."),
    ('Windows software documentation/removal guides', 'Detect installed software including AutoCAD and Microsoft products and open recommended help/removal pages.', 'Current request', 'Requested', 'Done', 'Read-only machine/agent-user uninstall registry and optional current-user Store inventory with curated official Autodesk/Microsoft/Office/Edge links. No uninstall strings, downloads or uninstall execution.'),
    ('Linux/macOS software inventory and guides', 'Include Linux and macOS software, process and socket visibility with appropriate official documentation and removal guidance.', 'Current request', 'Requested', 'Done', 'Bounded read-only dpkg/pacman/RPM and desktop-entry inventory, standard macOS app bundles, agent-account process/socket metadata, curated OS-specific links, physical identity/OS-switch checks and scoped synthetic examples. Flatpak/Snap/AppImage/Homebrew/receipts and other users are excluded.'),
    ('macOS native service support', 'Focus on macOS alongside Linux and Windows.', 'Current request', 'Requested', 'Partial', 'Current-context inventory plus explicitly approved ordinary-user GUI LaunchAgent start/stop/restart with domain/path/hash and fresh-state guards, and mocked ACL/xattr editing. Actual old-macOS compatibility, launchctl context/output, permissions and Intel/Apple Silicon deployment remain unverified; system/Apple jobs remain read-only.'),
]


def escape(value):
    return value.replace("|", "\\|").replace("\n", " ")


def main():
    sections = []
    heading = ""
    for line in (ROOT / "docs/feature-inventory.tsv").read_text(encoding="utf-8-sig").splitlines():
        if not line.strip():
            continue
        cells = line.split("\t")
        if len(cells) == 4 and cells[0] != "Feature":
            feature, description, source, planned = cells
            state = "Done" if feature in DONE else "Partial" if feature in PARTIAL else "Not started"
            if not sections or sections[-1]["title"] != heading:
                sections.append({"title": heading, "rows": []})
            sections[-1]["rows"].append([feature, description, source, planned, state, DONE.get(feature, PARTIAL.get(feature, ""))])
        elif len(cells) == 1 and not line.startswith("These appeared"):
            heading = line.strip()
    sections.append({"title": "Expanded scope and current additions", "rows": [list(row) for row in EXTRA]})
    counts = Counter(row[4] for section in sections for row in section["rows"])
    lines = ["# Complete feature inventory and implementation status", "",
             "Updated October 16, 2026. Descriptions, sources and planning status retain the supplied scope with lab-specific details generalized; implementation and coverage columns are added.", "",
             "**Done** = the described capability is implemented in the current app. **Partial** = a usable subset exists, with missing coverage listed. **Not started** = no implementation of that capability yet. Done is a code/workflow assessment, not a claim that the Pi, mini PC or laptop has been deployed or verified live.", "",
             f"**Totals: {counts['Done']} Done · {counts['Partial']} Partial · {counts['Not started']} Not started ({sum(counts.values())} entries).**", "",
             "Guarded restic backup/restore source workflows are implemented next after schedules, source power adapters and durable auditing. The six Partial rows remain native verification deferred by the owner. Broader integrations are paused pending target evidence. A disposable local restic restore is separate from NAS/application acceptance; no real-host deployment, privilege change, uninstall, wake packet, power command or Pi measurement was performed. See VERIFICATION.md, BACKUPS.md and FIRST-DEPLOYMENT.md.", "",
             "The original attachment ends at the heading ‘Alternatives and explicitly excluded capabilities’ without rows. The capabilities subsequently added back to scope are included in the final table. Security-tripwire ideas remain discussion items; they are separate from F12 telemetry.", ""]
    for section in sections:
        lines += ["## " + section["title"], "", "| Feature | What was discussed | Source | Planning status | Implementation | Current coverage / remaining work |",
                  "| --- | --- | --- | --- | --- | --- |"]
        lines += ["| " + " | ".join(escape(cell) for cell in row) + " |" for row in section["rows"]]
        lines.append("")
    (ROOT / "docs/FEATURE-STATUS.md").write_text("\n".join(lines), encoding="utf-8")
    (ROOT / "docs/feature-status.json").write_text(json.dumps({"counts": dict(counts), "sections": sections}, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"sections": len(sections), "entries": sum(counts.values()), "counts": dict(counts)}))


if __name__ == "__main__":
    main()
