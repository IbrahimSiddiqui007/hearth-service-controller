# Scoped secrets, schedules and host power

These are configuration contracts, not instructions to apply OS privileges or run real host controls during development. All examples are disabled. Existing `file_roots`, independently signed transport, ordinary-account limits and native exclusions remain required.

## Exact-file secret findings

Agent `secret_scan_files` is a map from an already registered reference to a list of at most20 exact `{root_index, path}` entries. Each path is relative to an existing approved `file_roots` entry. No directory is crawled. Non-secret UTF-8 files are at most64KB each and256KB total. Links/hardlinks, binary/oversized/unavailable paths make scope incomplete. Secret filenames produce a possible-secret category without reading contents. Docker environment assignments already obtained during discovery produce fixed categories only; environment values are not added to the exported service inventory.

```yaml
secret_scan_files: {}
power_actions: []
```

Findings contain service ID, a fixed source/category, first/last observation, a finding revision and an owner vault reference. They do not contain values, matched excerpts or value hashes. Repeated findings do not prove the same secret is still present, and a later scan cannot prove a credential was removed. Owner linking never verifies a vault item, changes a file or grants access. Vault CLI checks are not implemented.

## Service windows

The Schedules notebook tab saves disabled-by-default policy with its service revision. Up to eight start/stop rules use five-field cron in a validated IANA timezone (UTC by default): minute/hour/day/month/weekday; Sunday 0, numeric lists/ranges/steps, wildcard fields and conventional restricted day/weekday OR semantics. No arbitrary command is accepted. The next eight days show local timestamps and offsets. Spring-forward nonexistent minutes are skipped; fall-back repeated minutes are eligible only at the first occurrence. The current minute at enable/restart and all expired minutes are skipped. Grouped applications require explicit component consent; children cannot hold independent schedules. Parent and component controls use the established group order and recheck context before each action.

Fresh host/service/dependency observations, known states, exact revision/connection context, control allow-lists and free host reservations are required at dispatch. A stopped prerequisite or running/unknown dependent blocks the relevant action. Conflicting start/stop rules are refused. Each minute's durable decision is made once; offline/blocked/uncertain windows have no backlog and no automatic retry. Changing a service revision rearms its policy rather than replaying an old decision. Demo schedules save/preview but never dispatch automatically.

The UI's last controller request records manual/idle/schedule/backup origin and outcome. It is historical evidence, not a claim about the cause of every later external stop. Unknown stops/outcomes remain unknown.

## Host power

Controller `PSC_POWER_HOSTS` is a JSON list of explicitly approved registered host IDs; absent defaults to `[]`. Agent `power_actions` is separately disabled by default. Live actions need independent signing and private durable replay state, a configured nonempty physical-host identity with matching agent/active-OS evidence, a fresh online host and known fresh registered-service observations. OS permission is separate; this application grants none.

The host panel performs no agent power-profile read until **Review power plan** is chosen. It shows all registered services on that host and declared external dependents, plus the broader impact on unregistered processes/user sessions. Confirmation binds the current host/service/agent-profile context. Existing runtime/config/terminal operations and unresolved power requests inhibit dispatch.

Fixed source adapters: Linux `systemctl --no-ask-password suspend` / `poweroff`; macOS `pmset sleepnow` and the fixed System Events shutdown AppleScript; Windows `shutdown.exe /s /t 0` and typed `powrprof.dll` `SetSuspendState(0,0,0)` at fixed system paths. macOS shutdown also requires `macos_power_domain` to equal the explicitly approved current ordinary-user `gui/<uid>` domain; OS Automation permission is separate. No force-close flag, elevation, inhibitor bypass or configurable command string is used. Native availability/permissions/behavior remain owner-deferred evidence on actual targets.

Intent persists before dispatch at both controller and agent. A returned command, lost connection, crash or timeout never proves a sleep/shutdown state. Host/services become unobserved and further writes stay held. There is no automatic retry. Configured Wake-on-LAN remains available for recovery. After the owner inspects the host, fresh post-request host/service observations and an explicit acknowledgement release the hold; historical power uncertainty remains. An acknowledgement tombstones even an unreceived request so a delayed old request cannot execute later. No power scheduler exists.

Backup/restore workflows have separate local approval, mandatory pre-restore safety snapshots and durable host holds; see [backup scope](BACKUPS.md). They do not grant OS privileges. Boot-policy editing remains absent.

## Durable write auditing

Authenticated API writes persist an intent before validation or execution. Fixed route templates, known service/host IDs, correlation IDs and HTTP outcomes appear in Activity and notebook History. Refused inputs are recorded; interruption/server failure stays unknown. Restart recovery marks unfinished intents unknown and never replays them. Bodies, query strings, authorization values and raw error text are excluded. HTTP acceptance does not establish observed runtime success; semantic action history provides that context. Backup policy, dispatch, retention and inspection routes also inherit the write journal.
