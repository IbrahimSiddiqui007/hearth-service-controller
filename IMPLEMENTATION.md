# Implementation status

This file describes the code delivered in the current build sessions. The spec remains the broader roadmap. Tests use isolated demo databases and mocked runtime/network boundaries; real Pi/Linux deployment still needs verification on those machines.

Guarded restic backups and restores follow grouped IANA/DST schedules, scoped power adapters and durable write auditing. A disposable real-tool restore is verified locally; actual NAS/application recovery remains pending. Core discovery/boot/host-browsing/Kuma/vault workflows are now implemented; see [CORE-WORKFLOWS.md](docs/CORE-WORKFLOWS.md). Later integrations remain planned under the core-first selection. Six Partial rows remain native verification deferred. Exact evidence: [VERIFICATION.md](docs/VERIFICATION.md); backup scope: [BACKUPS.md](docs/BACKUPS.md).

| Spec feature | Current implementation | Remaining work |
| --- | --- | --- |
| F1 Discovery | Docker, Compose, systemd, optional pm2/configured processes and expanded Windows inventory; persistent diff/gone review, known-app fingerprints, six-hour reviews, enabled/unloaded unit inventory and OS reveal; observation refresh | Native listener visibility and real-host verification |
| F2 Control | Allow-listed Docker/Compose/systemd/verified pm2/fixed Linux process controls and ordered application groups; sequential reviewed bulk actions; durable outcomes; audits; dependent-stop confirmation and verified dependency startup; observed state after commands | Native startup-policy/permission verification |
| F3 Health | HTTP(S)/TCP/ICMP plus fixed agent profiles, periodic polling, latency, observed uptime/coverage, incidents, ntfy/Telegram outbox/settings, restart/host alerts, and per-service resource snapshots | Real Kuma/provider and target acceptance |
| F4 Service cards | Runtime/components, host, access/files, identity/notes, dependency graph, drift, credentials, owner documentation/history, AI drafts, backup policies/history and exports | Native deployment validation |
| F5 Install recorder | Named masked PTY/cast recording, before/after metadata and approved file hashes, noise exclusions/review, explicit history filtering/reconstruction and editable unverified instruction export | Native provider acceptance, verified reproducibility and retention/scale review |
| F6 Files/config history | Approved-root browser; opt-in text editing, etags/validation, native metadata checks/recovery, controller Git snapshots/diffs/restore and external capture | Actual Windows/macOS metadata verification, broader syntax coloring, comprehensive secret scanning and retention review |
| F7 Logs/terminal | Bounded authenticated log followers, filtering/download plus confirmed owner-bound interactive terminal sessions, signed requests, limits and cleanup | Actual POSIX/ConPTY lifecycle and browser acceptance |
| F8 AI explainer | Opt-in explanations, editable card summaries and installation cleanup drafts; saved settings/availability, bounded observed context, secret refusal/masking and separate owner review/save | Actual model quality and deployment validation |
| F9 Credentials | Labels, usernames, vault links/IDs, hints, UI, export inclusion | Real unlocked-CLI/provider acceptance |
| F10 Backup/restore | Fixed restic profiles, mounted storage checks, environment password references, manual/daily/weekly UTC policy, reviewed exact-ID retention, notebook-inclusive snapshots, bounded preview, safety snapshot, staged overlay, runtime/health recovery, alerts and persistent uncertain holds | Actual NAS/application recovery, target permissions and resource measurements; group stop-copy-start and automatic pruning are excluded |
| F11 Wake/sleep | Standalone/linked-group idle guards and dependency-ordered wake; confirmed fixed-profile host WOL with cooldown/audits and no inferred host state | Actual WOL network/hardware checks, suspend/shutdown and schedules |
| F12 Telemetry | Native host telemetry, mounted volumes/interfaces, reset-aware disk/network rates and selectable charts; sustained policies/state, notifications and monitoring links | Optional adapters and measured Pi resource budget |
| F13 Containers | Persistent individual/container-component screen, confirmed allow-listed controls, stale-state gating, logs/filter/download | Broader engine administration and resource charts |
| F14 Manual manifests | JSON/YAML schema, preview, ID/reference/cycle validation, reconciliation, revision conflicts, repeat-import stability, export/re-import | More granular field ownership and UI reconciliation |
| F15 App catalogue | Not implemented | Trusted templates, install progress, compatibility, failure cleanup |
| F16 Platforms | Not implemented | Kubernetes/Proxmox adapters and permissions |
| F17 Windows | Read-only services/apps/processes/TCP/UDP/events, official guides, telemetry and physical-host/OS reconciliation; opt-in native file metadata and ConPTY adapters | Native adapter verification, real Windows/dual-boot deployment and optional packaging; native service controls remain read-only |
| F18 Obsidian | Linked Markdown, properties, vault export, dedicated local sync, note revisions, conflict preservation | Automatic watching and owner-configured remote sharing |

## Verification

Installable PWA with offline public-shell caching, notebook banners and saved appearance settings (dark/light/system, accents, density, text size, reduced motion) are implemented. The complete row-by-row assessment of the supplied feature lists is in [docs/FEATURE-STATUS.md](docs/FEATURE-STATUS.md), with both original planning status and actual implementation status.

- Backend API/agent/health/AI tests are under `tests/`.
- Frontend type checking and production bundling run via `npm run build`.
- Browser checks cover dashboard rendering, service notes, health configuration/results, vault pointers, bulk actions, discovery review, manifest preview, logs/explanations, files, Obsidian vault generation, and a 390-pixel phone layout without horizontal overflow.
- Current exact automated/browser evidence is in [docs/VERIFICATION.md](docs/VERIFICATION.md); earlier session reports are historical. One Windows symlink test skips without creation privileges. No fresh dependency audit or real deployment is claimed.
- Unsaved service-note drafts prompt before navigation; cancelling preserves the draft. Controller connection loss is surfaced while retaining the last fetched inventory.
- No real homelab services were changed or automatically enrolled.
- Legacy authenticated polling and optional mutually authenticated sequence-signed persistent heartbeats coexist. State/event/log streams and confirmed interactive terminal WebSockets are implemented; native target verification remains.
- Linux runtime calls and Ollama are mocked in tests. The Windows symlink escape test skips when local policy prevents creating a symlink.

## Remaining work

The ledger is **121 Done / 6 Partial (native verification deferred) / 16 Not started (143 entries)**. Exact automated/browser results are maintained in VERIFICATION.md. Three cases per feature have explicit traceability; 48 cases remain planned for unimplemented features.

Deferred checks cover native file metadata, restricted OS privileges, Ubuntu/CachyOS deployment, ARM64/AMD64/Pi budget, telemetry resource measurements and macOS compatibility. Core boot, host browsing, Kuma and vault verification source workflows are implemented. Remaining post-v1/platform/security integrations stay planned under the core-first selection. See the complete ledger and manual platform checks; no real-host deployment or privilege changes were performed.
