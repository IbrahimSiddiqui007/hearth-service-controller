# Core workflow completion

The owner chose core controller features before the remaining post-v1/platform/security ideas. This milestone completes six source workflows: raw listening-process suggestions, boot-policy controls, Kuma import, Kuma data views, separately approved host browsing and linked vault-item existence checks. Six native platform rows still need owner-supplied evidence. None of these features enrolls a host, grants OS privileges, unlocks a vault or executes a native action automatically.

## Agent approval

The shipped agent examples keep these optional capabilities disabled:

```yaml
listener_suggestions: false
allow_boot_units: []
allow_boot_containers: []
allow_boot_projects: {}
host_browse_roots: {}
vault_check_items: []
vault_session_env: ''
```

Use an ignored `*.local.yaml` file for owner-reviewed approval. Live boot, vault and host-browsing endpoints require signed requests and private durable replay state. Existing bearer authentication and ordinary-account startup restrictions still apply. No broad polkit, Docker-group, administrator or root grant is made.

## Discovery and boot behavior

`listener_suggestions: true` adds bounded, read-only agent-account listening-process suggestions after normal runtime discovery. Known ports and process IDs are excluded; argv, environment and remote peer addresses are not read. Suggestions have no control/log/file permissions. Bounded suggestions and per-process permission gaps never establish a complete process inventory or prove disappearance. Separately configure a process profile before granting controls. Native socket visibility depends on account/OS permissions and remains target verification.

Review **Runtime & resources → Boot behavior** before each change. `allow_boot_units` approves exact systemd `.service` names with ordinary enabled/disabled states. `allow_boot_containers` approves exact Docker names; `allow_boot_projects` maps exact Compose projects to their configured directories. Container actions change existing container restart policies, including each reviewed Compose member. They do not edit Compose source; a later recreation can replace the runtime policy. Reboot/container recreation acceptance is still needed on the target. macOS launchd and Windows native-service startup editing are excluded.

Boot plans bind the current service revision, host identity/active OS, native policy and exact targets. Docker names resolve to exact inspected container IDs; recreated Docker or Compose members invalidate review. Dispatch uses those IDs, and replacement during dispatch leaves the outcome unverified. Changing startup persistence does not start/stop the service. Durable controller and agent intents prevent old request replay. Interrupted results retain a host-wide hold blocking further writes. Inspect actual startup settings and obtain fresh observations before acknowledging the hold; acknowledgement records inspection without claiming the original request succeeded. Delayed unreceived requests are tombstoned.

## Host browsing

**Hosts → Host files** is separate from service file roots. A locally approved `host_browse_roots` map names up to eight existing absolute roots; it may expose a wider host scope at the owner's explicit choice. Reviewing approved profile names does not open files. Select a root and explicitly open its read-only scope. Agent state, common private/credential/virtual paths, symlinks, junctions, hardlinks, special files and suspected secret content are excluded. Lists are bounded to 500 entries and UTF-8 previews to 2 MB. There is no host editor, binary download or privilege escalation. Secret detection is conservative and cannot recognize every custom credential format; approve only scopes appropriate for the ordinary agent account.

## Kuma monitor/history import and views

The service **Health** tab accepts a JSON monitor/heartbeat capture, or explicitly pulls a published status page from a controller-local approved origin. Configure optional `PSC_KUMA_SOURCES` as a JSON object such as `{"lab":"https://kuma.example"}`; it defaults to `{}`. No controller credential, arbitrary browser URL, redirect, vault login or background connection is used. Only the selected source's fixed published metadata/heartbeat endpoints are requested.

Select one monitor ID, review it, then explicitly link it to the current service. The ten-minute review snapshot contains only monitor identity/type/interval and normalized time/status/latency observations. Passwords, notification settings, tokens, response messages and unrelated monitor fields are discarded before storage. Matching imports deduplicate; conflicts refuse the transaction. Existing service notes, health configuration, native health series and runtime state stay unchanged. Imported data retains its separate source label; pending/maintenance are not successful probes and empty history does not imply uptime. History from earlier mappings is retained in storage.

This preserves **available** observations, not an assertion that a published endpoint exposes a complete historical database. Captures support up to 10,000 observations per selected monitor; public status pages commonly expose a smaller recent window. The view shows up to 120 stored observations. No automatic migration of private monitor credentials/check configuration or iframe embedding is provided. Pulling the data is the supported alternative to embedding.

Kuma's [own internal API documentation](https://github.com/louislam/uptime-kuma/wiki/Internal-API) describes published status-page metadata and heartbeat endpoints and warns that internal APIs can change between versions. Real-server compatibility remains deployment acceptance; tests mock the provider boundary.

## Vault references

**Credentials → Check linked vault items** accepts an exact UUID item reference or HTTPS vault link identifying one UUID. The chosen item must separately appear in local `vault_check_items`. Provision an already unlocked Bitwarden session privately through the environment variable named by `vault_session_env`; only `PSC_` references are accepted. Hearth never logs in, unlocks, syncs, edits or exports a vault item. The fixed CLI call checks one approved item, discards returned JSON and reports existence only. Locked/offline/denied/deleted/missing/malformed responses stay unverified. A linked item existing does not prove password correctness, secret removal or recovery access.

## Remaining scope

The ledger remains complete at 143 features: 121 Done, 6 Partial with native verification deferred, 16 Not started. The remaining planned rows are the later security-tool integrations/monitoring, PWA push, MCP, guarded application updates, out-of-band hardware, app catalogue and Kubernetes/Proxmox. They are not claimed complete by this core milestone. Read [first deployment acceptance](FIRST-DEPLOYMENT.md) before enabling additional production scope.
