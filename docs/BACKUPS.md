# Backup and restore

Backup workflows are experimental and disabled by default. Source tests and a disposable local restic restore have passed; no NAS, production service or real application recovery is claimed. Complete [first deployment acceptance](FIRST-DEPLOYMENT.md) before expanding a live deployment. The six [native platform checks](MANUAL-PLATFORM-CHECKS.md) remain deferred.

## Local approval

The ordinary agent account needs an installed restic executable, an existing mounted SMB/NFS share, an owner-provisioned encrypted repository and signed transport with private durable `state_dir`. Hearth does not install restic, mount storage, initialize repositories, unlock a vault or grant permissions. Supply the repository password privately from your vault through the named environment variable; never store its value in YAML or the registry.

The shipped examples use `backup_profiles: {}`. This illustrative Linux configuration belongs in an ignored `*.local.yaml` file only after reviewing the paths and permissions:

```yaml
backup_profiles:
  example-data:
    storage_root: /mnt/backup-share
    repository: /mnt/backup-share/hearth-example
    paths: [/srv/example/config, /srv/example/data]
    password_env: PSC_RESTIC_EXAMPLE_PASSWORD
    consistency: quiesced
    runtime:
      runtime: systemd
      handle: {unit: example.service}
    allow_restore: false
    allow_retention: false
    max_restore_files: 10000
    max_restore_bytes: 4294967296
```

This example grants neither restore nor snapshot deletion. Approve those independently when ready. Docker uses `runtime: docker` with `handle: {container: <exact-name>}`; Compose uses `runtime: compose` with the exact discovered control handle. The runtime must match one observed service and be stopped for a consistent copy or restore. Controller runtime permissions remain separate. Volumes must already be accessible through approved local directories; Hearth does not export anonymous volumes or copy remote Docker daemon paths.

Profiles approve one to eight existing, distinct absolute directories. Source roots, repository and private state must be separate; roots cannot overlap or be filesystem roots. Links/junctions in root paths are refused. The storage root must be recognized as a mount by the host OS. Missing or changed mounts refuse dispatch instead of writing to a local fallback. Windows SMB drive mappings and platform-specific mount detection require native acceptance. Restic password and repository overrides inherited from the shell are removed; a private agent cache is used. Repository contents are encrypted by restic, including any credentials intentionally contained in the approved service data; raw contents are never added to the controller registry or AI context.

## Review and run

Open a service's **Backups** tab, select its locally approved profile and save the policy. Review the current scope before confirming a manual backup. Static profiles can explicitly use `consistency: static` for live copying; changing application databases need stop-copy-start and application-specific recovery validation. Stop-copy-start currently supports independent services with stopped dependents. Linked applications support approved static-file backups only.

Manual, daily and weekly schedules are supported in UTC. Saving a policy does not run a backup. Missed/restart windows are skipped, no offline backlog is replayed and demo schedules never dispatch. History records snapshots, size, next window, successful backups and uncertain results. Failed operations feed the existing notification outbox; actual delivery depends on separately configured notifications.

Service-card Markdown is included with the approved data in one snapshot. Include Compose/unit files in approved roots if needed. Repository encryption and deduplication are restic's responsibility. Verify repository integrity separately and rehearse restores on a disposable dataset before relying on backups.

## Restore and retention

Select a full immutable snapshot ID and preview its files. Restore needs separate local approval, a configured health check, a controllable independent runtime and an explicit overwrite confirmation. The agent refuses out-of-scope files, traversal, links, hard links and special files, with bounded metadata and restore budgets.

A mandatory current-data safety snapshot completes before overwriting any target. Its ID is durably recorded before installing files. Restic restores into private staging with verification; Hearth then overlays regular files atomically one at a time and preserves extra current files. Existing native file permissions are checked and preserved. This is not a transaction across the whole directory tree: a failure can leave a partial overlay. New files use restricted permissions and missing directories do not reconstruct all original directory ACLs. Application-specific database consistency remains the owner's responsibility.

Originally running services are stopped, restored, restarted and health-checked. Originally stopped services remain stopped with health explicitly unverified. Restored notebook prose is available for review and does not replace current notes automatically. Safety snapshots remain available for a separately reviewed recovery; no automatic rollback occurs.

Retention is a separate reviewed action. A dry run selects data snapshots under the saved daily/weekly policy; confirmation deletes only those immutable IDs. Safety snapshots are excluded. Hearth never runs `prune`, so forgotten snapshots do not immediately reclaim repository data space. Repository administration remains an owner task.

Interrupted actions retain durable controller/agent holds and block further host writes. Inspect agent operation evidence, the service, repository, safety snapshot and any partially restored files. Obtain fresh post-operation observations before explicitly acknowledging the hold. Acknowledgement records inspection without claiming success and tombstones delayed requests. It never retries an old operation or automatically starts a service.

## Verification

Mocked tests cover valid, invalid and null/edge requests, missing storage/passwords, consistency, snapshot scope, unsafe archives, exact retention IDs, replay prevention, failure alerts and restart holds. Optional real-tool coverage creates only disposable local data, mocks the mount boundary and checks backup, safety snapshot, restore, notebook inclusion and repository integrity:

```sh
# Set to an official restic binary already verified for your platform.
PSC_TEST_RESTIC_BINARY=/absolute/path/to/restic python -m pytest tests/test_restic_integration.py
```

This test does not prove NAS mounts, your application's recovery, ordinary-account privileges on target hosts or Pi resource use. See [verification evidence](VERIFICATION.md).
