# First real deployment acceptance

The next deployment milestone is deliberately small: one controller, one worker agent, Docker/Compose discovery, and one owner-confirmed service control from a phone. The current public source and passing CI do not prove that this milestone works on any contributor's hardware.

Broader platform integrations and application installation should wait for this acceptance and the six Partial platform rows. Backup/restore and the remaining core source workflows are implemented, but actual NAS/application recovery and target acceptance are still pending. A written backup plan is documentation; it is not a backup, a completed restic run or a tested recovery path.

## 1. Read-only platform reports

On each intended controller/worker, as an ordinary user with an existing interpreter, from the project directory:

```sh
python3 scripts/platform_check.py
```

Record the OS/architecture, Python version, tool availability and any error. The supported CI/runtime baseline is Python 3.13. Do not install missing software, grant Docker access, enroll hosts or change privileges just to obtain the report. Do not publish actual network topology, device models or secret material with it. ARM64/resource measurements and older-macOS compatibility require separate evidence.

## 2. Review the smallest configuration

After the reports are reviewed, prepare ignored `*.local.yaml` profiles selecting Docker/Compose discovery only. Specify exact owned containers/projects and source paths; keep file editing, terminals, power, scheduling and broader scanners disabled. Provision credentials privately by environment-variable name. A Docker socket is powerful access; review the existing account's rights before deciding how to expose any operations.

No command here grants privileges, mounts storage or starts an agent. Starting agents and enrolling a real worker require the owner's explicit target authorization and a reviewed local configuration.

## 3. Observe before controlling

Start with controller/agent health and read-only discovery over the approved private transport. Confirm physical identity, active OS, worker reachability, exact Compose project path and the selected application's current state. Review candidates before registration. Verify that an offline worker refuses controls and that no missed operation is queued.

## 4. One reversible control from a phone

With the owner present and the selected application safe to interrupt, test one start/stop/restart through the private phone connection. Record the command outcome, fresh resulting-state observation and audit event. Check that dependent-service warnings appear. Do not test sleep/shutdown, arbitrary terminals, file writes or unrelated services as part of this milestone.

## 5. Record deployment evidence and recovery

Record the platform report, reviewed configuration scope, application control observation, phone access result, permission gaps and the owner's manual recovery path in private deployment notes. Update only the ledger rows for which evidence was actually collected. A mocked CI run is not a substitute.

For backup acceptance later, use a disposable dataset and an independently verified restic repository first. Verify a completed backup, a safety snapshot, a file-level restore and a resulting application health check before treating real service recovery as supported.
