# Verification baseline

Source milestone, October 17, 2026: **121 Done, 6 Partial (native verification deferred) and 16 Not started** across 143 features. The owner selected core completion before later integrations. See [the complete ledger](FEATURE-STATUS.md), [core workflow scope](CORE-WORKFLOWS.md), [feature list](FEATURE-LIST.md) and [case matrix](FEATURE-TEST-MATRIX.md).

- Final full local backend run: **440 passed, two skips** (Windows symlink privilege and opt-in real-restic), one existing Starlette/httpx deprecation warning. Includes Docker name-reuse and post-dispatch recreation regressions. The run uses a fresh workspace-local temporary directory, matching CI; private AppData browsing remains refused.
- Production TypeScript/Vite build passed.
- Six appearance and three PWA Node tests passed.
- Core synthetic browser acceptance covers reviewed boot policy, existence-only vault simulation, explicit Kuma history review/import with source labels and read-only host browsing. Earlier backup, schedule and audit browser checks remain historical evidence. Fresh 390px service/host/Health layouts and disabled offline service controls passed. At 320px with Large text, Health has document scrollWidth = clientWidth = 305px (320px viewport); uptime cards stack without global overflow hiding. Temporary viewport overrides were reset.
- Three named valid/invalid/null-or-edge cases exist per feature: 381 cases have passing behavioral evidence and 48 cases remain planned for unimplemented features. Shared assertions can cover multiple scenarios; this is not 429 distinct pytest tests.
- An opt-in real restic 0.19.1 test passed against disposable local data: encrypted repository backup, notebook inclusion, current-data safety snapshot, verified staged restore preserving extra files, and repository integrity check. Its mount boundary is synthetic; no NAS or real service was used. Other backup tests mock restic and runtime boundaries.

Grouped schedules require component consent and enforce dependency/context guards. IANA/DST schedules skip missing and repeated minutes and do not replay missed windows. Fixed Linux/macOS/Windows power adapters, durable uncertainty holds and authenticated write auditing are implemented with mocks. Native APIs, power commands, models and network effects were mocked; no target deployment or hardware measurement is claimed.

The owner deferred native file replacement/metadata, restricted OS privileges, Ubuntu/CachyOS deployment, ARM64/AMD64/Pi resource validation, telemetry resource budgets and macOS compatibility. Initial target reports use `python3 scripts/platform_check.py`. These checks do not enable native controls or change privileges.

## Hosted CI — October 16, 2026

[Source checks passed](https://github.com/IbrahimSiddiqui007/hearth-service-controller/actions/runs/38870937704) on backup implementation commit `bef7fc5`: **407 backend tests passed on each of Windows, Linux and macOS**, with no failures or errors and one opt-in real-restic test skipped per runner. The frontend build and all nine Node tests also passed. The orchestration fixture explicitly mocks native ACL providers; real target ownership/ACL acceptance remains deferred. The separate disposable local real-restic test passed as described above.

That hosted baseline predates the core workflows above. Core source is covered by the local evidence above; a hosted result is only claimed after its run completes.

Hosted CI uses isolated fixtures and mocks for native providers, including the backup orchestration fixture's ACL boundary. Native permission refusal remains enabled in production; metadata helpers have separate regression tests. The real restic test is opt-in locally. These checks do not demonstrate real deployment, an actual phone-to-service control, target privileges or a NAS restore. Follow [first deployment acceptance](FIRST-DEPLOYMENT.md) before claiming those outcomes.

## Public source cleanup

The repository remains public as requested. Published branch history was rewritten with the owner's explicit approval to replace the original lab-specific spec and remove earlier screenshots. The surviving dashboard image uses illustrative demo labels. Private recoverable bundles remain ignored locally. Existing clones should be replaced or carefully resynchronized without merging old history back. Rewriting the branch cannot erase forks, downloads or cached copies.
