# Verification baseline

Source milestone, October 16, 2026: **115 Done, 6 Partial (native verification deferred) and 22 Not started** across 143 features. See [the complete ledger](FEATURE-STATUS.md), [feature list](FEATURE-LIST.md) and [case matrix](FEATURE-TEST-MATRIX.md).

- Full local backend run: 406 passed, one Windows symlink privilege skip and one existing Starlette/httpx deprecation warning. The final exact-ID retention change then passed all 23 backup tests, including one added regression: combined evidence covers 407 distinct passing tests and one skip; this is not a claim that one run executed 407 passes.
- Production TypeScript/Vite build passed.
- Six appearance and three PWA Node tests passed.
- Synthetic browser checks cover manual backup, snapshot preview, separate overwrite confirmation, guided restore with safety evidence, phone layouts and offline control refusal. Earlier schedule/audit browser checks remain historical evidence.
- Three named valid/invalid/null-or-edge cases exist per feature: 363 cases have passing behavioral evidence and 66 cases remain planned for unimplemented features. Shared assertions can cover multiple scenarios; this is not 429 distinct pytest tests.
- An opt-in real restic 0.19.1 test passed against disposable local data: encrypted repository backup, notebook inclusion, current-data safety snapshot, verified staged restore preserving extra files, and repository integrity check. Its mount boundary is synthetic; no NAS or real service was used. Other backup tests mock restic and runtime boundaries.

Grouped schedules require component consent and enforce dependency/context guards. IANA/DST schedules skip missing and repeated minutes and do not replay missed windows. Fixed Linux/macOS/Windows power adapters, durable uncertainty holds and authenticated write auditing are implemented with mocks. Native APIs, power commands, models and network effects were mocked; no target deployment or hardware measurement is claimed.

The owner deferred native file replacement/metadata, restricted OS privileges, Ubuntu/CachyOS deployment, ARM64/AMD64/Pi resource validation, telemetry resource budgets and macOS compatibility. Initial target reports use `python3 scripts/platform_check.py`. These checks do not enable native controls or change privileges.

## Hosted CI — October 16, 2026

[Source checks passed](https://github.com/IbrahimSiddiqui007/hearth-service-controller/actions/runs/38868007362) on sanitized-history commit `a59e257`: **382 backend tests passed on each of Windows, Linux and macOS**, with no failures, errors or skips. The frontend build and all nine Node tests also passed. This hosted result predates the backup implementation above.

Hosted CI uses isolated fixtures and mocks for native providers; the real restic test is opt-in locally. These checks do not demonstrate real deployment, an actual phone-to-service control, target privileges or a NAS restore. Follow [first deployment acceptance](FIRST-DEPLOYMENT.md) before claiming those outcomes.

## Public source cleanup

The repository remains public as requested. Published branch history was rewritten with the owner's explicit approval to replace the original lab-specific spec and remove earlier screenshots. The surviving dashboard image uses illustrative demo labels. Private recoverable bundles remain ignored locally. Existing clones should be replaced or carefully resynchronized without merging old history back. Rewriting the branch cannot erase forks, downloads or cached copies.
