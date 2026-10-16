# Verification baseline

Source milestone, October 13, 2026: **102 Done, 6 Partial (native verification deferred) and 35 Not started** across 143 features. See [the complete ledger](FEATURE-STATUS.md), [feature list](FEATURE-LIST.md) and [case matrix](FEATURE-TEST-MATRIX.md).

- Full backend suite: 379 passed, one Windows symlink privilege skip and one existing Starlette/httpx deprecation warning.
- Production TypeScript/Vite build passed.
- Six appearance and three PWA Node tests passed.
- Separate synthetic browser checks passed for timezone validation/local previews, durable accepted/refused write records, offline control refusal and 320/390/1280 layouts. No console errors were observed.
- Three named valid/invalid/null-or-edge cases exist per feature: 324 cases have passing behavioral evidence and 105 cases remain planned for unimplemented features. Shared assertions can cover multiple scenarios; this is not 429 distinct pytest tests.

Grouped schedules require component consent and enforce dependency/context guards. IANA/DST schedules skip missing and repeated minutes and do not replay missed windows. Fixed Linux/macOS/Windows power adapters, durable uncertainty holds and authenticated write auditing are implemented with mocks. Native APIs, power commands, models and network effects were mocked; no target deployment or hardware measurement is claimed.

The owner deferred native file replacement/metadata, restricted OS privileges, Ubuntu/CachyOS deployment, ARM64/AMD64/Pi resource validation, telemetry resource budgets and macOS compatibility. Initial target reports use `python3 scripts/platform_check.py`. These checks do not enable native controls or change privileges.

## Hosted CI — October 16, 2026

[Source checks passed](https://github.com/IbrahimSiddiqui007/hearth-service-controller/actions/runs/38863166648) on commit `9c2b0de`: **382 backend tests passed on each of Windows, Linux and macOS**, with no failures, errors or skips. The frontend build and all nine Node tests also passed. The fixes covered fresh-checkout test-directory setup, portable PM2 fixture ownership and long Windows Git-history paths.

The earlier 379-pass local result is retained above as historical evidence. Hosted CI still uses isolated fixtures and mocks for native providers. It does not demonstrate real deployment, an actual phone-to-service control, native privileges or a NAS restore. Follow [first deployment acceptance](FIRST-DEPLOYMENT.md) before claiming those outcomes.
