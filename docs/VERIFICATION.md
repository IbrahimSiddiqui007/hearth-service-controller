# Verification baseline

Source milestone, October 13, 2026: **102 Done, 6 owner-deferred platform checks and 35 Not started** across 143 features. See [the complete ledger](FEATURE-STATUS.md), [feature list](FEATURE-LIST.md) and [case matrix](FEATURE-TEST-MATRIX.md).

- Full backend suite: 379 passed, one Windows symlink privilege skip and one existing Starlette/httpx deprecation warning.
- Production TypeScript/Vite build passed.
- Six appearance and three PWA Node tests passed.
- Separate synthetic browser checks passed for timezone validation/local previews, durable accepted/refused write records, offline control refusal and 320/390/1280 layouts. No console errors were observed.
- Three named valid/invalid/null-or-edge cases exist per feature: 324 cases have passing behavioral evidence and 105 cases remain planned for unimplemented features. Shared assertions can cover multiple scenarios; this is not 429 distinct pytest tests.

Grouped schedules require component consent and enforce dependency/context guards. IANA/DST schedules skip missing and repeated minutes and do not replay missed windows. Fixed Linux/macOS/Windows power adapters, durable uncertainty holds and authenticated write auditing are implemented with mocks. Native APIs, power commands, models and network effects were mocked; no target deployment or hardware measurement is claimed.

The owner deferred native file replacement/metadata, restricted OS privileges, Ubuntu/CachyOS deployment, ARM64/AMD64/Pi resource validation, telemetry resource budgets and macOS compatibility. Initial target reports use `python3 scripts/platform_check.py`. These checks do not enable native controls or change privileges.

GitHub Actions checks are configured for mocked backend tests on Linux/macOS/Windows and frontend builds/tests. Their actual run status is available in the repository's Actions tab; this local baseline is not evidence that hosted CI or native targets passed.
