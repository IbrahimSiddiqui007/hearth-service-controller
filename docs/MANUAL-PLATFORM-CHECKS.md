# Manual target checks

The six platform-dependent ledger rows remain **Partial**; their native verification is deferred. Grouped/IANA/DST schedules and fixed macOS shutdown/Windows suspend source adapters are implemented and tested with mocks. Initial `platform_check.py` reports are read-only. Do not enable power actions, provision OS privileges or attempt shutdown/suspend to collect them. See [scope contracts](POWER-AND-SCHEDULES.md) and [first deployment acceptance](FIRST-DEPLOYMENT.md).

No target is assumed reachable or configured. An ordinary-account report from a Linux controller, Linux worker and supported macOS target is useful when the owner is ready. Docker/ARM64 builds and resource measurements need their own environment. This checklist is not proof that target checks passed.

First, copy the project source to each machine using your usual method. From its project directory, run this with an existing Python interpreter, as your ordinary user:

```sh
python3 scripts/platform_check.py
```

The script prints OS, architecture, Python/dependency versions and tool availability. It does not install anything, inspect services or configuration, contact hosts, or run native controls. Paste the report back for each machine. If Python is missing or too old to run it, provide the OS version and the error instead. On the Mac, also provide the version displayed in About This Mac. Do not install dependencies or change system permissions just to obtain this report.

The project deployment images currently use Python 3.13. POSIX terminals use `os.login_tty` (introduced in Python 3.11); package availability and OS compatibility must be assessed before suggesting a runtime for an older Mac. A successful inventory report alone does not prove project compatibility.

If you already have a compatible project environment with dependencies and pytest, these checks use mocked providers and temporary test data:

```sh
python3 -m pytest tests/test_configuration.py tests/test_file_metadata.py tests/test_launchd_control.py tests/test_terminal.py
python3 -m pytest tests/test_installation.py tests/test_wake.py tests/test_ai.py
python3 -m pytest
```

Report the summary and failures, without credentials or private configuration. Tests do not enroll a host, install an agent or execute an approved shell profile. A frontend build can be checked with `npm run build` from `web` when its dependencies are already available.

| Target | Remaining acceptance evidence |
|---|---|
| Ubuntu and CachyOS | Actual non-root startup, package/systemd inventory, configured privilege policy, service controls, PTY disconnect cleanup and resource sampling |
| Older macOS | Compatible Python/dependencies, actual GUI launchd domain and output format, approved user plist controls, ACL/xattr preservation, PTY lifecycle and socket visibility |
| Windows | Native ACL-preserving replacement and recovery behavior, optional ConPTY dependency/runtime, ordinary-account permissions |
| Docker AMD64 and ARM64 | Both image builds, controller import without agent package, compose startup, health checks and image/runtime sizes |
| Raspberry Pi | ARM64 startup and sustained CPU/RAM budget, reconnect behavior and resource sampling |

Native writes and controls should eventually use disposable files and a disposable service/profile, after the version reports have been reviewed. Do not test by editing or stopping existing applications. Terminal profiles grant the ordinary agent account's capabilities; their cwd is not a filesystem sandbox. Recordings are opt-in and masking is best-effort, so avoid entering secrets.

Session 7 adds snapshot/watch providers across all three OS names through mocks. Actual package/unit/Docker metadata, file budgets/permissions and controller network reachability still need target evidence. Wake tests use mocked sockets and never wake a real device; the live wake destination remains absent unless explicitly configured locally. No wake packet should be sent as part of the initial compatibility report.

There are no commands here to install a service, apply privileges, bootstrap launchd, uninstall applications, or deploy images. Those steps need a concrete reviewed target setup. Until results are supplied, target deployment remains unverified.
