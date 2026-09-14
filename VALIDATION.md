# OpsForge v0.2.0-beta.1 candidate validation

Validation recorded on 2026-09-13. This record distinguishes deterministic unit coverage, clean-install integration checks, and live environment observations. It is not a production-readiness claim or a substitute for independent review.

## Local environment

- Ubuntu 24.04.1 LTS under WSL2
- Linux 6.18.33.2-microsoft-standard-WSL2, x86_64
- CPython 3.12.3
- OpenSSL 3.0.13
- systemd 255.4
- iproute2 `ss` 6.1.0

The release workflow remains configured for CPython 3.10, 3.11, 3.12, 3.13, and 3.14 on Ubuntu. Only Python 3.12 was available for this local run; the other interpreter jobs require the GitHub Actions matrix and are not claimed as locally executed.

## Unit tested

All implementation modules compiled with `python -m compileall`. The final `unittest` run passed 440 tests:

| Suite | Tests |
| --- | ---: |
| Shared output contract | 8 |
| PortLens | 35 |
| DiskHound | 46 |
| CertWatch | 62 |
| SvcDoctor | 51 |
| LogHound | 39 |
| ProcWatch | 28 |
| ConfigDiff | 31 |
| NetDoctor | 30 |
| HealthCtl | 47 |
| Incident Snapshot | 63 |
| **Total** | **440** |

Coverage includes legacy invocation paths and deterministic success/failure behavior, malformed input, bounds, partial observations, terminal-safe/JSON/brief/quiet output, safe output-file replacement, resolver de-duplication, PID identity, filesystem mutation cases, dependency cycles, subprocess timeout/output limits, and privacy-sensitive paths.

## Packaging and clean-install integration

`python -m build` successfully produced:

- `opsforge-0.2.0b1.tar.gz`
- `opsforge-0.2.0b1-py3-none-any.whl`

The wheel was installed with `pip install --no-deps` into a fresh virtual environment from outside the source tree. Metadata resolved as `opsforge 0.2.0b1`; all ten packages imported; every installed console command existed; and every `--help` invocation exited 0.

Nine installed commands then completed local schema-version-1 JSON smoke checks with expected exit semantics:

- DiskHound on a temporary directory
- LogHound on a controlled two-line log
- ConfigDiff on identical temporary files
- HealthCtl with a root free-space criterion
- ProcWatch against the live validation process
- Incident Snapshot with the `full` profile
- PortLens against a selected local port
- NetDoctor against a selected refused/local endpoint
- SvcDoctor against `dbus.service`

Every stdout document parsed as JSON and contained the shared schema/tool fields. The clean environment uninstalled OpsForge successfully, the installed command scripts disappeared, and the disposable environment was removed.

## Real-world validated

The following live surfaces were exercised on the environment above:

- Linux procfs/sysfs process, memory, load, PSI, cgroup, socket-table, route, and kernel scheduler sources
- root filesystem capacity and inode metadata
- local TCP refusal and `ss` listener inspection
- systemd service state and failed-service collection
- resolver and default-route context
- bounded full-profile Incident Snapshot collection
- one intentional public CertWatch request to `example.com:443`

The public CertWatch validation returned `VALID` with TLS 1.3, a negotiated cipher, leaf/SAN/fingerprint/validity evidence, successful CA trust and hostname identity, and explicit `revocation_checked: false`. Chain count was unavailable on CPython 3.12 as documented. No other public target was contacted.

These checks validate execution in this WSL environment only. They do not establish compatibility across distributions, namespace layouts, permission models, network policies, filesystems, systemd versions, OpenSSL versions, or all supported Python interpreters.

## Deferred and limited validation

- Semantic TOML is not implemented because CPython 3.10 lacks `tomllib` and the project retains no third-party runtime dependencies.
- Portable intermediate-certificate expiry inspection is not implemented because CPython 3.10-3.12 lack a consistent public verified-chain certificate API.
- Operating-system DNS resolution is not hard-cancellable through standard-library `getaddrinfo()`; socket/HTTP/TLS stages remain bounded.
- No broad public-network, high-scale filesystem, container-orchestrator, non-WSL distribution, elevated-permission, or formal penetration test was performed.
- GitHub Actions results for CPython 3.10-3.14 remain an external PR gate and must not be inferred from this local record.

Manual real-world testing by the user remains the final release gate before any merge or tag.

## Independent-review hardening gates

The release workflow now requires both wheel and source-distribution clean installs on CPython 3.10, 3.11, 3.12, 3.13, and 3.14. Each artifact/interpreter job verifies metadata, imports, all ten console scripts, `pip check`, nine installed-command JSON smoke checks, and complete console-script removal after uninstall.

Focused regressions additionally cover the stdout/file 16 MiB boundary, Unicode presentation-control escaping, proxy-independent HTTP routing, total post-resolution HTTP deadlines, bounded headers and redirects, CertWatch trusted-leaf fingerprint correlation, and termination/reaping of subprocess process groups on interruption. Results for the replacement PR head must be taken from its own GitHub Actions run; the earlier 440-test record above remains a historical statement about the pre-hardening head.
