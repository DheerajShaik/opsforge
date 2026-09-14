# Changelog

Notable changes to OpsForge will be recorded here.

## Unreleased

## 0.2.0-beta.1 - 2026-09-13

### Common output and safety

- Added a shared terminal-safe conclusion line plus `--brief`, schema-versioned `--json`, `--quiet`, elapsed timing, and safe `--output FILE`/`--force` behavior to all ten commands.
- All rendered stdout and file output is bounded to 16 MiB. Output files default to mode `0600`, refuse implicit overwrite, and do not follow symlinks or overwrite non-regular or multiply-linked targets.
- Hardened terminal rendering against Unicode presentation controls, bound and reap subprocess process groups on every exceptional path, and correlate CertWatch trust to the displayed leaf fingerprint.
- Retained the dependency-free CPython 3.10-3.14 and Linux-only package policy.

### Utility enhancements

- PortLens adds UDP, all-port and range selection, family/PID/process filters, bounded watch mode, ownership/executable/FD/cgroup evidence, bind interpretation, and likely shared-bind evidence.
- DiskHound adds top/depth/entry/size/age bounds, excludes, inode and mount context, largest-file, sparse-file, file-type, logical/allocation, cross-filesystem, and concentration evidence.
- CertWatch adds bounded multi-target operation, critical thresholds, explicit SNI, TLS/cipher/timing and fingerprint evidence, SAN identity checks, a separate trust handshake, capability-detected chain count, and explicit revocation limits.
- SvcDoctor adds bounded journal and direct dependency evidence, restart/exit/signal interpretation, unit/drop-in paths, activation, resource/task limits, selected execution identity, and safe follow-up commands.
- LogHound adds conservative RFC3339/PID/IP/UUID/labelled-ID normalization, literal filters, time windows, top-N, bounded rotations, severity/rate/burst summaries, stack-trace grouping evidence, and bounded-period comparison.
- ProcWatch adds bounded multi-sample/duration/continuous modes plus FD/socket, I/O, context-switch, child, thread CPU, and cgroup constraint evidence while preserving PID identity checks.
- ConfigDiff retains exact-byte mode and adds explicit bounded unified diff, whitespace/comment modes, semantic JSON and selected keys, metadata, permission/ownership, bounded directory, and optional symlink-target comparison.
- NetDoctor adds resolver/TCP/TLS timings, retries, address-family comparison, resolver/default-route/source/interface context, proxy-variable-name detection, and resolution/route/TCP/TLS stage classification.
- HealthCtl adds strict proxy-free HTTP(S), DNS, certificate-expiry, process, systemd, file existence/metadata, and SHA-256 checks with severity, groups, profiles, dependencies, retries, and bounded parallelism. HTTP response headers and post-resolution wall-clock duration are explicitly bounded; arbitrary commands remain prohibited.
- Incident Snapshot adds privacy-conscious `basic`, `network`, `process`, and `full` profiles with PSI, inode, interface, route, listener, process-ranking, failed-service, and selected kernel scheduler evidence.

### Compatibility and deferrals

- Existing normal positional invocations and established exit meanings remain compatible except that CertWatch now correctly returns exit `1` when trust or identity evidence produces `WARNING`.
- Semantic TOML is deferred because Python 3.10 lacks `tomllib` and OpsForge does not add a third-party runtime parser solely for this mode.
- Portable intermediate-certificate expiry decoding is deferred: Python 3.10-3.12 do not expose a consistent public verified-chain certificate API. CertWatch reports chain count when the runtime supports it without implying intermediate validity coverage.
- Direct DNS timeouts remain governed by the operating-system resolver because the Python standard library exposes no cancellable `getaddrinfo()` timeout. All subsequent socket and HTTP/TLS operations remain explicitly bounded.

## 0.1.0-beta.1 - 2026-09-12

- Transitioned OpsForge from Experimental to Beta after completion of the initial ten-utility roadmap, while retaining explicit non-production-readiness and compatibility limits.
- Added standard Python packaging with ten independent console commands and isolated local installation through `pipx install .`.
- Added a repository-wide CPython 3.10–3.14 Linux regression gate covering compilation, all utility suites, wheel and source-distribution builds, clean installation of both artifact types on every supported interpreter, installed entry points, nine safe JSON smoke checks, and complete script removal on uninstallation.
- Reconciled project, security, contribution, compatibility, and utility documentation with completed implementation and recorded validation evidence.
- Completed post-fix CertWatch real-world revalidation against `example.com:443` on Ubuntu 24.04.1 WSL2 with Python 3.12.3 and OpenSSL 3.0.13.

- Hardened CertWatch SAN-heading compatibility for bounded OpenSSL horizontal-whitespace variants, added deterministic regression coverage for captured OpenSSL 3.0.13 decoder formatting, clarified compatibility and validation status, and refreshed project security and contribution guidance.

- Added experimental Incident Snapshot V1 for bounded, low-sensitivity Linux incident context from an explicit source allowlist, with reduced platform, runtime, memory, and root-capacity evidence, useful partial-section semantics, deterministic tests, documentation, and dedicated CI.

- Added experimental HealthCtl V1 for evaluating a bounded JSON-configured set of filesystem free-space and TCP connection criteria, with strict configuration handling, conservative observation semantics, deterministic tests, documentation, and CI.

- Added experimental NetDoctor V1 for one-target OS resolver and TCP connection-establishment diagnostics, with bounded candidate handling, transport-only interpretation limits, deterministic tests, local loopback validation, documentation, and CI.

- Added experimental ConfigDiff V1 for bounded exact byte-content comparison of one local regular file against an explicit baseline, with conservative mutable-file checks, content-safe reporting, deterministic tests, documentation, and CI.

- Added experimental ProcWatch V1 for two-sample observation of one local Linux process, with bounded procfs reads, CPU and memory delta evidence, conservative identity handling, deterministic tests, documentation, and CI.

- Added experimental LogHound V1 for bounded recurrence analysis of one local regular log file, with conservative timestamp normalization, terminal-safe output, deterministic tests, documentation, and CI.

- Added experimental CertWatch v0.1 for bounded, one-target TLS leaf-certificate observation, identity-field reporting, encoded validity/expiration assessment, and deterministic tests, documentation, and CI.

- Added the experimental SvcDoctor v0.1 implementation for reporting structured state and raw execution evidence for one local systemd service, with deterministic diagnostics, bounded observation, documentation, and tests.
- Added the experimental DiskHound v0.1 implementation with same-device metadata traversal, allocated-block accounting, deterministic diagnostics, documentation, tests, and minimal CI.
- Added the experimental initial PortLens implementation for inspecting local TCP listening sockets, with best-effort process enrichment, tests, and minimal CI.
- Established the initial repository foundation documentation, license, and repository hygiene files.
