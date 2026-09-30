# Changelog

Notable changes to OpsForge will be recorded here.

## Unreleased

### Breaking

- Everything now lives under one `opsforge` package instead of eleven generically named top-level packages. `opsforge_common` is `opsforge.common`, and each utility module is `opsforge.<utility>.<utility>` (for example `opsforge.portlens.portlens`). The installed commands are unchanged. Anything that imported the old names must be updated.
- One status and exit-code policy for all ten utilities, defined once in `opsforge.common.status`. Exit 0 is a trustworthy observation with nothing to report, 1 a finding, 2 invalid invocation or a missing or wrong-type target, 3 no trustworthy answer, and 130 interrupted. An established finding decides the exit even when other parts of the run could not be observed, and a gap with no finding is never success: verdict utilities exit 3 (`INCOMPLETE` or `ERROR`), observation-only utilities report `PARTIAL` and exit 1. An `--output` failure is always 3.
- Exit codes that change: PortLens, SvcDoctor, and LogHound permission failures, missing tools, malformed or oversized output, and internal errors now exit 3 instead of 2; SvcDoctor exits 3 for a stopped unit whose dependencies could not be checked (`INCOMPLETE`) and 2 for a service that does not exist; ProcWatch exits 2 for a process that is gone but 3 for one that cannot be read; HealthCtl exits 3 only when no check failed, and a failed check exits 1 even if another check errored.
- Renamed or removed states: CertWatch's not-yet-valid state is `NOT_YET_VALID` (was `FAIL`), a CertWatch target not attempted because of the overall time limit is `SKIPPED`, and its partial aggregate is `INCOMPLETE` (was `PARTIAL`); HealthCtl's `fail_warn` summary key is `fail_warning`, its severities are `WARNING` and `CRITICAL` (`WARN` is still accepted in configuration), and `ERROR` and `SKIPPED` results have no severity (JSON `null`) instead of `CRITICAL` or `OK`.
- The ten per-tool GitHub Actions workflows are gone. `release-regression.yml` compiles the code and runs every suite on CPython 3.10 through 3.14 for each pull request and push to `main`, so they were redundant.

### Added

- `opsforge.common.net`: one strict host grammar (ASCII only, no name ending in a numeric label that a resolver would read as an IPv4 address), bounded TCP resolution that separates negative answers from resolver failures, SNI handling, and a connect loop with per-attempt and overall deadlines. NetDoctor, HealthCtl, and CertWatch use it instead of three near-copies.
- SvcDoctor reports the limit that really applies: the tightest of the unit's own `MemoryMax`, `MemoryHigh`, `CPUQuotaPerSecUSec`, and `TasksMax` and those of every slice above it, naming the slice that sets it. It also names exit statuses and signals (`203 (EXEC)`, `signal 9 (SIGKILL)`) and classifies `systemctl` failures from its stderr.
- DiskHound skips remote and network mounts unless `--include-remote-mounts` is given, and reports a `directory-limit` when a tree has more directories than it will visit.
- CertWatch reads the leaf from one verified handshake and reconnects only when verification fails (it used two connections and two handshakes per target), inspects up to eight targets at once, and keeps input order.
- HealthCtl runs checks on daemon threads as soon as their own dependencies finish, stops scheduling on Ctrl-C, and gives blocking probes (name resolution, capacity, `lstat`, hashing) a bound so a hung filesystem or resolver becomes an `ERROR` instead of a hang.
- Tests now cover real behavior: captured `ss`, `systemctl`, `journalctl`, and `/proc/self/mountinfo` output, loopback TCP, HTTP, and TLS servers with throwaway certificates (valid, expired, not yet valid, wrong name), real process, thread, and zombie PIDs, and real temporary directory trees.

### Fixed

- Shared output: `--force` replaces files atomically through a private temporary file, a reader closing stdout early (for example `| head`) no longer causes a traceback, non-finite numbers are emitted as JSON `null` so output stays standard JSON, and an empty `--output` path is refused.
- Shared helpers: terminal escaping, bounded subprocesses with trusted helper resolution and a minimal environment, regular-file opening, procfs parsing, and systemd unit-name normalization now have one implementation in `opsforge.common` instead of drifting per-tool copies.
- PortLens attributes socket owners by socket inode from `/proc/PID/fd` instead of trusting `ss -p` process text, and handles scoped IPv6 binds, dual-stack IPv4 matches, newline or non-UTF-8 process names, kernel-truncated names, and unparseable `ss` rows.
- DiskHound reports directories cut off by `--max-depth` as `PARTIAL` with reasons instead of omitting them silently, and counts skipped cross-device entries.
- ConfigDiff semantic JSON compares typed values (`true` no longer equals `1`); directory mode compares the root directory and symlink targets and reports unexamined directories; non-regular files are checked before opening; unified diffs are bounded.
- CertWatch checks identity against the SNI name actually sent, adds a `CRITICAL` state, ranks states so drift never hides expiry, and reports a failed target even when it is the only one.
- NetDoctor classifies TLS errors, reads a symlinked `/etc/resolv.conf`, ignores reject/unreachable default routes, and moves to the next candidate when a socket cannot be created.
- SvcDoctor reports failed, load-error, crash-looping, unsuccessfully stopped, and dependency-failed units as failures (exit 1); reads the journal by unit `Id` so aliases reach the real unit and keeps the newest lines; and checks dependencies of every unit type, including `Requisite` and `BindsTo`.
- HealthCtl rejects fields that belong to another check type, maps `systemctl is-active` statuses to `PASS`/`FAIL`/`ERROR` exactly, reports dependents of a non-passing check as `SKIPPED`, reports expired certificates as critical failures, isolates one check's crash from the rest of the run, backs off between retries, and no longer double-counts errors.
- LogHound parses RFC 3164 syslog and common ISO 8601 timestamp variants, so recurrence works on syslog-style files; `--window-seconds` reports undated lines instead of silently filtering them; syslog PIDs, ports, IPv6 addresses, JSON-quoted labels, and any UUID version are normalized; explicit log levels win over keywords and `failed=0` is not an error; stack traces group across source, caret, exception, and cause lines and JDK 9+ frames; NUL bytes and overlong lines, a failed rotation, or a crafted timestamp no longer abort analysis; memory is bounded at 100,000 distinct patterns.
- ProcWatch keeps earlier samples when a later one fails, stops at zombie or dead states, labels thread and child caps as truncated, and reads the tightest cgroup limits up the hierarchy from the real cgroup2 mount.
- Incident Snapshot reads socket tables up to 16 MiB, truncates capped lists with totals instead of discarding sections, keeps IPv4 evidence on hosts without IPv6, reports only unconnected UDP sockets as bound, and counts processes whose `stat` could not be parsed.
- PortLens no longer fails outright when `ss` output exceeds 8 MiB: matches in the complete rows before the limit are reported with a warning, and no match exits 3 instead of claiming the port is unused.
- CertWatch inspects multiple targets within a 120-second overall limit; targets not started in time are reported as `SKIPPED` (not attempted), and targets still running at the limit are abandoned and reported as `ERROR` so the run ends on time.
- A temporary or non-recoverable resolver failure (`EAI_AGAIN`, `EAI_FAIL`) is now a resolver failure (exit 3 in NetDoctor, `ERROR` in HealthCtl) instead of an unreachable or failed-check finding; only "no such name" and "no address records" remain negative answers.
- PortLens no longer reports `NOT_FOUND` when an `ss` row could not be parsed and nothing else matched; it exits 3 because absence cannot be established.
- Name resolution is bounded: `opsforge.common.net.resolve_tcp` takes a `timeout` and abandons a hung lookup on a daemon thread. CertWatch waits 5 seconds and NetDoctor 10 (both fail with exit 3), and CertWatch warns when a resolver returns more than 16 addresses.
- ConfigDiff directory mode reports an entry it cannot read (permission denied) or that vanished during the walk as not examined (`INCOMPLETE`, exit 3 unless drift is found) instead of aborting the whole run; paths under it are not reported as added or removed.
- JSON output spells lone surrogates (undecodable filename bytes) as visible `\udcXX` text instead of emitting ill-formed strings.
- PortLens JSON adds a typed `owners` array next to the comma-joined `pid`, `user`, and related fields; ProcWatch `--brief` shows CPU and RSS; SvcDoctor shows `StateChangeTimestamp` and `ExecMainExitTimestamp`.
- Documentation corrections: CertWatch's validation record no longer claims no key is committed, SvcDoctor's privacy note lists only what it collects, HealthCtl documents the disk percentage formula and `SSL_CERT_FILE`/`SSL_CERT_DIR`, PortLens documents NSS lookups and unconnected-only UDP, and DiskHound notes that `--include-remote-mounts` can use the network.

### Changed

- Internal restructuring without behavior changes: CertWatch's `main` is split into option parsing, per-target inspection, and summary steps; HealthCtl parses each check type with its own small parser registered with that type's allowed fields; test-only PortLens helpers are removed; PortLens and SvcDoctor gain tests driven by real `ss`, `systemctl`, and `journalctl` output captured on Ubuntu 24.04.
- New states: SvcDoctor adds `LOAD-ERROR`, `RESTARTING`, `DEGRADED`, and `DEPENDENCY-FAILED` (exit 1); ConfigDiff adds `INCOMPLETE` (exit 3); CertWatch adds `CRITICAL`; HealthCtl adds `SKIPPED`. Conditions that previously looked healthy can now return a non-zero exit.
- LogHound JSON patterns carry a bounded `key` excerpt with `key_truncated`, `key_length`, and `key_digest` instead of the full line, and LogHound results that include truncated lines, removed NUL bytes, undated lines under a window, or pattern limits are `PARTIAL` (exit 1).
- CI workflows use least-privilege permissions, `persist-credentials: false`, and pinned build tooling; the release workflow runs the unit tests from the extracted sdist; Dependabot tracks GitHub Actions. Tests ship in the sdist but not the wheel.

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

- Final hardening anchors ConfigDiff directory traversal to descriptors, makes DiskHound's enumeration/work budget global, correlates ProcWatch auxiliary evidence to the sampled PID identity, and distinguishes unavailable SvcDoctor dependency observations from confirmed zero failures.
- NetDoctor labels IPv4 default-route context without claiming an unproven connection interface. LogHound merges rotated timestamps/minute counts before deriving rates and bursts. HealthCtl certificate checks share bounded resolver candidates and one TCP/TLS deadline. PortLens explicitly labels process enrichment as live and non-atomic.
- Pin GitHub Actions to immutable commits on Ubuntu 24.04; retain the Python 3.10–3.14 full-suite and wheel/sdist clean-install matrices. Reconcile the Beta gate with completed WSL validation and explicitly unvalidated environments.
- Correct exceptional subprocess cleanup when a helper exits before its descendants, close interrupted CertWatch connection sockets, and preserve unavailable Incident Snapshot service/IPv6-route evidence instead of reporting an empty success.
- Correct ConfigDiff normalized-match wording and HealthCtl critical/error counts; reject HTTP port zero/empty credentials and malformed severity values without changing the requested target or reporting an internal failure.

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
