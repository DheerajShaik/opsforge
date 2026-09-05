# Changelog

Notable changes to OpsForge will be recorded here.

## Unreleased

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
