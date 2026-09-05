# Changelog

Notable changes to OpsForge will be recorded here.

## Unreleased

- Added experimental ProcWatch V1 for two-sample observation of one local Linux process, with bounded procfs reads, CPU and memory delta evidence, conservative identity handling, deterministic tests, documentation, and CI.

- Added experimental LogHound V1 for bounded recurrence analysis of one local regular log file, with conservative timestamp normalization, terminal-safe output, deterministic tests, documentation, and CI.

- Added experimental CertWatch v0.1 for bounded, one-target TLS leaf-certificate observation, identity-field reporting, encoded validity/expiration assessment, and deterministic tests, documentation, and CI.

- Added the experimental SvcDoctor v0.1 implementation for reporting structured state and raw execution evidence for one local systemd service, with deterministic diagnostics, bounded observation, documentation, and tests.
- Added the experimental DiskHound v0.1 implementation with same-device metadata traversal, allocated-block accounting, deterministic diagnostics, documentation, tests, and minimal CI.
- Added the experimental initial PortLens implementation for inspecting local TCP listening sockets, with best-effort process enrichment, tests, and minimal CI.
- Established the initial repository foundation documentation, license, and repository hygiene files.
