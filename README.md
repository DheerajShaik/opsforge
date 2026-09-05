# OpsForge

OpsForge is an evolving open-source collection of practical Linux, DevOps, and Site Reliability Engineering (SRE) utilities intended to solve real operational problems.

The project begins with focused utilities. Useful tools may mature over time through implementation improvements, automated testing, failure-path coverage, real-world usage, community feedback, compatibility validation, security analysis, documentation, and relevant integrations.

OpsForge has completed its repository foundation and now includes experimental implementations of PortLens, DiskHound, CertWatch, SvcDoctor, LogHound, and ProcWatch.

## Why OpsForge

Operational troubleshooting often involves many small investigations across areas such as ports and sockets, disk usage, TLS certificates, systemd services, logs, processes, configuration drift, network connectivity, system health, and incident state.

OpsForge aims to grow as a set of focused operational utilities rather than one large monolithic application. Each utility should start with a narrow, useful problem and expand only when actual requirements justify doing so.

## Engineering philosophy

OpsForge is guided by these principles:

- Practical over theoretical.
- Working solutions over proof-of-concepts.
- Small initial scope over premature complexity.
- Diagnostic before destructive.
- Composable over monolithic.
- Predictable over clever.
- Minimal dependencies where practical.
- Automation-friendly.
- Safe by default.
- Testable.
- Extensible.
- Open-source friendly.

Especially:

- Independent by default.
- Composable when useful.
- Shared when justified.

These principles describe the intended engineering direction. They are not claims that the project has already reached maturity.

## Current status

OpsForge is in its early utility implementation stage.

- PortLens has an experimental first implementation in Phase 1.
- DiskHound has an experimental first implementation in Phase 2.
- CertWatch has an experimental first implementation in Phase 3.
- SvcDoctor has an experimental first implementation in Phase 4.
- LogHound has an experimental first implementation in Phase 5.
- ProcWatch has an experimental first implementation in Phase 6.
- The roadmap may evolve as the project learns from implementation and usage.
- Interfaces may evolve as utilities mature.
- Nothing in the repository currently represents a production-ready utility.

## Planned utilities

The following utilities are part of the initial roadmap. PortLens, DiskHound, CertWatch, SvcDoctor, LogHound, and ProcWatch are experimental; the remaining utilities are planned and not currently implemented.

| Utility | Status | Purpose |
| --- | --- | --- |
| [PortLens](portlens/README.md) | Experimental | Inspect TCP listening sockets matching a local Linux port and report available process metadata. |
| [DiskHound](diskhound/README.md) | Experimental | Rank a directory's eligible immediate entries by recursively observed allocated space with filesystem-capacity context. |
| [CertWatch](certwatch/README.md) | Experimental | Observe one remote TLS leaf certificate and assess its encoded validity period. |
| [SvcDoctor](svcdoctor/README.md) | Experimental | Report current systemd state and direct execution evidence for one local system service. |
| [LogHound](loghound/README.md) | Experimental | Summarize recurring normalized messages in one bounded local regular log file. |
| [ProcWatch](procwatch/README.md) | Experimental | Sample one local Linux process for bounded CPU, memory, and process-state evidence without declaring abnormality. |
| ConfigDiff | Planned | Detect Linux configuration drift. |
| NetDoctor | Planned | Provide structured network connectivity diagnostics. |
| HealthCtl | Planned | Future configurable host and service health-check capability whose design should emerge from proven requirements. |
| Incident Snapshot | Planned | Collect useful local Linux diagnostic information during incidents with strong security and privacy considerations. |

## Initial roadmap phases

This is an initial roadmap, not a fixed final scope. Existing tools may grow substantially, phases may change based on what is learned, and additional utilities may be introduced later.

1. Phase 0 — Repository Foundation
2. Phase 1 — PortLens
3. Phase 2 — DiskHound
4. Phase 3 — CertWatch
5. Phase 4 — SvcDoctor
6. Phase 5 — LogHound
7. Phase 6 — ProcWatch
8. Phase 7 — ConfigDiff
9. Phase 8 — NetDoctor
10. Phase 9 — HealthCtl
11. Phase 10 — Incident Snapshot

## Long-term direction

Mature OpsForge utilities may eventually operate in real operational environments where relevant, including Linux servers, virtual machines, systemd systems, containers, CI/CD pipelines, cloud environments, monitoring or observability systems, infrastructure automation, and incident-response workflows.

These are possible future environments, not current integrations or requirements. Supported Linux distributions and operational environments should be documented by each utility as implementation and testing provide evidence.

## Security and privacy

OpsForge utilities should favor least privilege where practical, diagnostic-first behavior, safe defaults, deliberate handling of sensitive information, and clear communication about limitations.

Locally executed utilities must not include hidden telemetry or unexpected outbound communication. Any future feature that communicates with an external system must be explicit, documented, deliberately invoked or configured by the user, and limited to what the feature requires.

Production readiness must be demonstrated through evidence rather than assumed. See [SECURITY.md](SECURITY.md) for the current security and privacy posture.

## Contributing

OpsForge is intended to support open-source community contribution while remaining practical and scoped. See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution expectations.

## License

OpsForge is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for the full license text.
