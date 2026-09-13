# Security Policy

## Current security posture

OpsForge v0.2.0-beta.1 contains Beta implementations of PortLens, DiskHound, CertWatch, SvcDoctor, LogHound, ProcWatch, ConfigDiff, NetDoctor, HealthCtl, and Incident Snapshot. The expanded roadmap is implemented for independent review, but Beta is not a production-readiness guarantee.

Security validation and compatibility work remain ongoing. The repository does not claim a formal security audit, certification, penetration test, production hardening, or vulnerability-free status.

## Reporting vulnerabilities

A private vulnerability reporting mechanism has not yet been established for this project.

Please do not publish sensitive vulnerability details in public issues. A dedicated reporting mechanism should be established before security-sensitive or mature releases are made available.

## Privacy and telemetry

OpsForge utilities must not secretly transmit operational information to repository owners, maintainers, contributors, analytics systems, telemetry providers, or unrelated third parties.

External communication is acceptable only when:

- it is required by an explicit feature
- the behavior is documented
- the user deliberately invokes or configures it
- transmitted information is limited to what the feature requires

Hidden telemetry and unexpected outbound communication are not acceptable project behavior.

Some utilities intentionally perform network activity because it is their explicit diagnostic purpose:

- CertWatch connects to a caller-selected DNS/TCP/TLS endpoint.
- NetDoctor resolves and connects to a caller-selected TCP target.
- HealthCtl performs only caller-configured DNS, TCP, HTTP(S), and certificate checks.

This activity must remain deliberate, bounded, and documented. These utilities are not offline tools, and their network behavior must not expand silently.

## Sensitive information

Utilities may encounter sensitive operational information, including:

- hostnames
- usernames
- IP addresses
- process information
- command-line arguments
- environment variables
- filesystem paths
- logs
- configuration
- certificates
- credentials
- tokens
- incident information

Utilities should minimize unnecessary collection, display, storage, and transmission of sensitive information. Diagnostic output can contain operational metadata and should be stored, shared, and published with appropriate care.

The shared `--output` path creates private regular files and requires `--force` before replacing one. Even with `--force`, final-component symlinks, non-regular files, and multiply-linked files are rejected. Explicit ConfigDiff `--unified` output can reveal configuration values and prints a warning. Incident Snapshot never collects full command lines, environments, arbitrary logs, or home-directory content.

## Least privilege

Utilities should operate without elevated privileges where practical. When permissions limit diagnostic detail, tools should explain that clearly rather than silently escalating privileges.

OpsForge utilities must not silently escalate privileges.

## Security evolution

Project maturity may justify static analysis, dependency scanning, secret scanning, security testing, threat modeling, release verification, and community security review.

These mechanisms are not yet established and should be introduced when they provide concrete value.

## Packaging and installation

The Python package has no third-party runtime dependencies, install-time hooks, custom build commands, or executable setup script. Building and installing the package imports no utility module and performs no network request, telemetry, upload, system inspection, persistence, privilege escalation, or shell command.

The documented `pipx install .` workflow may contact the Python package index to obtain ordinary build tooling in pipx's isolated build environment. That package-management traffic belongs to pip/pipx, not to OpsForge runtime behavior. Install only from a trusted checkout or reviewed distribution artifact.
