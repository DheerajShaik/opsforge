# Security Policy

## Current security posture

OpsForge is currently early-stage and in the repository foundation phase. No utilities currently exist, no stable interfaces have been defined, and no production-readiness claim is made.

Security practices will evolve alongside implementation maturity, testing, compatibility validation, documentation, and community review.

## Reporting vulnerabilities

A private vulnerability reporting mechanism has not yet been established for this project.

Please do not publish sensitive vulnerability details in public issues. A dedicated reporting mechanism should be established before security-sensitive or mature releases are made available.

## Privacy and telemetry

OpsForge utilities must not secretly transmit operational information to repository owners, maintainers, contributors, analytics systems, telemetry providers, or unrelated third parties.

External communication may be introduced only when:

- it is required by an explicit feature
- the behavior is documented
- the user deliberately invokes or configures it
- transmitted information is limited to what the feature requires

Hidden telemetry and unexpected outbound communication are not acceptable project behavior.

## Sensitive information

Future utilities may encounter sensitive operational information, including:

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

Utilities should minimize unnecessary collection, display, storage, and transmission of sensitive information.

## Least privilege

Utilities should operate without elevated privileges where practical. When permissions limit diagnostic detail, tools should explain that clearly rather than silently escalating privileges.

OpsForge utilities must not silently escalate privileges.

## Security evolution

Future project maturity may justify static analysis, dependency scanning, secret scanning, security testing, threat modeling, release verification, and community security review.

These mechanisms are not yet established and should be introduced when they provide concrete value.
