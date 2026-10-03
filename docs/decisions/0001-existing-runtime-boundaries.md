# ADR 0001: Existing runtime and diagnostic boundaries

Status: descriptive baseline of existing policy
Recorded: 2026-10-03

## Context

OpsForge exposes ten independently invokable Linux diagnostic commands. This record
collects the rationale visible in existing project documentation; it does not claim
a new approval, a historical decision date, or a change in release readiness.

## Existing design

- Keep utilities focused and independently understandable. Share behavior where
  duplication justifies it; output, statuses/exits, network handling, and bounded
  helper behavior now live together in `opsforge.common`.
- Use the Python standard library at runtime. Build dependencies are declared separately.
- Diagnose before destructive action; bound collection and make external activity explicit.
- Preserve useful partial evidence and state limitations rather than fabricating success.

## Consequences and tradeoffs

Installation has no third-party runtime dependency graph. Implementations must work
within the documented interpreter range and platform facilities. Some capabilities
remain deferred: ConfigDiff's semantic TOML mode would need a parser on Python 3.10;
portable intermediate-certificate expiry inspection lacks a consistent public API
across the supported Python range. Tools cannot promise universal cancellation of
OS DNS resolution or local syscalls. Shared resolver waiting is bounded, but the
underlying OS lookup can outlive that wait on a daemon thread.

## Alternatives and future changes

A third-party runtime parser, a shared execution framework, or automatic remediation
would change these boundaries. Evaluate such changes against a concrete requirement,
compatibility, operational safety, and maintenance cost; record a new decision if adopted.

## Evidence

- [Project philosophy and contribution expectations](../../CONTRIBUTING.md)
- [Runtime and interpreter declarations](../../pyproject.toml)
- [Security policy](../../SECURITY.md)
- [ConfigDiff limitations](../../opsforge/configdiff/README.md)
- [CertWatch limitations](../../opsforge/certwatch/README.md)
