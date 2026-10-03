# OpsForge architecture

This describes the current repository, not a proposed AI service or execution framework.
See the [root README](../README.md) for the supported platform and utility catalog.

## Repository map

All installed modules live under the single `opsforge` package.

| Location | Responsibility |
| --- | --- |
| `opsforge/<utility>/<utility>.py` | Each of the ten diagnostic implementations |
| `opsforge/<utility>/README.md` and `tests/` | Utility semantics and unittest coverage |
| `opsforge/common/output.py` | JSON envelope, representation flags, conclusions, bounded rendering, safe file output |
| `opsforge/common/status.py` | Shared exit constants and common status names |
| `opsforge/common/net.py` | Strict host/SNI grammar, bounded resolver waiting, candidates, TCP connection loop |
| `opsforge/common/process.py` | Trusted helper lookup, bounded subprocess execution and cleanup |
| `opsforge/common/fs.py`, `procfs.py`, `systemd.py`, `text.py` | Shared filesystem, procfs, systemd, and terminal-text helpers |
| `opsforge/common/tests/` | Shared behavior tests plus controlled loopback/TLS fixtures |
| `pyproject.toml` | Package metadata, supported Python range, explicit packages, ten console entry points |
| `MANIFEST.in` | Source-distribution documentation and test inventory |
| `.github/workflows/release-regression.yml` | One full-suite and wheel/sdist validation workflow across supported interpreters |
| `.agents/skills/opsforge-pr-review/` | Reusable development review workflow; not a runtime component |

The utility directories are `portlens`, `diskhound`, `certwatch`, `svcdoctor`,
`loghound`, `procwatch`, `configdiff`, `netdoctor`, `healthctl`, and `incidentsnapshot`.

## Execution path

An installed command enters `opsforge.<utility>.<utility>:main`. The naming exception
is the command `incident-snapshot`, which enters
`opsforge.incidentsnapshot.incidentsnapshot:main`. From a checkout, use module
invocation, for example `python -m opsforge.configdiff.configdiff --help`.

Each implementation validates arguments and bounds, collects evidence, interprets
it using the shared status/exit policy, and constructs an `OutputRecord`. The shared
renderer emits the selected representation. Failures before a record exists can
emit only stderr and an error exit. See [CONTRACTS.md](CONTRACTS.md).

Utilities share networking and helper machinery without becoming one monolithic
command. CertWatch uses explicit endpoints and OpenSSL; SvcDoctor uses systemd helpers;
ProcWatch uses procfs. Consult the utility READMEs for exact requirements.
No background daemon, model API, or telemetry service is required by these commands.

HealthCtl schedules a fixed vocabulary of checks from strict JSON configuration on
bounded daemon workers as dependencies become ready. It is not an arbitrary command
runner. CertWatch also bounds concurrent target inspection. Incident Snapshot collects
allowlisted local evidence under explicit profiles, not an unrestricted support bundle.

## Boundaries that matter when changing code

- Separate evidence from what it establishes: connection success is not application
  readiness, and observed service state is not root cause.
- Shared output, status, networking, and helper changes affect multiple utilities;
  run the common suite and all consumers' suites using CONTRIBUTING.md.
- Runtime dependencies remain empty. Build tooling is separate from runtime imports.
  See [ADR 0001](decisions/0001-existing-runtime-boundaries.md).
- Filesystems, processes, sockets, and service state are live, non-atomic inputs.
  Identity checks and partial/unavailable evidence are part of correctness.
- Follow [SECURITY.md](../SECURITY.md) for explicit network activity, sensitive data,
  file protections, trusted executable lookup, privileges, and helper lifecycle.

## Where changes belong

Add utility behavior and regressions in `opsforge/<utility>/`. Use existing common
helpers for shared behavior rather than copying policies into tools. Packaging
changes belong in `pyproject.toml`, `MANIFEST.in`, and the release workflow as needed.
The sdist includes tests; wheel package-data rules exclude them.

For substantial work use [PLANS.md](PLANS.md); record lasting choices in
[decisions](decisions/README.md). Repeatable checks live in
[CONTRIBUTING.md](../CONTRIBUTING.md); dated evidence is in [VALIDATION.md](../VALIDATION.md).
