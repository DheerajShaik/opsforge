# OpsForge

OpsForge is an open-source collection of focused Linux diagnostics for practical DevOps and Site Reliability Engineering work. Each utility is independently invokable, diagnostic before destructive, safe by default, automation-friendly, and intentionally narrow.

OpsForge is currently in **Beta** (`0.2.0b1`): all ten utilities share one output contract and one status and exit-code policy, and they keep the v0.1 normal-invocation foundation.

Beta is not a production-readiness guarantee. Interfaces may still evolve before a stable release, observations remain subject to each utility's documented limits, and the project has not undergone a formal security audit or broad distribution certification.

## Utilities

| Utility | Command | Status | Purpose |
| --- | --- | --- | --- |
| [PortLens](opsforge/portlens/README.md) | `portlens` | Beta | Inspect bounded TCP/UDP listener scopes, ownership, and likely shared binds. |
| [DiskHound](opsforge/diskhound/README.md) | `diskhound` | Beta | Analyze bounded filesystem allocation, capacity, inodes, and file concentration. |
| [CertWatch](opsforge/certwatch/README.md) | `certwatch` | Beta | Separate TLS certificate validity, identity, trust, chain-count, and fingerprint evidence. |
| [SvcDoctor](opsforge/svcdoctor/README.md) | `svcdoctor` | Beta | Report bounded systemd state, execution, dependency, resource, and journal evidence. |
| [LogHound](opsforge/loghound/README.md) | `loghound` | Beta | Analyze recurring log patterns, severity, rates, bursts, stack evidence, and rotations. |
| [ProcWatch](opsforge/procwatch/README.md) | `procwatch` | Beta | Sample CPU, memory, I/O, FD, socket, thread, tree, and cgroup evidence. |
| [ConfigDiff](opsforge/configdiff/README.md) | `configdiff` | Beta | Compare files or bounded trees using exact, normalized, JSON-semantic, or metadata modes. |
| [NetDoctor](opsforge/netdoctor/README.md) | `netdoctor` | Beta | Explain targeted resolver, route, address-family, TCP, and optional TLS stages. |
| [HealthCtl](opsforge/healthctl/README.md) | `healthctl` | Beta | Evaluate strict, dependency-aware groups of bounded local and network criteria. |
| [Incident Snapshot](opsforge/incidentsnapshot/README.md) | `incident-snapshot` | Beta | Collect privacy-conscious basic, network, process, or full incident context. |

## Installation

The supported Beta installation path is an isolated local install from a trusted checkout using [pipx](https://pipx.pypa.io/):

```console
git clone https://github.com/DheerajShaik/opsforge.git
cd opsforge
pipx install .
```

This installs the default branch. To install a tagged state instead, run `git checkout <tag>` (for example `v0.2.0-beta.1`) before `pipx install .`. OpsForge is not published to PyPI as part of this Beta.

The install provides these independent commands:

```text
portlens           diskhound       certwatch
svcdoctor          loghound        procwatch
configdiff         netdoctor       healthctl
incident-snapshot
```

Run `<command> --help` for current syntax, then consult the linked utility README for semantics, exit codes, permissions, external activity, bounds, and limitations. Source-tree invocation with `python3 -m opsforge.<utility>.<utility>` (for example `python3 -m opsforge.portlens.portlens`) from the repository root remains available for contributors. Everything lives under the single `opsforge` package (`opsforge.common` holds the shared code), so installing it adds no generically named top-level modules.

Every command supports `--brief`, `--json`, `--quiet`, and safe `--output FILE`. Human output ends with a deterministic terminal-safe `Conclusion:` line. JSON schema version `1` contains `tool`, `status`, `target`, `observations`, `conclusion`, `next_action`, `warnings`, and `elapsed_seconds`. All rendered stdout and file output is capped at 16 MiB. Existing files are refused unless `--force` is explicit; symlinks, non-regular files, and multiply-linked overwrite targets are always refused.

## Status and exit codes

Every utility uses the same exit codes, defined once in `opsforge.common.status`:

| Exit | Meaning |
| --- | --- |
| 0 | The observation was trustworthy and found nothing to report. |
| 1 | A finding was established (or, for the observation-only utilities, the evidence was useful but incomplete). |
| 2 | Invalid invocation, or a target that does not exist or has the wrong type. |
| 3 | No trustworthy answer: a required tool or permission is missing, output was malformed or over its limit, a deadline passed, an internal error occurred, or the `--output` file could not be written. |
| 130 | Interrupted. |

Two rules keep the codes honest. An established finding decides the exit, even when other parts of the run could not be observed, so one unreachable target never hides an expired certificate elsewhere in the same run. And a gap with no finding is never reported as success: the verdict utilities (PortLens, CertWatch, SvcDoctor, NetDoctor, HealthCtl, ConfigDiff) exit 3, and most report `INCOMPLETE` or `ERROR`, while the observation-only utilities (DiskHound, LogHound, ProcWatch, Incident Snapshot), which report what they saw rather than a verdict, report `PARTIAL` and exit 1. Each utility keeps its own answer statuses (for example `FOUND`, `DRIFT`, `EXPIRED`, `CRITICAL`); see its README for the full list.

## Compatibility and support boundaries

### Supported for v0.2.0-beta.1

- CPython 3.10 through 3.14 on Ubuntu 24.04 LTS Linux.
- The standard-library-only runtime dependency model.
- Utility-specific Linux facilities and external tools described below.

Python 3.10 is the minimum because the existing implementation uses syntax introduced in Python 3.10. Python 3.15 and later are outside this Beta support policy until validated. The repository-wide release gate compiles and tests all ten utilities on CPython 3.10, 3.11, 3.12, 3.13, and 3.14.

### Validated environments

- The complete v0.2 pre-release suite and installed-command checks are recorded in [VALIDATION.md](VALIDATION.md).
- One GitHub Actions workflow compiles the code and runs every test suite on Ubuntu 24.04 with CPython 3.10 through 3.14 for each pull request and push to `main`, and builds the wheel and source distribution and installs each into a clean environment.
- [DiskHound's validation record](opsforge/diskhound/VALIDATION.md) documents automated and live WSL2 filesystem scenarios for its v0.1 behavior.
- [CertWatch's validation record](opsforge/certwatch/VALIDATION.md) documents Ubuntu 24.04, CPython 3.12–3.14, OpenSSL 3.0.13/3.5.5, controlled loopback validation, and the completed post-fix public-endpoint revalidation for its v0.1 behavior.
- SvcDoctor has no separate validation record; it was exercised with systemd 255.4 in the WSL2 campaign recorded in [VALIDATION.md](VALIDATION.md).

The complete Beta packaging and regression evidence is recorded in [VALIDATION.md](VALIDATION.md).

### May work but unvalidated

Kubernetes/container orchestrators, other Linux distributions, alternative libc implementations, different namespace layouts, and other systemd/iproute2/OpenSSL versions may work but are not claimed as validated for this Beta. Native Ubuntu 24.04 is exercised by GitHub Actions; manual validation is limited to WSL2 Ubuntu 24.04 and does not certify broad non-WSL production deployments. Python implementations other than CPython, Windows, and macOS are not supported execution platforms. NetDoctor and parts of HealthCtl use broadly available socket APIs, but the packaged project support policy remains Linux-only.

The Beta merge gate is final-head CPython 3.10–3.14 regression and wheel/sdist clean-install CI, completed WSL manual validation plus targeted hardening revalidation, and final external merge review. A separate Kubernetes or native production-host manual campaign is not a Beta merge requirement. See [VALIDATION.md](VALIDATION.md) for executed checks and honest limitations.

Utility requirements remain distinct:

- PortLens requires Linux procfs visibility and `ss` (normally from iproute2).
- DiskHound, LogHound, and ConfigDiff rely on Linux filesystem metadata and descriptor behavior.
- CertWatch deliberately connects to a caller-selected DNS/TCP/TLS endpoint and requires the system `openssl` executable with the documented `x509` options.
- SvcDoctor requires a local systemd system manager and `systemctl`.
- ProcWatch and Incident Snapshot require procfs mounted at `/proc`.
- NetDoctor uses OS resolution, local route/configuration reads, and caller-selected TCP/TLS connections.
- HealthCtl uses local filesystem/procfs/systemd APIs and performs only explicitly configured DNS, TCP, HTTP(S), or certificate connections.

## Engineering philosophy

- Practical over theoretical.
- Diagnostic before destructive.
- Independent and composable rather than monolithic.
- Predictable, bounded observation.
- Minimal dependencies where practical.
- Automation-friendly and safe by default.
- No hidden telemetry.
- Explicit network activity only where the selected utility requires it.

These principles guide the implementation; they do not override utility-specific interpretation limits or establish production readiness.

## Initial roadmap

The repository foundation and all ten planned utility phases are implemented. Future work is not part of this release and should be driven by concrete operational evidence rather than assumed scope.

1. Repository Foundation
2. PortLens
3. DiskHound
4. CertWatch
5. SvcDoctor
6. LogHound
7. ProcWatch
8. ConfigDiff
9. NetDoctor
10. HealthCtl
11. Incident Snapshot

## Security and privacy

OpsForge utilities do not include hidden telemetry, automatic uploads, background services, package-install hooks, privilege escalation, or remediation. CertWatch, NetDoctor, and configured HealthCtl TCP checks perform only their documented caller-initiated network activity. Other filesystem access can still cause ordinary OS or filesystem effects described by the relevant utility.

Diagnostic output can contain sensitive operational metadata. Review it before storing or sharing it. See [SECURITY.md](SECURITY.md) for the project policy and reporting guidance.

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and pull-request expectations. OpsForge is licensed under the Apache License 2.0; see [LICENSE](LICENSE).
