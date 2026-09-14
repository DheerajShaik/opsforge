# OpsForge

OpsForge is an open-source collection of focused Linux diagnostics for practical DevOps and Site Reliability Engineering work. Each utility is independently invokable, diagnostic before destructive, safe by default, automation-friendly, and intentionally narrow.

OpsForge is currently in **Beta**. This branch is the `v0.2.0-beta.1` candidate: it expands all ten utilities and introduces one coherent output contract while retaining the v0.1 normal-invocation foundation.

Beta is not a production-readiness guarantee. Interfaces may still evolve before a stable release, observations remain subject to each utility's documented limits, and the project has not undergone a formal security audit or broad distribution certification.

## Utilities

| Utility | Command | Status | Purpose |
| --- | --- | --- | --- |
| [PortLens](portlens/README.md) | `portlens` | Beta | Inspect bounded TCP/UDP listener scopes, ownership, and likely shared binds. |
| [DiskHound](diskhound/README.md) | `diskhound` | Beta | Analyze bounded filesystem allocation, capacity, inodes, and file concentration. |
| [CertWatch](certwatch/README.md) | `certwatch` | Beta | Separate TLS certificate validity, identity, trust, chain-count, and fingerprint evidence. |
| [SvcDoctor](svcdoctor/README.md) | `svcdoctor` | Beta | Report bounded systemd state, execution, dependency, resource, and journal evidence. |
| [LogHound](loghound/README.md) | `loghound` | Beta | Analyze recurring log patterns, severity, rates, bursts, stack evidence, and rotations. |
| [ProcWatch](procwatch/README.md) | `procwatch` | Beta | Sample CPU, memory, I/O, FD, socket, thread, tree, and cgroup evidence. |
| [ConfigDiff](configdiff/README.md) | `configdiff` | Beta | Compare files or bounded trees using exact, normalized, JSON-semantic, or metadata modes. |
| [NetDoctor](netdoctor/README.md) | `netdoctor` | Beta | Explain targeted resolver, route, address-family, TCP, and optional TLS stages. |
| [HealthCtl](healthctl/README.md) | `healthctl` | Beta | Evaluate strict, dependency-aware groups of bounded local and network criteria. |
| [Incident Snapshot](incidentsnapshot/README.md) | `incident-snapshot` | Beta | Collect privacy-conscious basic, network, process, or full incident context. |

## Installation

The supported Beta installation path is an isolated local install from a trusted checkout using [pipx](https://pipx.pypa.io/):

```console
git clone https://github.com/DheerajShaik/opsforge.git
cd opsforge
git checkout feat/opsforge-v0.2
pipx install .
```

Before the tag exists, use the reviewed release branch or commit instead of the tag. OpsForge is not published to PyPI as part of this Beta preparation.

The install provides these independent commands:

```text
portlens           diskhound       certwatch
svcdoctor          loghound        procwatch
configdiff         netdoctor       healthctl
incident-snapshot
```

Run `<command> --help` for current syntax, then consult the linked utility README for semantics, exit codes, permissions, external activity, bounds, and limitations. Source-tree invocation with `PYTHONPATH=. python3 utility/utility.py` remains available for contributors.

Every command supports `--brief`, `--json`, `--quiet`, and safe `--output FILE`. Human output ends with a deterministic terminal-safe `Conclusion:` line. JSON schema version `1` contains `tool`, `status`, `target`, `observations`, `conclusion`, `next_action`, `warnings`, and `elapsed_seconds`. All rendered stdout and file output is capped at 16 MiB. Existing files are refused unless `--force` is explicit; symlinks, non-regular files, and multiply-linked overwrite targets are always refused.

## Compatibility and support boundaries

### Supported for v0.2.0-beta.1

- CPython 3.10 through 3.14 on Ubuntu 24.04 LTS Linux.
- The standard-library-only runtime dependency model.
- Utility-specific Linux facilities and external tools described below.

Python 3.10 is the minimum because the existing implementation uses syntax introduced in Python 3.10. Python 3.15 and later are outside this Beta support policy until validated. The repository-wide release gate compiles and tests all ten utilities on CPython 3.10, 3.11, 3.12, 3.13, and 3.14.

### Validated environments

- The complete v0.2 pre-release suite and installed-command checks are recorded in [VALIDATION.md](VALIDATION.md).
- Existing focused GitHub Actions run on Ubuntu Linux; the Beta release workflow adds explicit CPython 3.10–3.14 coverage.
- [DiskHound's validation record](diskhound/VALIDATION.md) documents automated and live WSL2 filesystem scenarios.
- [CertWatch's validation record](certwatch/VALIDATION.md) documents Ubuntu 24.04, CPython 3.12–3.14, OpenSSL 3.0.13/3.5.5, controlled loopback validation, and the completed post-fix public-endpoint revalidation.
- SvcDoctor records empirical Ubuntu validation with systemd 255.4 in its utility documentation.

The complete Beta packaging and regression evidence is recorded in [VALIDATION.md](VALIDATION.md).

### May work but unvalidated

Other Linux distributions, non-WSL deployments, other systemd/iproute2/OpenSSL versions, alternative libc implementations, and Python implementations other than CPython may work but are not claimed as supported or validated for this Beta. Windows and macOS are not supported execution platforms. NetDoctor and parts of HealthCtl use broadly available socket APIs, but the packaged project support policy remains Linux-only.

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
