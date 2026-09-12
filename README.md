# OpsForge

OpsForge is an open-source collection of focused Linux diagnostics for practical DevOps and Site Reliability Engineering work. Each utility is independently invokable, diagnostic before destructive, safe by default, automation-friendly, and intentionally narrow.

OpsForge is currently in **Beta**. The initial ten-utility roadmap is implemented and has substantial automated and recorded real-world validation. The project is now focused on broader real-world usage, compatibility feedback, and release hardening.

Beta is not a production-readiness guarantee. Interfaces may still evolve before a stable release, observations remain subject to each utility's documented limits, and the project has not undergone a formal security audit or broad distribution certification.

## Utilities

| Utility | Command | Status | Purpose |
| --- | --- | --- | --- |
| [PortLens](portlens/README.md) | `portlens` | Beta | Inspect TCP listening sockets matching a local Linux port and report available process metadata. |
| [DiskHound](diskhound/README.md) | `diskhound` | Beta | Rank a directory's eligible immediate entries by recursively observed allocated space with filesystem-capacity context. |
| [CertWatch](certwatch/README.md) | `certwatch` | Beta | Observe one remote TLS leaf certificate and assess its encoded validity period. |
| [SvcDoctor](svcdoctor/README.md) | `svcdoctor` | Beta | Report current systemd state and direct execution evidence for one local system service. |
| [LogHound](loghound/README.md) | `loghound` | Beta | Summarize recurring normalized messages in one bounded local regular log file. |
| [ProcWatch](procwatch/README.md) | `procwatch` | Beta | Sample one local Linux process for bounded CPU, memory, and process-state evidence. |
| [ConfigDiff](configdiff/README.md) | `configdiff` | Beta | Compare one local regular file with an explicit baseline for exact byte-content drift. |
| [NetDoctor](netdoctor/README.md) | `netdoctor` | Beta | Report OS resolver candidates and TCP connection-establishment evidence for one endpoint. |
| [HealthCtl](healthctl/README.md) | `healthctl` | Beta | Evaluate a bounded JSON-configured set of filesystem free-space and TCP connection criteria. |
| [Incident Snapshot](incidentsnapshot/README.md) | `incident-snapshot` | Beta | Capture bounded local Linux platform, runtime, memory, and root-filesystem context. |

## Installation

The supported Beta installation path is an isolated local install from a trusted checkout using [pipx](https://pipx.pypa.io/):

```console
git clone https://github.com/DheerajShaik/opsforge.git
cd opsforge
git checkout v0.1.0-beta.1
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

Run `<command> --help` for its frozen Beta invocation syntax, then consult the linked utility README for semantics, exit codes, permissions, external activity, and limitations. Source-tree invocation with `python3 utility/utility.py` remains available for contributors and behaves the same as the installed entry point.

## Compatibility and support boundaries

### Supported for v0.1.0-beta.1

- CPython 3.10 through 3.14 on Ubuntu 24.04 LTS Linux.
- The standard-library-only runtime dependency model.
- Utility-specific Linux facilities and external tools described below.

Python 3.10 is the minimum because the existing implementation uses syntax introduced in Python 3.10. Python 3.15 and later are outside this Beta support policy until validated. The repository-wide release gate compiles and tests all ten utilities on CPython 3.10, 3.11, 3.12, 3.13, and 3.14.

### Validated environments

- The complete pre-release suite and installed-command checks were run on Ubuntu 24.04.1 LTS under WSL2 with CPython 3.12.3.
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
- NetDoctor uses OS resolution and caller-selected TCP connections.
- HealthCtl uses filesystem-capacity APIs and, only for configured TCP checks, OS resolution and caller-selected TCP connections.

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
