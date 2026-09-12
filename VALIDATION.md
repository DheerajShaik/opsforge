# OpsForge v0.1.0-beta.1 release validation

Validation recorded on 2026-09-12. This record covers release-regression and packaging work; it does not replace the utility-specific interpretation limits or claim production readiness.

## Local environment

- Ubuntu 24.04.1 LTS under WSL2
- Linux kernel 6.18.33.2-microsoft-standard-WSL2, x86_64
- CPython 3.12.3
- OpenSSL 3.0.13
- `ss` and `systemctl` available; the systemd system manager was running

This is the locally validated environment, not a claim of universal Linux, WSL, distribution, kernel, systemd, OpenSSL, or Python compatibility.

## Automated regression result

All ten modules compiled with `python3 -m py_compile`. Each existing suite then passed with `python3 -m unittest discover -s UTILITY/tests -q`:

| Utility | Tests |
| --- | ---: |
| PortLens | 28 |
| DiskHound | 44 |
| CertWatch | 56 |
| SvcDoctor | 48 |
| LogHound | 36 |
| ProcWatch | 27 |
| ConfigDiff | 27 |
| NetDoctor | 28 |
| HealthCtl | 41 |
| Incident Snapshot | 59 |
| **Total** | **394** |

No utility implementation was changed for this release transition.

## Distribution and clean-install result

`python -m build` successfully produced:

- `opsforge-0.1.0b1.tar.gz`
- `opsforge-0.1.0b1-py3-none-any.whl`

The wheel was installed with `pip install --no-deps` into a fresh virtual environment from outside the source tree. Metadata resolved as `opsforge 0.1.0b1`, with no runtime dependencies. All ten expected commands were present, and every installed `--help` invocation exited `0`.

Representative installed invocations also reached the existing implementations with their documented status semantics:

| Command | Scenario | Exit |
| --- | --- | ---: |
| `portlens` | no listener observed on selected local port | 1 |
| `diskhound` | bounded temporary directory scan | 0 |
| `certwatch` | `example.com:443` certificate observation | 0 |
| `svcdoctor` | active local `dbus.service` observation | 0 |
| `loghound` | two-line recurring-message sample | 0 |
| `procwatch` | two-sample observation of PID 1 | 0 |
| `configdiff` | identical temporary files | 0 |
| `netdoctor` | refused local TCP endpoint | 1 |
| `healthctl` | configured root free-space threshold of zero | 0 |
| `incident-snapshot` | complete local snapshot | 0 |

The clean environment then uninstalled `opsforge` successfully and removed its console scripts.

The local WSL image lacks Ubuntu's `python3.12-venv`/`ensurepip` package, so local `pipx install .` could not create its own managed environment without unavailable administrator access. The artifact itself was therefore validated through an equivalent clean virtual-environment installation. The repository-wide GitHub Actions package job exercises ordinary `venv` creation, wheel installation, all entry points, representative invocations, and uninstallation on a Python image with the required packaging prerequisites.

## CertWatch post-fix evidence

The previously pending real-world WSL revalidation completed at 2026-09-12T12:45:00Z. CertWatch successfully observed and decoded the public `example.com:443` leaf certificate using Python 3.12.3 and OpenSSL 3.0.13, including the SAN output shape that motivated the parser hardening. It exited `0` because the encoded validity period was current and outside the configured warning window. CA trust and hostname identity were not assessed.

Further details and historical environments remain in [certwatch/VALIDATION.md](certwatch/VALIDATION.md) and [diskhound/VALIDATION.md](diskhound/VALIDATION.md).
