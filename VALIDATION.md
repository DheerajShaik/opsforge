# OpsForge v0.2.0-beta.1 candidate validation

Hardening validation updated on 2026-09-19 for PR #16, branch `feat/opsforge-v0.2`. This record separates executed tests from support policy and outstanding environments. It is not production certification or a formal security audit.

## Candidate and release gate

The hardening baseline is reviewed commit `96a61406b2350abe3cdbd0a655cc822cc0454cdc`. The final hardened runtime is commit `c6e8e0fa843b1bae502e700095c90811694670aa`. Its [release regression run](https://github.com/DheerajShaik/opsforge/actions/runs/35443737283) and all ten focused utility workflows passed. A later documentation-only commit may move the branch head without changing the tested runtime, tests, packaging configuration, or workflows.

The supported Beta platform is **CPython 3.10–3.14 on Ubuntu 24.04 LTS Linux**. Merge readiness requires the final-head five-version regression matrix, both wheel and sdist clean-install matrices, the completed WSL2 manual campaign plus targeted hardening revalidation, and final external merge review. No merge, tag, publication, or GitHub release is part of this task.

The user's completed WSL2 manual campaign reported functional PASS across all ten utilities, negative/error scenarios, output/symlink/security scenarios, bounded-scale/interruption behavior, and a privilege comparison, with no product discrepancy observed in that environment. Its stricter NO-GO statement depended on additional native-host and Kubernetes campaigns. Those campaigns are **unvalidated environments**, not failed tests and not additional Beta merge gates: Kubernetes is outside the claimed Beta contract. GitHub Actions supplies native Ubuntu coverage, without implying manual production-host certification.

The previous local record referenced `f3dc8775b4ad11e7ff3bc043a8217b43d70f3188`. A Git diff of all Python files between that commit and `96a61406...` is empty: the previously validated runtime matched the reviewed runtime. The new hardening changes require the regression and targeted revalidation below; the older manual results do not claim execution of the new code.

Changes listed under **Unreleased** in [CHANGELOG.md](CHANGELOG.md) postdate the records for the beta candidate below. Their local validation is recorded in the next section; hosted CI has not yet run on them, and the other CPython versions have not been exercised for them.

## Unreleased changes: local validation

Executed locally on Ubuntu 24.04 under WSL2 with CPython 3.12.3, OpenSSL 3.0.13, systemd 255 (PID 1), and `ss` 6.1.0:

- **Suites.** All eleven suites passed, 826 tests: `opsforge.common` 62, PortLens 57, DiskHound 70, CertWatch 99, SvcDoctor 113, LogHound 67, ProcWatch 50, ConfigDiff 52, NetDoctor 39, HealthCtl 117, Incident Snapshot 100. Many now use real data rather than fakes: captured `ss`, `systemctl`, `journalctl`, and `mountinfo` output; loopback TCP, HTTP, and TLS servers presenting throwaway certificates (valid, expired, not yet valid, wrong name; `opsforge/common/tests/tls_fixtures.py`); real process, thread, and zombie PIDs; and real directory trees.
- **Live runs as root in WSL2** (everything started was stopped and removed afterwards). A single CertWatch run against four `openssl s_server` processes with a private CA ranked `VALID`, `EXPIRED`, `NOT_YET_VALID`, and `WARNING` (wrong name) and exited 1; an unreachable target next to an expired one still exited 1, and next to a valid one exited 3 (`INCOMPLETE`); eight targets against a server that never answers the handshake finished in about 5.4 seconds, not 40. HealthCtl ran eleven mixed real checks (TLS certificates, TCP, DNS, PID 1, disk, file) with the expected per-check results and exit 1, exited 3 when nothing could be evaluated, and exited 130 at once on SIGINT during a slow check (the run lasted 1.0 seconds against a check bounded at 5). SvcDoctor read the real `systemd-resolved` unit through its alias with the real slice chain, exited 2 for a missing service, and exited 3 with a classified message in a PID namespace without systemd. PortLens without `ss` exited 3; LogHound exited 3 for a file `nobody` cannot read and 2 for a missing file; ConfigDiff exited 3 for an unwritable `--output`; DiskHound skipped the 9p `/mnt/c` mount; NetDoctor and CertWatch rejected `127.1` with exit 2.
- **Packaging.** An sdist and wheel built from a copy of the tree contain all 39 test modules in the sdist, none in the wheel, and a single top-level `opsforge` package; all ten console-script entry points ran `--help` from the extracted wheel alone. This was built offline with setuptools 68, which predates string licence metadata, so the licence fields were rewritten for that build only.

Not executed for these changes: CPython 3.10, 3.11, 3.13, and 3.14, hosted CI, native non-WSL hosts, and Kubernetes.

## Local environment

- Ubuntu 24.04.1 LTS under WSL2, x86_64
- Linux 6.18.33.2-microsoft-standard-WSL2
- CPython 3.12.3
- OpenSSL 3.0.13
- systemd 255.4; iproute2 `ss` 6.1.0

Only CPython 3.12 is installed locally. Other interpreter results must come from the hosted CI matrix.

## Deterministic regression coverage

The final suite has 519 tests, preserving all 451 baseline tests and adding 68 regressions. Local CPython 3.12.3 compilation of shared code, all ten utilities, and tests passed; all 519 tests passed with no failures or skips. Hosted Ubuntu 24.04 compilation and all 519 tests passed independently on CPython 3.10, 3.11, 3.12, 3.13, and 3.14, with no failures or skips.

| Hosted interpreter | Compilation | Tests | Wheel clean install | sdist clean install |
| --- | --- | ---: | --- | --- |
| CPython 3.10 | PASS | 519 | PASS | PASS |
| CPython 3.11 | PASS | 519 | PASS | PASS |
| CPython 3.12 | PASS | 519 | PASS | PASS |
| CPython 3.13 | PASS | 519 | PASS | PASS |
| CPython 3.14 | PASS | 519 | PASS | PASS |

| Suite | Tests |
| --- | ---: |
| Shared output | 10 |
| PortLens | 39 |
| DiskHound | 51 |
| CertWatch | 66 |
| SvcDoctor | 63 |
| LogHound | 49 |
| ProcWatch | 34 |
| ConfigDiff | 39 |
| NetDoctor | 34 |
| HealthCtl | 64 |
| Incident Snapshot | 70 |
| **Total** | **519** |

New regressions cover descriptor-relative ConfigDiff traversal and deterministic same-filesystem/symlink replacement; DiskHound global enumeration/visit budgets at 1 and 10 entries against 2,000 files; ProcWatch auxiliary start-tick identity changes before, after, and during collection; dependency command/format/count/state failures with JSON null-versus-empty distinctions; IPv4/IPv6/loopback route context; global rotated timestamp/minute aggregation and bounded overflow; certificate candidate caps, fallback, trust/hostname failures, numeric hosts, expiry thresholds, total deadlines, and interrupts; explicit PortLens enrichment limitations; exited-helper process-group cleanup; and Incident Snapshot unavailable evidence.

Shared regression coverage retains schema version 1, 16 MiB output limits, terminal sanitization, 0600 output creation, symlink/non-regular/hardlink rejection, force semantics, and subprocess interruption/timeout bounds. Runtime dependencies remain empty.

Final review also added regressions for accurate normalized ConfigDiff match wording, rejecting HTTP port zero/empty credentials and malformed severity, and counting HealthCtl errors once in human summaries.

## Targeted local integration

Executed on 2026-09-19 against the hardened runtime:

- ConfigDiff: equal nested trees with explicitly compared directory symlinks.
- DiskHound: 2,000-file fixture, `--max-entries 10`, exactly 10 visited entries, one global-limit failure, exit 1, 3,679-byte JSON output.
- ProcWatch: live validation process, stable initial/final auxiliary evidence.
- SvcDoctor: active `dbus.service` and observed dependencies; unavailable paths covered deterministically.
- NetDoctor: successful local loopback listener; connection interface null and IPv4 default-route context separate.
- LogHound: rotations eight hours apart produced a 28,801-second span; overlapping minute counts summed correctly.
- HealthCtl certificate candidate/deadline/trust paths: deterministic controlled socket/resolver tests.

No public endpoints were contacted during this pass. Historical CertWatch controlled/public validation is retained in `opsforge/certwatch/VALIDATION.md`; the new CertWatch change concerns interrupted socket/helper cleanup, not certificate interpretation.

## Packaging

Both `opsforge-0.2.0b1-py3-none-any.whl` and `opsforge-0.2.0b1.tar.gz` built successfully from the final runtime. Disposable local CPython 3.12 environments outside the source tree passed metadata/version, empty runtime dependencies, imports, all ten commands and `--help`, nine installed schema-version-1 JSON smoke checks, `pip check`, and removal of every console script after uninstall. The hosted matrix repeated those checks for both artifacts on every supported interpreter from 3.10 through 3.14.

The nine JSON smoke commands are DiskHound, LogHound, ConfigDiff, HealthCtl, ProcWatch, Incident Snapshot, PortLens, NetDoctor, and SvcDoctor. Hosted SvcDoctor packaging smoke uses controlled systemd helper output; the targeted local service check used real systemd. CertWatch receives help/import checks and deterministic TLS tests, not unsolicited public-network packaging smoke.

## Limitations and unvalidated environments

- Kubernetes/container orchestrators, other Linux distributions, alternative libc implementations, different namespace layouts, broad production filesystems, broad scale campaigns, and other systemd/OpenSSL/iproute2 versions are not claimed validated.
- Native non-WSL manual production-host testing remains unperformed. Native Ubuntu GitHub Actions is a separate automated validation surface.
- The earlier user-reported WSL privilege comparison does not establish general elevated-permission support; no new privilege escalation or elevated-permission campaign was performed.
- No formal penetration test, formal security audit, or broad production certification was performed.
- OS `getaddrinfo()` cannot be hard-cancelled. HTTP/certificate checks use one deadline across subsequent network operations; resolver time consumes that budget, but the resolver itself may overrun it.
- Certificate revocation is not checked. Portable intermediate expiry inspection and semantic TOML remain deferred under the Python 3.10/standard-library-only boundary.
- Filesystem, procfs, systemd, and socket evidence is live and non-atomic. PortLens explicitly cannot prove that later procfs metadata belongs to the exact process incarnation reported by `ss`.

These limits are not failed compatibility tests. The Beta gate above is the single release-readiness policy; no additional full manual campaign is requested.
