# OpsForge v0.2.0-beta.1 candidate validation

Hardening validation updated on 2026-09-19 for PR #16, branch `feat/opsforge-v0.2`. This record separates executed tests from support policy and outstanding environments. It is not production certification or a formal security audit.

## Candidate and release gate

The hardening baseline is reviewed commit `96a61406b2350abe3cdbd0a655cc822cc0454cdc`. The final hardening commit and its CI results will be recorded here after the required matrix completes; baseline CI is not evidence that a changed head passed.

The supported Beta platform is **CPython 3.10–3.14 on Ubuntu 24.04 LTS Linux**. Merge readiness requires the final-head five-version regression matrix, both wheel and sdist clean-install matrices, the completed WSL2 manual campaign plus targeted hardening revalidation, and final external merge review. No merge, tag, publication, or GitHub release is part of this task.

The user's completed WSL2 manual campaign reported functional PASS across all ten utilities, negative/error scenarios, output/symlink/security scenarios, bounded-scale/interruption behavior, and a privilege comparison, with no product discrepancy observed in that environment. Its stricter NO-GO statement depended on additional native-host and Kubernetes campaigns. Those campaigns are **unvalidated environments**, not failed tests and not additional Beta merge gates: Kubernetes is outside the claimed Beta contract. GitHub Actions supplies native Ubuntu coverage, without implying manual production-host certification.

The previous local record referenced `f3dc8775b4ad11e7ff3bc043a8217b43d70f3188`. A Git diff of all Python files between that commit and `96a61406...` is empty: the previously validated runtime matched the reviewed runtime. The new hardening changes require the regression and targeted revalidation below; the older manual results do not claim execution of the new code.

## Local environment

- Ubuntu 24.04.1 LTS under WSL2, x86_64
- Linux 6.18.33.2-microsoft-standard-WSL2
- CPython 3.12.3
- OpenSSL 3.0.13
- systemd 255.4; iproute2 `ss` 6.1.0

Only CPython 3.12 is installed locally. Other interpreter results must come from the hosted CI matrix.

## Deterministic regression coverage

The final suite has 516 tests, preserving all 451 baseline tests and adding 65 regressions. Local CPython 3.12.3 compilation of shared code, all ten utilities, and tests passed; all 516 tests passed with no failures or skips. CI on this hardening head is pending.

| Suite | Tests |
| --- | ---: |
| Shared output | 10 |
| PortLens | 39 |
| DiskHound | 51 |
| CertWatch | 66 |
| SvcDoctor | 63 |
| LogHound | 49 |
| ProcWatch | 34 |
| ConfigDiff | 38 |
| NetDoctor | 34 |
| HealthCtl | 62 |
| Incident Snapshot | 70 |
| **Total** | **516** |

New regressions cover descriptor-relative ConfigDiff traversal and deterministic same-filesystem/symlink replacement; DiskHound global enumeration/visit budgets at 1 and 10 entries against 2,000 files; ProcWatch auxiliary start-tick identity changes before, after, and during collection; dependency command/format/count/state failures with JSON null-versus-empty distinctions; IPv4/IPv6/loopback route context; global rotated timestamp/minute aggregation and bounded overflow; certificate candidate caps, fallback, trust/hostname failures, numeric hosts, expiry thresholds, total deadlines, and interrupts; explicit PortLens enrichment limitations; exited-helper process-group cleanup; and Incident Snapshot unavailable evidence.

Shared regression coverage retains schema version 1, 16 MiB output limits, terminal sanitization, 0600 output creation, symlink/non-regular/hardlink rejection, force semantics, and subprocess interruption/timeout bounds. Runtime dependencies remain empty.

## Targeted local integration

Executed on 2026-09-19 against the hardened runtime:

- ConfigDiff: equal nested trees with explicitly compared directory symlinks.
- DiskHound: 2,000-file fixture, `--max-entries 10`, exactly 10 visited entries, one global-limit failure, exit 1, 3,679-byte JSON output.
- ProcWatch: live validation process, stable initial/final auxiliary evidence.
- SvcDoctor: active `dbus.service` and observed dependencies; unavailable paths covered deterministically.
- NetDoctor: successful local loopback listener; connection interface null and IPv4 default-route context separate.
- LogHound: rotations eight hours apart produced a 28,801-second span; overlapping minute counts summed correctly.
- HealthCtl certificate candidate/deadline/trust paths: deterministic controlled socket/resolver tests.

No public endpoints were contacted during this pass. Historical CertWatch controlled/public validation is retained in `certwatch/VALIDATION.md`; the new CertWatch change concerns interrupted socket/helper cleanup, not certificate interpretation.

## Packaging

Both `opsforge-0.2.0b1-py3-none-any.whl` and `opsforge-0.2.0b1.tar.gz` built successfully. Disposable CPython 3.12 environments outside the source tree passed metadata/version, empty runtime dependencies, imports, all ten commands and `--help`, nine installed schema-version-1 JSON smoke checks, `pip check`, and removal of every console script after uninstall. Final artifact rebuild and hosted matrix results are recorded when completed.

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
