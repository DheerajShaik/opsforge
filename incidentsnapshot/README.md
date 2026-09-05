# Incident Snapshot

Incident Snapshot is an experimental Linux diagnostic utility that captures a small, bounded set of low-sensitivity local host context during one read-only sequential pass. It answers: what observation timing, reduced platform metadata, uptime/load, aggregate memory capacity, and root-filesystem capacity were observable near the beginning of an incident?

It is context preservation, not a forensic collector, support bundle, monitor, health controller, or root-cause engine. Its output does not determine incident severity or prove that a host is healthy or unhealthy.

## Requirements

- Linux with procfs mounted at `/proc`
- Python 3
- standard library only
- no external commands or third-party packages

## Usage

```console
python3 incidentsnapshot/incidentsnapshot.py
python3 incidentsnapshot/incidentsnapshot.py --help
```

V1 accepts no positional arguments or options other than standard `-h`/`--help`. It has no configuration, environment-variable input, collector selection, target, threshold, timeout, or alternate output format.

The report goes to stdout. To preserve it, the caller may explicitly redirect stdout:

```console
python3 incidentsnapshot/incidentsnapshot.py > incident-snapshot.txt
```

Incident Snapshot does not create that file. Redirected output becomes caller-controlled persistent operational metadata; review its contents, permissions, sharing, and retention accordingly.

## Source allowlist and collected evidence

Collection consumes only UTC and monotonic clocks, one `os.uname()` call, `/proc/uptime`, `/proc/loadavg`, `/proc/meminfo`, and one `os.statvfs("/")` call. Running as root does not add sources or fields.

The fixed collectors are:

| Section | Evidence | Requirement |
| --- | --- | --- |
| Observation | UTC start/finish, monotonic elapsed duration, sequential-pass mode | Mandatory |
| Platform | `sysname`, kernel `release`, and `machine` from `os.uname()` | Mandatory |
| Runtime | Uptime and 1/5/15-minute load averages | Mandatory |
| Memory | `MemTotal`, `MemAvailable`, `SwapTotal`, and `SwapFree` | Best effort |
| Root filesystem | Total, used, caller-available, and capacity-used values for `/` | Best effort |

Platform deliberately ignores uname `nodename` and verbose `version`; no hostname field is emitted. Runtime ignores the idle token in `/proc/uptime` and the runnable/task and last-PID tokens in `/proc/loadavg`. Memory ignores all fields except the four listed above and does not synthesize a generic used-memory value.

Root capacity is scoped to `/` in the current mount namespace. Incident Snapshot does not enumerate mountpoints, devices, labels, UUIDs, filesystem types, or options. It distinguishes filesystem-free blocks from blocks available to the caller but does not interpret reserved capacity.

## Bounds

- `/proc/uptime`: 4 KiB
- `/proc/loadavg`: 4 KiB
- `/proc/meminfo`: 64 KiB and at most 256 nonblank records
- numeric integers: at most 20 ASCII digits
- uptime/load fractions: at most nine ASCII digits
- each consumed uname field: at most 256 Unicode code points
- calculated filesystem byte values: at most `2^127 - 1`

Procfs files are opened read-only and validated as regular objects after opening. Their content is read using a limit-plus-one strategy; procfs `st_size` is not treated as content length. Truncated prefixes are never parsed. NUL and non-ASCII procfs data are rejected.

There is intentionally no collection deadline, retry, watchdog, thread, worker process, polling, or second sample. The fixed operation count and input bounds constrain V1 work, but an unusual local kernel or filesystem operation can still block longer than expected. V1 cannot guarantee a hard timeout for a local syscall.

## Snapshot semantics

“Snapshot” means a deterministic report assembled from one fixed-order sequence of bounded local observations made between its displayed start and finish timestamps. Platform, Runtime, Memory, and Root filesystem are collected sequentially, once each. Elapsed duration comes from a monotonic clock rather than wall-clock subtraction.

This is not an atomic kernel snapshot, filesystem transaction, simultaneous or frozen system state, historical record, or complete incident record. Procfs and filesystem state can change during or immediately after collection, and independently read sections need not describe exactly the same instant.

## Output and partial evidence

Useful output always uses fixed `Observation`, `Platform`, `Runtime`, `Memory`, `Root filesystem`, `Collection warnings`, and `Interpretation limits` sections.

Successful sections say `Status: observed`. A best-effort section that cannot be trusted remains present with `Status: unavailable` and a stable reason. Zero is real evidence—zero swap or zero used bytes never means unavailable. If Memory parsing fails, no partial Memory values are printed; the same whole-section rule applies to Root filesystem.

Values use deterministic, locale-independent formatting. Bytes use IEC units and retain the exact byte count. Percentages have one decimal place. Uptime includes `d HH:MM:SS` plus seconds to two decimal places. Load averages have two decimal places. Externally derived strings are terminal-safe escaped; output has no color, ANSI styling, hyperlinks, width detection, or interaction.

## Exit codes and streams

| Code | Meaning |
| --- | --- |
| `0` | Help, or a complete snapshot with all mandatory and optional evidence observed. |
| `1` | Mandatory evidence produced a useful snapshot, but Memory and/or Root filesystem was unavailable. |
| `2` | Invalid invocation. |
| `3` | No trustworthy useful snapshot because the platform, mandatory observation, rendering, or internal execution failed. |
| `130` | Interrupted by SIGINT / Ctrl-C. |

Complete and useful-incomplete reports go to stdout. An incomplete report also emits `incidentsnapshot: snapshot incomplete; see Collection warnings` to stderr. Invocation and fatal errors go to stderr without a traceback. Interruption emits no intentional normal report.

## Security, privacy, and permissions

Incident Snapshot uses only the caller's permissions and never elevates privileges. It is read-only, subprocess-free, shell-free, local, offline, and non-persistent. It performs no DNS, TCP, UDP, ICMP, HTTP, TLS, telemetry, upload, analytics, update check, or other intentional network activity.

V1 does not inspect individual processes or enumerate PIDs. It collects no command names, arguments, environments, executable paths, users, IDs, or open files. It does not inspect sockets, interfaces, addresses, routes, DNS configuration, mounts, services, systemd units, logs, journal entries, configuration files, hostnames, machine/boot/DMI IDs, certificates, credentials, tokens, SSH material, shell history, cloud metadata, container runtimes, or Kubernetes data. Collection behavior does not consume environment variables as configuration, targets, enrichment, or evidence.

Kernel release, architecture, uptime, load, resource capacity, and timestamps remain potentially sensitive operational metadata. Review captured output before storing or sharing it.

## Relationship to other OpsForge utilities

Incident Snapshot does not replace focused diagnostics: PortLens inspects listening sockets; DiskHound ranks recursive allocation; CertWatch inspects remote TLS certificates; SvcDoctor reports systemd service evidence; LogHound analyzes logs; ProcWatch samples one process; ConfigDiff reports content drift; and NetDoctor diagnoses resolver/TCP establishment.

HealthCtl is the configured criterion controller. It accepts selected filesystem paths and free-space thresholds, can perform configured TCP checks, and reports `PASS`, `FAIL`, or `ERROR`. Incident Snapshot has no configuration, threshold, policy, network check, or health verdict. Its fixed root observation records capacity evidence only.

## Tests

Run from the repository root:

```console
python3 -m py_compile incidentsnapshot/incidentsnapshot.py
python3 -m unittest discover -s incidentsnapshot/tests -v
```

The deterministic suite uses injected clocks/readers/providers and requires no Internet, DNS, Docker, systemd, root, third-party package, or external service.

## V1 limitations and non-goals

V1 has no process inventory/count/state, command information, network inventory or probing, mount inventory, directory scan, inode or device diagnosis, systemd/service inspection, logs or journal, configuration reads/hashes/diffs, certificates, credentials, secrets, cloud/container/Kubernetes integration, support bundle, archive, persistence, compression, upload, telemetry, structured output, profiles, plugins, arbitrary commands, configurable collectors, retries, concurrency, sampling, deadline, watch mode, daemon, scheduling, thresholds, health/severity scoring, root-cause analysis, recommendations, remediation, or production-readiness claim.

Deferred features are not promises and should be considered only when concrete requirements justify expanding this privacy-minimized scope.
