# Incident Snapshot

Incident Snapshot collects a bounded, privacy-conscious operational snapshot useful at the beginning of a Linux incident. The default `basic` profile preserves the v0.1 invocation and avoids process/network/service enumeration.

## Usage and profiles

```console
incident-snapshot
incident-snapshot --profile network
incident-snapshot --profile process --top 10
incident-snapshot --profile full --json --output incident.json
```

Profiles are:

- `basic` (default): reduced platform/kernel release/machine, uptime, load averages, visible CPU count, memory/swap, and root-filesystem capacity.
- `network`: basic plus up to 128 interface names/state/MTU, bounded IPv4/IPv6 default routes/gateways, and up to 512 de-duplicated TCP listener/UDP bound-port summaries. Socket addresses are reduced to bind scope; no owning process is joined.
- `process`: basic plus top CPU-tick-since-start and RSS summaries. `--top` is 1-20 (default 5); at most 32,768 procfs PIDs are considered.
- `full`: every preceding section plus Linux PSI for CPU/memory/I/O, root inode use, up to 64 failed service names, and selected non-content kernel scheduler/taint counters.

Every optional section has `observed`, `unavailable`, or `error` evidence. Collection continues across optional gaps and prints ordered warnings.

## Bounds, privacy, and activity

Procfs/sysfs allowlisted files are byte-bounded and opened without following final symlinks. Route/socket tables are capped at 128 KiB. The failed-service query is shell-free, capped at 64 KiB, and has a three-second timeout. The tool performs no network traffic and never elevates privilege.

It never reads complete process command lines, environments, arbitrary logs/journal, home-directory content, shell history, SSH material, credentials, tokens, entire `/etc`, hostnames, or machine/boot identifiers. Process names/PIDs, interface names, gateway addresses, service names, ports, cgroups, and resource values are still operationally sensitive; review before sharing.

## Output and exits

Status is `OK` for complete requested collection or `WARN` for a partial snapshot. Exit 0 means all requested sections were observed, 1 means useful partial evidence, 2 means invalid invocation, 3 means mandatory observation/internal/output failure or unsupported platform, and 130 means interrupted.

Human output includes elapsed collection time, per-section state, interpretation limits, and the standard conclusion. `--brief`, schema-version-1 `--json`, `--quiet`, safe `--output FILE`, and `--force` follow the shared contract. With `--quiet`, ordinary stdout and partial-warning stderr are suppressed; an output file is still written when requested.

## Requirements and limitations

Linux with procfs is required; sysfs, PSI, cgroup/systemd visibility depend on the environment. The snapshot is sequential rather than atomic, and local syscalls do not have universal hard cancellation. CPU ranking uses lifetime ticks rather than instantaneous CPU rate. Root capacity/inodes cover only `/` in the current mount namespace. Evidence does not determine severity, application health, root cause, or remediation, and no archive/upload/support bundle is created.
