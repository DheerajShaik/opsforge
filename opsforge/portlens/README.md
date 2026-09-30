# PortLens

PortLens is a read-only Linux diagnostic for local TCP listeners and UDP sockets in the current network namespace. It helps answer what is bound, where it is exposed, and which visible process owns it; it is not a remote scanner and does not prove that an unmatched port is bindable.

## Usage

```console
portlens PORT
portlens START-END [--udp] [--ipv4 | --ipv6]
portlens --all [--pid PID] [--process NAME]
portlens 8080 --watch 5 --watch-interval 1
```

Supply exactly one port/range or `--all`. Ports are 1-65535. `--pid` accepts 1-2147483647; `--process` is an exact printable name of at most 128 characters, matched against each owner's process name or executable basename; names longer than 15 bytes also match the kernel-truncated process name. Watch count is 1-100 and interval is 0.1-60 seconds; default execution is one snapshot. `--watch-interval` defaults to one second.

## Evidence and interpretation

PortLens calls `ss` separately for each selected IPv4/IPv6 family; `--ipv4` also queries IPv6 and keeps IPv6 rows that accept IPv4 (the dual-stack `*` wildcard and IPv4-mapped addresses). The command is shell-free, runs with a minimal environment, has a 30-second deadline, and bounds each stdout/stderr stream to 8 MiB. If `ss` output exceeds 8 MiB, the complete rows before the limit are still used: a match is reported with a warning that more matching sockets may exist, and no match exits 3 because absence cannot be established. Unparseable `ss` rows are skipped with a warning instead of failing the run. Rows report protocol, state, family, local address/port, bound interface (JSON `interface`), bind scope, and best-effort PID, numeric UID, username, process name, executable basename, process FD count, socket FD, and cgroup v2 path.

Wildcard binds mean all local interfaces visible in this namespace; loopback binds are local-only. Link-local binds and binds restricted to one interface (shown as `ADDRESS%IFNAME`) are labeled as such, and IPv4-mapped addresses are classified by their IPv4 address. Multiple rows for the same protocol/family/address/interface/port are reported as a likely shared/reused bind group, counted before `--pid`/`--process` filtering. This can reflect `SO_REUSEPORT`, multiple owners, or duplicate kernel reporting and is not proof of a conflict.

Owners are found by matching each row's socket inode, as reported by `ss -e`, against the `/proc/PID/fd` links of visible processes; `ss` process-name text is never used. Rows without an inode are left without an owner, with a warning. Procfs enrichment is live, non-atomic, best-effort, and permission-dependent, as stated in human output and the JSON `process_enrichment` field. A later `/proc/PID` read may refer to another process if the PID has been reused; the enrichment is not proof of atomic ownership. PortLens never reads process command lines or environments. In JSON, each observation keeps the historical comma-joined `pid`, `user`, and related fields and also carries an `owners` array with one typed entry per owning process (`pid`, `socket_file_descriptor`, `uid`, `user`, `process`, `executable`, `file_descriptor_count`, `cgroup`; `null` when unavailable).

## Output and exit codes

All human output ends with `Conclusion: [STATUS] TARGET — finding. Next: action.` Status is `FOUND` or `NOT_FOUND`.

| Exit | Meaning |
| --- | --- |
| 0 | A match was observed (`FOUND`). |
| 1 | No match (`NOT_FOUND`). |
| 2 | Invalid invocation. |
| 3 | No trustworthy answer: `ss` missing, failing, or malformed, `ss` output over the limit or rows that could not be parsed with no match, an internal failure, or an `--output` failure. |
| 130 | Interrupted. |

With `--watch`, human output shows every snapshot, `FOUND` and exit 0 mean at least one snapshot matched, and socket and shared-bind counts come from the latest matching snapshot (or the last snapshot if none matched); JSON `snapshots_with_matches` counts matching snapshots alongside the per-snapshot `snapshots` list.

`--brief` emits essential counts, `--json` emits the suite schema-version-1 envelope, and `--quiet` suppresses ordinary stdout. `--output FILE` writes that selected representation. Existing files require `--force`; symlink, non-regular, and multiply-linked targets are refused. Output is capped at 16 MiB.

## Requirements, privacy, and examples

Linux, procfs, and `ss` (normally iproute2) are required; `ss` is used only from an absolute `PATH` directory where both the directory and the executable are modifiable only by root or the caller. Extra procfs permissions may improve owner attribution and metadata; PortLens never elevates privilege and sends no packets of its own, but resolving owner user names uses the system's name service (NSS), which may consult a network directory such as LDAP. `--udp` lists unconnected UDP sockets only (`ss -lu`); connected UDP sockets bound to the port are not shown.

```console
portlens 53 --udp --ipv4 --brief
portlens --all --process nginx --json
```

Results cover only one namespace and instant(s) in time. They do not establish firewall reachability, application health, port availability, root cause, or remediation.
