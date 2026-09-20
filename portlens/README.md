# PortLens

PortLens is a read-only Linux diagnostic for local TCP listeners and UDP sockets in the current network namespace. It helps answer what is bound, where it is exposed, and which visible process owns it; it is not a remote scanner and does not prove that an unmatched port is bindable.

## Usage

```console
portlens PORT
portlens START-END [--udp] [--ipv4 | --ipv6]
portlens --all [--pid PID | --process NAME]
portlens 8080 --watch 5 --watch-interval 1
```

Supply exactly one port/range or `--all`. Ports are 1-65535. `--pid` accepts 1-2147483647; `--process` is an exact printable name of at most 128 characters. Watch count is 1-100 and interval is 0.1-60 seconds; default execution is one snapshot. `--watch-interval` defaults to one second.

## Evidence and interpretation

PortLens calls `ss` separately for selected IPv4/IPv6 families. The command is shell-free, has a 30-second deadline, and bounds each stdout/stderr stream to 8 MiB. Rows report protocol, state, family, local address/port, bind scope, and best-effort PID, numeric UID, username, process name, executable basename, process FD count, socket FD, and cgroup path.

Wildcard binds mean all local interfaces visible in this namespace; loopback binds are local-only. Multiple rows for the same protocol/family/address/port are reported as a likely shared/reused bind group. This can reflect `SO_REUSEPORT`, multiple owners, or duplicate kernel reporting and is not proof of a conflict.

Procfs enrichment is live, non-atomic, best-effort, and permission-dependent, as stated in human output and the JSON `process_enrichment` field. `ss` supplies the socket/PID association. A later `/proc/PID` read may refer to another process if the PID has been reused; the enrichment is not proof of atomic ownership. PortLens never reads process command lines or environments.

## Output and exit codes

All human output ends with `Conclusion: [STATUS] TARGET — finding. Next: action.` Status is `FOUND` or `NOT_FOUND`. Exit 0 means a match was observed, 1 means no match, 2 means invalid invocation or an unusable observation, and 130 means interrupted.

`--brief` emits essential counts, `--json` emits the suite schema-version-1 envelope, and `--quiet` suppresses ordinary stdout. `--output FILE` writes that selected representation. Existing files require `--force`; symlink, non-regular, and multiply-linked targets are refused. Output is capped at 16 MiB.

## Requirements, privacy, and examples

Linux, procfs, and `ss` (normally iproute2) are required. Extra procfs permissions may improve owner metadata; PortLens never elevates privilege and performs no network traffic.

```console
portlens 53 --udp --ipv4 --brief
portlens --all --process nginx --json
```

Results cover only one namespace and instant(s) in time. They do not establish firewall reachability, application health, port availability, root cause, or remediation.
