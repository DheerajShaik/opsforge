# PortLens

PortLens is an experimental Linux diagnostic utility that reports TCP listening sockets matching one local port and adds associated process metadata where that information is available. It is the first working OpsForge utility; its interface and behavior may evolve.

## Scope and semantics

PortLens inspects:

- TCP `LISTEN` sockets only
- IPv4 and IPv6
- sockets visible in the current network namespace
- one exact local port per invocation
- every matching row returned by socket discovery

It does not scan networks, inspect UDP or connected TCP sockets, traverse network namespaces, test whether a port can be bound, or change system state. A no-match result means only that no matching TCP listening socket was observed. It does **not** prove that a port is free, available, or bindable for every address, namespace, configuration, or later point in time.

## Requirements

- Linux
- Python 3
- `ss`, commonly provided by iproute2

PortLens invokes separate fixed `ss` queries for IPv4 and IPv6. The parser is conservatively fixture-tested, including regression fixtures derived from the genuine output described below. No broad `ss` or distribution compatibility is claimed.

Readable procfs is optional and is used only for process enrichment. PortLens can report socket information when procfs metadata is unavailable.

## Tested environment

Manual validation was completed with Python 3 on Ubuntu 24.04.1 LTS under WSL using iproute2 `ss` 6.1.0. Controlled IPv4 and IPv6 listeners were exercised with both loopback and wildcard bindings. Matching sockets returned exit 0, a successful no-match inspection returned exit 1, and invalid input returned exit 2.

This records observed behavior in one tested environment. It is not a compatibility or support matrix, universal Ubuntu, WSL, iproute2, or Linux compatibility evidence, a stability guarantee, or a production-readiness claim.

## Usage

```console
python3 portlens/portlens.py <port>
python3 portlens/portlens.py --help
```

The port must be a decimal integer from 1 through 65535. Leading zeros are accepted as decimal. Missing, extra, unsupported, non-numeric, out-of-range, negative, and whitespace-containing argument values are rejected.

## Output

For matches, PortLens prints these columns:

| Column | Meaning |
| --- | --- |
| `PROTO` | `tcp` in this implementation |
| `STATE` | `LISTEN` |
| `FAMILY` | `ipv4` or `ipv6`, based on the discovery query |
| `LOCAL ADDRESS` | local address reported by `ss` |
| `PORT` | local TCP port |
| `PID` | associated process ID where reported by `ss` |
| `USER` | username resolved from the procfs owner, or numeric UID if name lookup fails |
| `PROCESS` | procfs process name, with the `ss` process name as a fallback |

The exact marker `-` means optional process information was unavailable. Multiple process references on one discovery row are shown as comma-separated values in the three process columns. Results are sorted deterministically, but distinct discovery rows are never deduplicated.

No-match output deliberately avoids claiming universal port availability or bindability.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Inspection completed and at least one matching socket was observed. |
| `1` | Inspection completed and no matching socket was observed. |
| `2` | Invalid usage, missing `ss`, discovery execution failure, fatal parser incompatibility, or internal execution failure prevented reliable completion. |

Missing or inaccessible PID, user, or process metadata does not invalidate an observed socket and does not change a matching result to exit code 2.

## Permissions and mutable state

PortLens does not invoke `sudo` or elevate privileges. Socket and process visibility depends on the invoking user's permissions, procfs configuration, Linux security controls, and namespace context. Process enrichment is best effort.

Socket discovery and process enrichment occur at different times. A socket or process can disappear between those operations. PortLens preserves an observed socket and PID while showing `-` for enrichment that is no longer available; it cannot provide an atomic snapshot or prevent PID reuse.

## Security and privacy

PortLens is read-only and performs no telemetry, outbound communication, remote probing, process or service control, firewall changes, or remediation. It invokes `ss` with fixed subprocess argument arrays and without a shell. System-derived display values are sanitized to prevent control characters from changing output structure.

Default output intentionally excludes executable paths, full command lines and arguments, environment variables, working directories, open files, and service configuration. Output still contains local addresses, PIDs, usernames, and process names; treat it as operational metadata when storing or sharing it.

## Tests

Run the standard-library test suite from the repository root:

```console
python3 -m unittest discover -s portlens/tests -v
```

The suite covers input validation, sanitized representative `ss` fixtures, regression fixtures derived from the tested live output, conservative parser failures, enrichment degradation, deterministic rendering, subprocess safety, CLI streams, and exit codes. One validated environment does not substitute for broader live integration testing with other `ss` releases and Linux environments.

## Current limitations and future direction

PortLens is an early implementation, not a stable or production-ready release. Current limitations include text parsing at the external `ss` boundary, permission-dependent process metadata, current-network-namespace visibility, mutable observations, and unvalidated cross-version `ss` behavior.

Future work may be considered only after the initial behavior is validated through real use. Possible areas include broader compatibility testing, structured output, UDP semantics, or namespace-aware inspection; none are implemented here.
