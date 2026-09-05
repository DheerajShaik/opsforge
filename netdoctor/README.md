# NetDoctor

NetDoctor is an experimental Linux/Unix-style network diagnostic utility that reports OS resolver evidence and TCP connection-establishment evidence for one explicitly selected remote endpoint. It answers one narrow question: for this host and TCP port, what address candidates did the local resolver provide, and did a TCP handshake complete to one of them during this invocation?

NetDoctor does not decide whether an application, service, website, API, TLS endpoint, host, or network is healthy. A TCP handshake is transport evidence only. A failed handshake does not identify root cause by itself.

## Requirements

- Python 3
- standard-library networking only
- no external commands or third-party packages

## Usage

```console
python3 netdoctor/netdoctor.py HOST PORT
python3 netdoctor/netdoctor.py --help
```

`HOST` is either a strict ASCII DNS-style hostname, an IPv4 literal, or an unbracketed IPv6 literal. Single-label hostnames and a final DNS root dot are accepted. Unicode/IDNA input, underscores, whitespace, control/presentation characters, bracketed IPv6, and scoped IPv6 zone identifiers are rejected in V1. IPv6 needs no brackets because `PORT` is a separate positional argument.

`PORT` is an ASCII decimal integer from 1 through 65535. Exactly one host and one port are required. NetDoctor has no configuration file, environment-variable input, target list, range, discovery, or scanning mode in V1.

## Resolution model

For hostname targets, NetDoctor makes one operating-system `getaddrinfo()` request for TCP stream candidates using `AF_UNSPEC`, suppresses exact duplicate socket candidates, and preserves first-seen resolver order. For numeric IPv4/IPv6 targets it still asks `getaddrinfo()` to construct socket candidates, but requests `AI_NUMERICHOST` so no hostname lookup is requested by NetDoctor.

The duration of an OS hostname lookup is not bounded by the TCP connect timeout. NetDoctor accepts at most 16 distinct resolver candidates in V1 after exact duplicate suppression; a larger distinct or structurally unsupported result is treated as an observation failure rather than silently truncated. Resolver records must describe IPv4 or IPv6 TCP stream candidates for the requested port.

A normal hostname-resolution failure is useful diagnostic evidence. NetDoctor reports it without making a TCP connection attempt and exits with code 1. It does not query a chosen DNS server directly, inspect `/etc/resolv.conf`, distinguish stub/caching layers, perform reverse DNS, or claim why resolution failed.

## TCP connection model

Distinct resolved candidates are attempted sequentially in first-seen resolver order; an exact duplicate socket candidate is not contacted twice. Each candidate gets one three-second TCP connect timeout. NetDoctor stops after the first successful handshake; candidates after that success are not contacted. If every candidate fails, each attempted outcome is reported.

NetDoctor classifies common connect outcomes such as timeout, connection refused, host unreachable, network unreachable, and permission denied. Other connect failures are reported as a generic connection error with the numeric OS error number when available. Numeric error evidence is intentionally preferred over localized operating-system error strings for stable output.

A successful attempt records the local socket endpoint when available and the connected peer endpoint, then immediately closes the TCP connection. NetDoctor sends no application bytes. It performs no TLS handshake, HTTP request, protocol banner read, authentication, or service-specific probe.

TCP state is live and non-atomic. Resolver results, routes, firewall policy, listener state, NAT behavior, and remote state can change before, during, or immediately after observation.

## Output

Normal output contains fixed `Target`, `Observation`, `Resolution candidates`, `Connection attempts`, and `Interpretation limits` sections. It reports the parsed target, target kind, resolver status, candidate count/order, attempt outcomes, and connected local/peer endpoints when available.

External target text is terminal-safe escaped. Resolver candidate addresses are validated and rendered as canonical numeric IP endpoints. IPv6 endpoints are bracketed in output; a resolver-provided numeric scope identifier is retained when present.

## Exit codes and streams

| Code | Meaning |
| --- | --- |
| `0` | A TCP handshake completed to one resolver candidate. |
| `1` | A useful diagnostic completed, but name resolution yielded no usable candidates or no attempted TCP candidate connected. |
| `2` | Invalid invocation or invalid/unsupported target. |
| `3` | No trustworthy structured diagnostic could be produced because of an unexpected resolver/socket API shape, resource/setup failure, defensive bound, or internal failure. |
| `130` | Interrupted by SIGINT / Ctrl-C. |

Normal connected and useful-negative diagnostics go to stdout. Invocation, fatal observation, interruption, and internal-failure messages go to stderr. Unexpected failures use stable wording without a traceback.

## Safety, privacy, and permissions

NetDoctor uses only the caller's existing networking permissions and never elevates privileges. It is diagnostic-only and performs no configuration, routing, firewall, interface, DNS, process, service, or filesystem modification.

Unlike OpsForge utilities that are purely local/offline, NetDoctor's purpose explicitly requires outbound network activity to the caller-selected endpoint. A hostname invocation can cause ordinary OS resolver traffic, and TCP attempts send transport-layer packets to resolver-provided addresses on the requested port. There is no hidden telemetry, analytics, upload, update check, or unrelated outbound communication.

Resolved IP addresses, the requested hostname/port, local source endpoint, peer endpoint, and connection outcomes are operational metadata. Treat captured output as potentially sensitive before storing or sharing it.

## Relationship to other OpsForge utilities

NetDoctor does not inspect local listening-port ownership; that is PortLens territory. It does not inspect or assess TLS certificates; that is CertWatch territory. It does not become a general service-health framework or configurable monitoring system; those concerns are reserved for later requirements such as HealthCtl.

## Tests

Run the standard-library suite from the repository root:

```console
python3 -m py_compile netdoctor/netdoctor.py
python3 -m unittest discover -s netdoctor/tests -v
```

The suite uses deterministic resolver/socket fakes for failure and edge paths and includes a real local IPv4 loopback TCP-handshake check. It requires no public DNS or Internet endpoint.

## V1 limitations and non-goals

V1 has no ICMP/ping, UDP, Unix sockets, traceroute, path MTU discovery, routing-table inspection, ARP/neighbor inspection, firewall inspection, packet capture, interface inventory, DNS-server selection or direct DNS protocol, reverse DNS, TLS, certificates, HTTP, STARTTLS, application banners, authentication, service semantics, local port ownership, target lists, CIDR/range scanning, concurrent probes, retries, persistence, watch mode, daemon mode, JSON output, configuration file, thresholds, alerting, remediation, root-cause analysis, health/readiness classification, or production-readiness claim.

Those capabilities should be considered only when concrete operational requirements justify expanding this focused transport diagnostic.
