# NetDoctor

NetDoctor explains where one destination-specific connection attempt succeeds or fails across operating-system resolution, route evidence, address family, TCP, and optional TLS. It is not a scanner and never expands a target into ports, hosts, ranges, or subnets.

## Usage

```console
netdoctor HOST PORT
netdoctor example.com 443 --compare-families --retries 1
netdoctor example.com 443 --tls
netdoctor 192.0.2.10 443 --tls --sni api.example.com --json
```

Host is a strict ASCII DNS-style name or unbracketed IPv4/IPv6 literal; port is 1-65535. Per-attempt timeout is 0.1-30 seconds (default 3). Retries are 0-3 additional bounded rounds. `--compare-families` attempts all resolved candidates rather than stopping on the first success. `--sni` requires `--tls` and an ASCII hostname.

## Evidence and network activity

NetDoctor times the OS resolver and each TCP attempt, suppresses exact duplicate candidates, and accepts at most 16 distinct IPv4/IPv6 results. It reports candidate/peer endpoints, selected local source IP, IPv4 default-route context, nameservers from bounded `/etc/resolv.conf`, and only the names—not values—of recognized proxy environment variables.

The IPv4 default-route gateway/interface is context only: policy routes, IPv6, VPNs, subnet routes, and namespaces can select a different path. It does not establish the successful connection's interface, even for loopback. JSON uses `ipv4_default_route_context`; `selected_interface` remains `null`, and human output calls the connection interface unavailable. No route interface is inferred from a successful TCP connection.

Network/host-unreachable outcomes are classified at the route stage; other failures remain resolution, TCP, or TLS stage evidence. Optional TLS performs one additional targeted handshake to the successful candidate, reports version/cipher/time, intentionally disables certificate trust and identity verification, sends no application data, and explicitly does not assess revocation or application readiness.

Socket attempts use explicit timeouts. The platform resolver call itself is not cancellable through Python's standard `getaddrinfo()` API and may exceed the TCP timeout.

## Output and exits

Status is `CONNECTED` or `UNREACHABLE`; the JSON `observations.stage` identifies resolution, route, TCP, or TLS. Exit 0 means the requested TCP/TLS stage completed, 1 means it did not, 2 means invalid invocation, 3 means malformed/untrustworthy observation or output failure, and 130 means interrupted.

`--brief`, schema-version-1 `--json`, `--quiet`, safe `--output FILE`, and explicit `--force` follow the common contract. Human output ends with the standard conclusion.

## Privacy and limits

NetDoctor deliberately performs DNS and destination-specific TCP/TLS activity. Hosts, IPs, routes, sources, interfaces, resolver addresses, proxy-variable presence, and timing can be sensitive. It does not ping, traceroute, inspect firewalls/neighbors, capture packets, send HTTP, authenticate, prove application readiness, identify root cause, or remediate.
