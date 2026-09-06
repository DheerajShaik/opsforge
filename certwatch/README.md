# CertWatch v0.1

> **Experimental:** CertWatch is not production-ready.

CertWatch answers one question: **what leaf TLS certificate is one remote endpoint presenting, and what does its encoded validity interval say about expiration?** It is a read-only, one-target diagnostic. It does not validate CA trust, match hostnames, inspect the chain, send HTTP/application data, or remediate anything.

## Requirements and use

- Python 3 with its standard library. Exercised versions are recorded in [VALIDATION.md](VALIDATION.md).
- The system `openssl` executable with `openssl x509 -ext subjectAltName -nameopt RFC2253`.

```console
python3 certwatch/certwatch.py example.com
python3 certwatch/certwatch.py example.com:8443
python3 certwatch/certwatch.py --warn-days 14 example.com
python3 certwatch/certwatch.py '[2001:db8::1]:443'
```

The default port is 443 and the default warning threshold is 30 days. `--warn-days` is a non-negative ASCII decimal integer. A target is a strict ASCII DNS-style hostname (a final root dot and single-label names are accepted), IPv4 literal, bare IPv6 literal with default port, `HOST_OR_IPV4:PORT`, or `[IPv6]:PORT`. Explicit IPv6 ports require brackets. Unicode/IDNA names, URI syntax, underscores, whitespace, zones, malformed labels, and ports outside 1–65535 are rejected.

## Observation model

CertWatch locates its mandatory decoder before networking. It resolves once with the OS resolver, whose duration is not bounded by the socket timeout. Resolver order and duplicates are retained. Each TCP candidate gets up to five seconds; TCP failures permit the next candidate. The first TCP success permanently ends fallback. TLS then receives a separate five-second timeout. A hostname is sent as SNI, which can influence the presented certificate; raw IP targets send no SNI. Python observes TLS using its runtime default TLS policy with verification disabled and retrieves the exact DER leaf. The DER limit is 1 MiB.

The DER stays in memory. Python computes its SHA-256 fingerprint. A fixed, shell-free OpenSSL command decodes names in RFC2253 rendering, serial, validity timestamps, and SAN. Decoder execution has a separate five-second limit and independent 64 KiB stdout/stderr limits. OpenSSL's text rendering is an external compatibility boundary: real-world validation exposed a legitimate SAN-heading horizontal-whitespace variant that required bounded parser hardening. Supported SAN values are DNS, IP (normalized), URI, and email; malformed or unsupported output fails rather than being guessed. Names are decoder-rendered certificate data, not validated identities.

The report contains the requested endpoint, actual peer IP from `getpeername()`, subject, issuer, serial, SHA-256 fingerprint, UTC `notBefore`/`notAfter`, supported SANs, and validity assessment. `-` is the sole unavailable marker. External text is escaped for terminal-safe display.

## Validity and warning semantics

CertWatch captures local UTC time once and uses inclusive certificate boundaries. Before `notBefore` is not-yet-within-period; after `notAfter` is expired. At both exact endpoints it is within the encoded interval. While within it, exact remaining time is compared to `warn_days * 86400`; equality warns. With zero warning days, only exact `notAfter` warns. Display truncation to whole seconds never drives classification. CertWatch relies on the local system clock and does not independently verify clock accuracy.

These statements concern only encoded time fields. **CA trust and hostname identity are not assessed.** TLS failure means only that the defined observation could not complete under the current runtime TLS policy.

## Streams and exit codes

Complete successful/attention reports go only to stdout. Invocation and operational diagnostics go only to stderr; partial reports and normal tracebacks are never emitted.

| Code | Meaning |
|---:|---|
| 0 | Observed; within interval and outside warning window |
| 1 | Observed; expired, not yet within interval, or in warning window |
| 2 | Invalid invocation or target |
| 3 | Reliable observation/decoding could not complete |
| 130 | Interrupted by SIGINT |

## Security, privacy, and limitations

DNS, TCP, and TLS communication exposes connection metadata to resolver infrastructure, intervening networks, and the selected endpoint. Certificate output can disclose internal names or organizational metadata and should be handled accordingly. CertWatch uses no credentials, persistence, telemetry, privilege elevation, update checks, scanning, or remediation.

It supports only direct TLS to one endpoint. It does not implement trust/hostname verification, chain analysis, OCSP/CRL/CT, protocol or cipher grading, HTTP, STARTTLS, client certificates, local files, configuration, JSON, multiple targets, monitoring, notification, renewal, or legacy TLS fallback. Compatibility is claimed only for the versions and decoder output shapes actually exercised in [VALIDATION.md](VALIDATION.md). Universal OpenSSL compatibility is not claimed, and LibreSSL or BoringSSL compatibility has not been tested or claimed.

## Tests

```console
python3 -m py_compile certwatch/certwatch.py
python3 -m unittest discover -s certwatch/tests -v
```

Tests use `unittest` and mocks and require no public DNS, Internet endpoint, or trust store.
