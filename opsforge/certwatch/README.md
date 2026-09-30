# CertWatch

CertWatch performs bounded TLS certificate diagnostics for up to 32 explicit endpoints. It keeps encoded validity, hostname/SAN identity, CA trust, chain visibility, fingerprint drift, and revocation status as separate concepts.

## Usage

```console
certwatch example.com
certwatch example.com:8443 api.example.com --warn-days 30 --critical-days 7
certwatch 192.0.2.10:443 --sni api.example.com
certwatch example.com --baseline-sha256 HEX --json
```

Targets accept `HOST`, `HOST:PORT`, bare IPv6, or `[IPv6]:PORT`; default port is 443. Warning and critical days are integers from 0 through 36500; warning defaults to 30 and critical to the smaller of 7 and the warning value, and critical cannot exceed warning. `--sni` accepts one ASCII hostname (not an IP literal) and only with one target. `--baseline-sha256` also requires exactly one target; a baseline fingerprint is exactly 64 hexadecimal SHA-256 digits.

## Network and certificate model

For each target, CertWatch uses the first 16 distinct resolved TCP candidates (the shared `opsforge.common.net` resolver and connect loop), tries them in order with five-second TCP attempts inside a 20-second connection budget, applies a five-second TLS bound, captures negotiated TLS version/cipher and per-stage timing, and decodes the leaf certificate with a shell-free, bounded `openssl x509` subprocess. It reports subject, issuer, serial, SANs, not-before/not-after, and SHA-256 fingerprint; SAN types other than DNS, IP, URI, and email are listed as `other` and never used for identity.

One connection and one handshake normally suffice. CertWatch first handshakes with default CA trust, so the leaf it reports is the leaf whose chain was verified. Only when that handshake fails certificate verification does it reconnect, to the same address, without verification, because an expired, not-yet-valid, or untrusted certificate must still be decoded and reported; `CA trust` is then `not verified` and the verification error is a warning. Any other handshake failure (timeout, protocol error, reset) is an `ERROR` with no second attempt. Hostname checking is left out of the handshake; identity is judged from the decoded SANs so it stays separate from trust.

Up to eight targets are inspected at once on daemon threads, and the output keeps input order. The overall limit is 120 seconds: a target's connection budget never exceeds the time left, and a target not yet started when the limit is reached is reported as `SKIPPED` (not attempted) instead of extending the run. A target still running when the limit passes (plus a one-second grace) is abandoned and reported as `ERROR`, so the run ends at the limit; the abandoned thread finishes on its own timeouts. An interrupt ends the run without waiting for in-flight network calls.

Identity is checked against the SNI name actually sent (`--sni` if given, otherwise the hostname target, minus any trailing dot); an IP target without `--sni` sends no SNI and is checked against its address. Identity matching uses SANs, exact IP comparison, exact DNS names, and one-label wildcards only; a certificate without SANs leaves identity unavailable, and one without a SAN of the required DNS or IP type is a mismatch. Hostnames follow the shared strict host grammar: ASCII only, valid labels, and no name whose last label is numeric (`127.1` and `0x7f.1` would be read by the resolver as IPv4 addresses), so write IPv4 addresses as four decimal octets. Verified-chain count is reported only when the running Python exposes the public `get_verified_chain` (3.13 and later). Revocation is never checked.

Portable intermediate-certificate expiry decoding is deferred because CPython 3.10-3.12 do not expose a consistent public verified-chain certificate API. Chain count must not be read as intermediate-validity proof.

## Output, statuses, and exits

A target is `VALID` or one of these findings, ranked `EXPIRED` > `NOT_YET_VALID` > `CRITICAL` (inside the critical window) > `DRIFT` (the fingerprint differs from `--baseline-sha256`) > `WARNING` (inside the warning window, or an untrusted chain or identity mismatch or gap). A target reports its most severe condition, so drift never hides expiry. A target that could not be observed is `ERROR`, and one that was never attempted because the overall limit was reached is `SKIPPED`; both still get a report and a JSON entry with an `error` field, even when it is the only target.

The overall status is the most severe finding. With no finding it is `VALID` when every target is, `INCOMPLETE` when some targets are `ERROR` or `SKIPPED`, and `ERROR` when none could be observed.

| Exit | Meaning |
| --- | --- |
| 0 | Every target is currently valid, trusted, identity-matched, and baseline-consistent. |
| 1 | At least one finding, even when other targets are `ERROR` or `SKIPPED`. |
| 2 | Invalid CLI syntax or an invalid target. |
| 3 | `INCOMPLETE` or `ERROR` with no finding, a missing decoder, or an internal or output failure. |
| 130 | Interrupted. |

`--brief`, schema-version-1 `--json`, `--quiet`, safe `--output FILE`, and `--force` follow the shared contract. Human output ends with the standard conclusion.

## Requirements, privacy, and limits

Linux/Python plus the system `openssl` executable are required; `openssl` is used only from an absolute `PATH` directory, and both that directory and the executable must be modifiable only by root or the caller. CertWatch initiates DNS, TCP, and TLS only to caller-selected targets; it stops waiting for a name lookup after five seconds, and a resolver answer of more than 16 distinct addresses is reported as a warning. The certificate a peer presents is untrusted input: its bytes reach `openssl x509` (a shell-free, bounded, size-capped process), whose text output is parsed and escaped before display. Certificates, addresses, names, issuers, and fingerprints can be sensitive. Success does not prove revocation status, application readiness, future availability, or overall endpoint health.
