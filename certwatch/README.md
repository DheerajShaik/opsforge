# CertWatch

CertWatch performs bounded TLS certificate diagnostics for up to 32 explicit endpoints. It keeps encoded validity, hostname/SAN identity, CA trust, chain visibility, fingerprint drift, and revocation status as separate concepts.

## Usage

```console
certwatch example.com
certwatch example.com:8443 api.example.com --warn-days 30 --critical-days 7
certwatch 192.0.2.10:443 --sni api.example.com
certwatch example.com --baseline-sha256 HEX --json
```

Targets accept `HOST`, `HOST:PORT`, bare IPv6, or `[IPv6]:PORT`; default port is 443. Warning and critical days are non-negative integers, defaulting to 30 and 7; critical cannot exceed warning. `--sni` accepts one ASCII hostname and only with one target. A baseline fingerprint is exactly 64 hexadecimal SHA-256 digits.

## Network and certificate model

For each target, CertWatch resolves at most 16 distinct TCP candidates, applies five-second TCP/TLS bounds, captures negotiated TLS version/cipher and per-stage timing, and decodes the leaf certificate with a shell-free, bounded `openssl x509` subprocess. It reports subject, issuer, serial, SANs, not-before/not-after, and SHA-256 fingerprint.

Identity matching uses SANs, exact IP comparison, exact DNS names, and one-label wildcards only. A second default-trust handshake supplies separate CA-trust evidence. Verified-chain count is reported only when the running Python exposes a compatible public capability. Revocation is never checked.

Portable intermediate-certificate expiry decoding is deferred because CPython 3.10-3.12 do not expose a consistent public verified-chain certificate API. Chain count must not be read as intermediate-validity proof.

## Output, statuses, and exits

Per-target states include `VALID`, `WARNING`, `CRITICAL`, `EXPIRED`, `FAIL`, `DRIFT`, or `ERROR`; multi-target failures can produce `PARTIAL`. A validity, trust, identity, or baseline warning exits 1. Exit 0 means all observed targets are currently valid, trusted, identity-matched, and baseline-consistent; exit 2 is invalid CLI syntax; exit 3 is an observation/internal/output failure; 130 is interruption.

`--brief`, schema-version-1 `--json`, `--quiet`, safe `--output FILE`, and `--force` follow the shared contract. Human output ends with the standard conclusion.

## Requirements, privacy, and limits

Linux/Python plus the system `openssl` executable are required. CertWatch initiates DNS, TCP, and TLS only to caller-selected targets. Certificates, addresses, names, issuers, and fingerprints can be sensitive. Success does not prove revocation status, application readiness, future availability, or overall endpoint health.
