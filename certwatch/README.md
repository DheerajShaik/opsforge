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

For each target, CertWatch uses the first 16 distinct resolved TCP candidates, tries them in order with five-second TCP attempts inside a 20-second connection budget, applies a five-second TLS bound, captures negotiated TLS version/cipher and per-stage timing, and decodes the leaf certificate with a shell-free, bounded `openssl x509` subprocess. It reports subject, issuer, serial, SANs, not-before/not-after, and SHA-256 fingerprint; SAN types other than DNS, IP, URI, and email are listed as `other` and never used for identity.

Identity is checked against the SNI name actually sent (`--sni` if given, otherwise the hostname target, minus any trailing dot); an IP target without `--sni` sends no SNI and is checked against its address. Identity matching uses SANs, exact IP comparison, exact DNS names, and one-label wildcards only; a certificate without SANs leaves identity unavailable, and one without a SAN of the required DNS or IP type is a mismatch. A second default-trust handshake to the same connected address supplies separate CA-trust evidence, and its leaf fingerprint must match the displayed leaf before the target can be `VALID`. CA trust is `not verified` only when certificate verification fails; it is `not assessed` (JSON `trust_verified: null`) when that handshake is otherwise unavailable or presents a different leaf. Verified-chain count is reported only when the running Python exposes a compatible public capability. Revocation is never checked.

Portable intermediate-certificate expiry decoding is deferred because CPython 3.10-3.12 do not expose a consistent public verified-chain certificate API. Chain count must not be read as intermediate-validity proof.

## Output, statuses, and exits

Per-target states include `VALID`, `WARNING`, `CRITICAL`, `EXPIRED`, `FAIL` (not yet valid), `DRIFT`, or `ERROR` (observation failed). A target reports its most severe condition, ranked `EXPIRED` > `FAIL` > `CRITICAL` (inside the critical window) > `DRIFT` > `WARNING`, so drift never hides expiry; trust, identity, and trusted-leaf gaps are `WARNING`. The overall status is the most severe target state, or `PARTIAL` when some but not all targets are `ERROR`. A target that cannot be observed still gets a report and a JSON entry with an `error` field, even when it is the only target. A validity, trust, identity, or baseline warning exits 1. Exit 0 means all observed targets are currently valid, trusted, identity-matched, and baseline-consistent; exit 2 is invalid CLI syntax; exit 3 is an observation/internal/output failure, including any `ERROR` target; 130 is interruption.

`--brief`, schema-version-1 `--json`, `--quiet`, safe `--output FILE`, and `--force` follow the shared contract. Human output ends with the standard conclusion.

## Requirements, privacy, and limits

Linux/Python plus the system `openssl` executable are required; `openssl` is used only from an absolute `PATH` directory, and both that directory and the executable must be modifiable only by root or the caller. CertWatch initiates DNS, TCP, and TLS only to caller-selected targets. Certificates, addresses, names, issuers, and fingerprints can be sensitive. Success does not prove revocation status, application readiness, future availability, or overall endpoint health.
