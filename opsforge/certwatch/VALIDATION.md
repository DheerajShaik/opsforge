# CertWatch v0.1 validation record

Scope: this record covers CertWatch v0.1 behavior. Later changes, listed in [CHANGELOG.md](../CHANGELOG.md), are covered by the automated suite but were not re-recorded here.

Validation recorded at **2026-08-14T10:44:30Z**.

## Environment

- Linux distribution: Ubuntu 24.04.4 LTS (Noble Numbat)
- Kernel: Linux 6.18.35
- Architecture: x86_64
- Python: 3.14.4
- Python `ssl.OPENSSL_VERSION`: OpenSSL 3.0.13 30 Jan 2024
- External decoder: OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13)
- IPv4: loopback/local stack available; exercised through deterministic socket mocks
- IPv6: parser and peer rendering exercised through deterministic mocks; external IPv6 availability not asserted

## Automated evidence

`python3 -m py_compile opsforge/certwatch/certwatch.py` passed. The initial `python3 -m unittest discover -s opsforge/certwatch/tests -v` run passed (45 tests) in this environment. Tests exercise target grammar, temporal boundaries, sanitization, deterministic decoder parsing/fingerprinting, resolver ordering, TCP fallback, no TLS fallback, SNI selection, peer-address evidence, cleanup, size limits, and stable CLI failures without public networking.

The PR review follow-up added regression coverage for bounded decoder stdin/stdout/stderr handling, decoder timeout and overflow paths, critical SAN parsing, empty subject rendering, and extremely large numeric CLI inputs. On the updated PR head, GitHub Actions ran with Python 3.14.7 and passed compilation plus **53 CertWatch tests**.

## Controlled local validation

The initial automated suite used controlled in-process fakes for self-contained network/TLS boundary behavior, including non-default ports, warning boundaries, empty/oversized certificates, TLS timeout/failure, and interruption mapping. No private key is committed by this initial suite; the later real-TLS suite (`opsforge/common/tests/tls_fixtures.py`) embeds throwaway test-CA and leaf keys that protect nothing.

A post-review loopback end-to-end check was also exercised in an isolated Linux environment with Python 3.13.5, Python/OpenSSL 3.5.5, and external OpenSSL 3.5.5. A temporary local CA signed a leaf certificate with an empty subject DN and a **critical** `DNS:localhost` SAN. CertWatch connected to a local `openssl s_server` listener on a non-default port, negotiated TLS with verification disabled as designed, retrieved the leaf DER, decoded the critical SAN, rendered `Subject: -`, reported the actual connected IPv6 loopback peer, produced a complete warning-window diagnostic on stdout, and exited `1` with empty stderr. The synthetic CA, leaf key, and certificate existed only in the temporary validation directory and are not committed.

A separate controlled fake decoder that did not consume its 1 MiB stdin was terminated by the configured decoder deadline, confirming that the review fix bounds decoder input writing as well as output draining/process completion.

Live local servers for expired, future-dated, SNI-dependent alternate-certificate selection, plain-TCP handshake failure, closed-port behavior, and SIGINT remain unclaimed unless separately recorded later.

## Controlled external validation

During the 2026-08-14 validation recorded above, no public endpoint was contacted. External endpoint behavior and external IPv6 connectivity were therefore not claimed for that validation. Its compatibility evidence remains limited to the environments explicitly recorded in its sections.

## 2026-09-05 real-world WSL finding and implementation follow-up

A separate real-world validation used Ubuntu 24.04.1 LTS under WSL2 with Python 3.12.3 and OpenSSL 3.0.13. Native OpenSSL retrieved and decoded the public `example.com:443` leaf certificate successfully, including its two DNS SAN values. CertWatch retrieved the leaf but reported `certificate decoder returned malformed output` and exited `3`.

The captured decoder output contained `X509v3 Subject Alternative Name: ` with one trailing ASCII space before the newline. The parser required the heading to end immediately after the colon or the optional ` critical` marker, so it rejected this legitimate formatting variant. The same behavior was independently reproduced with another OpenSSL version; it was an implementation compatibility defect rather than a version-specific anomaly.

This update makes the SAN-heading compatibility boundary accept only trailing ASCII horizontal whitespace while preserving strict rejection of unsupported suffixes and malformed decoder output. Deterministic offline regression coverage includes the ordinary and critical headings with and without trailing space, explicit tab cases, strict negative cases, and a compact decoder-output fixture captured from the public `example.com` leaf observation.

## 2026-09-12 post-fix real-world revalidation

At **2026-09-12T12:45:00Z**, the corrected merged implementation was revalidated from Ubuntu 24.04.1 LTS under WSL2 with Python 3.12.3, Python/OpenSSL 3.0.13, and external OpenSSL 3.0.13.

CertWatch connected to the public `example.com:443` endpoint selected by the caller, retrieved and decoded the presented leaf certificate, accepted the OpenSSL SAN heading with trailing ASCII space, reported both DNS SAN values, produced a complete report on stdout with empty stderr, classified the certificate as within its encoded validity interval and outside the 30-day warning window, and exited `0`. CA trust and hostname identity were not assessed, consistent with the utility's scope.

**Status:** The implementation correction, deterministic regression coverage, and the previously pending WSL real-world revalidation are complete for the recorded environment. This does not broaden compatibility beyond the versions and output shape documented here.

## Unreleased: one handshake per target, real TLS

The earlier records above describe the original design, in which each target used two connections and two handshakes (an unverified one for the leaf and a second, verified one for trust). CertWatch now reads the leaf from a single CA-verifying handshake and reconnects to the same address without verification only when verification fails, inspects up to eight targets at once, and reports NOT_YET_VALID, SKIPPED, and INCOMPLETE.

Validated locally on Ubuntu 24.04 under WSL2 with Python 3.12.3 and OpenSSL 3.0.13. The suite (99 tests) includes real loopback TLS handshakes against throwaway certificates (valid, expired, not yet valid, wrong name) with server-side accept counts: a valid certificate costs one connection, an expired or not-yet-valid one two. Live, one run against four openssl s_server processes with a private CA (trusted through SSL_CERT_FILE) ranked VALID, EXPIRED, NOT_YET_VALID, and WARNING (wrong name) and exited 1. An unreachable target beside an expired one exited 1, and beside a valid one exited 3 (INCOMPLETE). Eight targets against a server that accepts TCP but never answers the handshake finished in about 5.4 seconds, each reported as a five-second handshake timeout. Public endpoints were not contacted for this change. Other CPython versions and hosted CI have not been run for it.
