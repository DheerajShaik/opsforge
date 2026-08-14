# CertWatch v0.1 validation record

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

`python3 -m py_compile certwatch/certwatch.py` passed. The initial `python3 -m unittest discover -s certwatch/tests -v` run passed (45 tests) in this environment. Tests exercise target grammar, temporal boundaries, sanitization, deterministic decoder parsing/fingerprinting, resolver ordering, TCP fallback, no TLS fallback, SNI selection, peer-address evidence, cleanup, size limits, and stable CLI failures without public networking.

The PR review follow-up added regression coverage for bounded decoder stdin/stdout/stderr handling, decoder timeout and overflow paths, critical SAN parsing, empty subject rendering, and extremely large numeric CLI inputs. GitHub Actions is the authoritative automated result for the updated branch.

## Controlled local validation

The initial automated suite used controlled in-process fakes for self-contained network/TLS boundary behavior, including non-default ports, warning boundaries, empty/oversized certificates, TLS timeout/failure, and interruption mapping. No private key is committed.

A post-review loopback end-to-end check was also exercised in an isolated Linux environment with Python 3.13.5, Python/OpenSSL 3.5.5, and external OpenSSL 3.5.5. A temporary local CA signed a leaf certificate with an empty subject DN and a **critical** `DNS:localhost` SAN. CertWatch connected to a local `openssl s_server` listener on a non-default port, negotiated TLS with verification disabled as designed, retrieved the leaf DER, decoded the critical SAN, rendered `Subject: -`, reported the actual connected IPv6 loopback peer, produced a complete warning-window diagnostic on stdout, and exited `1` with empty stderr. The synthetic CA, leaf key, and certificate existed only in the temporary validation directory and are not committed.

A separate controlled fake decoder that did not consume its 1 MiB stdin was terminated by the configured decoder deadline, confirming that the review fix bounds decoder input writing as well as output draining/process completion.

Live local servers for expired, future-dated, SNI-dependent alternate-certificate selection, plain-TCP handshake failure, closed-port behavior, and SIGINT remain unclaimed unless separately recorded later.

## Controlled external validation

No public endpoint was contacted. External endpoint behavior and external IPv6 connectivity are therefore not claimed. Compatibility evidence remains limited to the environments explicitly recorded above.
