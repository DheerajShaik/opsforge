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

`python3 -m py_compile certwatch/certwatch.py` passed. `python3 -m unittest discover -s certwatch/tests -v` passed (45 tests) in this environment. Tests exercise target grammar, temporal boundaries, sanitization, deterministic decoder parsing/fingerprinting, resolver ordering, TCP fallback, no TLS fallback, SNI selection, peer-address evidence, cleanup, size limits, and stable CLI failures without public networking.

## Controlled local validation

The automated suite uses controlled in-process fakes for self-contained network/TLS boundary behavior, including non-default ports, warning boundaries, empty/oversized certificates, TLS timeout/failure, and interruption mapping. No private key is committed. Live local servers for self-signed, expired, future-dated, SNI-dependent, plain-TCP, closed-port, and SIGINT scenarios were not exercised in this implementation environment and remain unclaimed.

## Controlled external validation

No public endpoint was contacted. External endpoint behavior and external IPv6 connectivity are therefore not claimed. Compatibility evidence is limited to the environment above.
