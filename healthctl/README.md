# HealthCtl

HealthCtl is an experimental Linux/Unix-style utility that evaluates a bounded set of explicitly configured host and service criteria and reports `PASS`, `FAIL`, or `ERROR` for each one. V1 supports two built-in check types: filesystem free-space percentage and TCP connection establishment.

HealthCtl does not infer universal health thresholds. The caller chooses every target and threshold in the configuration. A `PASS` means only that one configured criterion was satisfied during this invocation; it does not prove overall host, application, service, network, or storage health. A `FAIL` does not identify root cause.

## Requirements

- Python 3
- standard library only
- no external commands or third-party packages

## Usage

```console
python3 healthctl/healthctl.py CONFIG.json
python3 healthctl/healthctl.py --help
```

Exactly one explicit JSON configuration file is required. HealthCtl has no default configuration path, environment-variable configuration, include mechanism, directory discovery, stdin mode, remote configuration, or implicit check discovery in V1.

## V1 configuration

The configuration must be UTF-8 JSON with this top-level shape:

```json
{
  "version": 1,
  "checks": [
    {
      "name": "root-space",
      "type": "disk_free_percent",
      "path": "/",
      "minimum_free_percent": 10
    },
    {
      "name": "api-tcp",
      "type": "tcp_connect",
      "host": "127.0.0.1",
      "port": 8080,
      "timeout_seconds": 1.0
    }
  ]
}
```

V1 accepts at most 32 checks. Check names must be unique and contain 1 through 64 ASCII letters, digits, `.`, `_`, or `-`, starting with a letter or digit. Duplicate JSON object fields, unknown top-level fields, unknown check fields, and unsupported check types are rejected instead of ignored so configuration mistakes fail visibly.

The configuration file itself is bounded to 64 KiB (65,536 bytes), must be a regular file, and must not be a final-component symlink on Linux systems where Python exposes `O_NOFOLLOW`. HealthCtl opens it read-only, reads exactly the size observed immediately after opening, verifies that no additional byte appeared, and rechecks descriptor identity/size/timestamps before accepting the document. These checks reduce some pathname and concurrent-change hazards but do not create a filesystem snapshot or eliminate every race.

Relative filesystem-check paths are interpreted relative to the caller's current working directory. Displayed configuration and filesystem paths are absolute and lexically normalized; they are not claimed to be canonical physical paths.

## `disk_free_percent`

A filesystem free-space check has these fields:

```json
{
  "name": "root-space",
  "type": "disk_free_percent",
  "path": "/",
  "minimum_free_percent": 10
}
```

`minimum_free_percent` must be a finite JSON number from 0 through 100. HealthCtl calls the standard-library filesystem-capacity API for the selected path and calculates:

```text
free bytes
---------- * 100
 total bytes
```

The check is `PASS` when the observed percentage is greater than or equal to the configured minimum and `FAIL` when it is lower. If capacity cannot be observed trustworthily, the check is `ERROR`.

This is point-in-time filesystem-capacity evidence only. It does not measure inode exhaustion, quotas, thin-provisioning behavior, reserved-block policy, filesystem errors, writeability, I/O latency, storage-device health, or future growth rate. It does not recursively scan the path; DiskHound remains the focused utility for ranking observed allocated space beneath a directory.

## `tcp_connect`

A TCP check has these fields:

```json
{
  "name": "api-tcp",
  "type": "tcp_connect",
  "host": "example.com",
  "port": 443,
  "timeout_seconds": 1.0
}
```

`host` is either a strict ASCII DNS-style hostname, an IPv4 literal, or an unbracketed IPv6 literal. Single-label hostnames and a final DNS root dot are accepted. Unicode/IDNA input, underscores, whitespace, control/presentation characters, bracketed IPv6, and scoped IPv6 zone identifiers are rejected in V1.

`port` must be a JSON integer from 1 through 65535. `timeout_seconds` is optional, defaults to 1.0 second, and must be a finite JSON number from 0.1 through 5.0 seconds.

For a hostname, HealthCtl makes one operating-system `getaddrinfo()` request for TCP stream candidates using `AF_UNSPEC`. Numeric IP targets request `AI_NUMERICHOST`. Exact duplicate socket candidates are suppressed while preserving first-seen order. V1 accepts at most 16 distinct candidates; larger or structurally unsupported resolver results become `ERROR` rather than being silently truncated or guessed.

Distinct candidates are attempted sequentially. Each candidate receives the configured connect timeout, and HealthCtl stops after the first completed TCP handshake. A normal resolver failure or a set of ordinary connection failures produces `FAIL`; unexpected resolver/socket API shapes or setup failures produce `ERROR`.

A passing TCP criterion means only that a transport-layer handshake completed. HealthCtl sends no application bytes and performs no TLS handshake, HTTP request, banner read, authentication, protocol-specific request, or application-readiness test. NetDoctor remains the focused utility for richer resolver and TCP-attempt evidence for one endpoint.

The duration of an OS hostname lookup is not bounded by `timeout_seconds`; that setting applies to TCP connection attempts only.

## Execution model

Checks run sequentially in configuration order. V1 has no concurrency, retries, scheduling, watch mode, daemon mode, persistence, history, alerting, or background execution.

A failed criterion does not stop later configured checks. HealthCtl attempts the remaining checks so one invocation can produce a complete bounded report. An individual observation error is represented as `ERROR` for that check when possible.

## Output

Normal output contains fixed `Configuration`, `Results`, `Summary`, and `Interpretation limits` sections. Each result reports:

- check name;
- check type;
- selected target;
- `PASS`, `FAIL`, or `ERROR`;
- short evidence explaining the criterion result.

Externally derived strings are terminal-safe escaped. HealthCtl uses no terminal styling, width detection, or interactive output.

## Exit codes and streams

| Code | Meaning |
| --- | --- |
| `0` | Every configured check produced a trustworthy `PASS`. |
| `1` | At least one configured criterion produced `FAIL`, and no check produced `ERROR`. |
| `2` | Invalid invocation or invalid/untrustworthy configuration. |
| `3` | At least one check produced `ERROR`, or no trustworthy aggregate report could be produced because of an observation/internal failure. |
| `130` | Interrupted by SIGINT / Ctrl-C. |

Normal aggregate reports go to stdout. Invocation/configuration, fatal observation, interruption, and unexpected internal failures go to stderr. Unexpected failures use stable wording without a traceback.

`ERROR` takes precedence over `FAIL` for the process exit code because an unevaluated criterion means the aggregate result is incomplete. The per-check report still preserves any trustworthy `PASS` or `FAIL` observations gathered for other checks.

## Safety, privacy, and permissions

HealthCtl never elevates privileges and performs no remediation or configuration modification. The filesystem check reads capacity metadata only. The TCP check intentionally causes outbound network activity only for caller-configured endpoints: hostname checks can trigger ordinary OS resolver traffic, and connection attempts send TCP packets to resolver-provided addresses on the configured port.

There is no hidden telemetry, analytics, upload, update check, external AI, database, cache, or unrelated network activity.

Configuration paths, filesystem paths, hostnames, resolved endpoint behavior, thresholds, and criterion results can reveal operational information. Treat configuration files and captured output as potentially sensitive before storing or sharing them. V1 deliberately has no credentials, headers, request bodies, arbitrary command execution, environment substitution, or secret interpolation.

## Relationship to other OpsForge utilities

HealthCtl is intentionally a small policy/evaluation layer, not a replacement for the focused diagnostics already in OpsForge. DiskHound provides directory allocation evidence; SvcDoctor provides systemd state evidence; ProcWatch provides process sampling; ConfigDiff provides exact content-drift evidence; NetDoctor provides detailed one-endpoint resolver/TCP evidence; CertWatch provides TLS certificate evidence.

V1 does not invoke those utilities as subprocesses or import them as dependencies. The first HealthCtl version uses only two narrowly defined built-in criteria so cross-utility abstractions can emerge later from demonstrated requirements rather than speculation.

## Tests

Run from the repository root:

```console
python3 -m py_compile healthctl/healthctl.py
python3 -m unittest discover -s healthctl/tests -v
```

The suite uses temporary files and deterministic filesystem/resolver/socket fakes. It does not require public DNS or an Internet endpoint.

## V1 limitations and non-goals

V1 has no systemd-unit check, process check, file-content check, certificate-expiration check, HTTP/HTTPS request, application protocol, Unix socket, UDP, ICMP, DNS-server selection, direct DNS protocol, command/exec check, script/plugin execution, environment expansion, secrets, headers, authentication, retries, dependencies between checks, concurrency, scheduling, watch mode, daemon mode, history, persistence, metrics export, JSON output, alerting, notification integration, remediation, auto-healing, remote configuration, configuration includes, directory discovery, threshold auto-tuning, anomaly detection, root-cause analysis, or production-readiness claim.

Those capabilities should be considered only when concrete operational requirements justify expanding the controller without weakening its safety and predictability.
