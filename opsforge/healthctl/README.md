# HealthCtl

HealthCtl is the strict, bounded composition layer for OpsForge-style health criteria. It reads one explicit JSON file, evaluates dependency-safe groups, and reports `PASS`, `FAIL`, `ERROR`, or `SKIPPED` without arbitrary command execution or remediation.

## Usage

```console
healthctl health.json
healthctl health.json --profile production --group edge --workers 4
healthctl health.json --json
```

The configuration file must be a no-follow regular UTF-8 file no larger than 64 KiB. Duplicate JSON keys, unknown fields (including fields that belong to another check type), unsupported types, cycles, missing/self dependencies, and unsafe values are rejected. Root fields are `version` (currently integer `1`), `checks` (1-32), and optional `max_workers` (1-8, default 4).

Every check has `name`, `type`, optional `severity` (`WARNING` or `CRITICAL`, default `CRITICAL`; `WARN` is still accepted as a spelling of `WARNING`), `group`, `profile`, `depends_on`, and `retries` (0-3). Names/groups/profiles are 1-64 restricted ASCII characters. CLI `--profile`/`--group` select exact names; all dependencies must remain selected. `--workers` overrides bounded parallelism.

## Check types

- `disk_free_percent`: `path`, `minimum_free_percent` 0-100. The percentage is the space available to unprivileged users (`df` Avail, `f_bavail`) over the total capacity including root-reserved blocks, so it is slightly lower than `100% - df Use%`, which divides by used plus available space. The capacity call runs with a 5 second bound, like the file checks' `lstat` and hashing, so a hung network filesystem yields an `ERROR` instead of a hang.
- `tcp_connect`: strict `host`, `port` 1-65535, optional `timeout_seconds` 0.1-5 (default 1); tries at most the first 16 distinct resolver candidates, moving to the next after a socket or connection error, and notes in the evidence when more were returned. A name that does not resolve (no such name or no address records) is a `FAIL`; any other resolver failure, including a temporary or non-recoverable DNS failure, is an `ERROR`.
- `http` / `https`: credential-free same-scheme ASCII `url` (at most 2,048 characters) without query or fragment, optional exact `expected_status` 100-599 (default 200), and total post-resolution deadline 0.1-5 seconds. Uses a proxy-free HEAD request, default HTTPS trust/identity verification, at most 64 KiB of response headers, and at most three same-origin/same-transport redirects without query or fragment (a redirect beyond that policy, including a malformed `Location`, is an `ERROR`); no authorization header or response body is sent/read.
- `dns`: strict `host`; reports at most the first 16 unique addresses and notes in the evidence when more were returned. The OS resolver call runs on a daemon thread and is abandoned after 5 seconds (an `ERROR`), so a hung resolver cannot hang the run.
- `certificate_expiry`: `host`, optional `port` (443), timeout 0.1-5 seconds, `warn_days` (30), and `critical_days` (7). Uses the same validated resolver/candidate path as TCP/HTTP, at most 16 distinct candidates, and one deadline shared across connection attempts and TLS. The handshake uses default CA trust, hostname verification, and appropriate SNI; revocation is not checked. No proxies are used. An expired or not-yet-valid certificate is `FAIL` with `CRITICAL` severity, other verification failures are `FAIL` at the configured severity, and resolution, connection, timeout, or other TLS failures are `ERROR`.
- `process`: positive `pid`; reads `/proc/PID/status` through one bounded no-follow descriptor. It is a `PASS` only for a live process whose `Tgid` equals the PID. A thread ID (`Tgid` differs), a zombie or dead process, and a PID with no `/proc` entry are `FAIL`; an unreadable entry is an `ERROR`.
- `systemd_service`: concrete `service` (`.service` is appended when omitted; patterns, templates, and other unit types are rejected) and timeout; checks `systemctl is-active` without capturing output, using a minimal environment and only a `systemctl` from an absolute `PATH` directory that only root or the caller can modify. A `systemctl` exit status of 0 is `PASS`, 3 or 4 is `FAIL`, and any other status, a timeout, or no trusted `systemctl` is `ERROR`.
- `file_exists`: `path`, refusing final symlinks.
- `file_metadata`: `path` plus optional `minimum_bytes` and `maximum_bytes`.
- `config_hash`: regular-file `path` and 64-digit `sha256`; reads at most 64 MiB through a no-follow descriptor and rejects identity changes.

Example:

```json
{
  "version": 1,
  "max_workers": 4,
  "checks": [
    {"name":"dns","type":"dns","host":"example.com","severity":"WARNING","profile":"production"},
    {"name":"web","type":"https","url":"https://example.com/health","depends_on":["dns"],"retries":1,"profile":"production"}
  ]
}
```

## Execution, output, and exits

Checks run on daemon threads, at most `max_workers` (eight at most) at a time. A check starts as soon as its own dependencies have finished, not when a whole layer has; configuration order is preserved in output. A check whose dependency did not pass (including a skipped one) is not run and is reported as `SKIPPED` with zero attempts. Retries apply only within the configured bound, stop at the first `PASS`, and wait 0.1, 0.2, then 0.3 seconds before successive retries. An unexpected failure inside one check becomes that check's `ERROR` instead of aborting the run. On Ctrl-C, scheduling stops at once: queued checks never start, running ones are abandoned rather than joined, and the exit status is 130.

HTTP(S) and certificate deadlines start before resolution; time spent resolving consumes the available connection/TLS budget, and each remaining candidate gets an equal share of the time left (at least 0.25 seconds). Once the budget is spent, no further network attempts start. HTTP redirects share the same deadline. TCP-only checks keep their per-candidate timeouts. Resolution, parsing of hosts, candidate handling, and the connect loop are the shared `opsforge.common.net` code that NetDoctor uses.

Each result is `PASS`, `FAIL` (a finding: the criterion was observed and not met), `ERROR` (the criterion could not be evaluated), or `SKIPPED`. A `PASS` has severity `OK`; a `FAIL` has the check's severity, `WARNING` or `CRITICAL`; `ERROR` and `SKIPPED` results established nothing and have no severity (JSON `null`, shown as `-`). The aggregate status is the most severe finding: `CRITICAL` or `WARNING`; with no finding it is `OK` when everything passed, `INCOMPLETE` when some checks passed but others errored or were skipped, and `ERROR` when nothing could be evaluated.

| Exit | Meaning |
| --- | --- |
| 0 | `OK`: every selected check passed. |
| 1 | `WARNING` or `CRITICAL`: at least one check failed. A finding decides the exit even when other checks errored. |
| 2 | Invalid configuration or invocation. |
| 3 | `INCOMPLETE` or `ERROR` with no finding, or an observation or `--output` failure. |
| 130 | Interrupted. |

`--brief`, schema-version-1 `--json`, `--quiet`, safe `--output FILE`, and `--force` follow the shared contract. Human output ends with an aggregate conclusion. JSON `observations.summary` counts `pass`, `fail_warning`, `fail_critical`, `error`, and `skipped` results; `--brief` shows `PASS/FAIL/ERROR/SKIPPED` counts and names each non-passing check with its reason.

## Safety, privacy, and limits

HealthCtl never accepts shell commands, scripts, plugins, environment interpolation, credentials, headers, or request bodies and never remediates. HTTP(S) checks ignore ambient proxy configuration. HTTPS and certificate checks use Python's default trust store, which honors `SSL_CERT_FILE` and `SSL_CERT_DIR` from the environment; `SSLKEYLOGFILE` is ignored. It reads only explicit local targets and contacts only configured network targets. Paths, names, endpoints, hashes, and results can be sensitive. A passed criterion proves only that narrow observation during this run—not overall host/service health or root cause.

## Automation and development references

For JSON fields, output destinations, quiet-mode behavior, and cross-utility exit
semantics, see [CLI and evidence contracts](../../docs/CONTRACTS.md). The tool-specific
inputs, evidence, bounds, and limitations above remain authoritative for this utility.
See [AI-assisted usage](../../docs/AI_USAGE.md) before interpreting observations as health
or taking a follow-up action. Contributors can use the focused test commands in
[CONTRIBUTING.md](../../CONTRIBUTING.md).
