# HealthCtl

HealthCtl is the strict, bounded composition layer for OpsForge-style health criteria. It reads one explicit JSON file, evaluates dependency-safe groups, and reports `PASS`, `FAIL`, `ERROR`, or `SKIPPED` without arbitrary command execution or remediation.

## Usage

```console
healthctl health.json
healthctl health.json --profile production --group edge --workers 4
healthctl health.json --json
```

The configuration file must be a no-follow regular UTF-8 file no larger than 64 KiB. Duplicate JSON keys, unknown fields (including fields that belong to another check type), unsupported types, cycles, missing/self dependencies, and unsafe values are rejected. Root fields are `version` (currently integer `1`), `checks` (1-32), and optional `max_workers` (1-8, default 4).

Every check has `name`, `type`, optional `severity` (`WARN` or `CRITICAL`, default `CRITICAL`), `group`, `profile`, `depends_on`, and `retries` (0-3). Names/groups/profiles are 1-64 restricted ASCII characters. CLI `--profile`/`--group` select exact names; all dependencies must remain selected. `--workers` overrides bounded parallelism.

## Check types

- `disk_free_percent`: `path`, `minimum_free_percent` 0-100.
- `tcp_connect`: strict `host`, `port` 1-65535, optional `timeout_seconds` 0.1-5 (default 1); tries at most the first 16 distinct resolver candidates, moving to the next after a socket or connection error, and notes in the evidence when more were returned.
- `http` / `https`: credential-free same-scheme ASCII `url` (at most 2,048 characters) without query or fragment, optional exact `expected_status` 100-599 (default 200), and total post-resolution deadline 0.1-5 seconds. Uses a proxy-free HEAD request, default HTTPS trust/identity verification, at most 64 KiB of response headers, and at most three same-origin/same-transport redirects without query or fragment (a redirect beyond that policy, including a malformed `Location`, is an `ERROR`); no authorization header or response body is sent/read.
- `dns`: strict `host`; reports at most the first 16 unique addresses and notes in the evidence when more were returned. OS resolution has no safe cancellable standard-library timeout.
- `certificate_expiry`: `host`, optional `port` (443), timeout 0.1-5 seconds, `warn_days` (30), and `critical_days` (7). Uses the same validated resolver/candidate path as TCP/HTTP, at most 16 distinct candidates, and one deadline shared across connection attempts and TLS. The handshake uses default CA trust, hostname verification, and appropriate SNI; revocation is not checked. No proxies are used. An expired or not-yet-valid certificate is `FAIL` with `CRITICAL` severity, other verification failures are `FAIL` at the configured severity, and resolution, connection, timeout, or other TLS failures are `ERROR`.
- `process`: positive `pid`; checks only that the procfs process directory is observable.
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
    {"name":"dns","type":"dns","host":"example.com","severity":"WARN","profile":"production"},
    {"name":"web","type":"https","url":"https://example.com/health","depends_on":["dns"],"retries":1,"profile":"production"}
  ]
}
```

## Execution, output, and exits

Ready checks run in dependency layers with at most eight workers; configuration order is preserved in output. A check whose dependency did not pass (including a skipped one) is not run and is reported as `SKIPPED` with zero attempts. Retries apply only within the configured bound, stop at the first `PASS`, and wait 0.1, 0.2, then 0.3 seconds before successive retries. An unexpected failure inside one check becomes that check's `ERROR` instead of aborting the run.

HTTP(S) and certificate deadlines start before resolution; time spent resolving consumes the available connection/TLS budget. The OS resolver itself cannot be hard-cancelled and may overrun that deadline. Once control returns, expired budgets prevent further network attempts. HTTP redirects also share the same deadline. TCP-only checks retain their documented per-candidate timeouts.

Passing and skipped checks have severity `OK`; negative results retain `WARN`/`CRITICAL`, while observation errors are critical. Aggregate status is `OK`, `WARN`, or `CRITICAL`. Exit 0 means all selected checks passed, 1 means at least one failed with no error, 2 means invalid configuration/invocation, 3 means at least one error or an execution/output failure, and 130 means interrupted.

`--brief`, schema-version-1 `--json`, `--quiet`, safe `--output FILE`, and `--force` follow the shared contract. Human output ends with an aggregate conclusion. JSON `observations.summary` counts `pass`, `fail_warn`, `fail_critical`, `error`, and `skipped` results; `--brief` shows `PASS/FAIL/ERROR/SKIPPED` counts and names each non-passing check.

## Safety, privacy, and limits

HealthCtl never accepts shell commands, scripts, plugins, environment interpolation, credentials, headers, or request bodies and never remediates. HTTP(S) checks ignore ambient proxy configuration. It reads only explicit local targets and contacts only configured network targets. Paths, names, endpoints, hashes, and results can be sensitive. A passed criterion proves only that narrow observation during this run—not overall host/service health or root cause.
