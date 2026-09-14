# HealthCtl

HealthCtl is the strict, bounded composition layer for OpsForge-style health criteria. It reads one explicit JSON file, evaluates dependency-safe groups, and reports `PASS`, `FAIL`, or `ERROR` without arbitrary command execution or remediation.

## Usage

```console
healthctl health.json
healthctl health.json --profile production --group edge --workers 4
healthctl health.json --json
```

The configuration file must be a no-follow regular UTF-8 file no larger than 64 KiB. Duplicate JSON keys, unknown fields, unsupported types, cycles, missing/self dependencies, and unsafe values are rejected. Root fields are `version` (currently integer `1`), `checks` (1-32), and optional `max_workers` (1-8, default 4).

Every check has `name`, `type`, optional `severity` (`WARN` or `CRITICAL`, default `CRITICAL`), `group`, `profile`, `depends_on`, and `retries` (0-3). Names/groups/profiles are 1-64 restricted ASCII characters. CLI `--profile`/`--group` select exact names; all dependencies must remain selected. `--workers` overrides bounded parallelism.

## Check types

- `disk_free_percent`: `path`, `minimum_free_percent` 0-100.
- `tcp_connect`: strict `host`, `port` 1-65535, optional `timeout_seconds` 0.1-5 (default 1); at most 16 resolver candidates.
- `http` / `https`: credential-free same-scheme ASCII `url` (at most 2,048 characters) without query or fragment, optional exact `expected_status` 100-599 (default 200), and total post-resolution deadline 0.1-5 seconds. Uses a proxy-free HEAD request, default HTTPS trust/identity verification, at most 64 KiB of response headers, and at most three same-origin/same-transport redirects without query or fragment; no authorization header or response body is sent/read.
- `dns`: strict `host`, with at most 16 unique addresses. OS resolution has no safe cancellable standard-library timeout.
- `certificate_expiry`: `host`, optional `port` (443), timeout, `warn_days` (30), and `critical_days` (7). The handshake uses default trust and hostname verification; revocation is not checked.
- `process`: positive `pid`; checks only that the procfs process directory is observable.
- `systemd_service`: concrete `service` and timeout; checks `systemctl is-active` without capturing output.
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

Ready checks run in dependency layers with at most eight workers; configuration order is preserved in output. A failed/error dependency skips dependents visibly. Retries apply only within the configured bound.

Passing checks have severity `OK`; negative results retain `WARN`/`CRITICAL`, while observation errors are critical. Aggregate status is `OK`, `WARN`, or `CRITICAL`. Exit 0 means all selected checks passed, 1 means at least one failed with no error, 2 means invalid configuration/invocation, 3 means at least one error or an execution/output failure, and 130 means interrupted.

`--brief`, schema-version-1 `--json`, `--quiet`, safe `--output FILE`, and `--force` follow the shared contract. Human output ends with an aggregate conclusion.

## Safety, privacy, and limits

HealthCtl never accepts shell commands, scripts, plugins, environment interpolation, credentials, headers, or request bodies and never remediates. HTTP(S) checks ignore ambient proxy configuration. It reads only explicit local targets and contacts only configured network targets. Paths, names, endpoints, hashes, and results can be sensitive. A passed criterion proves only that narrow observation during this run—not overall host/service health or root cause.
