# SvcDoctor

SvcDoctor is an experimental Linux diagnostic utility that reports the current systemd state and direct execution evidence for one local system service. It reports systemd evidence; it does not determine application root cause, desired state, health, readiness, or remediation.

## Scope and semantics

SvcDoctor queries the local systemd **system manager** about exactly one concrete `.service` unit. Bare names receive `.service`, so `nginx` becomes `nginx.service`. Concrete instances such as `worker@3` and `worker@3.service` are supported. Uninstantiated templates such as `worker@.service`, paths, and non-service units are rejected.

One invocation performs one read-only `systemctl show` query for exactly:

```text
Id
LoadState
ActiveState
SubState
Result
ExecMainCode
ExecMainStatus
```

`Id`, `LoadState`, and `ActiveState` are required for a normal diagnostic. Missing or empty supporting evidence is displayed as `-`. `ExecMainCode` and `ExecMainStatus` are separate raw systemd values; SvcDoctor does not decode their application or signal meaning.

SvcDoctor classifies a service as currently failed only when `ActiveState` is exactly `failed`. Exit `0` means only that the observed `ActiveState` was not exactly `failed`; it does **not** mean healthy, ready, correctly configured, or that an inactive service should be running.

`LoadState=not-found` is a missing-unit error. Neither `Result=success` nor the `systemctl` process exit status proves that a service exists or is not failed.

## Requirements

- Linux
- Python 3
- a local `systemctl` and systemd system manager

Compatibility has so far been empirically validated only on Ubuntu with systemd 255.4. Broader distribution and systemd-version support is not yet claimed.

## Usage

```console
python3 svcdoctor/svcdoctor.py SERVICE
python3 svcdoctor/svcdoctor.py --help
```

Examples:

```console
python3 svcdoctor/svcdoctor.py nginx
python3 svcdoctor/svcdoctor.py nginx.service
python3 svcdoctor/svcdoctor.py worker@3.service
```

## Output

Successful output has fixed `Target`, `State`, `Execution evidence`, and `Assessment` sections. The assessment states only whether `ActiveState` equals `failed`.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Help, or a successful observation where `ActiveState` is not exactly `failed`. |
| `1` | A successful observation where `ActiveState` is exactly `failed`. |
| `2` | Invocation, missing-unit, or observation failure. |

The `systemctl` process return code is not mirrored as SvcDoctor's service-state result.

## Permissions, safety, and privacy

SvcDoctor uses the caller's existing privileges and never invokes `sudo`, `su`, or `pkexec`. It is read-only and performs no service control, configuration changes, journal inspection, dependency traversal, remote access, network requests, telemetry, analytics, or update checks. It uses a fixed subprocess argument array without a shell and sanitizes untrusted display values.

The local observation command has a five-second timeout. SvcDoctor performs no retries, polling, or fallback queries.

## Live-system limitation

SvcDoctor reports values returned by one live `systemctl show` query, not an atomic snapshot. A service may change state during or immediately after the query, and supporting execution evidence may describe an earlier execution.

## Tests

Run the standard-library test suite from the repository root:

```console
python3 -m unittest discover -s svcdoctor/tests -v
```
