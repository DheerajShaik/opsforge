# SvcDoctor

SvcDoctor is a read-only diagnostic for one concrete local systemd service. It gathers structured unit, execution, dependency, resource, activation, and bounded recent-journal evidence without changing service state.

## Usage

```console
svcdoctor nginx
svcdoctor example@worker.service --journal-lines 50
svcdoctor ssh.service --brief
```

Bare names receive `.service`. Globs, template-only units, non-service suffixes, control characters, and option-like targets are rejected. `--journal-lines` is 0-200 and defaults to 20.

## Evidence

One bounded `systemctl show` query reports load/active/sub states, result, main/control PID and execution status/code, signal/exit interpretation, restart count/policy, activation timestamps, fragment path, drop-ins, direct Requires/Wants dependencies, CPU/memory/task limits and current use, and selected user/group/dynamic-user context. Up to 32 direct service dependencies are checked for failed state.

Recent evidence uses `journalctl --system --unit UNIT --lines N`; lines are escaped and truncated to 512 characters. Subprocess argument arrays are shell-free, have five-second timeouts, and cap stdout and stderr at 64 KiB. Suggested follow-up commands are informational and never executed.

Dependency evidence requires one recognized state per queried unit and a consistent command exit status. Confirmed zero failures render as `none observed` and JSON `failed_dependencies: []` with `dependencies_observed: true`. Failed, malformed, or unavailable dependency queries render as `unavailable`, JSON `failed_dependencies: null` and `dependencies_observed: false`, and a warning. Trustworthy main service state and its exit semantics remain available despite optional dependency failure.

SvcDoctor never starts, stops, restarts, reloads, enables, disables, masks, or unmasks a unit. It does not print service environment variables.

## Output and exits

Status is `ACTIVE`, `INACTIVE`, or `FAILED`. Exit 0 means `ActiveState` was observed and was not `failed`; it does not require the service to be active. Exit 1 means `ActiveState=failed`; exit 2 covers invalid invocation, unavailable tools/manager, permissions, malformed/oversized output, timeout, and output failure; exit 130 means interrupted.

`--brief`, schema-version-1 `--json`, `--quiet`, safe `--output FILE`, and explicit `--force` follow the common contract. Human output ends with the standard conclusion. Optional journal unavailability is a warning rather than a fabricated empty success.

## Requirements, privacy, and limits

A Linux systemd system manager, `systemctl`, and (for journal evidence) `journalctl` are required. Caller permissions and unit/journal policy determine visibility. Unit names, paths, process IDs, users, cgroups, resource usage, dependencies, and journal lines may be sensitive. Evidence is live and non-atomic; it does not prove readiness, explain root cause, inspect transitive dependency chains, or remediate failure.
