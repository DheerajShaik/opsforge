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

One bounded `systemctl show` query reports load/active/sub states, result, main-process execution status/code, signal/exit interpretation, restart count/policy, last active-entry timestamp, fragment path, drop-ins, direct Requires/Requisite/BindsTo/Wants dependencies, CPU use, memory/task limits and current use, and selected user/group/dynamic-user context. Up to 32 unique direct dependencies of any unit type are checked for failed state.

Recent evidence uses `journalctl --system --reverse --unit ID --lines N` with the unit's reported `Id`, so an alias reaches its real unit; `--journal-lines 0` skips the query. The newest N lines are kept in chronological order; each raw line is capped at 512 characters (marked `... [truncated]`) and escaped in human output. Subprocess argument arrays are shell-free; subprocesses run with a minimal `C`-locale, `TZ=UTC` environment, have five-second timeouts, and cap stdout and stderr at 64 KiB (256 KiB for `journalctl`, where oversized stdout is cut to keep the newest lines, with a warning if fewer than N remain). Suggested follow-up commands use the shell-quoted `Id`, are informational, and are never executed.

Dependency evidence requires one recognized state per queried unit and a consistent command exit status. Confirmed zero failures render as `none of N checked`, or `none checked (no dependencies)` when the unit lists none, with JSON `failed_dependencies: []` and `dependencies_observed: true`. JSON `dependencies_checked` lists the dependency names selected for checking; `dependencies_truncated` is `true` when more than 32 existed, and rendered results then note that only the first 32 were checked. Failed, malformed, or unavailable dependency queries render as `unavailable`, JSON `failed_dependencies: null` and `dependencies_observed: false`, and a warning. Trustworthy main service state and its exit semantics remain available despite optional dependency failure, but `DEPENDENCY-FAILED` cannot then be established.

SvcDoctor never starts, stops, restarts, reloads, enables, disables, masks, or unmasks a unit. It does not print service environment variables.

## Output and exits

Status comes from the first matching rule: `FAILED` (`ActiveState=failed`), `LOAD-ERROR` (`LoadState` is `bad-setting` or `error`), `RESTARTING` (`SubState=auto-restart`, a crash loop), `DEGRADED` (`ActiveState` is not `active` and the reported `Result` is not `success`), or `DEPENDENCY-FAILED` (`ActiveState` is not `active` and a checked dependency is failed); otherwise it is the uppercased `ActiveState`: `ACTIVE`, `INACTIVE`, `ACTIVATING`, `DEACTIVATING`, `RELOADING`, `MAINTENANCE`, or `REFRESHING`. Exit 0 means no service failure was established; it does not require the service to be active. Exit 1 means one of the five failure statuses above; exit 2 covers invalid invocation, unavailable tools/manager, a unit that is not found, permissions, malformed/oversized output, timeout, and output failure; exit 130 means interrupted. A `not-found` unit that systemd still reports in a state other than `inactive`, such as a deleted unit that is still running or failed, is diagnosed instead.

`--brief`, schema-version-1 `--json`, `--quiet`, safe `--output FILE`, and explicit `--force` follow the common contract. Human output ends with the standard conclusion. Optional journal unavailability is a warning rather than a fabricated empty success.

## Requirements, privacy, and limits

A Linux systemd system manager, `systemctl`, and (for journal evidence) `journalctl` are required; each is used only from an absolute `PATH` directory, and both that directory and the executable must be modifiable only by root or the caller. Caller permissions and unit/journal policy determine visibility. Unit names, paths, process IDs, users, cgroups, resource usage, dependencies, and journal lines may be sensitive. Evidence is live and non-atomic; it does not prove readiness, explain root cause, inspect transitive dependency chains, or remediate failure.
