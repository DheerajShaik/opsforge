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

Exit statuses are named the way `systemctl status` names them: `status 1 (FAILURE)`, `203 (EXEC)`, `217 (USER)`, and so on, with a note that 200-245 are the statuses systemd uses when it cannot set up or execute the command. Signals are named too (`signal 9 (SIGKILL)`, and `dumped core after signal 11 (SIGSEGV)`).

A limit set on the unit is not always the limit that applies, because the slices above it can be tighter. One more `systemctl show` query reads the unit's slice and every parent slice (derived from the dashes in the slice name, ending at `-.slice`, and checked against each slice's own `Slice=`). Each of `MemoryMax`, `MemoryHigh`, `CPUQuotaPerSecUSec`, and `TasksMax` is shown as the unit's own value and the effective one: the tightest across the unit and its slices, naming the nearest level that sets it (`effective 20887 (tightest; set by user-1000.slice)`), or `no limit at any level`. JSON `slice_chain` and `effective_limits` carry the same. If the slice query fails or a value is missing or unrecognized, the affected limits are reported `unavailable` with a warning, and the rest of the diagnosis is unaffected.

Recent evidence uses `journalctl --system --reverse --unit ID --lines N` with the unit's reported `Id`, so an alias reaches its real unit; `--journal-lines 0` skips the query. The newest N lines are kept in chronological order; each raw line is capped at 512 characters (marked `... [truncated]`) and escaped in human output. Subprocess argument arrays are shell-free; subprocesses run with a minimal `C`-locale, `TZ=UTC` environment, have five-second timeouts, and cap stdout and stderr at 64 KiB (256 KiB for `journalctl`, where oversized stdout is cut to keep the newest lines, with a warning if fewer than N remain). Suggested follow-up commands use the shell-quoted `Id`, are informational, and are never executed.

Dependency evidence requires one recognized state per queried unit and a consistent command exit status. Confirmed zero failures render as `none of N checked`, or `none checked (no dependencies)` when the unit lists none, with JSON `failed_dependencies: []` and `dependencies_observed: true`. JSON `dependencies_checked` lists the dependency names selected for checking; `dependencies_truncated` is `true` when more than 32 existed, and rendered results then note that only the first 32 were checked. Failed, malformed, or unavailable dependency queries render as `unavailable`, JSON `failed_dependencies: null` and `dependencies_observed: false`, and a warning. Trustworthy main service state and its exit semantics remain available despite optional dependency failure, but `DEPENDENCY-FAILED` cannot then be established. A running service is still reported as a success, but a stopped one is reported `INCOMPLETE` (see below), because a failed dependency might be why it is stopped.

SvcDoctor never starts, stops, restarts, reloads, enables, disables, masks, or unmasks a unit. It does not print service environment variables.

## Output and exits

Status comes from the first matching rule: `FAILED` (`ActiveState=failed`), `LOAD-ERROR` (`LoadState` is `bad-setting` or `error`), `RESTARTING` (`SubState=auto-restart`, a crash loop), `DEGRADED` (`ActiveState` is not `active` and the reported `Result` is not `success`), or `DEPENDENCY-FAILED` (`ActiveState` is not `active` and a checked dependency is failed); then `INCOMPLETE` (`ActiveState` is not `active` and the dependencies could not be checked, or only the first 32 were, so a dependency failure cannot be ruled out); otherwise it is the uppercased `ActiveState`: `ACTIVE`, `INACTIVE`, `ACTIVATING`, `DEACTIVATING`, `RELOADING`, `MAINTENANCE`, or `REFRESHING`. The human report states `Service failure established:` as `yes`, `no`, or `undetermined`.

| Exit | Meaning |
| --- | --- |
| 0 | No service failure was established. It does not require the service to be active. |
| 1 | One of the five failure statuses above. |
| 2 | Invalid invocation, or a service that does not exist or that systemd rejects as a target. |
| 3 | No trustworthy answer: `INCOMPLETE`, `systemctl` or the system manager unavailable, permission denied, malformed or oversized output, timeout, or an `--output` failure. |
| 130 | Interrupted. |

When `systemctl` itself fails, the error is classified from its C-locale stderr (manager unavailable, permission denied, rejected target) and carries the first line of stderr, bounded to 200 characters and escaped. A `not-found` unit that systemd still reports in a state other than `inactive`, such as a deleted unit that is still running or failed, is diagnosed instead.

`--brief`, schema-version-1 `--json`, `--quiet`, safe `--output FILE`, and explicit `--force` follow the common contract. Human output ends with the standard conclusion. Optional journal unavailability is a warning rather than a fabricated empty success.

## Requirements, privacy, and limits

A Linux systemd system manager, `systemctl`, and (for journal evidence) `journalctl` are required; each is used only from an absolute `PATH` directory, and both that directory and the executable must be modifiable only by root or the caller. Caller permissions and unit/journal policy determine visibility. Unit names, paths, users, slice names, timestamps, resource usage, dependencies, and journal lines may be sensitive. Evidence is live and non-atomic; it does not prove readiness, explain root cause, inspect transitive dependency chains, or remediate failure.
