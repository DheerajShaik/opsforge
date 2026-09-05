# ProcWatch

ProcWatch is an experimental Linux diagnostic utility that samples one explicitly selected process twice and reports bounded CPU and memory evidence from Linux procfs. It answers: for this PID, did the same observed process remain available across the sampling interval, how much process CPU time accumulated, what one-logical-CPU utilization does that imply, and how did selected process state, thread, resident-memory, and virtual-memory values change?

ProcWatch does not decide whether a process is abnormal, healthy, unhealthy, leaking memory, overloaded, or responsible for an incident. A short sample without a workload baseline, cgroup or quota context, host pressure, and application semantics cannot support those conclusions reliably.

## Requirements

- Linux with procfs mounted at `/proc`
- Python 3
- no external commands or third-party packages

## Usage

```console
python3 procwatch/procwatch.py PID
python3 procwatch/procwatch.py PID --interval SECONDS
python3 procwatch/procwatch.py --help
```

`PID` must be a positive decimal integer. The sampling delay defaults to 1 second and may be set from 0.1 through 60 seconds inclusive. ProcWatch does not discover or rank processes in V1; the caller chooses exactly one PID.

## Observation model

ProcWatch opens `/proc/PID` read-only as a directory and keeps that directory descriptor open for the observation. It then opens and reads `stat` relative to that descriptor for each sample. Linux `O_CLOEXEC`, `O_DIRECTORY`, `O_NOFOLLOW`, and `O_NONBLOCK` are used where Python exposes them. Descriptor metadata is checked as a directory before sampling.

Each `stat` read is bounded to 64 KiB (65,536 bytes). A larger record, NUL-containing record, unsupported record shape, missing required field, invalid required integer, or read failure is not silently truncated or guessed. The initial sample must be trustworthy before any normal report is possible.

The two samples are separated by the requested sleep interval. ProcWatch records a monotonic timestamp immediately after each bounded `stat` read and uses the difference between those timestamps as the observed sample interval. The observed interval can therefore be slightly different from the requested delay.

Procfs is live kernel state, not an atomic snapshot. Individual fields can change while a record is being generated, the process can change state between reads, and ProcWatch does not freeze or attach to the target.

## Process identity

ProcWatch validates that the PID encoded in each `stat` record matches the requested PID. It also records Linux `starttime` ticks from field 22. A complete delta report requires the second sample to carry the same start-time value as the initial sample.

The open process-directory descriptor already narrows pathname races and PID-reuse ambiguity; the start-time comparison is an additional identity check. If a trustworthy second sample cannot be obtained, if the identity token changes, or if cumulative CPU counters move backwards, ProcWatch preserves the useful initial snapshot, marks the observation incomplete, withholds delta calculations, emits a warning, and exits with code 1.

## Fields observed

V1 reads only `/proc/PID/stat` and uses these process fields:

- PID
- command name (`comm`)
- process state code
- parent PID
- user CPU ticks
- system CPU ticks
- thread count
- process start-time ticks since boot
- virtual-memory size
- resident-set size in pages

ProcWatch intentionally does not read `/proc/PID/cmdline`, `/proc/PID/environ`, open-file lists, sockets, maps, stack data, credentials, namespaces, cgroup files, or other procfs records in V1.

The command name is treated as untrusted display data. Backslashes, terminal controls, Unicode format controls, line/paragraph separators, malformed UTF-8 bytes preserved through `surrogateescape`, and surrogates are escaped before display.

## CPU evidence

For a complete observation, ProcWatch subtracts the initial process user and system CPU counters from the final counters. Linux clock ticks are converted to seconds using `SC_CLK_TCK`.

The displayed utilization is:

```text
(process user CPU delta + process system CPU delta)
--------------------------------------------------- * 100
             observed wall interval
```

This is utilization relative to one logical CPU. A multithreaded process can therefore exceed 100%. It is not normalized by machine CPU count and is not adjusted for CPU affinity, cpusets, cgroup CPU quotas, throttling, steal time, scheduler delay, or host load.

The result is a short sampled measurement, not a historical average or anomaly score. CPU time accumulated by child processes is not added as a separate child-usage metric.

## Memory evidence

Resident-set pages from `stat` are converted using `SC_PAGE_SIZE`. ProcWatch reports initial and final resident-set size and their signed difference. It also reports initial and final virtual-memory size and their signed difference.

RSS is a lightweight process-residency observation, not private memory, proportional set size, cgroup charge, allocator usage, working-set size, peak memory, or proof of a leak. Linux procfs documentation explicitly describes the RSS value in `/proc/PID/stat` as inaccurate; ProcWatch reports it only as sampled evidence and does not upgrade it into a stronger memory claim. A positive RSS delta over one short interval does not establish a leak, and a flat or negative delta does not establish healthy memory behavior.

## Other process evidence

For complete observations, ProcWatch displays initial and final process state codes, parent PIDs, and thread counts. It does not interpret the Linux state code as severity or health, and it does not infer why a parent or thread count changed.

The process start-time tick value is displayed as an identity token. ProcWatch does not convert it into a wall-clock process start timestamp.

## Exit codes and streams

| Code | Meaning |
| --- | --- |
| `0` | Help, or a complete two-sample observation for the same process identity. |
| `1` | A useful initial process report was produced, but a trustworthy same-identity second sample or delta report was unavailable. |
| `2` | Invalid invocation or the initial target could not be opened/read as the requested process. |
| `3` | No trustworthy useful report could be produced because required system parameters, timing, observation shape, or internal execution failed. |
| `130` | Interrupted by SIGINT / Ctrl-C. |

Help and complete or useful-incomplete reports go to stdout. Invalid-target, fatal-observation, and interruption messages go to stderr. An incomplete report is printed to stdout and its warning is printed to stderr. Unexpected failures use stable wording without a traceback.

## Permissions, security, and privacy

ProcWatch uses only the caller's existing procfs permissions and never elevates privileges. It is read-only and performs no process signaling, priority changes, affinity changes, tracing, ptrace attachment, cgroup modification, filesystem modification, remediation, or process control.

ProcWatch is local and offline. It has no subprocess, shell, application-level network communication, telemetry, upload, external AI, database, cache, configuration file, or persistent analysis state.

Even though V1 deliberately avoids command-line arguments and environment variables, process names, PIDs, parent relationships, thread counts, and resource measurements can still reveal operational information. Treat captured output as potentially sensitive before storing or sharing it.

## Tests

Run the standard-library suite from the repository root:

```console
python3 -m unittest discover -s procwatch/tests -v
```

Compile-check the implementation with:

```console
python3 -m py_compile procwatch/procwatch.py
```

## V1 limitations and non-goals

V1 has no process discovery, process list, ranking, `top`-style refresh loop, daemon mode, historical baseline, anomaly score, thresholds, alerting, persistence, JSON output, configuration, remote/container selection, cgroup or namespace analysis, host-load correlation, CPU affinity analysis, scheduler-delay analysis, I/O rates, network rates, file-descriptor analysis, open-file inspection, command-line or environment inspection, memory maps, PSS, peak-memory analysis, per-thread sampling, signal delivery, remediation, root-cause analysis, or production-readiness claim.

Those capabilities may be considered only when concrete operational requirements justify expanding the utility.
