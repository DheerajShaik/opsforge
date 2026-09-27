# ProcWatch

ProcWatch is a read-only Linux procfs sampler for one caller-selected process. It reports bounded CPU, memory, I/O, descriptor, socket, context-switch, child, thread, and cgroup evidence without attaching to or modifying the process.

## Usage

```console
procwatch PID
procwatch PID --samples 10 --interval 0.5
procwatch PID --duration 30
procwatch PID --continuous 20 --json
```

PID is a strict decimal 1-2147483647. Interval is 0.1-60 seconds (default 1). `--samples` and `--continuous` are 2-100; default is two samples. `--duration` is 0.1-3600 seconds; its sample count is one more than the number of whole `--interval` steps in the duration (2-100, and enough that no gap exceeds 60 seconds), and the effective interval divides the duration evenly between samples. The three sampling selectors are mutually exclusive, so no invocation runs forever.

## Observation model

Every main sample is anchored to a no-follow `/proc/PID` directory and checks the stat PID/start-time identity. Exit (including a zombie `Z` or dead `X` state), replacement, malformed procfs evidence, or PID reuse stops sampling instead of silently joining different processes. Once the first sample has been read, stopping keeps the samples already captured and reports `PARTIAL` (exit 1); with at least two, CPU and memory results cover those samples.

Auxiliary collection is bracketed by start-tick checks on the same open procfs descriptor. Both initial and final auxiliary identities must match the main analysis identity; mismatches discard the affected sample with a warning. Initial cgroup context is also discarded on an identity mismatch. Final auxiliary evidence is not collected when sampling stops early, and no auxiliary delta is calculated without two correlated samples. This does not make individual procfs fields an atomic snapshot.

Main evidence includes state, parent PID, thread count, CPU ticks and elapsed/normalized CPU use, virtual size, resident pages/bytes, and memory change. Best-effort initial/final auxiliary evidence adds FD/socket counts, read/write bytes, voluntary/nonvoluntary context switches, up to 256 child PIDs, and CPU counters for the lowest 256 thread IDs. Thread counters are matched across samples by thread ID and start time and show as `N of M (truncated)` when the process has more threads; child PIDs come from those threads' `children` lists and are marked `(truncated)` when more than 256 exist or the thread cap left threads unread. Procfs enumeration is capped at 100,000 FD or task entries; beyond that the affected evidence is unavailable with a warning. Cgroup v2 evidence reports the process cgroup path and the tightest `cpu.max` and `memory.max` found from that cgroup up to the cgroup2 mount root, naming the cgroup level that set each limit; `max` at every readable level is reported as no limit.

Growth wording is deliberately observational: memory or FD increases do not establish a leak. CPU percentage is bounded-sample evidence, not a scheduler or health verdict.

## Output and exits

Status is `OBSERVED` or `PARTIAL`. Exit 0 means a stable requested observation completed, 1 means useful but incomplete evidence, 2 means invalid target/invocation, 3 means no trustworthy observation, and 130 means interrupted. Auxiliary gaps appear as warnings and do not invent zero values.

`--brief`, schema-version-1 `--json`, `--quiet`, safe `--output FILE`, and explicit `--force` follow the shared output contract. Human output ends with the standard conclusion. JSON observations include `sample_count` (captured), `requested_sample_count`, `requested_interval_seconds` (the `--interval` value), `effective_interval_seconds`, `observed_interval_seconds`, `clock_ticks_per_second`, `page_size_bytes`, `cpu_utilization_percent`, `initial_rss_bytes`, `final_rss_bytes`, `rss_delta_bytes`, the `initial`/`final` and `auxiliary_initial`/`auxiliary_final` samples (auxiliary samples add `thread_count`, `threads_truncated`, and `children_truncated`), `cgroup`, and `cpu_constraint`/`memory_constraint` with the level in `cpu_constraint_source`/`memory_constraint_source` (`null` when no level sets a limit); other unobserved values are also `null`.

## Privacy, permissions, and limits

ProcWatch never reads `cmdline`, `environ`, memory maps, file contents, or socket payloads. Process names, IDs, cgroup paths, children, and resource values can still be sensitive. Kernel hidepid, namespaces, cgroups, and caller permissions can reduce visibility. Local syscalls have no hard cancellation guarantee. ProcWatch does not discover/rank processes, attach a debugger, send signals, diagnose leaks, determine root cause, or remediate.
