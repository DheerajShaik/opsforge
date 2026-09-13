# ProcWatch

ProcWatch is a read-only Linux procfs sampler for one caller-selected process. It reports bounded CPU, memory, I/O, descriptor, socket, context-switch, child, thread, and cgroup evidence without attaching to or modifying the process.

## Usage

```console
procwatch PID
procwatch PID --samples 10 --interval 0.5
procwatch PID --duration 30
procwatch PID --continuous 20 --json
```

PID is a strict decimal 1-2147483647. Interval is 0.1-60 seconds (default 1). `--samples` and `--continuous` are 2-100; default is two samples. `--duration` is 0.1-3600 seconds and chooses at most 100 evenly spaced samples. The three sampling selectors are mutually exclusive, so no invocation runs forever.

## Observation model

Every main sample is anchored to a no-follow `/proc/PID` directory and checks the stat PID/start-time identity. Exit, replacement, malformed procfs evidence, or PID reuse produces partial/error semantics instead of silently joining different processes.

Main evidence includes state, parent PID, thread count, CPU ticks and elapsed/normalized CPU use, virtual size, resident pages/bytes, and memory change. Best-effort initial/final auxiliary evidence adds FD/socket counts, read/write bytes, voluntary/nonvoluntary context switches, up to 256 child PIDs, and up to 256 thread CPU counters. Procfs enumeration is capped at 100,000 FD entries. Cgroup v2 path, `cpu.max`, and `memory.max` are read when visible.

Growth wording is deliberately observational: memory or FD increases do not establish a leak. CPU percentage is bounded-sample evidence, not a scheduler or health verdict.

## Output and exits

Status is `OBSERVED` or `PARTIAL`. Exit 0 means a stable requested observation completed, 1 means useful but incomplete evidence, 2 means invalid target/invocation, 3 means no trustworthy observation, and 130 means interrupted. Auxiliary gaps appear as warnings and do not invent zero values.

`--brief`, schema-version-1 `--json`, `--quiet`, safe `--output FILE`, and explicit `--force` follow the shared output contract. Human output ends with the standard conclusion.

## Privacy, permissions, and limits

ProcWatch never reads `cmdline`, `environ`, memory maps, file contents, or socket payloads. Process names, IDs, cgroup paths, children, and resource values can still be sensitive. Kernel hidepid, namespaces, cgroups, and caller permissions can reduce visibility. Local syscalls have no hard cancellation guarantee. ProcWatch does not discover/rank processes, attach a debugger, send signals, diagnose leaks, determine root cause, or remediate.
