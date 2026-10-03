# CLI and evidence contracts

This is the cross-utility reference for the current Beta interface. Utility READMEs
define their options and evidence fields. Implementations share
[output.py](../opsforge/common/output.py) and [status.py](../opsforge/common/status.py).
The [root status policy](../README.md#status-and-exit-codes) is authoritative.

## Representations and destinations

- Default human output ends with a deterministic, terminal-safe
  `Conclusion: [STATUS] TARGET ... Next: ...` line when a result is emitted.
- `--brief` selects essential human evidence; `--json` selects the JSON envelope.
  These flags are mutually exclusive.
- `--quiet` suppresses ordinary stdout without changing diagnostic exit meaning.
  It does not universally suppress stderr. DiskHound and LogHound retain incomplete
  warnings; Incident Snapshot suppresses partial warnings in quiet mode.
- `--output FILE` writes the selected representation instead of stdout, including
  when combined with `--quiet`. Empty output paths are invalid.
- `--force` requires `--output`. Existing files require explicit force; symlink,
  non-regular, and multiply-linked overwrite targets are refused. Force writes and
  syncs a private temporary sibling, then replaces the destination name atomically.
  New output files use mode `0600`; replacement uses a fresh private inode.
- Rendered output is capped at 16 MiB. Exceeding it fails instead of emitting
  truncated JSON. Output-file failures always exit 3, even after a diagnostic finding.

`--help`, argument errors, collection failures, and output failures need not produce
a JSON envelope. Capture exit code and stderr separately; do not parse empty stdout
as JSON or combine stderr into the JSON stream. A closed stdout pipe is handled
without replacing the diagnostic exit status.

## JSON envelope, schema version 1

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | integer | Currently `1`; explicitly handle unsupported versions |
| `tool` | string | Utility identifier; `incidentsnapshot` for `incident-snapshot` |
| `status` | string | Aggregate answer state; its interpretation remains tool-specific |
| `target` | string | Display label for target/scope, not executable input |
| `observations` | object | Utility-specific evidence |
| `conclusion` | string | Human summary, not a stable decision field to parse |
| `next_action` | string | Advisory text; never execute it as code |
| `warnings` | array of strings | Accompanying limitations and warnings |
| `elapsed_seconds` | number | Nonnegative elapsed time, rounded to six decimal places |

JSON uses escaped non-ASCII text and deterministic key ordering. Consume keys and
types, not key order or exact timing. Datetimes become ISO strings, Decimals become
strings, and dataclass evidence becomes objects. Non-finite floating-point evidence
becomes null; JSON serialization rejects NaN/Infinity. This envelope is not a complete
schema for every utility's observations.

Unavailable, unobserved, empty, and zero remain distinct. Preserve null values,
evidence states, and warnings; no warnings alone does not establish service health.

## Shared exit policy

Use constants from `opsforge.common.status` in code, not duplicated numeric literals.

| Exit | Constant | Meaning |
| --- | --- | --- |
| 0 | `EXIT_OK` | Trustworthy expected answer or complete requested observation |
| 1 | `EXIT_FINDING` | Established finding, or useful partial observation from an observation-only utility |
| 2 | `EXIT_USAGE` | Invalid invocation/configuration or an invalid target |
| 3 | `EXIT_FAILURE` | No trustworthy answer, required observation failure, or output failure |
| 130 | `EXIT_INTERRUPTED` | Handled interruption |

An established finding decides exit 1 even when other observations are missing.
Without a finding, gaps that prevent a verdict produce exit 3, commonly `INCOMPLETE`
or `ERROR`. The observation-only tools (DiskHound, LogHound, ProcWatch, Incident
Snapshot) preserve useful partial evidence as `PARTIAL` with exit 1. Optional evidence
gaps do not automatically invalidate a trustworthy verdict; read the utility's policy.
An output failure overrides any finding and always exits 3.

## Utility answers within that policy

| Utility | Exit 0 answer | Exit 1 answer | Evidence limitation to inspect |
| --- | --- | --- | --- |
| [PortLens](../opsforge/portlens/README.md) | `FOUND`: a selected match observed | `NOT_FOUND`: no match | Incomplete/unparseable socket data without a match cannot establish absence and exits 3 |
| [DiskHound](../opsforge/diskhound/README.md) | `OBSERVED`: bounded scan complete | `PARTIAL`: useful incomplete evidence | Traversal budgets, inaccessible paths, races |
| [CertWatch](../opsforge/certwatch/README.md) | `VALID`: all targets verified | Most severe certificate finding | A finding outranks ERROR/SKIPPED targets; gaps alone yield INCOMPLETE/ERROR and exit 3 |
| [SvcDoctor](../opsforge/svcdoctor/README.md) | No service failure established; may be inactive | FAILED, LOAD-ERROR, RESTARTING, DEGRADED, or DEPENDENCY-FAILED | Stopped service with unavailable/truncated dependency evidence is INCOMPLETE and exits 3 |
| [LogHound](../opsforge/loghound/README.md) | `OBSERVED`: bounded input analyzed | `PARTIAL`: useful incomplete analysis | Rotations, truncated lines, window exclusions, pattern/minute caps |
| [ProcWatch](../opsforge/procwatch/README.md) | `OBSERVED`: requested stable sampling complete | `PARTIAL`: useful incomplete sampling | PID identity, process exit, auxiliary gaps |
| [ConfigDiff](../opsforge/configdiff/README.md) | `UNCHANGED` under selected semantics | `DRIFT`, even with unexamined paths | No drift plus unexamined paths is INCOMPLETE, exit 3 |
| [NetDoctor](../opsforge/netdoctor/README.md) | `CONNECTED`: selected TCP/TLS stage completed | `UNREACHABLE`: selected stage failed | Candidates that could not be tested do not establish failure; no trustworthy answer exits 3 |
| [HealthCtl](../opsforge/healthctl/README.md) | `OK`: every selected check passed | `WARNING`/`CRITICAL`: a check failed | With no finding, ERROR/SKIPPED gaps yield INCOMPLETE/ERROR and exit 3 |
| [Incident Snapshot](../opsforge/incidentsnapshot/README.md) | `OBSERVED`: requested collection complete | `PARTIAL`: useful partial snapshot | Per-section observed/partial/unavailable/error states |

For HealthCtl, per-check `PASS`/`FAIL`/`ERROR`/`SKIPPED` differs from aggregate status.
ERROR and SKIPPED have null severity, not an invented critical finding. CertWatch
ranks findings and preserves one record per target, including ERROR/SKIPPED targets.
Exit 0 never establishes more than the utility's documented question.

## Bounds and compatibility

Network tools share strict host parsing, candidate handling, and bounded resolver
waiting in `opsforge.common.net`. A timed-out OS lookup can remain on a daemon thread;
stopping the wait does not cancel the OS call. Connection budgets, total run limits,
concurrency, and helper deadlines differ by utility. Local syscalls still do not have
universal hard cancellation. Consult the utility README before changing a bound.

Preserve CLI defaults and current shared policy. For contract changes, identify
affected consumers, add behavioral regressions, explain migration, and decide whether
schema/version changes are required. Update code and docs together. The support
policy is in [README.md](../README.md); revision-specific evidence is in
[VALIDATION.md](../VALIDATION.md).
