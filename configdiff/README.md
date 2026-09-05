# ConfigDiff

ConfigDiff is an experimental Linux diagnostic utility that compares one explicitly selected local regular file with one explicitly selected baseline regular file and reports whether their observed byte content is exactly identical. It answers one narrow question: did the current file's observed bytes drift from the baseline file's observed bytes?

ConfigDiff does not parse configuration syntax, decide whether either file is valid, determine whether a changed setting is effective, classify severity, identify who or what caused a change, or recommend remediation. Exact byte equality is content evidence only; it is not proof that a service is correctly configured or healthy.

## Requirements

- Linux
- Python 3
- no external commands or third-party packages

## Usage

```console
python3 configdiff/configdiff.py BASELINE CURRENT
python3 configdiff/configdiff.py --help
```

Exactly two paths are required. `BASELINE` is the expected reference file and `CURRENT` is the file being checked. Relative and absolute paths are accepted. ConfigDiff has no default paths, discovery, stdin mode, configuration file, or environment-variable input in V1.

Displayed paths are absolute and lexically normalized. They are not claimed to be canonical physical paths.

## Comparison model

ConfigDiff opens both requested paths read-only and keeps both descriptors open for the comparison. The final opened objects must be regular files. Final-component symlinks, directories, FIFOs, sockets, devices, and other non-regular objects are rejected. Parent path components may contain symlinks.

Where Linux exposes them through Python, ConfigDiff uses `O_CLOEXEC`, `O_NOFOLLOW`, and `O_NONBLOCK` in addition to read-only open mode. Descriptor metadata is authoritative after opening. These measures reduce some pathname and blocking hazards but do not prevent every pathname-resolution race.

Each file may be at most 16 MiB (16,777,216 bytes) in V1. The size captured immediately after opening is the read boundary. ConfigDiff reads exactly that many bytes and then verifies that no additional byte is present at that descriptor offset. It also checks descriptor device, inode, size, modification-time, and change-time metadata after both reads. A short read, growth past the captured boundary, metadata change, or read/verification failure prevents a trustworthy comparison and exits with code 3 rather than silently comparing an unstable observation.

Both files are opened before either is read. Path replacement after open does not redirect an already opened descriptor. ConfigDiff does not lock, copy, freeze, or atomically snapshot either file, so it cannot eliminate every possible concurrent-change race. Its result applies to the opened objects and bytes that passed the documented consistency checks.

V1 retains the two bounded byte strings in memory long enough to make the exact equality decision and calculate their digests. At the 16 MiB-per-file limit, payload buffers can therefore approach 32 MiB in addition to Python and hashing overhead. The returned comparison result does not retain the raw file contents.

## Drift definition

V1 defines drift strictly as byte inequality:

- same length and exactly the same bytes: no content drift;
- any byte addition, removal, replacement, encoding change, whitespace change, comment change, line-ending change, or ordering change: content drift detected.

The comparison is binary-safe. ConfigDiff does not decode either file and does not reject NUL or malformed text bytes. It does not ignore comments, whitespace, generated fields, timestamps, ordering, or format-specific semantics.

Because the equality decision is made from the actual observed byte strings, SHA-256 is supporting evidence in the report rather than the equality decision itself.

## Output

Normal output reports:

- the baseline absolute displayed path, observed byte count, and SHA-256 digest;
- the current absolute displayed path, observed byte count, and SHA-256 digest;
- `NO CONTENT DRIFT` or `CONTENT DRIFT DETECTED`;
- short interpretation limits.

ConfigDiff deliberately does not print configuration-file contents, line diffs, excerpts, changed keys, or inferred values in V1. Configuration files commonly contain credentials, tokens, endpoints, internal names, or other sensitive operational data. A content-revealing diff mode may be considered later only with an explicit security and output design.

Paths and operating-system error text are treated as untrusted display data. Backslashes, terminal controls, Unicode format controls, line/paragraph separators, malformed path bytes preserved through Python surrogate handling, and surrogates are escaped before display. Output uses no terminal styling or width detection.

## Exit codes and streams

| Code | Meaning |
| --- | --- |
| `0` | Help, or a trustworthy comparison whose observed byte content is exactly identical. |
| `1` | A trustworthy comparison completed and content drift was detected. |
| `2` | Invalid invocation or an invalid/unsupported baseline or current target. |
| `3` | No trustworthy comparison could be produced because an input changed during observation or an observation/internal failure occurred. |
| `130` | Interrupted by SIGINT / Ctrl-C. |

The drift result intentionally affects exit status so ConfigDiff is composable in shell scripts and CI. Normal match/drift reports go to stdout. Invalid-target, observation, interruption, and internal-failure messages go to stderr. Unexpected failures use stable wording without a traceback.

## Permissions, security, and privacy

ConfigDiff uses only the caller's existing filesystem permissions and never elevates privileges. It is read-only and performs no intentional content, permission, ownership, configuration, service, or process modification. Ordinary reads may update filesystem-managed metadata such as access time, depending on filesystem and mount behavior.

ConfigDiff is local and offline. It has no subprocess, shell, application-level network communication, telemetry, upload, external AI, database, cache, persistence, or remediation.

V1 avoids printing file contents, but paths, sizes, digests, and the fact that two files match or differ can still reveal operational information. SHA-256 digests can also fingerprint known content. Treat captured output as potentially sensitive before storing or sharing it.

## Tests

Run the standard-library suite from the repository root:

```console
python3 -m unittest discover -s configdiff/tests -v
```

Compile-check the implementation with:

```console
python3 -m py_compile configdiff/configdiff.py
```

## V1 limitations and non-goals

V1 has no directories, recursive comparison, file discovery, globs, manifests, package-manager state, Git integration, remote/container/cloud sources, service-manager integration, multiple-file baselines, baseline creation, persistence, watch mode, daemon, alerts, JSON output, configuration file, semantic parsing, format awareness, key-level comparison, comment/whitespace normalization, templating, secret detection, line diff, excerpt output, ownership/permission drift verdicts, timestamp drift verdicts, symlink-target comparison, remediation, rollback, root-cause analysis, policy enforcement, or production-readiness claim.

Those capabilities may be considered only when concrete operational requirements justify expanding the utility.
