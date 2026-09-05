# LogHound

LogHound is an experimental Linux diagnostic utility that summarizes recurring normalized messages in one explicitly selected local regular log file. It answers: within the bounded bytes observed from that file, which normalized nonblank messages occur at least twice, how often do they occur, and where do they occur in physical file order?

Recurrence is textual evidence only. LogHound is not an anomaly, severity, incident, health, security, or root-cause detector. Frequent messages do not establish failure, and an absence of recurring or error-looking messages does not establish health.

## Requirements

- Linux
- Python 3
- no external commands or third-party packages

## Usage

```console
python3 loghound/loghound.py PATH
python3 loghound/loghound.py --help
```

Exactly one path is required. Relative and absolute paths are accepted. There is no default, stdin mode, configuration file, or other V1 option. The displayed target is absolute and lexically normalized; it is not claimed to be a canonical physical path.

## Target and observation scope

The final opened object must be a non-symlink regular file. Missing paths, final-component symlinks, directories, FIFOs, sockets, devices, and other non-regular objects are rejected. Parent path components may contain symlinks. LogHound uses read-only, final-component no-follow and nonblocking open flags where Linux provides them, then treats descriptor metadata as authoritative. These measures do not prevent every pathname-resolution race.

Immediately after opening and validating the descriptor, LogHound captures its initial `st_size`. Files larger than 256 MiB (268,435,456 bytes) are rejected. The captured size is the observation boundary: LogHound reads no more than that many bytes, does not refresh the size, and excludes later appends.

V1 analyzes uncompressed content. It recognizes only these leading content signatures: gzip, bzip2, xz, ZIP, and Zstandard. Recognized content is rejected without decompression. Detection is finite and is not universal compression or archive detection. Filenames are not content types, so an ordinary text file named `application.log.gz` is accepted.

## Bytes, encoding, and lines

Input is read as bounded binary chunks and decoded per logical line as UTF-8 with `errors="surrogateescape"`. Malformed UTF-8 bytes therefore remain losslessly distinct. A NUL byte anywhere in the observation boundary makes the input unsupported and fatally ends analysis.

Byte LF separates logical records. The LF is removed; if the record then ends in one CR, that CR is removed as CRLF handling. Other CR bytes are preserved. A final nonempty unterminated record is a line, while a trailing LF does not invent an extra record. One-based physical line numbers include blank lines.

The maximum logical line is 1 MiB (1,048,576 bytes), excluding its line ending. A longer line is fatal and is neither truncated, skipped, nor partially counted. Empty lines, Unicode-whitespace-only lines, and lines whose normalized messages are blank remain physical lines but do not enter analysis.

## Normalization

LogHound performs exactly one normalization beyond line-ending removal. At character position zero, it recognizes:

```text
YYYY-MM-DDTHH:MM:SS[.fraction](Z|+HH:MM|-HH:MM)
```

Digits must be ASCII, fixed fields must have the displayed widths, `T` and `Z` must be uppercase, fractional seconds must contain at least one digit, and date, time, and offset fields must pass Python standard-library validation. The timestamp must be followed by at least one ASCII space. When all conditions hold, LogHound removes the timestamp and every immediately following ASCII space.

Otherwise it removes nothing. In particular, timezone-less, legacy syslog, bracketed, lowercase `t`/`z`, malformed, indented, and later-occurring timestamps are preserved. A tab is not a qualifying separator.

No PIDs, numbers, UUIDs, addresses, ports, paths, request IDs, hexadecimal values, names, severity tokens, capitalization, or general whitespace are normalized. Timestamp values are not retained or interpreted, and LogHound performs no chronological, duration, rate, or burst analysis.

## Recurrence, ranking, and output

The complete normalized decoded string is the pattern key. A pattern is recurring when its count is at least two; the threshold is fixed. Singleton patterns contribute to analyzable-line and distinct-pattern totals but are not listed.

At most ten recurring patterns are displayed. They are ordered by:

1. count descending;
2. first physical line ascending;
3. last physical line ascending;
4. complete key encoded with UTF-8 plus `surrogateescape`, bytewise ascending.

Each displayed record gives count, its percentage of all analyzable normalized lines to two decimal places, and first and last physical line numbers. These line numbers describe file order, not parsed timestamp chronology. Strings such as `DEBUG`, `WARN`, and `ERROR` are ordinary case-sensitive text and receive no classification or priority.

Normal output has fixed `Target`, `Observation`, `Analysis summary`, `Recurring patterns`, and `Interpretation limits` sections. Pattern excerpts use at most the first 160 decoded Unicode code points before escaping. Longer values receive `... [truncated]`; the complete value still controls equality. Backslashes, malformed bytes, terminal controls, Unicode format controls, line/paragraph separators, and surrogates are escaped. Output uses no terminal styling or width detection.

## Exit codes and streams

| Code | Meaning |
| --- | --- |
| `0` | Help, or a complete bounded analysis with no known required-observation gap. |
| `1` | A useful report was produced from a completely observed analyzable prefix, but the initial boundary was not fully observed. |
| `2` | Invalid invocation or invalid/unsupported target. |
| `3` | No trustworthy useful report could be produced because of an observation, data-shape, resource, or internal failure. |
| `130` | Interrupted by SIGINT / Ctrl-C. |

Message content never determines exit status. Help and complete or useful-incomplete reports go to stdout. Errors, incomplete-observation warnings, and interruption messages go to stderr. Unexpected failures use stable wording without a traceback.

A useful incomplete report requires at least one fully observed analyzable nonblank normalized line. Only complete lines are included; an in-progress record is discarded. A blank-only prefix is not useful. NUL and overlong-line failures remain fatal even after valid lines and discard accumulated normal output. User interruption never produces a partial report.

## Mutable files and resources

LogHound does not provide an atomic snapshot. Appends beyond the captured size are excluded. Truncation can produce a defined incomplete prefix or fatal failure. Rotation or pathname replacement does not redirect the already opened descriptor, and an opened file may remain readable after deletion on Linux. In-place rewrites can make the observed bytes reflect multiple live states. LogHound does not lock, copy, hash, re-read, or verify the file for consistency.

Scanning takes time proportional to observed bytes. Input reading is streaming, but exact normalized keys are retained. Memory grows with distinct-pattern count, total key size, and Python object overhead; a pathological 256 MiB input can require substantially more than 256 MiB of memory.

## Permissions, security, and privacy

LogHound uses only the caller's existing filesystem permissions and never elevates privileges. It performs no intentional content, permission, ownership, configuration, service, or process modification. Ordinary reads may update filesystem-managed metadata such as access time, depending on filesystem and mount behavior.

LogHound is local, offline, and read-only. It has no subprocess, shell, application-level network communication, telemetry, upload, external AI, remediation, database, cache, or persistent analysis state.

Log excerpts may contain credentials, tokens, personal or customer information, usernames, hostnames, addresses, URLs, request data, paths, or stack traces. The excerpt limit is an output bound, not secret or personal-information redaction. Treat output as potentially sensitive and review it before storing or sharing it.

## Tests

Run the standard-library suite from the repository root:

```console
python3 -m unittest discover -s loghound/tests -v
```

## V1 limitations and non-goals

V1 has no stdin or multiple-file input, directories, discovery, globs, rotated-log discovery, decompression, journald, remote/container/cloud sources, follow mode, daemon, shipping, monitoring, alerts, persistence, configuration, or structured JSON output. It performs no severity classification, anomaly or rarity detection, baselines, machine learning, timestamp chronology, incident/security/health/root-cause assessment, multiline reconstruction, semantic log-format parsing, plugins, user regex normalization, variable-token substitution, secret detection, or remediation.
