# LogHound

LogHound performs bounded, local recurrence analysis on one regular text log and up to three explicitly requested numeric rotations. It never uploads logs or invokes cloud/LLM services.

## Usage

```console
loghound /var/log/app.log
loghound app.log --top 25 --include ERROR --exclude healthcheck
loghound app.log --window-seconds 3600 --rotated 2 --json
```

`--top` is 1-100 (default 10). Include and exclude are literal, case-sensitive substrings, each repeatable at most 16 times; values are at most 256 characters without control, format, or line/paragraph separator characters (backslashes are allowed). `--window-seconds` is 1-31,536,000. `--rotated` is 0-3 and reads `PATH.1`, `PATH.2`, and `PATH.3` without discovery or decompression.

## Input, bounds, and analysis

Each final-component target must be a non-symlink regular file no larger than 256 MiB. PATH is opened as given, so `..` after a symlinked directory resolves the way the kernel resolves it. Reads stop at the size captured after open. Lines longer than 1 MiB are truncated to 1 MiB and NUL bytes (for example from a zero-filled or sparse region after a crash) are removed; both are counted and make the analysis partial instead of discarding it. Known gzip, bzip2, xz, ZIP, and Zstandard signatures are rejected.

Normalization removes one leading timestamp: RFC 3339/ISO 8601 (`T`, `t`, or space separator; optional `.` or `,` fraction; `Z`, `z`, `+HH:MM`, `+HHMM`, or no zone) or RFC 3164 syslog (`Sep  5 12:34:56`). Zone-less timestamps are read as local time and counted. RFC 3164 has no year, so LogHound uses the latest year that does not place the entry more than one day after the file's modification time, which handles December-to-January rollover. Normalization then replaces validated IPv4 and IPv6 addresses, UUIDs of any version, syslog tag PIDs (`sshd[4242]:`), labelled PIDs and ports (`pid=12`, `port 22`), and labelled request/trace/user/job IDs, including JSON-quoted labels such as `"pid": 12`. It retains unlabeled numbers, paths, case, and spacing.

Severity is evidence, not a health verdict. An explicit level wins: a syslog `<PRI>` prefix, a glog `E0905 12:34:56` prefix, a `level=`/`severity=` field (including JSON), an uppercase level word such as `ERROR` or `WARN` in the first 128 characters, or a bracketed `[error]`. Otherwise keywords are used, ignoring path segments such as `/error` and zero or negated forms such as `failed=0`, `fatal=false`, `no errors`, and `0 errors`.

The report includes recurring pattern counts, severity counts, timestamp span, approximate message rate, peak timestamp-minute burst, bounded earlier/later-period counts, and recognized stack-trace groups (maximum 256 recognized lines per group). A Python group covers `Traceback` headers, frames, source and caret lines, the final exception line, and chained tracebacks joined by `During handling of the above exception` or `The above exception was the direct cause`. A Java group covers an exception header line, `at` frames including module-qualified JDK 9+ frames, `... N more`, `Caused by:`, and `Suppressed:`; `Exception in thread` starts a new group. Grouping does not reconstruct arbitrary multiline events or infer exception causes.

`--window-seconds N` keeps lines timestamped within N seconds before now. An undated line inherits the latest timestamp above it in the same file, so stack frames follow their record. Undated lines with no earlier timestamp are excluded, counted, and make the analysis partial, so an unparseable log never looks like a quiet one.

Rotated sources share one earliest/latest timestamp range and merged minute counts. Overlapping minutes add their messages; gaps between rotations remain part of the observed span. Rate uses timestamped analyzed messages only. Earlier/later periods split the global minute range at its midpoint. Physical source order and line evidence remain current file, then numbered rotations. Every source is opened before any is read, and a rotation that is the same file (device and inode) as an earlier source is skipped. A rotation that cannot be opened or analyzed is reported with its reason and makes the analysis partial; only a failure of PATH itself is fatal. At most 46,080 distinct minute buckets (32 days) and 100,000 distinct normalized patterns are retained; overflow is counted and marks the analysis partial. Minute overflow makes peak/period counts unavailable while the timestamp span remains available. Untimestamped messages still contribute to pattern and severity evidence.

## Output and exits

Status is `OBSERVED` or `PARTIAL`. Exit 0 means the requested bounded input was analyzed, 1 means useful but incomplete evidence (including missing or unreadable requested rotations, truncated lines, removed NUL bytes, undated lines under a window, and pattern or minute limits), 2 means invalid target/invocation, 3 means no trustworthy analysis, and 130 means interrupted.

`--brief`, schema-version-1 `--json`, `--quiet`, safe `--output FILE`, and `--force` follow the suite contract. Human output ends with the standard conclusion. Incomplete warnings remain on stderr. JSON reports `distinct_patterns`, `recurring_patterns`, per-source `unavailable_sources` reasons, and the counters above. Each JSON pattern `key` is at most 160 code points, with `key_truncated`, `key_length`, and `key_digest` (BLAKE2b-128 of the full normalized key); undecodable bytes appear as `\xNN` text.

## Privacy and limits

Log content, paths, IPs, identifiers, and excerpts may be sensitive even after conservative normalization. Output should be reviewed before sharing; JSON carries bounded excerpts rather than whole lines. LogHound does not follow, tail, decompress, query journald, parse every timestamp/log format, detect secrets, determine incident severity, identify root cause, or remediate. File observation is live rather than atomic.
