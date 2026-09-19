# LogHound

LogHound performs bounded, local recurrence analysis on one regular text log and up to three explicitly requested numeric rotations. It never uploads logs or invokes cloud/LLM services.

## Usage

```console
loghound /var/log/app.log
loghound app.log --top 25 --include ERROR --exclude healthcheck
loghound app.log --window-seconds 3600 --rotated 2 --json
```

`--top` is 1-100 (default 10). Include and exclude are literal, case-sensitive substrings, each repeatable at most 16 times; values are printable and at most 256 characters. `--window-seconds` is 1-31,536,000. `--rotated` is 0-3 and reads `PATH.1`, `PATH.2`, and `PATH.3` without discovery or decompression.

## Input, bounds, and analysis

Each final-component target must be a non-symlink regular file no larger than 256 MiB. Reads stop at the size captured after open; logical lines are capped at 1 MiB. Known gzip, bzip2, xz, ZIP, and Zstandard signatures are rejected.

Normalization removes valid leading RFC3339 timestamps and conservatively replaces validated IPv4 addresses, UUIDs, labelled PIDs, and labelled request/trace/user/job IDs. It deliberately retains unlabeled numbers, ports, paths, case, and spacing. Severity is keyword-based evidence, not a health verdict.

The report includes recurring pattern counts, severity counts, timestamp span, approximate message rate, peak timestamp-minute burst, bounded earlier/later-period counts, and recognized Python/Java-style stack-trace groups (maximum 256 recognized lines per group). Stack evidence counts/grouping do not reconstruct arbitrary multiline events or infer exception causes.

Rotated sources share one earliest/latest timestamp range and merged minute counts. Overlapping minutes add their messages; gaps between rotations remain part of the observed span. Rate uses timestamped analyzed messages only. Earlier/later periods split the global minute range at its midpoint. Physical source order and line evidence remain current file, then numbered rotations. At most 10,000 distinct minute buckets are retained; overflow marks the analysis partial and makes peak/period counts unavailable, while the timestamp span remains available. Untimestamped messages still contribute to pattern and severity evidence.

## Output and exits

Status is `OBSERVED` or `PARTIAL`. Exit 0 means the requested bounded input was analyzed, 1 means useful but incomplete evidence (including missing requested rotations), 2 means invalid target/invocation, 3 means no trustworthy analysis, and 130 means interrupted.

`--brief`, schema-version-1 `--json`, `--quiet`, safe `--output FILE`, and `--force` follow the suite contract. Human output ends with the standard conclusion. Incomplete warnings remain on stderr.

## Privacy and limits

Log content, paths, IPs, identifiers, and excerpts may be sensitive even after conservative normalization. Output should be reviewed before sharing. LogHound does not follow, tail, decompress, query journald, parse every timestamp/log format, detect secrets, determine incident severity, identify root cause, or remediate. File observation is live rather than atomic.
