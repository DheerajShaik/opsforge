# DiskHound

DiskHound is a bounded, read-only Linux filesystem diagnostic. It combines filesystem capacity/inode context with allocation-focused ranking, largest-file, age, sparse-file, and extension-group evidence without following symlinks or silently crossing filesystems.

## Usage

```console
diskhound PATH
diskhound PATH --top 20 --max-depth 8 --max-entries 50000
diskhound PATH --min-size 10MiB --exclude '*.cache' --age-days 90
diskhound PATH --cross-filesystems --json
```

`--top` is 1-100 (default 10), `--max-depth` is 0-256 (default 64), and `--max-entries` is 1-1,000,000 (default 100,000). Each directory is independently capped at 100,000 entries. `--min-size` accepts bounded byte quantities. `--exclude` is repeatable up to 32 printable relative-path glob patterns of at most 256 characters. `--age-days` is 0-36,500 (default 30).

Traversal stays on the target device unless `--cross-filesystems` is explicit. Final and encountered symlinks are not followed.

The global entry budget includes enumeration and metadata attempts, including excluded, cross-device, and inaccessible entries. Enumeration retains at most the remaining budget, with one extra directory entry used only to detect truncation. Retained children are sorted before processing; when a directory exceeds the budget, its retained subset depends on filesystem enumeration order. Already observed metadata is retained, further descent stops, and one global entry-limit warning marks the scan partial. An unexamined directory at the budget boundary is conservatively partial even if it might be empty. The per-directory ceiling still applies when the global limit is larger.

## Evidence and interpretation

The report includes byte capacity and inode use for the target filesystem, target-directory allocation, unique observed allocation with hard-link de-duplication, top immediate branches, largest individual regular files, logical versus allocated bytes, sparse-file count, old-file count, suffix groups, visited/excluded/depth-limited counts, and inaccessible or raced entries.

Ranking uses allocated bytes; `--min-size` filters ranked branches by logical bytes. Sparse means logical size exceeds observed allocation and does not diagnose why. Concentration and age are observations, not deletion advice. Filesystems may report delayed, compressed, shared, reserved, or synthetic allocation differently.

## Output and exit codes

Status is `OBSERVED` or `PARTIAL`. Exit 0 means the bounded scan completed, 1 means useful but incomplete evidence, 2 means an invalid target/invocation, 3 means no trustworthy diagnostic could be produced, and 130 means interrupted. Partial warnings remain on stderr, including with `--quiet`.

`--brief`, schema-version-1 `--json`, `--quiet`, `--output FILE`, and explicit `--force` follow the shared safe-output contract. Human output ends with the standard conclusion line.

## Permissions, privacy, and limits

DiskHound performs no network activity or mutation and never elevates privileges. Paths, metadata, sizes, ages, and filenames can still be sensitive. Directory trees are live rather than atomic; entries may change or disappear. Mount-namespace visibility and caller permissions define scope. The tool does not decide what is safe to remove, diagnose storage hardware, inspect file content, or remediate capacity.
