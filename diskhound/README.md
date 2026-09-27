# DiskHound

DiskHound is a bounded, read-only Linux filesystem diagnostic. It combines filesystem capacity/inode context with allocation-focused ranking, largest-file, age, sparse-file, and extension-group evidence without following symlinks or silently crossing filesystems.

## Usage

```console
diskhound PATH
diskhound PATH --top 20 --max-depth 8 --max-entries 50000
diskhound PATH --min-size 10485760 --exclude '*.cache' --age-days 90
diskhound PATH --cross-filesystems --json
```

`--top` is 1-100 (default 10), `--max-depth` is 1-256 levels below PATH (default 64; 1 ranks immediate entries by their own allocation), and `--max-entries` is 1-1,000,000 (default 100,000). Each directory is independently capped at 100,000 entries. `--min-size` is a decimal byte count (default 0). `--exclude` is repeatable up to 32 printable relative-path glob patterns of at most 256 characters. `--age-days` is 0-36,500 (default 30).

Traversal stays on the target device unless `--cross-filesystems` is explicit; skipped immediate and nested cross-device entries are counted separately (JSON `cross_device_immediate_excluded` and `cross_device_nested_skipped`). Final and encountered symlinks are not followed. Directories at `--max-depth` are not descended; each one that is non-empty, or cannot be checked, counts as depth-limited and makes the scan partial.

The global entry budget includes enumeration and metadata attempts, including excluded, cross-device, and inaccessible entries. Enumeration retains at most the remaining budget, with one extra directory entry used only to detect truncation. Retained children are sorted before processing; when a directory exceeds the budget, its retained subset depends on filesystem enumeration order. Already observed metadata is retained, further descent stops, and one global entry-limit warning marks the scan partial. An unexamined directory at the budget boundary is conservatively partial even if it might be empty. The per-directory ceiling still applies when the global limit is larger.

## Evidence and interpretation

The report includes byte capacity and inode use for the target filesystem, target-directory allocation, unique observed allocation with hard-link de-duplication, top immediate branches, largest individual regular files, logical versus allocated bytes, sparse-file count, old-file count, suffix groups, visited/excluded/cross-device/depth-limited counts, partial reasons, and inaccessible or raced entries.

Branches are ranked by allocated bytes and largest files by logical bytes. `--min-size` filters only the detailed human report, hiding branches whose logical and allocated bytes are both below it and files whose logical bytes are below it. Sparse means logical size exceeds observed allocation and does not diagnose why. Concentration and age are observations, not deletion advice. Filesystems may report delayed, compressed, shared, reserved, or synthetic allocation differently.

## Output and exit codes

Status is `OBSERVED` or `PARTIAL`; `PARTIAL` reasons (observation failures, entry limits, depth-limited directories, or unavailable capacity) appear in the human observation line, the conclusion, and JSON `incomplete_reasons`. Exit 0 means the bounded scan completed, 1 means useful but incomplete evidence, 2 means an invalid target/invocation, 3 means no trustworthy diagnostic could be produced, and 130 means interrupted. Partial warnings remain on stderr, including with `--quiet`; depth-limited directories are reported only as partial reasons, not as warnings.

`--brief`, schema-version-1 `--json`, `--quiet`, `--output FILE`, and explicit `--force` follow the shared safe-output contract. Human output ends with the standard conclusion line.

## Permissions, privacy, and limits

DiskHound performs no network activity or mutation and never elevates privileges. Paths, metadata, sizes, ages, and filenames can still be sensitive. Directory trees are live rather than atomic; entries may change or disappear. Mount-namespace visibility and caller permissions define scope. The tool does not decide what is safe to remove, diagnose storage hardware, inspect file content, or remediate capacity.
