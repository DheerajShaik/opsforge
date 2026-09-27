# ConfigDiff

ConfigDiff compares two explicit local files or two bounded directory trees. Exact byte equality remains the default; every content-revealing diff is opt-in.

## Usage

```console
configdiff BASELINE CURRENT
configdiff BASELINE CURRENT --ignore-whitespace
configdiff a.json b.json --json-semantic --keys service.port,feature.enabled
configdiff BASELINE CURRENT --unified --max-diff-lines 200
configdiff BASELINE_DIR CURRENT_DIR --directory --permissions --ownership
```

File modes are mutually exclusive: exact (default), `--ignore-whitespace` (removes ASCII whitespace), `--ignore-comments` (ignores blank and full-line `#`/`;` comments, but keeps `#include`, `#includedir`, and `#<digit>` lines, which sudoers does not treat as comments), `--json-semantic`, or `--metadata-only`. Semantic JSON compares typed values, so `true`, `1`, and `1.0` differ, and rejects duplicate keys, `NaN`/`Infinity`, floats that overflow (such as `1e999`), and nesting too deep to process. `--keys` accepts at most 64 comma-separated non-empty dotted keys of at most 256 characters and requires JSON mode; a selected key absent from only one file is drift, and absent keys are listed as details.

`--unified` warns that secrets may be displayed and renders a diff only when content drift is detected; the diff requires UTF-8 files, is capped by `--max-diff-lines` 1-1000 (default 200), cuts lines at 1,000 characters, is skipped with a detail when an input exceeds 20,000 lines, and reports truncation. Each file is limited to 16 MiB.

Directory mode is capped by `--max-files` 1-10,000 (default 1,000), `--max-depth` 0-32 (default 16), and 512 MiB of total file reads; exceeding the file or read cap fails with exit 3. It stays on the root device, never follows symlinks, and compares each entry's type, regular-file size and SHA-256, symlink target text, and character/block device numbers. The root directory is compared as `.`, so `--permissions` and `--ownership` cover it too. Directories on other filesystems and non-empty directories at the `--max-depth` limit are not descended and are listed as not examined. `--symlinks` is accepted for compatibility and has no effect. Directory mode cannot be mixed with file content modes.

## Evidence, status, and exits

Reports include normalized absolute paths, sizes and SHA-256 fingerprints; content drift, selected permission and numeric owner/group drift, and details such as absent selected keys (JSON `content_drift`, `metadata_drift`, and `details`); or added/removed/changed and not-examined tree paths (JSON `unexamined`). `--metadata-only` uses size, permission mode, UID, and GID for comparison; bounded file reads still supply the displayed hashes. Normalized/semantic/metadata matches do not establish byte equality. Exact and semantic equality do not prove that a configuration is valid or effective.

Status is `UNCHANGED`, `DRIFT`, or `INCOMPLETE`; `INCOMPLETE` means directory mode found no drift among examined entries but left some directories unexamined, and drift takes precedence. Exit 0 means no difference under the selected semantics, 1 means drift, 2 means invalid target/invocation, 3 means `INCOMPLETE`, an unstable/untrustworthy observation, or output failure, and 130 means interrupted.

`--brief`, schema-version-1 `--json`, `--quiet`, safe `--output FILE`, and `--force` follow the shared contract. Human output ends with the standard conclusion.

## Security and limitations

Paths are `lstat`-checked before opening, so FIFOs and device nodes are rejected or compared by metadata instead of being opened. Final file targets use no-follow descriptors and are rechecked for identity/size/time changes. Directory traversal is anchored to open no-follow directory descriptors; child opens are relative to their parent descriptor and checked against the observed device/inode before descent. Regular files are identity-checked before reading, and symlink text is rechecked after reading. Root symlinks are refused. Directory trees are live and cannot be atomic; detected replacement races fail visibly. Paths, hashes, metadata, link targets, and explicit unified content can be sensitive. No remediation or baseline creation occurs.

Semantic TOML is deferred because supported CPython 3.10 has no `tomllib`; adding a third-party runtime parser solely for this mode would violate the dependency policy. YAML and format-guessing are intentionally absent.
