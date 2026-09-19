# ConfigDiff

ConfigDiff compares two explicit local files or two bounded directory trees. Exact byte equality remains the default; every content-revealing diff is opt-in.

## Usage

```console
configdiff BASELINE CURRENT
configdiff BASELINE CURRENT --ignore-whitespace
configdiff a.json b.json --json-semantic --keys service.port,feature.enabled
configdiff BASELINE CURRENT --unified --max-diff-lines 200
configdiff BASELINE_DIR CURRENT_DIR --directory --permissions --ownership --symlinks
```

File modes are mutually exclusive: exact (default), `--ignore-whitespace` (removes ASCII whitespace), `--ignore-comments` (ignores blank and full-line `#`/`;` comments), `--json-semantic`, or `--metadata-only`. Semantic JSON rejects duplicate keys; `--keys` accepts at most 64 comma-separated dotted keys of at most 256 characters and requires JSON mode.

`--unified` requires UTF-8 files, is capped by `--max-diff-lines` 1-1000 (default 200), reports truncation, and warns that secrets may be displayed. Each file is limited to 16 MiB.

Directory mode is capped by `--max-files` 1-10,000 (default 1,000) and `--max-depth` 0-32 (default 16), stays on the root device, never follows symlinks, and compares regular-file SHA-256 metadata. `--symlinks` compares link target text rather than following it. Directory mode cannot be mixed with file content modes.

## Evidence, status, and exits

Reports include normalized absolute paths, sizes and SHA-256 fingerprints; selected permission and numeric owner/group drift; or added/removed/changed tree paths. `--metadata-only` compares size, permission mode, UID, and GID without content. Exact and semantic equality do not prove that a configuration is valid or effective.

Status is `UNCHANGED` or `DRIFT`. Exit 0 means no difference under the selected semantics, 1 means drift, 2 means invalid target/invocation, 3 means an unstable/untrustworthy observation or output failure, and 130 means interrupted.

`--brief`, schema-version-1 `--json`, `--quiet`, safe `--output FILE`, and `--force` follow the shared contract. Human output ends with the standard conclusion.

## Security and limitations

Final file targets use no-follow descriptors and are rechecked for identity/size/time changes. Directory traversal is anchored to open no-follow directory descriptors; child opens are relative to their parent descriptor and checked against the observed device/inode before descent. Regular files are identity-checked before reading, and optional symlink text is rechecked after reading. Root symlinks are refused. Directory trees are live and cannot be atomic; detected replacement races fail visibly. Paths, hashes, metadata, link targets, and explicit unified content can be sensitive. No remediation or baseline creation occurs.

Semantic TOML is deferred because supported CPython 3.10 has no `tomllib`; adding a third-party runtime parser solely for this mode would violate the dependency policy. YAML and format-guessing are intentionally absent.
