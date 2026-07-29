# DiskHound v0.1 Validation

DiskHound v0.1 was validated with both automated tests and manual Linux/WSL2 checks before the first-version behavior was frozen.

## Automated validation

From the repository root:

```console
python3 -m unittest discover -s diskhound/tests -v
```

Result at validation time:

```text
Ran 44 tests
OK
```

The suite covers normal CLI behavior, parsing, formatting, ranking, allocation accounting, hard-link handling, symlink behavior, partial failures, warning handling, terminal-safe output, and other frozen v0.1 semantics.

## Manual Linux/WSL2 validation

The following behaviors were exercised directly against a live WSL2 Linux environment.

| Scenario | Observed result |
| --- | --- |
| Controlled directory allocation | Immediate branches ranked correctly by allocated bytes, with directory inode allocation included. |
| Sparse file | A 10 GiB sparse file with zero allocated blocks was reported as `0 B`, confirming `st_blocks * 512` semantics rather than apparent file size. |
| Hard links | Duplicate links within one branch counted once for that branch; a shared inode reachable from sibling branches counted once per branch but once in the global unique total. |
| Descendant symlinks | Symlink targets were not traversed; symlink metadata allocation only was observed. |
| Final target symlink | Rejected as an invalid target with exit code `2`. |
| Partial permission failure | Unreadable descendant directory produced a useful incomplete report, warning on stderr, and exit code `1`. |
| Fatal target-level permission failure | An unreadable target directory could not be enumerated and produced exit code `3` without a normal report. |
| FIFO | FIFO was observed metadata-only, did not block, and reported zero allocation. |
| Unix-domain socket | Socket was observed metadata-only without connection or blocking and reported zero allocation. |
| Cross-device immediate entries | Scanning `/mnt` in WSL2 excluded `/mnt/c`, `/mnt/wsl`, and `/mnt/wslg` because their `st_dev` values differed from `/mnt`; exclusion was not treated as an error. |
| SIGINT / Ctrl-C | Interrupted scan exited with status `130`. |
| Real `/var` scan | Permission-dependent observation gaps were surfaced while useful branch ranking was still produced with exit code `1`. |
| Real drill-down | Scanning `/var/cache` correctly narrowed the largest `/var` branch to its immediate consumers while preserving incomplete-observation warnings. |
| Warning suppression | 25 unreadable branches produced 20 individual deterministic warnings plus `diskhound: warning: 5 additional observation failures were suppressed`, with exit code `1`. |
| Nonexistent target | Rejected with exit code `2`. |
| Regular-file target | Rejected as not a directory with exit code `2`. |

## Representative real-world observations

A normal-user scan of `/var` produced a useful incomplete result with 16 permission-related observation failures. The largest observed immediate branches were `/var/cache`, `/var/lib`, and `/var/log`.

Drilling into `/var/cache` identified `/var/cache/apt` as the dominant immediate branch while separately reporting three unreadable locations.

These checks demonstrate the intended workflow: use DiskHound to identify the next branch worth inspecting while retaining explicit visibility into observation gaps.

## Interpretation

This validation supports the frozen DiskHound v0.1 contract on the environment exercised. It does not make DiskHound production-ready or imply support for every Linux filesystem, mount topology, race condition, permission model, or storage implementation.

The existing documented limitations still apply, including live-filesystem non-atomicity, permission-dependent visibility, `st_blocks` interpretation limits, same-device bind-mount limitations, and the distinction between filesystem capacity and pathname-tree allocation.

Future feature work should preserve these v0.1 semantics unless a deliberate versioned contract change is made.
