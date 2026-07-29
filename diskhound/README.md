# DiskHound

DiskHound is an experimental Linux diagnostic utility that reports capacity context for one explicitly selected directory's filesystem and ranks eligible immediate entries by recursively observed allocated space. It helps an operator choose the next branch to inspect without modifying the filesystem.

## Scope and semantics

DiskHound accepts exactly one directory and performs a single-process, single-threaded, metadata-only scan. It does not read file contents, hash data, clean files, recommend deletion, elevate privileges, or invoke external commands.

Allocated bytes are calculated from Linux inode metadata as:

```text
st_blocks * 512
```

Directory inodes, symlink inodes, and metadata-reported allocation for special objects count. DiskHound never intentionally follows an entry observed as a symlink and never intentionally traverses a symlink target. A final-component target symlink is rejected.

The accepted target's `st_dev` defines the scan device. Entries on another device are excluded from allocation and traversal. Cross-device immediate entries are reported separately and do not enter the ranking denominator. This is device awareness, not complete mount-topology awareness: same-device bind mounts may still be traversed.

## Usage

```console
python3 diskhound/diskhound.py PATH
python3 diskhound/diskhound.py --help
```

There is no default target. Absolute paths, relative paths, `.`, explicit `/`, and trailing slashes are accepted when they identify an inspectable directory. The displayed target is absolute and lexically normalized, not claimed to be a canonical physical path.

## Output

DiskHound prints:

- target and scan scope;
- complete or incomplete observation status;
- filesystem `Total`, `Used`, `Filesystem free`, `Available to caller`, and caller-oriented `Use%`;
- target-directory allocation;
- globally deduplicated Unique observed target allocation;
- eligible and cross-device-excluded immediate-entry counts;
- at most ten eligible immediate entries ranked by exact allocated bytes.

Every displayed byte quantity includes an IEC value and its authoritative exact integer bytes, for example `8.4 GiB (9019431321 bytes)`. Exact bytes, not rounded display values, determine totals and ranking.

Filesystem capacity and observed tree allocation are separate observations and need not reconcile. Capacity includes filesystem-wide information that a pathname walk cannot attribute, while tree observations depend on visibility and live inode metadata.

## Hard links

Within one immediate branch, an inode identified by `(st_dev, st_ino)` counts once. If an inode is reachable through multiple eligible sibling branches, it counts once in each branch; DiskHound does not invent a pathname owner.

Unique observed target allocation includes the target directory once and every successfully observed eligible descendant inode once globally. Consequently, branch totals are not additive and their sum may exceed the global unique total. Neither value represents unique physical storage, exclusive ownership, or reclaimable bytes; CoW, reflinks, compression, and shared extents can further limit physical interpretation.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Diagnostic completed with no known required-observation gaps. |
| `1` | A useful diagnostic was produced, but known observation or capacity-context gaps exist. |
| `2` | Invalid invocation or invalid target. |
| `3` | DiskHound could not produce a useful target ranking. |
| `130` | Interrupted by SIGINT / Ctrl-C. |

Known descendant failures are reported on stderr, while useful partial results remain on stdout. At most 20 deterministic path-specific warnings are shown; any additional count is reported in one suppression warning. Capacity-context failure has a separate warning and does not prevent an otherwise useful tree scan.

## Live filesystem and permissions

DiskHound does not require root or elevate privileges. Permissions determine visibility. A target-level failure is fatal; descendant failures normally make a useful result incomplete.

The scan is not a filesystem snapshot or a security boundary. Entries, allocation, permissions, mounts, and pathname resolution can change between operations. DiskHound uses no-follow and descriptor-relative operations where practical, but does not promise immunity from every pathname TOCTOU race. An exit code of `0` means no required observation gap was detected, not that the output represents one atomic instant.

Large, deep, wide, remote, or pathological trees may require substantial time, memory, metadata I/O, and page-cache activity. Explicitly scanning a network-backed mount may cause ordinary filesystem-client network traffic.

## Security and privacy

DiskHound is read-only and contains no telemetry, analytics, update checks, application-level network communication, remote inspection, or persistent scan state. It does not open file contents, FIFOs, sockets, or device contents. Filesystem-derived paths and errors are escaped so control characters cannot alter terminal output structure.

Output contains filesystem pathnames and allocation information; treat it as operational metadata when storing or sharing it.

## Tests

Run the standard-library test suite from the repository root:

```console
python3 -m unittest discover -s diskhound/tests -v
```

## Current limitations

DiskHound is experimental and not production-ready. Its observations are permission-dependent and non-atomic. `st_blocks` does not establish unique physical allocation on every filesystem, same-device bind mounts are not detected, full mount topology is not interpreted, and results are not promised to equal `df` or `du`.
