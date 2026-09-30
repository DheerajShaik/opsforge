#!/usr/bin/env python3
"""Report filesystem capacity and allocated space beneath one directory."""

from __future__ import annotations

import argparse
import bisect
from dataclasses import dataclass, field
from decimal import Decimal, ROUND_HALF_EVEN
import errno
import fnmatch
import os
import re
import stat
import sys
import time
from typing import NamedTuple, Sequence

from opsforge.common import (
  OutputError,
  OutputRecord,
  add_output_arguments,
  emit_output,
  has_unsafe_characters,
  make_conclusion,
  sanitize_text as display_safe,
  validate_output_arguments,
)
from opsforge.common.fs import open_regular_file
from opsforge.common.status import (
  EXIT_FAILURE,
  EXIT_FINDING,
  EXIT_INTERRUPTED,
  EXIT_OK,
  EXIT_USAGE,
  OBSERVED,
  PARTIAL,
)


ALLOCATED_BLOCK_BYTES = 512
SECONDS_PER_DAY = 86_400
MAX_INDIVIDUAL_WARNINGS = 20
RESULT_LIMIT = 10
MAX_TOP = 100
DEFAULT_MAX_DEPTH = 64
MAX_DEPTH = 256
DEFAULT_MAX_ENTRIES = 100_000
MAX_ENTRIES = 1_000_000
MAX_EXCLUDES = 32
MAX_EXCLUDE_LENGTH = 256
MAX_AGE_DAYS = 36_500
MAX_DIRECTORY_ENTRIES = 100_000
LIMIT_CATEGORIES = frozenset({"entry-limit", "directory-limit"})
MAX_TYPE_GROUPS = 128
MAX_SUFFIX_LENGTH = 32
MAX_JSON_BRANCHES = 1_000
MAX_JSON_FAILURES = 100
MAX_JSON_MOUNTS = 100
MOUNTINFO_PATH = "/proc/self/mountinfo"
MAX_MOUNTINFO_BYTES = 16 * 1024 * 1024
MOUNTINFO_ESCAPE = re.compile(rb"\\([0-7]{3})")
# Stat or traversal of these can wait on a server, a FUSE daemon, or an automount.
REMOTE_FILESYSTEM_TYPES = frozenset({
  "9p", "afs", "autofs", "beegfs", "ceph", "cifs", "coda", "fuse", "fuseblk", "gfs2", "gpfs",
  "lustre", "ncpfs", "nfs", "nfs4", "ocfs2", "pvfs2", "smb3", "smbfs", "vboxsf", "virtiofs",
})
IEC_UNITS = (
  (1 << 50, "PiB"),
  (1 << 40, "TiB"),
  (1 << 30, "GiB"),
  (1 << 20, "MiB"),
  (1 << 10, "KiB"),
)


class InvalidTargetError(Exception):
  """A path that does not satisfy the CLI target contract."""


class DiagnosticError(Exception):
  """A failure that prevents a useful target ranking."""


@dataclass(frozen=True)
class Capacity:
  total_bytes: int
  used_bytes: int
  free_bytes: int
  available_bytes: int
  use_percent: Decimal | None
  inode_total: int | None = None
  inode_used: int | None = None
  inode_free: int | None = None
  inode_use_percent: Decimal | None = None


@dataclass(frozen=True)
class ObservationFailure:
  path: str
  category: str
  detail: str


class EntryMetadata(NamedTuple):
  """The stat fields kept for each pending entry; a full os.stat_result costs about three times more."""
  st_dev: int
  st_ino: int
  st_mode: int
  st_blocks: int
  st_size: int
  st_mtime: float


class ObservedEntry(NamedTuple):
  path: str
  # None for a remote mount point that was deliberately not statted.
  metadata: EntryMetadata | None


class Mount(NamedTuple):
  device: int
  filesystem_type: str

  @property
  def remote(self) -> bool:
    return self.filesystem_type in REMOTE_FILESYSTEM_TYPES or self.filesystem_type.startswith("fuse.")


@dataclass(frozen=True)
class RemoteMount:
  path: str
  filesystem_type: str


@dataclass(frozen=True)
class BranchResult:
  path: str
  allocated_bytes: int
  logical_bytes: int = 0
  file_count: int = 0


@dataclass(frozen=True)
class FileResult:
  path: str
  logical_bytes: int
  allocated_bytes: int
  age_days: int
  sparse: bool


@dataclass(frozen=True)
class TypeGroup:
  name: str
  files: int
  logical_bytes: int
  allocated_bytes: int


@dataclass(frozen=True)
class ScanOptions:
  max_depth: int = DEFAULT_MAX_DEPTH
  max_entries: int = DEFAULT_MAX_ENTRIES
  cross_filesystems: bool = False
  include_remote_mounts: bool = False
  excludes: tuple[str, ...] = ()
  top: int = RESULT_LIMIT
  age_days: int = 30


@dataclass
class ScanAccumulator:
  options: ScanOptions
  target: str
  device: int
  mounts: dict[str, Mount] = field(default_factory=dict)
  visited_entries: int = 0
  enumerated_entries: int = 0
  entry_limit_reached: bool = False
  excluded_entries: int = 0
  depth_limited_directories: int = 0
  cross_device_immediate: int = 0
  cross_device_skipped: int = 0
  old_file_count: int = 0
  sparse_file_count: int = 0
  largest_files: list[FileResult] = field(default_factory=list)
  largest_keys: list[tuple[int, bytes]] = field(default_factory=list)
  type_groups: dict[str, list[int]] = field(default_factory=dict)
  global_inodes: set[tuple[int, int]] = field(default_factory=set)
  remote_mounts: list[RemoteMount] = field(default_factory=list)
  now: float = field(default_factory=time.time)


@dataclass(frozen=True)
class ScanResult:
  target: str
  target_allocated_bytes: int | None
  unique_allocated_bytes: int
  capacity: Capacity | None
  capacity_warning: str | None
  branches: tuple[BranchResult, ...]
  cross_device_immediate: int
  failures: tuple[ObservationFailure, ...]
  largest_files: tuple[FileResult, ...] = ()
  type_groups: tuple[TypeGroup, ...] = ()
  excluded_entries: int = 0
  depth_limited_directories: int = 0
  visited_entries: int = 0
  old_file_count: int = 0
  sparse_file_count: int = 0
  max_depth: int = DEFAULT_MAX_DEPTH
  max_entries: int = DEFAULT_MAX_ENTRIES
  crossed_filesystems: bool = False
  cross_device_skipped: int = 0
  include_remote_mounts: bool = False
  remote_mounts_not_entered: tuple[RemoteMount, ...] = ()
  mount_table_warning: str | None = None

  @property
  def incomplete(self) -> bool:
    return (
      self.capacity_warning is not None or bool(self.failures) or self.depth_limited_directories > 0
      or bool(self.remote_mounts_not_entered)
    )

  def incomplete_reasons(self) -> list[str]:
    reasons = []
    other = [failure for failure in self.failures if failure.category not in LIMIT_CATEGORIES]
    if other:
      reasons.append(f"{len(other)} observation failure(s)")
    if any(failure.category == "entry-limit" for failure in self.failures):
      reasons.append(f"the {self.max_entries}-entry budget was reached")
    crowded = sum(failure.category == "directory-limit" for failure in self.failures)
    if crowded:
      reasons.append(f"{crowded} director(ies) exceeded the {MAX_DIRECTORY_ENTRIES}-entry per-directory limit")
    if self.depth_limited_directories:
      reasons.append(f"{self.depth_limited_directories} non-empty director(ies) were not descended at --max-depth {self.max_depth}")
    if self.remote_mounts_not_entered:
      reasons.append(f"{len(self.remote_mounts_not_entered)} network, FUSE, or autofs mount(s) were not entered")
    if self.capacity_warning is not None:
      reasons.append("filesystem capacity was unavailable")
    return reasons


def build_argument_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(
    prog="diskhound",
    description=(
      "Report filesystem capacity and rank eligible immediate entries by "
      "recursively observed allocated space."
    ),
  )
  parser.add_argument("path", help="Linux directory to inspect")
  parser.add_argument("--top", type=parse_bounded_int(1, MAX_TOP, "top"), default=RESULT_LIMIT, metavar="N")
  parser.add_argument("--max-depth", type=parse_bounded_int(1, MAX_DEPTH, "depth"), default=DEFAULT_MAX_DEPTH, metavar="N", help="levels to descend; 1 ranks immediate entries by their own allocation")
  parser.add_argument("--max-entries", type=parse_bounded_int(1, MAX_ENTRIES, "entry limit"), default=DEFAULT_MAX_ENTRIES, metavar="N")
  parser.add_argument("--min-size", type=parse_size, default=0, metavar="BYTES", help="show ranked branches/files at or above this size (branch allocated or logical, file logical)")
  parser.add_argument("--exclude", action="append", default=[], metavar="PATTERN", help="exclude a relative path glob (repeatable, maximum 32)")
  parser.add_argument("--age-days", type=parse_bounded_int(0, MAX_AGE_DAYS, "age"), default=30, metavar="DAYS")
  parser.add_argument("--cross-filesystems", action="store_true", help="also traverse other filesystems mounted below PATH, except network, FUSE, and autofs mounts")
  parser.add_argument("--include-remote-mounts", action="store_true", help="with --cross-filesystems, also enter network, FUSE, and autofs mounts; this can block and cause network activity")
  add_output_arguments(parser)
  return parser


def parse_bounded_int(minimum: int, maximum: int, label: str):
  def parse(value: str) -> int:
    if not value.isascii() or not value.isdecimal():
      raise argparse.ArgumentTypeError(f"{label} must be a decimal integer from {minimum} through {maximum}")
    result = int(value, 10)
    if not minimum <= result <= maximum:
      raise argparse.ArgumentTypeError(f"{label} must be from {minimum} through {maximum}")
    return result
  return parse


def parse_size(value: str) -> int:
  if not value.isascii() or not value.isdecimal():
    raise argparse.ArgumentTypeError("size must be a decimal byte count")
  result = int(value, 10)
  if not 0 <= result <= (1 << 63) - 1:
    raise argparse.ArgumentTypeError("size is outside the supported range")
  return result


def normalize_target(path: str) -> str:
  """Return an absolute lexical path without canonical symlink resolution."""
  return os.path.abspath(os.path.normpath(path))


def path_sort_key(path: str) -> bytes:
  """Use filesystem bytes, not locale collation, for deterministic ordering."""
  return os.fsencode(path)


def allocated_bytes(metadata: EntryMetadata | os.stat_result) -> int:
  # A FUSE daemon can report a 64-bit block count that wraps negative.
  if metadata.st_blocks < 0:
    raise ValueError("unusable st_blocks value")
  return metadata.st_blocks * ALLOCATED_BLOCK_BYTES


def calculate_capacity(metadata: os.statvfs_result) -> Capacity:
  fragment_size = metadata.f_frsize
  if fragment_size <= 0:
    raise ValueError("unusable f_frsize value")
  total = metadata.f_blocks * fragment_size
  free = metadata.f_bfree * fragment_size
  available = metadata.f_bavail * fragment_size
  used = total - free
  denominator = used + available
  percentage = None
  if denominator > 0:
    percentage = Decimal(used) * Decimal(100) / Decimal(denominator)
  inode_total, inode_free = metadata.f_files, metadata.f_ffree
  inode_used = inode_percentage = None
  # Python reports 64-bit counts of 2**63 or more as negative numbers.
  if inode_total < 0 or inode_free < 0:
    inode_total = inode_free = None
  else:
    inode_used = inode_total - inode_free
    if inode_total > 0:
      inode_percentage = Decimal(inode_used) * Decimal(100) / Decimal(inode_total)
  return Capacity(
    total, used, free, available, percentage,
    inode_total, inode_used, inode_free, inode_percentage,
  )


def format_bytes(value: int) -> str:
  magnitude = abs(value)
  for divisor, unit in IEC_UNITS:
    if magnitude >= divisor:
      number = (Decimal(value) / Decimal(divisor)).quantize(
        Decimal("0.1"), rounding=ROUND_HALF_EVEN,
      )
      return f"{number:.1f} {unit} ({value} bytes)"
  return f"{value} B ({value} bytes)"


def format_percent(value: Decimal | None) -> str:
  if value is None:
    return "unavailable"
  rounded = value.quantize(Decimal("0.1"), rounding=ROUND_HALF_EVEN)
  return f"{rounded:.1f}%"


def _open_directory(path: str) -> int:
  flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
  flags |= getattr(os, "O_NOFOLLOW", 0)
  return os.open(path, flags)


def _mountinfo_text(value: bytes) -> str:
  return os.fsdecode(MOUNTINFO_ESCAPE.sub(lambda match: bytes((int(match.group(1), 8),)), value))


def parse_mountinfo(data: bytes) -> dict[str, Mount]:
  """Map each mount point in /proc/self/mountinfo text to the mount visible there."""
  mounts = {}
  for line in data.split(b"\n"):
    fields = line.split(b" ")
    try:
      separator = fields.index(b"-", 6)
      major, minor = fields[2].split(b":")
      # The kernel lists mounts in mount order, so a later mount on the same point covers an earlier one.
      mounts[_mountinfo_text(fields[4])] = Mount(
        os.makedev(int(major), int(minor)), _mountinfo_text(fields[separator + 1]),
      )
    except (ValueError, IndexError):
      continue
  return mounts


def read_nested_mounts(target: str) -> dict[str, Mount]:
  """Return the mounts strictly below TARGET, keyed by the lexical paths a scan builds."""
  descriptor, _ = open_regular_file(MOUNTINFO_PATH)
  chunks = []
  size = 0
  try:
    while True:
      chunk = os.read(descriptor, 65536)
      if not chunk:
        break
      size += len(chunk)
      if size > MAX_MOUNTINFO_BYTES:
        raise ValueError(f"{MOUNTINFO_PATH} exceeds {MAX_MOUNTINFO_BYTES} bytes")
      chunks.append(chunk)
  finally:
    os.close(descriptor)
  # mountinfo names mount points by their resolved path.
  prefix = os.path.realpath(target).rstrip("/") + "/"
  base = target.rstrip("/") + "/"
  return {
    base + point[len(prefix):]: mount
    for point, mount in parse_mountinfo(b"".join(chunks)).items()
    if point.startswith(prefix) and point != prefix
  }


def list_directory(
  path: str,
  expected: EntryMetadata | os.stat_result,
  accumulator: ScanAccumulator,
) -> tuple[list[ObservedEntry], list[ObservationFailure]]:
  """Inspect direct children relative to a no-follow directory descriptor."""
  options = accumulator.options
  if accumulator.enumerated_entries >= options.max_entries:
    accumulator.entry_limit_reached = True
    return [], []
  descriptor = _open_directory(path)
  try:
    opened = os.fstat(descriptor)
    if opened.st_dev != expected.st_dev or opened.st_ino != expected.st_ino:
      raise OSError(errno.ESTALE, "directory was replaced during inspection", path)
    entries = []
    failures = []
    with os.scandir(descriptor) as iterator:
      for entry in iterator:
        if accumulator.enumerated_entries >= options.max_entries:
          accumulator.entry_limit_reached = True
          break
        accumulator.enumerated_entries += 1
        if len(entries) + len(failures) >= MAX_DIRECTORY_ENTRIES:
          failures.append(ObservationFailure(
            path, "directory-limit", f"directory exceeded {MAX_DIRECTORY_ENTRIES} entries",
          ))
          break
        child_path = os.path.join(path, entry.name)
        mount = accumulator.mounts.get(child_path)
        if (
          mount is not None and mount.remote and mount.device != accumulator.device
          and not options.include_remote_mounts
        ):
          # Stat would wait on the server, FUSE daemon, or automount behind the mount point.
          entries.append(ObservedEntry(child_path, None))
          continue
        try:
          observed = os.stat(entry.name, dir_fd=descriptor, follow_symlinks=False)
        except OSError as error:
          failures.append(ObservationFailure(child_path, "metadata", str(error)))
        else:
          entries.append(ObservedEntry(child_path, EntryMetadata(
            observed.st_dev, observed.st_ino, observed.st_mode,
            observed.st_blocks, observed.st_size, observed.st_mtime,
          )))
    entries.sort(key=lambda item: path_sort_key(item.path))
    return entries, failures
  finally:
    os.close(descriptor)


def _directory_has_entries(path: str, expected: EntryMetadata) -> bool:
  """Return whether a directory that will not be descended contains anything (unknown counts as yes)."""
  try:
    descriptor = _open_directory(path)
  except OSError:
    return True
  try:
    opened = os.fstat(descriptor)
    if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
      return True
    with os.scandir(descriptor) as iterator:
      return next(iterator, None) is not None
  except OSError:
    return True
  finally:
    os.close(descriptor)


def _record_file(accumulator: ScanAccumulator, path: str, metadata: EntryMetadata, allocation: int) -> None:
  """Add the first observation of a regular-file inode to the scan-wide file statistics."""
  size = metadata.st_size
  age_days = max(0, int((accumulator.now - metadata.st_mtime) // SECONDS_PER_DAY))
  sparse = size > allocation
  if sparse:
    accumulator.sparse_file_count += 1
  if age_days >= accumulator.options.age_days:
    accumulator.old_file_count += 1
  keys = accumulator.largest_keys
  top = accumulator.options.top
  if len(keys) < top or -size <= keys[-1][0]:
    key = (-size, path_sort_key(path))
    if len(keys) < top or key < keys[-1]:
      index = bisect.bisect_right(keys, key)
      keys.insert(index, key)
      accumulator.largest_files.insert(index, FileResult(path, size, allocation, age_days, sparse))
      if len(keys) > top:
        keys.pop()
        accumulator.largest_files.pop()
  suffix = os.path.splitext(path)[1].lower()[:MAX_SUFFIX_LENGTH] or "[no extension]"
  if suffix not in accumulator.type_groups and len(accumulator.type_groups) >= MAX_TYPE_GROUPS:
    suffix = "[other]"
  group = accumulator.type_groups.setdefault(suffix, [0, 0, 0])
  group[0] += 1
  group[1] += size
  group[2] += allocation


def _skip_other_filesystem(accumulator: ScanAccumulator, entry: ObservedEntry, *, immediate: bool) -> bool:
  """Count ENTRY and return True when it is on a filesystem that this scan does not enter."""
  cross = accumulator.options.cross_filesystems
  if entry.metadata is not None and (cross or entry.metadata.st_dev == accumulator.device):
    return False
  if entry.metadata is None and cross:
    accumulator.remote_mounts.append(RemoteMount(entry.path, accumulator.mounts[entry.path].filesystem_type))
  elif immediate:
    accumulator.cross_device_immediate += 1
  else:
    accumulator.cross_device_skipped += 1
  return True


def _scan_branch(
  initial: ObservedEntry,
  accumulator: ScanAccumulator,
) -> tuple[int, int, list[ObservationFailure], int, int]:
  options = accumulator.options
  branch_inodes: set[tuple[int, int]] = set()
  failures: list[ObservationFailure] = []
  total = 0
  logical_total = 0
  file_count = 0
  new_global_total = 0
  pending = [(initial, 1)]

  while pending:
    entry, depth = pending.pop()
    if accumulator.visited_entries >= options.max_entries:
      accumulator.entry_limit_reached = True
      break
    accumulator.visited_entries += 1
    if options.excludes:
      relative = os.path.relpath(entry.path, accumulator.target)
      if any(fnmatch.fnmatchcase(relative, pattern) for pattern in options.excludes):
        accumulator.excluded_entries += 1
        continue
    if _skip_other_filesystem(accumulator, entry, immediate=False):
      continue
    metadata = entry.metadata
    identity = (metadata.st_dev, metadata.st_ino)
    if identity in branch_inodes:
      continue
    branch_inodes.add(identity)
    first_observation = identity not in accumulator.global_inodes
    accumulator.global_inodes.add(identity)
    allocation = 0
    try:
      allocation = allocated_bytes(metadata)
    except ValueError as error:
      failures.append(ObservationFailure(entry.path, "allocation", str(error)))
    else:
      total += allocation
      if first_observation:
        new_global_total += allocation

    if stat.S_ISREG(metadata.st_mode):
      logical_total += metadata.st_size
      file_count += 1
      if first_observation:
        _record_file(accumulator, entry.path, metadata, allocation)
    elif stat.S_ISDIR(metadata.st_mode):
      if depth >= options.max_depth:
        if _directory_has_entries(entry.path, metadata):
          accumulator.depth_limited_directories += 1
        continue
      try:
        children, child_failures = list_directory(entry.path, metadata, accumulator)
      except OSError as error:
        failures.append(ObservationFailure(entry.path, "enumeration", str(error)))
      else:
        failures.extend(child_failures)
        pending.extend((child, depth + 1) for child in reversed(children))
  return total, new_global_total, failures, logical_total, file_count


def validate_target(path: str) -> tuple[str, os.stat_result]:
  if not path:
    raise InvalidTargetError("target path must not be empty")
  target = normalize_target(path)
  try:
    metadata = os.lstat(target)
  except FileNotFoundError as error:
    raise InvalidTargetError(f"target does not exist: {display_safe(target)}") from error
  except OSError as error:
    if error.errno in (errno.ENOTDIR, errno.ELOOP, errno.ENAMETOOLONG):
      raise InvalidTargetError(
        f"target path cannot be resolved: {display_safe(target)}: {display_safe(error.strerror)}"
      ) from error
    raise DiagnosticError(f"could not inspect target {display_safe(target)}: {display_safe(error)}") from error
  if stat.S_ISLNK(metadata.st_mode):
    raise InvalidTargetError(
      f"target must be a directory, not a symbolic link: {display_safe(target)}"
    )
  if not stat.S_ISDIR(metadata.st_mode):
    raise InvalidTargetError(f"target is not a directory: {display_safe(target)}")
  return target, metadata


def scan(path: str, options: ScanOptions | None = None) -> ScanResult:
  options = ScanOptions() if options is None else options
  target, target_metadata = validate_target(path)
  accumulator = ScanAccumulator(options, target, target_metadata.st_dev)
  mount_table_warning = None
  try:
    accumulator.mounts = read_nested_mounts(target)
  except (OSError, ValueError) as error:
    mount_table_warning = (
      f"mount table unavailable ({display_safe(error)}); network, FUSE, and autofs mount points "
      "are not recognized before they are statted"
    )
  try:
    immediate, initial_failures = list_directory(target, target_metadata, accumulator)
  except OSError as error:
    raise DiagnosticError(
      f"could not enumerate target {display_safe(target)}: {display_safe(error)}"
    ) from error

  capacity = None
  capacity_warning = None
  try:
    descriptor = _open_directory(target)
    try:
      reopened = os.fstat(descriptor)
      if (
        reopened.st_dev != target_metadata.st_dev
        or reopened.st_ino != target_metadata.st_ino
      ):
        raise DiagnosticError(
          f"target was replaced during inspection: {display_safe(target)}"
        )
      capacity = calculate_capacity(os.fstatvfs(descriptor))
    finally:
      os.close(descriptor)
  except DiagnosticError:
    raise
  except (OSError, ValueError) as error:
    capacity_warning = f"filesystem capacity unavailable: {display_safe(error)}"

  failures = list(initial_failures)
  target_allocation = None
  unique_total = 0
  accumulator.global_inodes.add((target_metadata.st_dev, target_metadata.st_ino))
  try:
    target_allocation = allocated_bytes(target_metadata)
  except ValueError as error:
    failures.append(ObservationFailure(target, "allocation", str(error)))
  else:
    unique_total = target_allocation

  eligible = []
  for entry in immediate:
    if any(fnmatch.fnmatchcase(os.path.relpath(entry.path, target), pattern) for pattern in options.excludes):
      accumulator.excluded_entries += 1
    elif not _skip_other_filesystem(accumulator, entry, immediate=True):
      eligible.append(entry)

  branches = []
  for entry in eligible:
    if accumulator.visited_entries >= options.max_entries:
      accumulator.entry_limit_reached = True
      break
    total, new_global_total, branch_failures, logical_total, file_count = _scan_branch(entry, accumulator)
    failures.extend(branch_failures)
    branches.append(BranchResult(entry.path, total, logical_total, file_count))
    unique_total += new_global_total

  if accumulator.entry_limit_reached:
    failures.append(ObservationFailure(
      target, "entry-limit", f"scan stopped at the global {options.max_entries}-entry budget",
    ))

  branches.sort(key=lambda branch: (-branch.allocated_bytes, path_sort_key(branch.path)))
  return ScanResult(
    target=target,
    target_allocated_bytes=target_allocation,
    unique_allocated_bytes=unique_total,
    capacity=capacity,
    capacity_warning=capacity_warning,
    branches=tuple(branches),
    cross_device_immediate=accumulator.cross_device_immediate,
    failures=tuple(failures),
    largest_files=tuple(accumulator.largest_files),
    type_groups=tuple(
      TypeGroup(name, values[0], values[1], values[2])
      for name, values in sorted(
        accumulator.type_groups.items(), key=lambda item: (-item[1][1], item[0]),
      )
    ),
    excluded_entries=accumulator.excluded_entries,
    depth_limited_directories=accumulator.depth_limited_directories,
    visited_entries=accumulator.visited_entries,
    old_file_count=accumulator.old_file_count,
    sparse_file_count=accumulator.sparse_file_count,
    max_depth=options.max_depth,
    max_entries=options.max_entries,
    crossed_filesystems=options.cross_filesystems,
    cross_device_skipped=accumulator.cross_device_skipped,
    include_remote_mounts=options.include_remote_mounts,
    remote_mounts_not_entered=tuple(accumulator.remote_mounts),
    mount_table_warning=mount_table_warning,
  )


def render_result(result: ScanResult, *, top: int = RESULT_LIMIT, minimum_bytes: int = 0) -> str:
  if not result.crossed_filesystems:
    device_scope = "same st_dev only"
  elif result.include_remote_mounts:
    device_scope = "all filesystems crossed on request"
  else:
    device_scope = "other filesystems crossed on request except network, FUSE, and autofs mounts"
  lines = [
    f"DiskHound: {display_safe(result.target)}",
    f"Scope: immediate entries; recursive metadata scan up to depth {result.max_depth}; {device_scope}; symlinks not intentionally followed",
    f"Observation: incomplete ({'; '.join(result.incomplete_reasons())}; not a filesystem snapshot)"
      if result.incomplete else "Observation: complete (not a filesystem snapshot)",
    "",
    "Filesystem capacity:",
  ]
  if result.capacity is None:
    lines.append("  unavailable")
  else:
    lines.extend([
      f"  Total:               {format_bytes(result.capacity.total_bytes)}",
      f"  Used:                {format_bytes(result.capacity.used_bytes)}",
      f"  Filesystem free:     {format_bytes(result.capacity.free_bytes)}",
      f"  Available to caller: {format_bytes(result.capacity.available_bytes)}",
      f"  Use%:                {format_percent(result.capacity.use_percent)}",
    ])
    if result.capacity.inode_total is not None:
      lines.extend([
        f"  Inodes total:        {result.capacity.inode_total}",
        f"  Inodes used:         {result.capacity.inode_used}",
        f"  Inodes free:         {result.capacity.inode_free}",
        f"  Inode use%:          {format_percent(result.capacity.inode_use_percent)}",
      ])

  target_allocation = (
    format_bytes(result.target_allocated_bytes)
    if result.target_allocated_bytes is not None else "unavailable"
  )
  eligible_branches = tuple(
    item for item in result.branches
    if max(item.logical_bytes, item.allocated_bytes) >= minimum_bytes
  )
  displayed = eligible_branches[:top]
  eligible_count = len(result.branches)
  lines.extend([
    "",
    "Observed allocation:",
    f"  Target directory allocation:     {target_allocation}",
    f"  Unique observed target allocation: {format_bytes(result.unique_allocated_bytes)}",
    f"  Eligible immediate entries: {eligible_count}",
    f"  Cross-device immediate entries excluded: {result.cross_device_immediate}",
    f"  Cross-device nested entries skipped: {result.cross_device_skipped}",
    f"  Excluded entries: {result.excluded_entries}",
    f"  Visited entries: {result.visited_entries} (limit {result.max_entries})",
    f"  Depth-limited directories: {result.depth_limited_directories} (maximum depth {result.max_depth})",
    f"  Showing {len(displayed)} of {eligible_count} eligible immediate entries",
  ])
  if displayed:
    lines.extend(["", "  ALLOCATED  PATH"])
    for branch in displayed:
      lines.append(f"  {format_bytes(branch.allocated_bytes)}  {display_safe(branch.path)}")
  else:
    lines.extend(["", "  No eligible immediate entries were observed."])
  files = tuple(item for item in result.largest_files if item.logical_bytes >= minimum_bytes)[:top]
  lines.extend(["", f"Largest individual files (showing {len(files)}):"])
  for item in files:
    sparse = "; sparse" if item.sparse else ""
    lines.append(
      f"  {format_bytes(item.logical_bytes)} logical; {format_bytes(item.allocated_bytes)} allocated; "
      f"age {item.age_days}d{sparse}  {display_safe(item.path)}"
    )
  if not files:
    lines.append("  none observed")
  lines.extend([
    "",
    f"Age/sparse summary: {result.old_file_count} files at or beyond the configured age; "
    f"{result.sparse_file_count} sparse files",
    "File types:",
  ])
  for group in result.type_groups[:top]:
    lines.append(
      f"  {display_safe(group.name)}: {group.files} files; "
      f"{format_bytes(group.logical_bytes)} logical; {format_bytes(group.allocated_bytes)} allocated"
    )
  if not result.type_groups:
    lines.append("  none observed")
  lines.extend([
    "",
    "Branch totals are path-reachable observations and are not additive when hard links span branches.",
    "Filesystem capacity and observed tree allocation are separate observations and need not reconcile.",
  ])
  return "\n".join(lines)


def ordered_failures(result: ScanResult) -> list[ObservationFailure]:
  return sorted(
    result.failures,
    key=lambda failure: (
      path_sort_key(failure.path), failure.category, display_safe(failure.detail),
    ),
  )


def render_warnings(result: ScanResult) -> list[str]:
  warnings = []
  ordered = ordered_failures(result)
  for failure in ordered[:MAX_INDIVIDUAL_WARNINGS]:
    warnings.append(
      "diskhound: warning: "
      f"{failure.category} failure for {display_safe(failure.path)}: {display_safe(failure.detail)}"
    )
  suppressed = len(ordered) - MAX_INDIVIDUAL_WARNINGS
  if suppressed > 0:
    warnings.append(
      f"diskhound: warning: {suppressed} additional observation failures were suppressed"
    )
  for mount in result.remote_mounts_not_entered[:MAX_INDIVIDUAL_WARNINGS]:
    warnings.append(
      f"diskhound: warning: {display_safe(mount.filesystem_type)} mount not entered: {display_safe(mount.path)}"
      " (--include-remote-mounts enters network, FUSE, and autofs mounts)"
    )
  suppressed = len(result.remote_mounts_not_entered) - MAX_INDIVIDUAL_WARNINGS
  if suppressed > 0:
    warnings.append(f"diskhound: warning: {suppressed} additional unentered mounts were suppressed")
  if result.capacity_warning is not None:
    warnings.append(f"diskhound: warning: {result.capacity_warning}")
  if result.mount_table_warning is not None:
    warnings.append(f"diskhound: warning: {result.mount_table_warning}")
  return warnings


def brief_result(result: ScanResult) -> str:
  use = format_percent(result.capacity.use_percent) if result.capacity is not None else "unavailable"
  largest = display_safe(result.branches[0].path) if result.branches else "none"
  return "\n".join([
    f"Target: {display_safe(result.target)}",
    f"Filesystem use: {use}",
    f"Observed allocation: {format_bytes(result.unique_allocated_bytes)}",
    f"Largest immediate entry: {largest}",
    f"Observation failures: {len(result.failures)}",
  ])


def result_observations(result: ScanResult) -> dict[str, object]:
  failures = ordered_failures(result)
  return {
    "filesystem_capacity": result.capacity,
    "target_allocated_bytes": result.target_allocated_bytes,
    "unique_allocated_bytes": result.unique_allocated_bytes,
    "branches": result.branches[:MAX_JSON_BRANCHES],
    "branches_total": len(result.branches),
    "largest_files": result.largest_files,
    "file_types": result.type_groups,
    "cross_device_immediate_excluded": result.cross_device_immediate,
    "cross_device_nested_skipped": result.cross_device_skipped,
    "cross_filesystems": result.crossed_filesystems,
    "include_remote_mounts": result.include_remote_mounts,
    "remote_mounts_not_entered": result.remote_mounts_not_entered[:MAX_JSON_MOUNTS],
    "remote_mounts_not_entered_total": len(result.remote_mounts_not_entered),
    "excluded_entries": result.excluded_entries,
    "depth_limited_directories": result.depth_limited_directories,
    "incomplete_reasons": result.incomplete_reasons(),
    "visited_entries": result.visited_entries,
    "old_file_count": result.old_file_count,
    "sparse_file_count": result.sparse_file_count,
    "failures": failures[:MAX_JSON_FAILURES],
    "failures_total": len(failures),
  }


def inspect_result_code(result: ScanResult) -> int:
  return EXIT_FINDING if result.incomplete else EXIT_OK


def describe_result(result: ScanResult) -> tuple[str, str]:
  """Return the conclusion's finding and next action."""
  reasons = result.incomplete_reasons()
  finding = (
    f"the bounded scan observed {format_bytes(result.unique_allocated_bytes)} of unique allocation"
    + (f" but is incomplete because {'; '.join(reasons)}" if result.incomplete else "")
  )
  if not result.incomplete:
    next_action = "review the ranked entries before changing or removing data"
  elif any(failure.category not in LIMIT_CATEGORIES for failure in result.failures):
    next_action = "review the stderr warnings (often permissions) and rerun the same bounded scope"
  elif result.remote_mounts_not_entered:
    next_action = (
      "scan each listed network, FUSE, or autofs mount as its own PATH, "
      "or add --include-remote-mounts if touching it is acceptable"
    )
  elif result.depth_limited_directories or any(failure.category == "entry-limit" for failure in result.failures):
    next_action = "raise --max-depth/--max-entries or narrow PATH before relying on totals"
  elif result.failures:
    next_action = "treat totals as lower bounds because the listed directories were read only in part"
  else:
    next_action = "treat capacity figures as unavailable and rerun if the filesystem recovers"
  return finding, next_action


def main(argv: Sequence[str] | None = None) -> int:
  parser = build_argument_parser()
  arguments = parser.parse_args(argv)
  validate_output_arguments(parser, arguments)
  if len(arguments.exclude) > MAX_EXCLUDES:
    parser.error(f"--exclude may be repeated at most {MAX_EXCLUDES} times")
  if any(not pattern or len(pattern) > MAX_EXCLUDE_LENGTH or has_unsafe_characters(pattern) for pattern in arguments.exclude):
    parser.error(f"exclude patterns must be printable and at most {MAX_EXCLUDE_LENGTH} characters")
  if arguments.include_remote_mounts and not arguments.cross_filesystems:
    parser.error("--include-remote-mounts requires --cross-filesystems")
  options = ScanOptions(
    max_depth=arguments.max_depth,
    max_entries=arguments.max_entries,
    cross_filesystems=arguments.cross_filesystems,
    include_remote_mounts=arguments.include_remote_mounts,
    excludes=tuple(arguments.exclude),
    top=arguments.top,
    age_days=arguments.age_days,
  )
  started = time.monotonic()
  # Error messages are escaped where they are built, so they are printed as they are.
  try:
    result = scan(arguments.path, options)
    output = render_result(result, top=arguments.top, minimum_bytes=arguments.min_size)
    warnings = tuple(render_warnings(result))
    for warning in warnings:
      print(warning, file=sys.stderr)
    status = PARTIAL if result.incomplete else OBSERVED
    finding, next_action = describe_result(result)
    record = OutputRecord(
      tool="diskhound",
      status=status,
      target=result.target,
      observations=result_observations(result),
      conclusion=make_conclusion(status, result.target, finding, next_action),
      next_action=next_action + ".",
      warnings=warnings,
      elapsed_seconds=time.monotonic() - started,
    )
    emit_output(
      record,
      detailed=output,
      brief=brief_result(result),
      json_mode=arguments.json,
      brief_mode=arguments.brief,
      quiet=arguments.quiet,
      output_path=arguments.output,
      force=arguments.force,
    )
  except InvalidTargetError as error:
    print(f"diskhound: {error}", file=sys.stderr)
    return EXIT_USAGE
  except (DiagnosticError, OutputError) as error:
    print(f"diskhound: {error}", file=sys.stderr)
    return EXIT_FAILURE
  except KeyboardInterrupt:
    print("diskhound: interrupted", file=sys.stderr)
    return EXIT_INTERRUPTED
  except Exception:
    print("diskhound: internal execution failure", file=sys.stderr)
    return EXIT_FAILURE
  return inspect_result_code(result)


if __name__ == "__main__":
  raise SystemExit(main())
