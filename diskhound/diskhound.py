#!/usr/bin/env python3
"""Report filesystem capacity and allocated space beneath one directory."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from decimal import Decimal, ROUND_HALF_EVEN
import errno
import fnmatch
import os
import stat
import sys
import time
import unicodedata
from typing import Sequence

from opsforge_common import (
  OutputError,
  OutputRecord,
  add_output_arguments,
  emit_output,
  make_conclusion,
  validate_output_arguments,
)


ALLOCATED_BLOCK_BYTES = 512
MAX_INDIVIDUAL_WARNINGS = 20
RESULT_LIMIT = 10
MAX_TOP = 100
DEFAULT_MAX_DEPTH = 64
MAX_DEPTH = 256
DEFAULT_MAX_ENTRIES = 100_000
MAX_ENTRIES = 1_000_000
MAX_EXCLUDES = 32
MAX_DIRECTORY_ENTRIES = 100_000
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


@dataclass(frozen=True)
class ObservedEntry:
  path: str
  metadata: os.stat_result


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
  excludes: tuple[str, ...] = ()
  top: int = RESULT_LIMIT
  minimum_bytes: int = 0
  age_days: int = 30


@dataclass
class ScanAccumulator:
  options: ScanOptions
  target: str
  visited_entries: int = 0
  enumerated_entries: int = 0
  entry_limit_reached: bool = False
  excluded_entries: int = 0
  depth_limited_directories: int = 0
  old_file_count: int = 0
  sparse_file_count: int = 0
  largest_files: list[FileResult] = field(default_factory=list)
  type_groups: dict[str, list[int]] = field(default_factory=dict)


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

  @property
  def incomplete(self) -> bool:
    return self.capacity_warning is not None or bool(self.failures)


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
  parser.add_argument("--max-depth", type=parse_bounded_int(0, MAX_DEPTH, "depth"), default=DEFAULT_MAX_DEPTH, metavar="N")
  parser.add_argument("--max-entries", type=parse_bounded_int(1, MAX_ENTRIES, "entry limit"), default=DEFAULT_MAX_ENTRIES, metavar="N")
  parser.add_argument("--min-size", type=parse_size, default=0, metavar="BYTES", help="show ranked items at or above this logical byte size")
  parser.add_argument("--exclude", action="append", default=[], metavar="PATTERN", help="exclude a relative path glob (repeatable, maximum 32)")
  parser.add_argument("--age-days", type=parse_bounded_int(0, 36500, "age"), default=30, metavar="DAYS")
  parser.add_argument("--cross-filesystems", action="store_true", help="allow traversal onto filesystems other than the target filesystem")
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


def display_safe(value: object) -> str:
  """Render filesystem text without terminal controls or ambiguous escapes."""
  result = []
  for character in str(value):
    codepoint = ord(character)
    if character == "\\":
      result.append("\\\\")
    elif 0xDC80 <= codepoint <= 0xDCFF:
      result.append(f"\\x{codepoint - 0xDC00:02x}")
    elif unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"}:
      if codepoint <= 0xFF:
        result.append(f"\\x{codepoint:02x}")
      else:
        result.append(f"\\u{codepoint:04x}")
    else:
      result.append(character)
  return "".join(result)


def path_sort_key(path: str) -> bytes:
  """Use filesystem bytes, not locale collation, for deterministic ordering."""
  return os.fsencode(path)


def allocated_bytes(metadata: os.stat_result) -> int:
  blocks = getattr(metadata, "st_blocks", None)
  if not isinstance(blocks, int) or isinstance(blocks, bool) or blocks < 0:
    raise ValueError("unusable st_blocks value")
  return blocks * ALLOCATED_BLOCK_BYTES


def calculate_capacity(metadata: object) -> Capacity:
  fields = ("f_frsize", "f_blocks", "f_bfree", "f_bavail")
  values = []
  for field in fields:
    value = getattr(metadata, field, None)
    if not isinstance(value, int) or isinstance(value, bool):
      raise ValueError(f"unusable {field} value")
    values.append(value)
  fragment_size, blocks, free_blocks, available_blocks = values
  if fragment_size <= 0:
    raise ValueError("unusable f_frsize value")
  total = blocks * fragment_size
  free = free_blocks * fragment_size
  available = available_blocks * fragment_size
  used = total - free
  denominator = used + available
  percentage = None
  if denominator > 0:
    percentage = Decimal(used) * Decimal(100) / Decimal(denominator)
  inode_total = getattr(metadata, "f_files", None)
  inode_free = getattr(metadata, "f_ffree", None)
  if not isinstance(inode_total, int) or isinstance(inode_total, bool) or inode_total < 0:
    inode_total = None
  if not isinstance(inode_free, int) or isinstance(inode_free, bool) or inode_free < 0:
    inode_free = None
  inode_used = None
  inode_percentage = None
  if inode_total is not None and inode_free is not None:
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


def list_directory(
  path: str,
  expected: os.stat_result | None = None,
  accumulator: ScanAccumulator | None = None,
) -> tuple[list[ObservedEntry], list[ObservationFailure]]:
  """Inspect direct children relative to a no-follow directory descriptor."""
  if accumulator is not None and accumulator.enumerated_entries >= accumulator.options.max_entries:
    accumulator.entry_limit_reached = True
    return [], []
  descriptor = _open_directory(path)
  try:
    opened = os.fstat(descriptor)
    if expected is not None and (
      opened.st_dev != expected.st_dev or opened.st_ino != expected.st_ino
    ):
      raise OSError(errno.ESTALE, "directory was replaced during inspection", path)
    entries = []
    failures = []
    with os.scandir(descriptor) as iterator:
      for entry in iterator:
        if accumulator is not None:
          if accumulator.enumerated_entries >= accumulator.options.max_entries:
            accumulator.entry_limit_reached = True
            break
          accumulator.enumerated_entries += 1
        if len(entries) + len(failures) >= MAX_DIRECTORY_ENTRIES:
          failures.append(ObservationFailure(
            path, "entry-limit", f"directory exceeded {MAX_DIRECTORY_ENTRIES} entries",
          ))
          break
        child_path = os.path.join(path, entry.name)
        try:
          metadata = os.stat(entry.name, dir_fd=descriptor, follow_symlinks=False)
        except OSError as error:
          failures.append(ObservationFailure(child_path, "metadata", str(error)))
        else:
          entries.append(ObservedEntry(child_path, metadata))
    entries.sort(key=lambda item: path_sort_key(item.path))
    return entries, failures
  finally:
    os.close(descriptor)


def _scan_branch(
  initial: ObservedEntry,
  scan_device: int,
  global_inodes: set[tuple[int, int]],
  accumulator: ScanAccumulator | None = None,
) -> tuple[int, int, list[ObservationFailure], int, int]:
  branch_inodes: set[tuple[int, int]] = set()
  failures: list[ObservationFailure] = []
  total = 0
  logical_total = 0
  file_count = 0
  new_global_total = 0
  pending = [(initial, 1)]

  while pending:
    entry, depth = pending.pop()
    metadata = entry.metadata
    if accumulator is not None:
      if accumulator.visited_entries >= accumulator.options.max_entries:
        accumulator.entry_limit_reached = True
        break
      accumulator.visited_entries += 1
      relative = os.path.relpath(entry.path, accumulator.target)
      if any(fnmatch.fnmatchcase(relative, pattern) for pattern in accumulator.options.excludes):
        accumulator.excluded_entries += 1
        continue
    if metadata.st_dev != scan_device and not (
      accumulator is not None and accumulator.options.cross_filesystems
    ):
      continue
    identity = (metadata.st_dev, metadata.st_ino)
    if identity in branch_inodes:
      continue
    branch_inodes.add(identity)
    allocation = 0
    try:
      allocation = allocated_bytes(metadata)
    except ValueError as error:
      failures.append(ObservationFailure(entry.path, "allocation", str(error)))
    else:
      total += allocation
      if identity not in global_inodes:
        global_inodes.add(identity)
        new_global_total += allocation

    logical_size = getattr(metadata, "st_size", 0)
    if not isinstance(logical_size, int) or logical_size < 0:
      logical_size = 0
    if accumulator is not None and stat.S_ISREG(metadata.st_mode):
      file_allocation = allocation
      modified = getattr(metadata, "st_mtime", time.time())
      age_days = max(0, int((time.time() - modified) // 86400)) if isinstance(modified, (int, float)) else 0
      sparse = logical_size > file_allocation
      if sparse:
        accumulator.sparse_file_count += 1
      if age_days >= accumulator.options.age_days:
        accumulator.old_file_count += 1
      candidate = FileResult(entry.path, logical_size, file_allocation, age_days, sparse)
      logical_total += logical_size
      file_count += 1
      accumulator.largest_files.append(candidate)
      accumulator.largest_files.sort(key=lambda item: (-item.logical_bytes, path_sort_key(item.path)))
      del accumulator.largest_files[accumulator.options.top:]
      suffix = os.path.splitext(entry.path)[1].lower()[:32] or "[no extension]"
      if suffix not in accumulator.type_groups and len(accumulator.type_groups) >= 128:
        suffix = "[other]"
      group = accumulator.type_groups.setdefault(suffix, [0, 0, 0])
      group[0] += 1
      group[1] += logical_size
      group[2] += file_allocation

    if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
      if accumulator is not None and depth >= accumulator.options.max_depth:
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
  accumulator = ScanAccumulator(options, target)
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
  target_identity = (target_metadata.st_dev, target_metadata.st_ino)
  global_inodes: set[tuple[int, int]] = {target_identity}
  try:
    target_allocation = allocated_bytes(target_metadata)
  except ValueError as error:
    failures.append(ObservationFailure(target, "allocation", str(error)))
  else:
    unique_total = target_allocation

  eligible = []
  cross_device = 0
  for entry in immediate:
    if any(fnmatch.fnmatchcase(os.path.relpath(entry.path, target), pattern) for pattern in options.excludes):
      accumulator.excluded_entries += 1
    elif entry.metadata.st_dev != target_metadata.st_dev and not options.cross_filesystems:
      cross_device += 1
    else:
      eligible.append(entry)

  branches = []
  for entry in eligible:
    if accumulator.visited_entries >= options.max_entries:
      accumulator.entry_limit_reached = True
      break
    if options.max_depth == 0:
      accumulator.depth_limited_directories += int(stat.S_ISDIR(entry.metadata.st_mode))
      continue
    total, new_global_total, branch_failures, logical_total, file_count = _scan_branch(
      entry, target_metadata.st_dev, global_inodes, accumulator,
    )
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
    cross_device_immediate=cross_device,
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
  )


def render_result(result: ScanResult, *, top: int = RESULT_LIMIT, minimum_bytes: int = 0) -> str:
  failure_count = len(result.failures)
  state = "incomplete" if result.incomplete else "complete"
  lines = [
    f"DiskHound: {display_safe(result.target)}",
    "Scope: immediate entries; recursive metadata scan; same st_dev only; symlinks not intentionally followed",
    f"Observation: {state} ({failure_count} known observation failures; not a filesystem snapshot)"
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


def render_warnings(result: ScanResult) -> list[str]:
  warnings = []
  ordered = sorted(
    result.failures,
    key=lambda failure: (
      path_sort_key(failure.path), failure.category, display_safe(failure.detail),
    ),
  )
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
  if result.capacity_warning is not None:
    warnings.append(f"diskhound: warning: {result.capacity_warning}")
  return warnings


def inspect(path: str) -> tuple[str, tuple[str, ...], int]:
  result = scan(path)
  return render_result(result), tuple(render_warnings(result)), inspect_result_code(result)


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
  return {
    "filesystem_capacity": result.capacity,
    "target_allocated_bytes": result.target_allocated_bytes,
    "unique_allocated_bytes": result.unique_allocated_bytes,
    "branches": result.branches,
    "largest_files": result.largest_files,
    "file_types": result.type_groups,
    "cross_device_immediate_excluded": result.cross_device_immediate,
    "cross_filesystems": result.crossed_filesystems,
    "excluded_entries": result.excluded_entries,
    "depth_limited_directories": result.depth_limited_directories,
    "visited_entries": result.visited_entries,
    "old_file_count": result.old_file_count,
    "sparse_file_count": result.sparse_file_count,
    "failures": result.failures,
  }


def inspect_result_code(result: ScanResult) -> int:
  return 1 if result.incomplete else 0


def main(argv: Sequence[str] | None = None) -> int:
  parser = build_argument_parser()
  arguments = parser.parse_args(argv)
  validate_output_arguments(parser, arguments)
  if len(arguments.exclude) > MAX_EXCLUDES:
    parser.error(f"--exclude may be repeated at most {MAX_EXCLUDES} times")
  if any(not pattern or len(pattern) > 256 or display_safe(pattern) != pattern for pattern in arguments.exclude):
    parser.error("exclude patterns must be printable and at most 256 characters")
  options = ScanOptions(
    max_depth=arguments.max_depth,
    max_entries=arguments.max_entries,
    cross_filesystems=arguments.cross_filesystems,
    excludes=tuple(arguments.exclude),
    top=arguments.top,
    minimum_bytes=arguments.min_size,
    age_days=arguments.age_days,
  )
  started = time.monotonic()
  try:
    result = scan(arguments.path, options)
    output = render_result(result, top=arguments.top, minimum_bytes=arguments.min_size)
    warnings = tuple(render_warnings(result))
    exit_code = inspect_result_code(result)
    for warning in warnings:
      print(warning, file=sys.stderr)
  except InvalidTargetError as error:
    print(f"diskhound: {display_safe(error)}", file=sys.stderr)
    return 2
  except DiagnosticError as error:
    print(f"diskhound: {display_safe(error)}", file=sys.stderr)
    return 3
  except KeyboardInterrupt:
    print("diskhound: interrupted", file=sys.stderr)
    return 130
  except Exception:
    print("diskhound: internal execution failure", file=sys.stderr)
    return 3
  status = "PARTIAL" if result.incomplete else "OBSERVED"
  finding = (
    f"the bounded scan observed {format_bytes(result.unique_allocated_bytes)} of unique allocation"
    + (f" with {len(result.failures)} observation failures" if result.incomplete else "")
  )
  next_action = (
    "review permissions and rerun the same bounded scope" if result.incomplete
    else "review the ranked entries before changing or removing data"
  )
  conclusion = make_conclusion(status, result.target, finding, next_action)
  record = OutputRecord(
    tool="diskhound",
    status=status,
    target=result.target,
    observations=result_observations(result),
    conclusion=conclusion,
    next_action=next_action + ".",
    warnings=warnings,
    elapsed_seconds=time.monotonic() - started,
  )
  try:
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
  except OutputError as error:
    print(f"diskhound: {display_safe(error)}", file=sys.stderr)
    return 3
  return exit_code


if __name__ == "__main__":
  raise SystemExit(main())
