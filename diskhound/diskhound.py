#!/usr/bin/env python3
"""Report filesystem capacity and allocated space beneath one directory."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_EVEN
import errno
import os
import stat
import sys
import unicodedata
from typing import Sequence


ALLOCATED_BLOCK_BYTES = 512
MAX_INDIVIDUAL_WARNINGS = 20
RESULT_LIMIT = 10
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
  return parser


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
  return Capacity(total, used, free, available, percentage)


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
) -> tuple[list[ObservedEntry], list[ObservationFailure]]:
  """Inspect direct children relative to a no-follow directory descriptor."""
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
        child_path = os.path.join(path, entry.name)
        try:
          metadata = os.stat(entry.name, dir_fd=descriptor, follow_symlinks=False)
        except OSError as error:
          failures.append(ObservationFailure(child_path, "metadata", str(error)))
        else:
          entries.append(ObservedEntry(child_path, metadata))
    return entries, failures
  finally:
    os.close(descriptor)


def _scan_branch(
  initial: ObservedEntry,
  scan_device: int,
  global_inodes: set[tuple[int, int]],
) -> tuple[int, int, list[ObservationFailure]]:
  branch_inodes: set[tuple[int, int]] = set()
  failures: list[ObservationFailure] = []
  total = 0
  new_global_total = 0
  pending = [initial]

  while pending:
    entry = pending.pop()
    metadata = entry.metadata
    if metadata.st_dev != scan_device:
      continue
    identity = (metadata.st_dev, metadata.st_ino)
    if identity in branch_inodes:
      continue
    branch_inodes.add(identity)
    try:
      allocation = allocated_bytes(metadata)
    except ValueError as error:
      failures.append(ObservationFailure(entry.path, "allocation", str(error)))
    else:
      total += allocation
      if identity not in global_inodes:
        global_inodes.add(identity)
        new_global_total += allocation

    if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
      try:
        children, child_failures = list_directory(entry.path, metadata)
      except OSError as error:
        failures.append(ObservationFailure(entry.path, "enumeration", str(error)))
      else:
        failures.extend(child_failures)
        pending.extend(children)
  return total, new_global_total, failures


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


def scan(path: str) -> ScanResult:
  target, target_metadata = validate_target(path)
  try:
    immediate, initial_failures = list_directory(target, target_metadata)
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
    if entry.metadata.st_dev != target_metadata.st_dev:
      cross_device += 1
    else:
      eligible.append(entry)

  branches = []
  for entry in eligible:
    total, new_global_total, branch_failures = _scan_branch(
      entry, target_metadata.st_dev, global_inodes,
    )
    failures.extend(branch_failures)
    branches.append(BranchResult(entry.path, total))
    unique_total += new_global_total

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
  )


def render_result(result: ScanResult) -> str:
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

  target_allocation = (
    format_bytes(result.target_allocated_bytes)
    if result.target_allocated_bytes is not None else "unavailable"
  )
  displayed = result.branches[:RESULT_LIMIT]
  eligible_count = len(result.branches)
  lines.extend([
    "",
    "Observed allocation:",
    f"  Target directory allocation:     {target_allocation}",
    f"  Unique observed target allocation: {format_bytes(result.unique_allocated_bytes)}",
    f"  Eligible immediate entries: {eligible_count}",
    f"  Cross-device immediate entries excluded: {result.cross_device_immediate}",
    f"  Showing {len(displayed)} of {eligible_count} eligible immediate entries",
  ])
  if displayed:
    lines.extend(["", "  ALLOCATED  PATH"])
    for branch in displayed:
      lines.append(f"  {format_bytes(branch.allocated_bytes)}  {display_safe(branch.path)}")
  else:
    lines.extend(["", "  No eligible immediate entries were observed."])
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


def inspect_result_code(result: ScanResult) -> int:
  return 1 if result.incomplete else 0


def main(argv: Sequence[str] | None = None) -> int:
  parser = build_argument_parser()
  arguments = parser.parse_args(argv)
  try:
    output, warnings, exit_code = inspect(arguments.path)
    print(output)
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
  return exit_code


if __name__ == "__main__":
  raise SystemExit(main())
