#!/usr/bin/env python3
"""Detect bounded file or directory drift under explicit comparison semantics."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import difflib
import hashlib
import json
import math
import os
import re
import stat
import sys
import time
from typing import Sequence

from opsforge_common import (
  OutputError,
  OutputRecord,
  add_output_arguments,
  emit_output,
  make_conclusion,
  print_safe,
  sanitize_text as display_safe,
  validate_output_arguments,
)


MAX_FILE_BYTES = 16 * 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024
MAX_DIFF_LINES = 1000
MAX_DIFF_INPUT_LINES = 20_000
MAX_DIFF_LINE_CHARS = 1000
MAX_DIRECTORY_FILES = 10_000
MAX_DIRECTORY_DEPTH = 32
MAX_DIRECTORY_READ_BYTES = 512 * 1024 * 1024
DIRECTIVE_COMMENT = re.compile(rb"#(?:include|[0-9])")
MISSING = ("missing",)


class InvalidTargetError(Exception):
  """A requested comparison input is invalid or unsupported."""


class ObservationError(Exception):
  """No trustworthy comparison can be produced."""


@dataclass(frozen=True)
class FileObservation:
  path: str
  size: int
  sha256: str
  mode: int | None = None
  uid: int | None = None
  gid: int | None = None
  symlink_target: str | None = None


@dataclass(frozen=True)
class ComparisonResult:
  baseline: FileObservation
  current: FileObservation
  drift_detected: bool
  mode: str = "exact"
  metadata_drift: tuple[str, ...] = ()
  diff_lines: tuple[str, ...] = ()
  diff_truncated: bool = False
  content_drift: bool | None = None
  details: tuple[str, ...] = ()


@dataclass(frozen=True)
class DirectoryEntry:
  relative_path: str
  kind: str
  size: int
  sha256: str | None
  mode: int
  uid: int
  gid: int
  symlink_target: str | None
  device: int | None = None


@dataclass(frozen=True)
class DirectoryComparison:
  baseline: str
  current: str
  baseline_entries: tuple[DirectoryEntry, ...]
  current_entries: tuple[DirectoryEntry, ...]
  added: tuple[str, ...]
  removed: tuple[str, ...]
  changed: tuple[str, ...]
  drift_detected: bool
  unexamined: tuple[str, ...] = ()


def build_argument_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(
    prog="configdiff",
    description=(
      "Detect bounded file or directory drift under explicit comparison semantics."
    ),
  )
  parser.add_argument("baseline", help="baseline regular file or directory")
  parser.add_argument("current", help="current regular file or directory to compare with the baseline")
  modes = parser.add_mutually_exclusive_group()
  modes.add_argument("--ignore-whitespace", action="store_true", help="compare after removing ASCII whitespace")
  modes.add_argument("--ignore-comments", action="store_true", help="ignore blank and full-line # or ; comments")
  modes.add_argument("--json-semantic", action="store_true", help="compare JSON values with duplicate-key rejection")
  modes.add_argument("--metadata-only", action="store_true", help="compare selected metadata without comparing content")
  parser.add_argument("--keys", metavar="KEYS", help="comma-separated dotted JSON keys (requires --json-semantic)")
  parser.add_argument("--unified", action="store_true", help="show a bounded unified text diff; may expose sensitive content")
  parser.add_argument("--max-diff-lines", type=bounded_int(1, MAX_DIFF_LINES, "diff line limit"), default=200, metavar="N")
  parser.add_argument("--directory", action="store_true", help="compare bounded directory trees instead of regular files")
  parser.add_argument("--max-files", type=bounded_int(1, MAX_DIRECTORY_FILES, "file limit"), default=1000, metavar="N")
  parser.add_argument("--max-depth", type=bounded_int(0, MAX_DIRECTORY_DEPTH, "depth"), default=16, metavar="N")
  parser.add_argument("--permissions", action="store_true", help="include permission bits in drift classification")
  parser.add_argument("--ownership", action="store_true", help="include numeric owner/group in drift classification")
  parser.add_argument("--symlinks", action="store_true", help="accepted for compatibility; --directory always compares symlink target text")
  add_output_arguments(parser)
  return parser


def bounded_int(minimum: int, maximum: int, label: str):
  def parse(value: str) -> int:
    if not value.isascii() or not value.isdecimal() or not minimum <= int(value, 10) <= maximum:
      raise argparse.ArgumentTypeError(f"{label} must be from {minimum} through {maximum}")
    return int(value, 10)
  return parse


def normalized_display_path(path: str) -> str:
  try:
    return os.path.abspath(path)
  except OSError as error:
    raise InvalidTargetError(
      f"cannot normalize path {display_safe(path)}: {display_safe(error)}"
    ) from error


def _open_flags() -> int:
  flags = os.O_RDONLY | os.O_NOCTTY
  flags |= getattr(os, "O_CLOEXEC", 0)
  flags |= getattr(os, "O_NOFOLLOW", 0)
  flags |= getattr(os, "O_NONBLOCK", 0)
  return flags


def open_regular_file(path: str, label: str, *, dir_fd: int | None = None) -> tuple[int, os.stat_result]:
  # Inspect without opening first: opening some device nodes has side effects even if rejected later.
  try:
    inspected = os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
  except (OSError, ValueError) as error:
    raise InvalidTargetError(
      f"cannot open {label} file {display_safe(path)}: {display_safe(error)}"
    ) from error
  if not stat.S_ISREG(inspected.st_mode):
    raise InvalidTargetError(f"{label} path {display_safe(path)} is not a regular file")
  try:
    descriptor = os.open(path, _open_flags(), dir_fd=dir_fd)
  except (OSError, ValueError) as error:
    raise InvalidTargetError(
      f"cannot open {label} file {display_safe(path)}: {display_safe(error)}"
    ) from error

  try:
    try:
      metadata = os.fstat(descriptor)
    except OSError as error:
      raise ObservationError(
        f"cannot inspect {label} file after opening: {display_safe(error)}"
      ) from error
    if not stat.S_ISREG(metadata.st_mode):
      raise InvalidTargetError(
        f"{label} path {display_safe(path)} is not a regular file"
      )
    if (metadata.st_dev, metadata.st_ino) != (inspected.st_dev, inspected.st_ino):
      raise ObservationError(f"{label} file changed while it was being opened")
    if metadata.st_size < 0:
      raise ObservationError(f"{label} file reported an invalid size")
    if metadata.st_size > MAX_FILE_BYTES:
      raise InvalidTargetError(
        f"{label} file exceeds the {MAX_FILE_BYTES}-byte V1 limit"
      )
    return descriptor, metadata
  except BaseException:
    os.close(descriptor)
    raise


def metadata_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
  return (
    metadata.st_dev,
    metadata.st_ino,
    metadata.st_size,
    metadata.st_mtime_ns,
    metadata.st_ctime_ns,
  )


def read_exact_snapshot(
  descriptor: int,
  initial_metadata: os.stat_result,
  label: str,
) -> bytes:
  expected_size = initial_metadata.st_size
  chunks = []
  remaining = expected_size

  while remaining:
    try:
      chunk = os.read(descriptor, min(READ_CHUNK_BYTES, remaining))
    except OSError as error:
      raise ObservationError(
        f"cannot read {label} file: {display_safe(error)}"
      ) from error
    if not chunk:
      raise ObservationError(f"{label} file changed while it was being read")
    chunks.append(chunk)
    remaining -= len(chunk)

  try:
    extra = os.read(descriptor, 1)
  except OSError as error:
    raise ObservationError(
      f"cannot finish reading {label} file: {display_safe(error)}"
    ) from error
  if extra:
    raise ObservationError(f"{label} file changed while it was being read")

  return b"".join(chunks)


def verify_unchanged(
  descriptor: int,
  initial_metadata: os.stat_result,
  label: str,
) -> None:
  try:
    final_metadata = os.fstat(descriptor)
  except OSError as error:
    raise ObservationError(
      f"cannot verify {label} file after reading: {display_safe(error)}"
    ) from error
  if metadata_identity(final_metadata) != metadata_identity(initial_metadata):
    raise ObservationError(f"{label} file changed during the comparison")


def make_observation(path: str, data: bytes, metadata: os.stat_result | None = None) -> FileObservation:
  return FileObservation(
    path=normalized_display_path(path),
    size=len(data),
    sha256=hashlib.sha256(data).hexdigest(),
    mode=stat.S_IMODE(metadata.st_mode) if metadata is not None else None,
    uid=metadata.st_uid if metadata is not None else None,
    gid=metadata.st_gid if metadata is not None else None,
  )


def read_file_pair(baseline_path: str, current_path: str) -> tuple[bytes, bytes, FileObservation, FileObservation]:
  baseline_fd = current_fd = None
  try:
    baseline_fd, baseline_metadata = open_regular_file(baseline_path, "baseline")
    current_fd, current_metadata = open_regular_file(current_path, "current")
    baseline_data = read_exact_snapshot(baseline_fd, baseline_metadata, "baseline")
    current_data = read_exact_snapshot(current_fd, current_metadata, "current")
    verify_unchanged(baseline_fd, baseline_metadata, "baseline")
    verify_unchanged(current_fd, current_metadata, "current")
    return (
      baseline_data, current_data,
      make_observation(baseline_path, baseline_data, baseline_metadata),
      make_observation(current_path, current_data, current_metadata),
    )
  finally:
    if current_fd is not None:
      os.close(current_fd)
    if baseline_fd is not None:
      os.close(baseline_fd)


def _strict_json(pairs):
  result = {}
  for key, value in pairs:
    if key in result:
      raise ValueError(f"duplicate JSON key {display_safe(key[:64])!r}")
    result[key] = value
  return result


def _reject_constant(name: str) -> object:
  raise ValueError(f"non-standard JSON constant {name}")


def _finite_float(text: str) -> float:
  value = float(text)
  if not math.isfinite(value):
    raise ValueError("JSON number overflows a finite float")
  return value


def load_json(data: bytes) -> object:
  return json.loads(
    data.decode("utf-8"), object_pairs_hook=_strict_json,
    parse_constant=_reject_constant, parse_float=_finite_float,
  )


def canonical_json(value: object) -> object:
  """Tag JSON values by type so true, 1, and 1.0 never compare equal."""
  if value is MISSING:
    return MISSING
  if value is None:
    return ("null",)
  if isinstance(value, bool):
    return ("bool", value)
  if isinstance(value, int):
    return ("int", value)
  if isinstance(value, float):
    return ("float", value)
  if isinstance(value, str):
    return ("string", value)
  if isinstance(value, list):
    return ("array", tuple(canonical_json(item) for item in value))
  if isinstance(value, dict):
    return ("object", tuple(sorted((key, canonical_json(item)) for key, item in value.items())))
  raise ValueError(f"unsupported JSON value type {type(value).__name__}")


def _selected_json(value: object, keys: tuple[str, ...]) -> dict[str, object]:
  selected = {}
  for dotted in keys:
    current = value
    for component in dotted.split("."):
      if not isinstance(current, dict) or component not in current:
        current = MISSING
        break
      current = current[component]
    selected[dotted] = current
  return selected


def _bounded_diff_line(line: str) -> str:
  return line if len(line) <= MAX_DIFF_LINE_CHARS else line[:MAX_DIFF_LINE_CHARS] + "... [line truncated]"


def compare_files_mode(
  baseline_path: str,
  current_path: str,
  *,
  mode: str,
  permissions: bool,
  ownership: bool,
  selected_keys: tuple[str, ...],
  unified: bool,
  max_diff_lines: int,
) -> ComparisonResult:
  baseline_data, current_data, baseline, current = read_file_pair(baseline_path, current_path)
  details: list[str] = []
  try:
    if mode == "whitespace":
      left, right = b"".join(baseline_data.split()), b"".join(current_data.split())
    elif mode == "comments":
      def meaningful(data: bytes) -> tuple[bytes, ...]:
        kept = []
        for line in data.splitlines():
          stripped = line.strip()
          # sudoers treats #include, #includedir, and #<uid> as directives, not comments.
          if stripped and (not stripped.startswith((b"#", b";")) or DIRECTIVE_COMMENT.match(stripped)):
            kept.append(line)
        return tuple(kept)
      left, right = meaningful(baseline_data), meaningful(current_data)
    elif mode == "json":
      left_value, right_value = load_json(baseline_data), load_json(current_data)
      if selected_keys:
        left_value, right_value = _selected_json(left_value, selected_keys), _selected_json(right_value, selected_keys)
        for key in selected_keys:
          missing = [side for side, values in (("baseline", left_value), ("current", right_value)) if values[key] is MISSING]
          if missing:
            details.append(f"selected key {display_safe(key)} is absent in {' and '.join(missing)}")
      left, right = canonical_json(left_value), canonical_json(right_value)
    elif mode == "metadata":
      left = (baseline.size, baseline.mode, baseline.uid, baseline.gid)
      right = (current.size, current.mode, current.uid, current.gid)
    else:
      left, right = baseline_data, current_data
  except RecursionError as error:
    raise InvalidTargetError(f"cannot apply {mode} comparison: JSON nesting is too deep") from error
  except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
    raise InvalidTargetError(f"cannot apply {mode} comparison: {display_safe(error)}") from error
  metadata_drift = []
  if permissions and baseline.mode != current.mode:
    metadata_drift.append("permissions")
  if ownership and (baseline.uid, baseline.gid) != (current.uid, current.gid):
    metadata_drift.append("ownership")
  content_drift = left != right
  drift = content_drift or bool(metadata_drift)
  diff_lines = ()
  diff_truncated = False
  if unified and content_drift:
    try:
      baseline_text = baseline_data.decode("utf-8", "strict").splitlines()
      current_text = current_data.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError as error:
      raise InvalidTargetError("--unified requires UTF-8 text inputs") from error
    if max(len(baseline_text), len(current_text)) > MAX_DIFF_INPUT_LINES:
      details.append(f"unified diff skipped: an input exceeds {MAX_DIFF_INPUT_LINES} lines")
      generated = iter(())
    else:
      generated = difflib.unified_diff(
        baseline_text, current_text, fromfile=baseline.path, tofile=current.path, lineterm="",
      )
    collected = []
    for index, next_line in enumerate(generated):
      if index >= max_diff_lines:
        diff_truncated = True
        break
      collected.append(_bounded_diff_line(next_line))
    diff_lines = tuple(collected)
  return ComparisonResult(
    baseline, current, drift, mode, tuple(metadata_drift), diff_lines, diff_truncated,
    content_drift, tuple(details),
  )


def hash_exact_snapshot(descriptor: int, initial_metadata: os.stat_result, label: str) -> str:
  """Stream-hash exactly the initially observed size, failing if the file grows or shrinks."""
  digest = hashlib.sha256()
  remaining = initial_metadata.st_size
  try:
    while remaining:
      chunk = os.read(descriptor, min(READ_CHUNK_BYTES, remaining))
      if not chunk:
        raise ObservationError(f"{label} file changed while it was being read")
      digest.update(chunk)
      remaining -= len(chunk)
    if os.read(descriptor, 1):
      raise ObservationError(f"{label} file changed while it was being read")
  except OSError as error:
    raise ObservationError(f"cannot read {label} file: {display_safe(error)}") from error
  return digest.hexdigest()


def _special_kind(mode: int) -> str:
  if stat.S_ISFIFO(mode):
    return "fifo"
  if stat.S_ISSOCK(mode):
    return "socket"
  if stat.S_ISCHR(mode):
    return "char-device"
  if stat.S_ISBLK(mode):
    return "block-device"
  return "special"


def collect_directory(
  path: str, *, max_files: int, max_depth: int,
) -> tuple[str, tuple[DirectoryEntry, ...], DirectoryEntry, tuple[str, ...], tuple[str, ...]]:
  """Return (root, entries, root entry, depth-limited directories, other-filesystem directories)."""
  root = normalized_display_path(path)
  try:
    root_metadata = os.lstat(root)
  except OSError as error:
    raise InvalidTargetError(f"cannot inspect directory {display_safe(root)}: {display_safe(error)}") from error
  if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
    raise InvalidTargetError(f"directory target is not a non-symlink directory: {display_safe(root)}")
  flags = _open_flags() | getattr(os, "O_DIRECTORY", 0)
  try:
    root_fd = os.open(root, flags)
  except OSError as error:
    raise InvalidTargetError(f"cannot open directory {display_safe(root)}: {display_safe(error)}") from error
  entries = []
  depth_limited: list[str] = []
  other_filesystems: list[str] = []
  observed = 0
  read_budget = MAX_DIRECTORY_READ_BYTES

  def verify_directory(descriptor: int, expected: os.stat_result) -> None:
    opened = os.fstat(descriptor)
    if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
      raise ObservationError("directory identity changed during comparison")

  def has_entries(name: str, descriptor: int, expected: os.stat_result) -> bool:
    child_fd = os.open(name, flags, dir_fd=descriptor)
    try:
      verify_directory(child_fd, expected)
      with os.scandir(child_fd) as iterator:
        return next(iterator, None) is not None
    finally:
      os.close(child_fd)

  def visit(descriptor: int, prefix: str, depth: int) -> None:
    nonlocal observed, read_budget
    children = []
    with os.scandir(descriptor) as iterator:
      for child in iterator:
        if observed >= max_files:
          raise ObservationError(f"directory comparison exceeded the {max_files}-entry limit")
        observed += 1
        metadata = os.stat(child.name, dir_fd=descriptor, follow_symlinks=False)
        children.append((child.name, metadata))
    for name, metadata in sorted(children, key=lambda item: os.fsencode(item[0])):
      relative = os.path.join(prefix, name)
      mode, uid, gid = stat.S_IMODE(metadata.st_mode), metadata.st_uid, metadata.st_gid
      if stat.S_ISLNK(metadata.st_mode):
        target = os.readlink(name, dir_fd=descriptor)
        current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if metadata_identity(current) != metadata_identity(metadata):
          raise ObservationError(f"symlink changed during comparison: {display_safe(relative)}")
        entries.append(DirectoryEntry(relative, "symlink", metadata.st_size, None, mode, uid, gid, target))
      elif stat.S_ISDIR(metadata.st_mode):
        entries.append(DirectoryEntry(relative, "directory", 0, None, mode, uid, gid, None))
        if metadata.st_dev != root_metadata.st_dev:
          other_filesystems.append(relative)
        elif depth < max_depth:
          child_fd = os.open(name, flags, dir_fd=descriptor)
          try:
            verify_directory(child_fd, metadata)
            visit(child_fd, relative, depth + 1)
          finally:
            os.close(child_fd)
        elif has_entries(name, descriptor, metadata):
          depth_limited.append(relative)
      elif stat.S_ISREG(metadata.st_mode):
        file_fd, opened = open_regular_file(name, "directory entry", dir_fd=descriptor)
        try:
          if metadata_identity(opened) != metadata_identity(metadata):
            raise ObservationError(f"file changed during comparison: {display_safe(relative)}")
          read_budget -= opened.st_size
          if read_budget < 0:
            raise ObservationError(f"directory comparison exceeded the {MAX_DIRECTORY_READ_BYTES}-byte read budget")
          digest = hash_exact_snapshot(file_fd, opened, "directory entry")
          verify_unchanged(file_fd, opened, "directory entry")
        finally:
          os.close(file_fd)
        entries.append(DirectoryEntry(relative, "file", opened.st_size, digest, mode, opened.st_uid, opened.st_gid, None))
      else:
        device = metadata.st_rdev if stat.S_ISCHR(metadata.st_mode) or stat.S_ISBLK(metadata.st_mode) else None
        entries.append(DirectoryEntry(relative, _special_kind(metadata.st_mode), 0, None, mode, uid, gid, None, device))
  try:
    verify_directory(root_fd, root_metadata)
    visit(root_fd, "", 0)
  except (OSError, InvalidTargetError) as error:
    raise ObservationError(f"cannot observe directory {display_safe(root)}: {display_safe(error)}") from error
  finally:
    os.close(root_fd)
  root_entry = DirectoryEntry(
    ".", "directory", 0, None, stat.S_IMODE(root_metadata.st_mode), root_metadata.st_uid, root_metadata.st_gid, None,
  )
  return (
    root, tuple(sorted(entries, key=lambda item: os.fsencode(item.relative_path))), root_entry,
    tuple(depth_limited), tuple(other_filesystems),
  )


def compare_directories(
  baseline_path: str,
  current_path: str,
  *,
  max_files: int,
  max_depth: int,
  permissions: bool,
  ownership: bool,
) -> DirectoryComparison:
  baseline, baseline_entries, baseline_root, baseline_limited, baseline_other = collect_directory(
    baseline_path, max_files=max_files, max_depth=max_depth,
  )
  current, current_entries, current_root, current_limited, current_other = collect_directory(
    current_path, max_files=max_files, max_depth=max_depth,
  )
  left = {entry.relative_path: entry for entry in (baseline_root, *baseline_entries)}
  right = {entry.relative_path: entry for entry in (current_root, *current_entries)}
  added = tuple(sorted(set(right) - set(left), key=os.fsencode))
  removed = tuple(sorted(set(left) - set(right), key=os.fsencode))
  changed = []
  for name in sorted(set(left) & set(right), key=os.fsencode):
    a, b = left[name], right[name]
    content_key_a = (a.kind, a.size, a.sha256, a.symlink_target, a.device)
    content_key_b = (b.kind, b.size, b.sha256, b.symlink_target, b.device)
    if content_key_a != content_key_b or (permissions and a.mode != b.mode) or (ownership and (a.uid, a.gid) != (b.uid, b.gid)):
      changed.append(name)
  unexamined = tuple(sorted(
    {f"{item} (below --max-depth)" for item in (*baseline_limited, *current_limited)}
    | {f"{item} (other filesystem)" for item in (*baseline_other, *current_other)},
    key=os.fsencode,
  ))
  return DirectoryComparison(
    baseline, current, baseline_entries, current_entries, added, removed,
    tuple(changed), bool(added or removed or changed), unexamined,
  )


def render_report(result: ComparisonResult) -> str:
  content_drift = result.drift_detected if result.content_drift is None else result.content_drift
  if result.mode == "exact":
    status = "CONTENT DRIFT DETECTED" if content_drift else "NO CONTENT DRIFT"
    evidence = (
      "Observed current bytes differ from the observed baseline bytes."
      if content_drift
      else "Observed current bytes are exactly identical to the observed baseline bytes."
    )
  else:
    status = "CONTENT DRIFT DETECTED" if content_drift else "NO CONTENT DRIFT"
    evidence = (
      f"Observed inputs {'differ' if content_drift else 'match'} under {result.mode} comparison; "
      "this does not establish exact byte equality."
    )
  if result.metadata_drift:
    status = f"{status}; METADATA DRIFT DETECTED"
  header = "exact configuration-content comparison" if result.mode == "exact" else f"{result.mode} configuration comparison"
  return "\n".join(
    [
      f"ConfigDiff: {header}",
      "",
      "Baseline",
      f"  Path: {display_safe(result.baseline.path)}",
      f"  Bytes: {result.baseline.size}",
      f"  SHA-256: {result.baseline.sha256}",
      "",
      "Current",
      f"  Path: {display_safe(result.current.path)}",
      f"  Bytes: {result.current.size}",
      f"  SHA-256: {result.current.sha256}",
      "",
      "Comparison",
      f"  Mode: {display_safe(result.mode)}",
      f"  Status: {status}",
      f"  Evidence: {evidence}",
      f"  Metadata differences: {', '.join(result.metadata_drift) or 'none selected/observed'}",
      *(f"  Detail: {item}" for item in result.details),
      *( ["", "Unified diff (explicit content rendering; sensitive values may be present):", *[
        f"  {display_safe(line)}" for line in result.diff_lines
      ], *( ["  ... diff truncated at the configured line limit"] if result.diff_truncated else [] )] if result.diff_lines else [] ),
      "",
      "Interpretation limits",
      "  Exact byte equality does not prove that a configuration is valid, effective, or healthy.",
      "  Content drift does not identify cause, severity, semantic meaning, or required remediation.",
    ]
  )


def directory_status(result: DirectoryComparison) -> str:
  if result.drift_detected:
    return "DIRECTORY DRIFT DETECTED"
  return "INCOMPLETE (no drift among examined entries)" if result.unexamined else "NO DIRECTORY DRIFT"


def render_directory_report(result: DirectoryComparison) -> str:
  return "\n".join([
    "ConfigDiff: bounded directory comparison",
    f"Baseline: {display_safe(result.baseline)} ({len(result.baseline_entries)} entries)",
    f"Current: {display_safe(result.current)} ({len(result.current_entries)} entries)",
    f"Status: {directory_status(result)}",
    f"Added ({len(result.added)}): {', '.join(map(display_safe, result.added)) or 'none'}",
    f"Removed ({len(result.removed)}): {', '.join(map(display_safe, result.removed)) or 'none'}",
    f"Changed ({len(result.changed)}): {', '.join(map(display_safe, result.changed)) or 'none'}",
    f"Not examined ({len(result.unexamined)}): {', '.join(map(display_safe, result.unexamined)) or 'none'}",
    "The root directory is compared as '.'; symlink targets are compared as text and never followed.",
    "Content is represented by SHA-256 metadata and is not rendered.",
  ])


def main(argv: Sequence[str] | None = None) -> int:
  parser = build_argument_parser()
  arguments = parser.parse_args(argv)
  validate_output_arguments(parser, arguments)
  if arguments.keys is not None and not arguments.json_semantic:
    parser.error("--keys requires --json-semantic")
  if arguments.directory and (arguments.unified or arguments.json_semantic or arguments.ignore_comments or arguments.ignore_whitespace or arguments.metadata_only or arguments.keys is not None):
    parser.error("--directory cannot be combined with file content comparison modes")
  selected_keys = tuple(item.strip() for item in arguments.keys.split(",")) if arguments.keys is not None else ()
  if len(selected_keys) > 64 or any(len(item) > 256 or not item for item in selected_keys):
    parser.error("--keys accepts at most 64 non-empty dotted keys of at most 256 characters")
  mode = (
    "whitespace" if arguments.ignore_whitespace else
    "comments" if arguments.ignore_comments else
    "json" if arguments.json_semantic else
    "metadata" if arguments.metadata_only else "exact"
  )
  started = time.monotonic()
  try:
    if arguments.directory:
      result = compare_directories(
        arguments.baseline, arguments.current,
        max_files=arguments.max_files,
        max_depth=arguments.max_depth,
        permissions=arguments.permissions,
        ownership=arguments.ownership,
      )
      report = render_directory_report(result)
      drift = result.drift_detected
      incomplete = bool(result.unexamined) and not drift
      observations = {
        "comparison_mode": "directory", "added": result.added,
        "removed": result.removed, "changed": result.changed,
        "unexamined": result.unexamined,
        "baseline_entries": len(result.baseline_entries),
        "current_entries": len(result.current_entries),
      }
      target = f"{result.baseline} -> {result.current}"
    else:
      result = compare_files_mode(
        arguments.baseline, arguments.current, mode=mode,
        permissions=arguments.permissions, ownership=arguments.ownership,
        selected_keys=selected_keys, unified=arguments.unified,
        max_diff_lines=arguments.max_diff_lines,
      )
      report = render_report(result)
      drift = result.drift_detected
      incomplete = False
      observations = {
        "comparison_mode": mode,
        "baseline": result.baseline,
        "current": result.current,
        "content_drift": result.content_drift,
        "metadata_drift": result.metadata_drift,
        "details": result.details,
        "selected_keys": selected_keys,
        "unified_diff_lines": len(result.diff_lines),
        "unified_diff_truncated": result.diff_truncated,
      }
      target = f"{result.baseline.path} -> {result.current.path}"
    exit_code = 1 if drift else 3 if incomplete else 0
  except InvalidTargetError as error:
    print_safe(f"configdiff: {error}", file=sys.stderr)
    return 2
  except ObservationError as error:
    print_safe(f"configdiff: {error}", file=sys.stderr)
    return 3
  except KeyboardInterrupt:
    print_safe("configdiff: interrupted", file=sys.stderr)
    return 130
  except Exception:
    print_safe("configdiff: internal execution failure", file=sys.stderr)
    return 3

  status = "DRIFT" if drift else "INCOMPLETE" if incomplete else "UNCHANGED"
  if drift:
    finding = "the selected comparison detected differences"
    next_action = "review explicit diff or metadata evidence before applying changes"
  elif incomplete:
    finding = f"no differences were found among examined entries, but {len(result.unexamined)} director(ies) were not examined"
    next_action = "raise --max-depth or compare the unexamined directories separately before concluding there is no drift"
  else:
    finding = "the selected comparison detected no differences"
    next_action = "no drift was observed under the selected comparison semantics"
  conclusion = make_conclusion(status, target, finding, next_action)
  warnings = ("Unified diff output may contain sensitive configuration values.",) if arguments.unified else ()
  if arguments.unified:
    print_safe("configdiff: warning: unified diff may contain sensitive values", file=sys.stderr)
  record = OutputRecord(
    tool="configdiff", status=status, target=target, observations=observations,
    conclusion=conclusion, next_action=next_action + ".", warnings=warnings,
    elapsed_seconds=time.monotonic() - started,
  )
  brief = "\n".join([f"Comparison: {display_safe(target)}", f"Mode: {'directory' if arguments.directory else mode}", f"Drift: {'yes' if drift else 'no'}"])
  try:
    emit_output(
      record, detailed=report, brief=brief, json_mode=arguments.json,
      brief_mode=arguments.brief, quiet=arguments.quiet,
      output_path=arguments.output, force=arguments.force, stdout=sys.stdout,
    )
  except OutputError as error:
    print_safe(f"configdiff: {display_safe(error)}", file=sys.stderr)
    return 3
  return exit_code


if __name__ == "__main__":
  raise SystemExit(main())
