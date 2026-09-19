#!/usr/bin/env python3
"""Detect exact byte-content drift between one baseline and one current file."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import difflib
import hashlib
import json
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


MAX_FILE_BYTES = 16 * 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024
MAX_DIFF_LINES = 1000
MAX_DIRECTORY_FILES = 10_000
MAX_DIRECTORY_DEPTH = 32


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
  parser.add_argument("--symlinks", action="store_true", help="compare symlink targets in --directory mode")
  add_output_arguments(parser)
  return parser


def bounded_int(minimum: int, maximum: int, label: str):
  def parse(value: str) -> int:
    if not value.isascii() or not value.isdecimal() or not minimum <= int(value, 10) <= maximum:
      raise argparse.ArgumentTypeError(f"{label} must be from {minimum} through {maximum}")
    return int(value, 10)
  return parse


def display_safe(value: object) -> str:
  """Escape terminal controls, presentation controls, and ambiguous escapes."""
  rendered = []
  for character in str(value):
    codepoint = ord(character)
    category = unicodedata.category(character)
    if character == "\\":
      rendered.append("\\\\")
    elif 0xDC80 <= codepoint <= 0xDCFF:
      rendered.append(f"\\x{codepoint - 0xDC00:02x}")
    elif category in {"Cc", "Cf", "Cs", "Zl", "Zp"}:
      if codepoint <= 0xFF:
        rendered.append(f"\\x{codepoint:02x}")
      elif codepoint <= 0xFFFF:
        rendered.append(f"\\u{codepoint:04x}")
      else:
        rendered.append(f"\\U{codepoint:08x}")
    else:
      rendered.append(character)
  return "".join(rendered)


def stream_safe(value: object, stream: object) -> str:
  text = str(value)
  encoding = getattr(stream, "encoding", None)
  if not encoding:
    return text
  try:
    return text.encode(encoding, errors="backslashreplace").decode(encoding)
  except (LookupError, UnicodeError):
    return text.encode("ascii", errors="backslashreplace").decode("ascii")


def print_safe(value: object, *, file: object) -> None:
  print(stream_safe(value, file), file=file)


def normalized_display_path(path: str) -> str:
  try:
    return os.path.abspath(path)
  except OSError as error:
    raise InvalidTargetError(
      f"cannot normalize path {display_safe(path)}: {display_safe(error)}"
    ) from error


def _open_flags() -> int:
  flags = os.O_RDONLY
  flags |= getattr(os, "O_CLOEXEC", 0)
  flags |= getattr(os, "O_NOFOLLOW", 0)
  flags |= getattr(os, "O_NONBLOCK", 0)
  return flags


def open_regular_file(path: str, label: str, *, dir_fd: int | None = None) -> tuple[int, os.stat_result]:
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


def compare_files(baseline_path: str, current_path: str) -> ComparisonResult:
  baseline_fd = None
  current_fd = None
  try:
    baseline_fd, baseline_metadata = open_regular_file(baseline_path, "baseline")
    current_fd, current_metadata = open_regular_file(current_path, "current")

    baseline_data = read_exact_snapshot(baseline_fd, baseline_metadata, "baseline")
    current_data = read_exact_snapshot(current_fd, current_metadata, "current")

    verify_unchanged(baseline_fd, baseline_metadata, "baseline")
    verify_unchanged(current_fd, current_metadata, "current")

    baseline = make_observation(baseline_path, baseline_data, baseline_metadata)
    current = make_observation(current_path, current_data, current_metadata)
    return ComparisonResult(
      baseline=baseline,
      current=current,
      drift_detected=baseline_data != current_data,
    )
  finally:
    if current_fd is not None:
      os.close(current_fd)
    if baseline_fd is not None:
      os.close(baseline_fd)


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
      raise ValueError(f"duplicate JSON key {key!r}")
    result[key] = value
  return result


def _selected_json(value: object, keys: tuple[str, ...]) -> dict[str, object]:
  selected = {}
  for dotted in keys:
    current = value
    for component in dotted.split("."):
      if not isinstance(current, dict) or component not in current:
        raise InvalidTargetError(f"selected JSON key is missing: {display_safe(dotted)}")
      current = current[component]
    selected[dotted] = current
  return selected


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
  try:
    if mode == "whitespace":
      left, right = b"".join(baseline_data.split()), b"".join(current_data.split())
    elif mode == "comments":
      def meaningful(data: bytes) -> tuple[bytes, ...]:
        return tuple(line for line in data.splitlines() if line.strip() and not line.lstrip().startswith((b"#", b";")))
      left, right = meaningful(baseline_data), meaningful(current_data)
    elif mode == "json":
      left = json.loads(baseline_data.decode("utf-8"), object_pairs_hook=_strict_json)
      right = json.loads(current_data.decode("utf-8"), object_pairs_hook=_strict_json)
      if selected_keys:
        left, right = _selected_json(left, selected_keys), _selected_json(right, selected_keys)
    elif mode == "metadata":
      left = (baseline.size, baseline.mode, baseline.uid, baseline.gid)
      right = (current.size, current.mode, current.uid, current.gid)
    else:
      left, right = baseline_data, current_data
  except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
    raise InvalidTargetError(f"cannot apply {mode} comparison: {display_safe(error)}") from error
  metadata_drift = []
  if permissions and baseline.mode != current.mode:
    metadata_drift.append("permissions")
  if ownership and (baseline.uid, baseline.gid) != (current.uid, current.gid):
    metadata_drift.append("ownership")
  drift = left != right or bool(metadata_drift)
  diff_lines = ()
  diff_truncated = False
  if unified:
    try:
      baseline_text = baseline_data.decode("utf-8", "strict").splitlines()
      current_text = current_data.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError as error:
      raise InvalidTargetError("--unified requires UTF-8 text inputs") from error
    generated = difflib.unified_diff(
      baseline_text, current_text, fromfile=baseline.path, tofile=current.path, lineterm="",
    )
    collected = []
    for index, next_line in enumerate(generated):
      if index >= max_diff_lines:
        diff_truncated = True
        break
      collected.append(next_line)
    diff_lines = tuple(collected)
  return ComparisonResult(
    baseline, current, drift, mode, tuple(metadata_drift), diff_lines, diff_truncated,
  )


def collect_directory(path: str, *, max_files: int, max_depth: int, symlinks: bool) -> tuple[str, tuple[DirectoryEntry, ...]]:
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
  observed = 0

  def verify_directory(descriptor: int, expected: os.stat_result) -> None:
    opened = os.fstat(descriptor)
    if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
      raise ObservationError("directory identity changed during comparison")

  def visit(descriptor: int, prefix: str, depth: int) -> None:
    nonlocal observed
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
      if metadata.st_dev != root_metadata.st_dev:
        continue
      if stat.S_ISLNK(metadata.st_mode):
        target = None
        if symlinks:
          target = os.readlink(name, dir_fd=descriptor)
          current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
          if metadata_identity(current) != metadata_identity(metadata):
            raise ObservationError(f"symlink changed during comparison: {display_safe(relative)}")
        entries.append(DirectoryEntry(relative, "symlink", 0, None, stat.S_IMODE(metadata.st_mode), metadata.st_uid, metadata.st_gid, target))
      elif stat.S_ISDIR(metadata.st_mode):
        entries.append(DirectoryEntry(relative, "directory", 0, None, stat.S_IMODE(metadata.st_mode), metadata.st_uid, metadata.st_gid, None))
        if depth < max_depth:
          child_fd = os.open(name, flags, dir_fd=descriptor)
          try:
            verify_directory(child_fd, metadata)
            visit(child_fd, relative, depth + 1)
          finally:
            os.close(child_fd)
      elif stat.S_ISREG(metadata.st_mode):
        file_fd, opened = open_regular_file(name, "directory entry", dir_fd=descriptor)
        try:
          if metadata_identity(opened) != metadata_identity(metadata):
            raise ObservationError(f"file changed during comparison: {display_safe(relative)}")
          data = read_exact_snapshot(file_fd, opened, "directory entry")
          verify_unchanged(file_fd, opened, "directory entry")
        finally:
          os.close(file_fd)
        entries.append(DirectoryEntry(
          relative, "file", len(data), hashlib.sha256(data).hexdigest(),
          stat.S_IMODE(opened.st_mode), opened.st_uid, opened.st_gid, None,
        ))
      else:
        entries.append(DirectoryEntry(relative, "special", 0, None, stat.S_IMODE(metadata.st_mode), metadata.st_uid, metadata.st_gid, None))
  try:
    verify_directory(root_fd, root_metadata)
    visit(root_fd, "", 0)
  except (OSError, InvalidTargetError) as error:
    raise ObservationError(f"cannot observe directory {display_safe(root)}: {display_safe(error)}") from error
  finally:
    os.close(root_fd)
  return root, tuple(sorted(entries, key=lambda item: os.fsencode(item.relative_path)))


def compare_directories(
  baseline_path: str,
  current_path: str,
  *,
  max_files: int,
  max_depth: int,
  permissions: bool,
  ownership: bool,
  symlinks: bool,
) -> DirectoryComparison:
  baseline, baseline_entries = collect_directory(baseline_path, max_files=max_files, max_depth=max_depth, symlinks=symlinks)
  current, current_entries = collect_directory(current_path, max_files=max_files, max_depth=max_depth, symlinks=symlinks)
  left = {entry.relative_path: entry for entry in baseline_entries}
  right = {entry.relative_path: entry for entry in current_entries}
  added = tuple(sorted(set(right) - set(left), key=os.fsencode))
  removed = tuple(sorted(set(left) - set(right), key=os.fsencode))
  changed = []
  for name in sorted(set(left) & set(right), key=os.fsencode):
    a, b = left[name], right[name]
    content_key_a = (a.kind, a.size, a.sha256, a.symlink_target if symlinks else None)
    content_key_b = (b.kind, b.size, b.sha256, b.symlink_target if symlinks else None)
    if content_key_a != content_key_b or (permissions and a.mode != b.mode) or (ownership and (a.uid, a.gid) != (b.uid, b.gid)):
      changed.append(name)
  return DirectoryComparison(
    baseline, current, baseline_entries, current_entries, added, removed,
    tuple(changed), bool(added or removed or changed),
  )


def render_report(result: ComparisonResult) -> str:
  status = "CONTENT DRIFT DETECTED" if result.drift_detected else "NO CONTENT DRIFT"
  evidence = (
    "Observed current bytes differ from the observed baseline bytes."
    if result.drift_detected
    else "Observed current bytes are exactly identical to the observed baseline bytes."
  )
  return "\n".join(
    [
      "ConfigDiff: exact configuration-content comparison",
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
      *( ["", "Unified diff (explicit content rendering; sensitive values may be present):", *[
        f"  {display_safe(line)}" for line in result.diff_lines
      ], *( ["  ... diff truncated at the configured line limit"] if result.diff_truncated else [] )] if result.diff_lines else [] ),
      "",
      "Interpretation limits",
      "  Exact byte equality does not prove that a configuration is valid, effective, or healthy.",
      "  Content drift does not identify cause, severity, semantic meaning, or required remediation.",
    ]
  )


def render_directory_report(result: DirectoryComparison) -> str:
  return "\n".join([
    "ConfigDiff: bounded directory comparison",
    f"Baseline: {display_safe(result.baseline)} ({len(result.baseline_entries)} entries)",
    f"Current: {display_safe(result.current)} ({len(result.current_entries)} entries)",
    f"Status: {'DIRECTORY DRIFT DETECTED' if result.drift_detected else 'NO DIRECTORY DRIFT'}",
    f"Added ({len(result.added)}): {', '.join(map(display_safe, result.added)) or 'none'}",
    f"Removed ({len(result.removed)}): {', '.join(map(display_safe, result.removed)) or 'none'}",
    f"Changed ({len(result.changed)}): {', '.join(map(display_safe, result.changed)) or 'none'}",
    "Content is represented by SHA-256 metadata and is not rendered.",
  ])


def inspect(baseline_path: str, current_path: str) -> tuple[str, int]:
  result = compare_files(baseline_path, current_path)
  return render_report(result), 1 if result.drift_detected else 0


def main(argv: Sequence[str] | None = None) -> int:
  parser = build_argument_parser()
  arguments = parser.parse_args(argv)
  validate_output_arguments(parser, arguments)
  if arguments.keys and not arguments.json_semantic:
    parser.error("--keys requires --json-semantic")
  if arguments.directory and (arguments.unified or arguments.json_semantic or arguments.ignore_comments or arguments.ignore_whitespace or arguments.metadata_only or arguments.keys):
    parser.error("--directory cannot be combined with file content comparison modes")
  selected_keys = tuple(item for item in (arguments.keys.split(",") if arguments.keys else ()) if item)
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
        symlinks=arguments.symlinks,
      )
      report = render_directory_report(result)
      drift = result.drift_detected
      observations = {
        "comparison_mode": "directory", "added": result.added,
        "removed": result.removed, "changed": result.changed,
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
      observations = {
        "comparison_mode": mode,
        "baseline": result.baseline,
        "current": result.current,
        "metadata_drift": result.metadata_drift,
        "selected_keys": selected_keys,
        "unified_diff_lines": len(result.diff_lines),
        "unified_diff_truncated": result.diff_truncated,
      }
      target = f"{result.baseline.path} -> {result.current.path}"
    exit_code = 1 if drift else 0
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

  status = "DRIFT" if drift else "UNCHANGED"
  finding = "the selected comparison detected differences" if drift else "the selected comparison detected no differences"
  next_action = "review explicit diff or metadata evidence before applying changes" if drift else "no drift was observed under the selected comparison semantics"
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
