#!/usr/bin/env python3
"""Detect exact byte-content drift between one baseline and one current file."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import os
import stat
import sys
import unicodedata
from typing import Sequence


MAX_FILE_BYTES = 16 * 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024


class InvalidTargetError(Exception):
  """A requested comparison input is invalid or unsupported."""


class ObservationError(Exception):
  """No trustworthy comparison can be produced."""


@dataclass(frozen=True)
class FileObservation:
  path: str
  size: int
  sha256: str


@dataclass(frozen=True)
class ComparisonResult:
  baseline: FileObservation
  current: FileObservation
  drift_detected: bool


def build_argument_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(
    prog="configdiff",
    description=(
      "Detect exact byte-content drift between one local regular file and an explicit baseline."
    ),
  )
  parser.add_argument("baseline", help="baseline regular file")
  parser.add_argument("current", help="current regular file to compare with the baseline")
  return parser


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


def open_regular_file(path: str, label: str) -> tuple[int, os.stat_result]:
  try:
    descriptor = os.open(path, _open_flags())
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


def make_observation(path: str, data: bytes) -> FileObservation:
  return FileObservation(
    path=normalized_display_path(path),
    size=len(data),
    sha256=hashlib.sha256(data).hexdigest(),
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

    baseline = make_observation(baseline_path, baseline_data)
    current = make_observation(current_path, current_data)
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
      f"  Status: {status}",
      f"  Evidence: {evidence}",
      "",
      "Interpretation limits",
      "  Exact byte equality does not prove that a configuration is valid, effective, or healthy.",
      "  Content drift does not identify cause, severity, semantic meaning, or required remediation.",
    ]
  )


def inspect(baseline_path: str, current_path: str) -> tuple[str, int]:
  result = compare_files(baseline_path, current_path)
  return render_report(result), 1 if result.drift_detected else 0


def main(argv: Sequence[str] | None = None) -> int:
  parser = build_argument_parser()
  arguments = parser.parse_args(argv)
  try:
    report, exit_code = inspect(arguments.baseline, arguments.current)
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

  print_safe(report, file=sys.stdout)
  return exit_code


if __name__ == "__main__":
  raise SystemExit(main())
