#!/usr/bin/env python3
"""Summarize recurring messages in one bounded local log file."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import os
import re
import stat
import sys
import unicodedata
from typing import Sequence


MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024
RESULT_LIMIT = 10
EXCERPT_CODEPOINTS = 160
COMPRESSED_SIGNATURES = (
  (b"\x1f\x8b", "gzip"),
  (b"BZh", "bzip2"),
  (b"\xfd7zXZ\x00", "xz"),
  (b"PK\x03\x04", "ZIP"),
  (b"PK\x05\x06", "ZIP"),
  (b"PK\x07\x08", "ZIP"),
  (b"\x28\xb5\x2f\xfd", "Zstandard"),
)
TIMESTAMP_PREFIX = re.compile(
  r"^(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})"
  r"T(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
  r"(?:\.(?P<fraction>[0-9]+))?"
  r"(?P<zone>Z|(?P<sign>[+-])(?P<zone_hour>[0-9]{2}):(?P<zone_minute>[0-9]{2}))"
  r"(?P<spaces> +)"
)


class InvalidTargetError(Exception):
  """The selected path does not satisfy the target contract."""


class ObservationError(Exception):
  """No trustworthy useful analysis can be produced."""


@dataclass(frozen=True)
class PatternEvidence:
  key: str
  count: int
  first_line: int
  last_line: int


@dataclass(frozen=True)
class AnalysisResult:
  target: str
  boundary_bytes: int
  consumed_bytes: int
  physical_lines: int
  analyzable_lines: int
  patterns: tuple[PatternEvidence, ...]
  incomplete_warning: str | None = None

  @property
  def incomplete(self) -> bool:
    return self.incomplete_warning is not None


def build_argument_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(
    prog="loghound",
    description=(
      "Summarize recurring normalized messages in one bounded local regular log file."
    ),
  )
  parser.add_argument("path", help="local regular log file to inspect")
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


def display_excerpt(value: str) -> str:
  prefix = value[:EXCERPT_CODEPOINTS]
  suffix = "... [truncated]" if len(value) > EXCERPT_CODEPOINTS else ""
  return display_safe(prefix) + suffix


def normalize_message(message: str) -> str:
  """Remove only a valid timezone-qualified RFC 3339 prefix and spaces."""
  match = TIMESTAMP_PREFIX.match(message)
  if match is None:
    return message
  try:
    zone = match.group("zone")
    if zone == "Z":
      zone_info = timezone.utc
    else:
      offset = timedelta(
        hours=int(match.group("zone_hour")),
        minutes=int(match.group("zone_minute")),
      )
      if match.group("sign") == "-":
        offset = -offset
      zone_info = timezone(offset)
    datetime(
      int(match.group("year")), int(match.group("month")), int(match.group("day")),
      int(match.group("hour")), int(match.group("minute")), int(match.group("second")),
      tzinfo=zone_info,
    )
  except (TypeError, ValueError, OverflowError):
    return message
  return message[match.end():]


def compressed_format(prefix: bytes) -> str | None:
  for signature, name in COMPRESSED_SIGNATURES:
    if prefix.startswith(signature):
      return name
  return None


def normalize_target(path: str) -> str:
  if not path:
    raise InvalidTargetError("target path must not be empty")
  return os.path.abspath(os.path.normpath(path))


def open_target(path: str) -> tuple[int, int]:
  flags = os.O_RDONLY
  flags |= getattr(os, "O_CLOEXEC", 0)
  flags |= getattr(os, "O_NOFOLLOW", 0)
  flags |= getattr(os, "O_NONBLOCK", 0)
  try:
    descriptor = os.open(path, flags)
  except OSError as error:
    if error.errno == getattr(os, "ELOOP", 40):
      raise InvalidTargetError("final target must not be a symbolic link") from error
    raise InvalidTargetError(f"cannot open target: {display_safe(error)}") from error
  try:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
      raise InvalidTargetError("target is not a regular file")
    if metadata.st_size < 0:
      raise InvalidTargetError("target has an invalid initial size")
    if metadata.st_size > MAX_FILE_BYTES:
      raise InvalidTargetError(
        f"initial file size exceeds {MAX_FILE_BYTES} bytes"
      )
    return descriptor, metadata.st_size
  except Exception:
    os.close(descriptor)
    raise


def _record_pattern(
  record: bytes,
  physical_line: int,
  patterns: dict[str, list[int]],
) -> bool:
  if record.endswith(b"\r"):
    record = record[:-1]
  if len(record) > MAX_LINE_BYTES:
    raise ObservationError(f"logical line {physical_line} exceeds {MAX_LINE_BYTES} bytes")
  message = record.decode("utf-8", errors="surrogateescape")
  normalized = normalize_message(message)
  if not normalized or normalized.isspace():
    return False
  evidence = patterns.get(normalized)
  if evidence is None:
    patterns[normalized] = [1, physical_line, physical_line]
  else:
    evidence[0] += 1
    evidence[2] = physical_line
  return True


def observe_descriptor(descriptor: int, target: str, boundary: int) -> AnalysisResult:
  remaining = boundary
  consumed = 0
  buffer = bytearray()
  physical_lines = 0
  analyzable_lines = 0
  patterns: dict[str, list[int]] = {}
  checked_signature = False
  signature_prefix = bytearray()
  signature_length = min(boundary, max(len(item[0]) for item in COMPRESSED_SIGNATURES))
  warning = None

  while remaining:
    try:
      chunk = os.read(descriptor, min(READ_CHUNK_BYTES, remaining))
    except OSError as error:
      warning = f"read failed before the initial byte boundary: {display_safe(error)}"
      break
    if not chunk:
      warning = "reached end of file before the initial byte boundary"
      break
    if not checked_signature:
      signature_prefix.extend(chunk[:signature_length - len(signature_prefix)])
      if len(signature_prefix) >= signature_length:
        checked_signature = True
      kind = compressed_format(bytes(signature_prefix))
      if kind is not None:
        raise InvalidTargetError(f"unsupported compressed {kind} content")
    consumed += len(chunk)
    remaining -= len(chunk)
    if b"\x00" in chunk:
      raise ObservationError("NUL byte found in observed input")
    buffer.extend(chunk)
    while True:
      separator = buffer.find(b"\n")
      if separator < 0:
        break
      record = bytes(buffer[:separator])
      del buffer[:separator + 1]
      physical_lines += 1
      if _record_pattern(record, physical_lines, patterns):
        analyzable_lines += 1
    if len(buffer) > MAX_LINE_BYTES + 1 or (
      len(buffer) == MAX_LINE_BYTES + 1 and not buffer.endswith(b"\r")
    ):
      raise ObservationError(
        f"logical line {physical_lines + 1} exceeds {MAX_LINE_BYTES} bytes"
      )

  if warning is None and buffer:
    physical_lines += 1
    if _record_pattern(bytes(buffer), physical_lines, patterns):
      analyzable_lines += 1
  elif warning is not None:
    buffer.clear()

  if warning is not None and analyzable_lines == 0:
    raise ObservationError(warning)
  evidence = tuple(
    PatternEvidence(key, values[0], values[1], values[2])
    for key, values in patterns.items()
  )
  return AnalysisResult(
    target=target,
    boundary_bytes=boundary,
    consumed_bytes=consumed,
    physical_lines=physical_lines,
    analyzable_lines=analyzable_lines,
    patterns=evidence,
    incomplete_warning=warning,
  )


def analyze(path: str) -> AnalysisResult:
  target = normalize_target(path)
  descriptor, boundary = open_target(target)
  try:
    return observe_descriptor(descriptor, target, boundary)
  finally:
    os.close(descriptor)


def rank_recurring(patterns: Sequence[PatternEvidence]) -> list[PatternEvidence]:
  recurring = [pattern for pattern in patterns if pattern.count >= 2]
  return sorted(recurring, key=lambda pattern: (
    -pattern.count,
    pattern.first_line,
    pattern.last_line,
    pattern.key.encode("utf-8", errors="surrogateescape"),
  ))


def render_result(result: AnalysisResult) -> str:
  recurring = rank_recurring(result.patterns)
  displayed = recurring[:RESULT_LIMIT]
  lines = [
    "Target",
    f"  Path: {display_safe(result.target)}",
    "Observation",
    f"  Status: {'incomplete' if result.incomplete else 'complete'}",
    f"  Initial byte boundary: {result.boundary_bytes}",
    f"  Bytes consumed: {result.consumed_bytes}",
    f"  Completely observed physical lines: {result.physical_lines}",
    "  Scope: one opened regular file; bytes beyond the initial boundary excluded",
    "  Snapshot: no; the file may have changed during observation",
    "Analysis summary",
    f"  Analyzable nonblank normalized lines: {result.analyzable_lines}",
    f"  Distinct normalized patterns: {len(result.patterns)}",
    f"  Recurring patterns: {len(recurring)}",
    f"  Displayed recurring patterns: {len(displayed)} of {len(recurring)}",
    "Recurring patterns",
  ]
  if not displayed:
    lines.append("  No normalized pattern occurred at least twice in the observed data.")
  for rank, pattern in enumerate(displayed, 1):
    percentage = pattern.count * 100 / result.analyzable_lines
    lines.extend((
      f"  Pattern {rank}",
      f"    Count: {pattern.count}",
      f"    Percentage: {percentage:.2f}%",
      f"    First physical line: {pattern.first_line}",
      f"    Last physical line: {pattern.last_line}",
      f"    Excerpt: {display_excerpt(pattern.key)}",
    ))
  lines.extend((
    "Interpretation limits",
    "  Recurrence is textual evidence only; it does not establish incident, failure, severity, anomaly, health, maliciousness, or root cause.",
    "  Absence of recurrence does not establish health.",
    "  Physical file order is not parsed timestamp chronology.",
    "  This observation is not an atomic snapshot.",
  ))
  return "\n".join(lines)


def inspect(path: str) -> tuple[str, str | None, int]:
  result = analyze(path)
  warning = None
  if result.incomplete_warning is not None:
    warning = f"loghound: warning: incomplete observation: {result.incomplete_warning}"
  return render_result(result), warning, 1 if result.incomplete else 0


def main(argv: Sequence[str] | None = None) -> int:
  parser = build_argument_parser()
  arguments = parser.parse_args(argv)
  try:
    output, warning, exit_code = inspect(arguments.path)
  except InvalidTargetError as error:
    print(f"loghound: {display_safe(error)}", file=sys.stderr)
    return 2
  except ObservationError as error:
    print(f"loghound: {display_safe(error)}", file=sys.stderr)
    return 3
  except KeyboardInterrupt:
    print("loghound: interrupted", file=sys.stderr)
    return 130
  except Exception:
    print("loghound: internal execution failure", file=sys.stderr)
    return 3
  print(output)
  if warning is not None:
    print(warning, file=sys.stderr)
  return exit_code


if __name__ == "__main__":
  raise SystemExit(main())
