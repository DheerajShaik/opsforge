#!/usr/bin/env python3
"""Summarize recurring messages in one bounded local log file."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import ipaddress
import os
import re
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


MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024
RESULT_LIMIT = 10
EXCERPT_CODEPOINTS = 160
MAX_TOP = 100
MAX_ROTATED = 3
MAX_FILTERS = 16
MAX_STACK_LINES_PER_GROUP = 256
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
UUID_TOKEN = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b")
IPV4_TOKEN = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
PID_TOKEN = re.compile(r"(?i)\b(pid|process_id)([=: ]+)[0-9]{1,10}\b")
IDENTIFIER_TOKEN = re.compile(r"(?i)\b(request[_-]?id|trace[_-]?id|user[_-]?id|job[_-]?id)([=: ]+)[A-Za-z0-9._-]{1,128}")
SEVERITIES = ("critical", "error", "warning", "info", "debug")
STACK_LINE = re.compile(
  r'^(?:Traceback \(most recent call last\):|\s+File ".{0,512}", line [0-9]+|'
  r'\s+at [A-Za-z0-9_.$<>-]+\(.{0,512}\)|\s*Caused by:|\s*During handling of the above exception)'
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
  severity_counts: tuple[tuple[str, int], ...] = ()
  filtered_lines: int = 0
  timestamped_lines: int = 0
  duration_seconds: float | None = None
  peak_messages_per_minute: int | None = None
  sources: tuple[str, ...] = ()
  stack_trace_groups: int = 0
  stack_trace_lines: int = 0
  earlier_period_messages: int | None = None
  later_period_messages: int | None = None

  @property
  def incomplete(self) -> bool:
    return self.incomplete_warning is not None


@dataclass(frozen=True)
class AnalysisOptions:
  include: tuple[str, ...] = ()
  exclude: tuple[str, ...] = ()
  window_seconds: int | None = None


@dataclass
class LineMetrics:
  severity: dict[str, int] = field(default_factory=dict)
  filtered: int = 0
  timestamped: int = 0
  first_timestamp: datetime | None = None
  last_timestamp: datetime | None = None
  minute_counts: dict[int, int] = field(default_factory=dict)
  stack_groups: int = 0
  stack_lines: int = 0
  last_stack_line: int | None = None
  current_stack_lines: int = 0


def build_argument_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(
    prog="loghound",
    description=(
      "Summarize recurring normalized messages in bounded local regular log files."
    ),
  )
  parser.add_argument("path", help="local regular log file to inspect")
  parser.add_argument("--top", type=bounded_int(1, MAX_TOP, "top"), default=RESULT_LIMIT, metavar="N")
  parser.add_argument("--include", action="append", default=[], metavar="TEXT", help="include lines containing literal text")
  parser.add_argument("--exclude", action="append", default=[], metavar="TEXT", help="exclude lines containing literal text")
  parser.add_argument("--window-seconds", type=bounded_int(1, 31_536_000, "window"), metavar="N")
  parser.add_argument("--rotated", type=bounded_int(0, MAX_ROTATED, "rotated count"), default=0, metavar="N")
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


def display_excerpt(value: str) -> str:
  prefix = value[:EXCERPT_CODEPOINTS]
  suffix = "... [truncated]" if len(value) > EXCERPT_CODEPOINTS else ""
  return display_safe(prefix) + suffix


def stream_safe(value: object, stream: object) -> str:
  """Escape characters the destination text stream cannot encode."""
  text = str(value)
  encoding = getattr(stream, "encoding", None)
  if not encoding:
    return text
  try:
    return text.encode(encoding, errors="backslashreplace").decode(encoding)
  except (LookupError, UnicodeError):
    return text.encode("ascii", errors="backslashreplace").decode("ascii")


def print_safe(value: object, *, file: object) -> None:
  """Print without leaking UnicodeEncodeError for a restrictive text stream."""
  print(stream_safe(value, file), file=file)


def extract_timestamp(message: str) -> tuple[datetime | None, str]:
  match = TIMESTAMP_PREFIX.match(message)
  if match is None:
    return None, message
  try:
    zone = match.group("zone")
    if zone == "Z":
      zone_info = timezone.utc
    else:
      zone_hour = int(match.group("zone_hour"))
      zone_minute = int(match.group("zone_minute"))
      if zone_hour > 23 or zone_minute > 59:
        return None, message
      offset = timedelta(hours=zone_hour, minutes=zone_minute)
      if match.group("sign") == "-":
        offset = -offset
      zone_info = timezone(offset)
    parsed = datetime(
      int(match.group("year")), int(match.group("month")), int(match.group("day")),
      int(match.group("hour")), int(match.group("minute")), int(match.group("second")),
      tzinfo=zone_info,
    )
  except (TypeError, ValueError, OverflowError):
    return None, message
  return parsed.astimezone(timezone.utc), message[match.end():]


def _replace_ipv4(match: re.Match[str]) -> str:
  try:
    ipaddress.IPv4Address(match.group(0))
  except ValueError:
    return match.group(0)
  return "<ip>"


def normalize_message(message: str) -> str:
  """Conservatively normalize timestamps and well-delimited operational identifiers."""
  _, normalized = extract_timestamp(message)
  normalized = UUID_TOKEN.sub("<uuid>", normalized)
  normalized = IPV4_TOKEN.sub(_replace_ipv4, normalized)
  normalized = PID_TOKEN.sub(lambda match: f"{match.group(1).lower()}{match.group(2)}<pid>", normalized)
  normalized = IDENTIFIER_TOKEN.sub(lambda match: f"{match.group(1).lower()}{match.group(2)}<id>", normalized)
  return normalized


def classify_severity(message: str) -> str:
  lowered = message.lower()
  if re.search(r"\b(fatal|panic|critical|crit)\b", lowered):
    return "critical"
  if re.search(r"\b(error|exception|failed|failure)\b", lowered):
    return "error"
  if re.search(r"\b(warn|warning)\b", lowered):
    return "warning"
  if re.search(r"\bdebug\b", lowered):
    return "debug"
  return "info"


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
  *,
  terminated_by_lf: bool,
  options: AnalysisOptions | None = None,
  metrics: LineMetrics | None = None,
  cutoff: datetime | None = None,
) -> bool:
  if terminated_by_lf and record.endswith(b"\r"):
    record = record[:-1]
  if len(record) > MAX_LINE_BYTES:
    raise ObservationError(f"logical line {physical_line} exceeds {MAX_LINE_BYTES} bytes")
  message = record.decode("utf-8", errors="surrogateescape")
  timestamp, content = extract_timestamp(message)
  options = AnalysisOptions() if options is None else options
  if cutoff is not None and (timestamp is None or timestamp < cutoff):
    if metrics is not None:
      metrics.filtered += 1
    return False
  if options.include and not any(value in content for value in options.include):
    if metrics is not None:
      metrics.filtered += 1
    return False
  if options.exclude and any(value in content for value in options.exclude):
    if metrics is not None:
      metrics.filtered += 1
    return False
  normalized = normalize_message(message)
  if not normalized or normalized.isspace():
    return False
  evidence = patterns.get(normalized)
  if evidence is None:
    patterns[normalized] = [1, physical_line, physical_line]
  else:
    evidence[0] += 1
    evidence[2] = physical_line
  if metrics is not None:
    severity = classify_severity(content)
    metrics.severity[severity] = metrics.severity.get(severity, 0) + 1
    if timestamp is not None:
      metrics.timestamped += 1
      metrics.first_timestamp = timestamp if metrics.first_timestamp is None else min(metrics.first_timestamp, timestamp)
      metrics.last_timestamp = timestamp if metrics.last_timestamp is None else max(metrics.last_timestamp, timestamp)
      bucket = int(timestamp.timestamp()) // 60
      if bucket in metrics.minute_counts or len(metrics.minute_counts) < 10_000:
        metrics.minute_counts[bucket] = metrics.minute_counts.get(bucket, 0) + 1
    if STACK_LINE.match(content):
      continues = (
        metrics.last_stack_line == physical_line - 1
        and metrics.current_stack_lines < MAX_STACK_LINES_PER_GROUP
      )
      if not continues:
        metrics.stack_groups += 1
        metrics.current_stack_lines = 0
      metrics.stack_lines += 1
      metrics.current_stack_lines += 1
      metrics.last_stack_line = physical_line
  return True


def observe_descriptor(
  descriptor: int,
  target: str,
  boundary: int,
  options: AnalysisOptions | None = None,
  clock=lambda: datetime.now(timezone.utc),
) -> AnalysisResult:
  options = AnalysisOptions() if options is None else options
  cutoff = clock() - timedelta(seconds=options.window_seconds) if options.window_seconds is not None else None
  metrics = LineMetrics()
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
    record_start = 0
    while True:
      separator = buffer.find(b"\n", record_start)
      if separator < 0:
        break
      record = bytes(buffer[record_start:separator])
      record_start = separator + 1
      physical_lines += 1
      if _record_pattern(
        record, physical_lines, patterns, terminated_by_lf=True,
        options=options, metrics=metrics, cutoff=cutoff,
      ):
        analyzable_lines += 1
    if record_start:
      del buffer[:record_start]
    if len(buffer) > MAX_LINE_BYTES + 1 or (
      len(buffer) == MAX_LINE_BYTES + 1 and not buffer.endswith(b"\r")
    ):
      raise ObservationError(
        f"logical line {physical_lines + 1} exceeds {MAX_LINE_BYTES} bytes"
      )

  if warning is None and buffer:
    physical_lines += 1
    if _record_pattern(
      bytes(buffer), physical_lines, patterns, terminated_by_lf=False,
      options=options, metrics=metrics, cutoff=cutoff,
    ):
      analyzable_lines += 1
  elif warning is not None:
    buffer.clear()

  if warning is not None and analyzable_lines == 0:
    raise ObservationError(warning)
  evidence = tuple(
    PatternEvidence(key, values[0], values[1], values[2])
    for key, values in patterns.items()
  )
  earlier = later = None
  if metrics.minute_counts:
    first_bucket = min(metrics.minute_counts)
    last_bucket = max(metrics.minute_counts)
    midpoint = (first_bucket + last_bucket) / 2
    earlier = sum(count for bucket, count in metrics.minute_counts.items() if bucket <= midpoint)
    later = sum(count for bucket, count in metrics.minute_counts.items() if bucket > midpoint)
  return AnalysisResult(
    target=target,
    boundary_bytes=boundary,
    consumed_bytes=consumed,
    physical_lines=physical_lines,
    analyzable_lines=analyzable_lines,
    patterns=evidence,
    incomplete_warning=warning,
    severity_counts=tuple((name, metrics.severity.get(name, 0)) for name in SEVERITIES),
    filtered_lines=metrics.filtered,
    timestamped_lines=metrics.timestamped,
    duration_seconds=(metrics.last_timestamp - metrics.first_timestamp).total_seconds()
      if metrics.first_timestamp is not None and metrics.last_timestamp is not None else None,
    peak_messages_per_minute=max(metrics.minute_counts.values(), default=None),
    sources=(target,),
    stack_trace_groups=metrics.stack_groups,
    stack_trace_lines=metrics.stack_lines,
    earlier_period_messages=earlier,
    later_period_messages=later,
  )


def analyze(path: str, options: AnalysisOptions | None = None) -> AnalysisResult:
  target = normalize_target(path)
  descriptor, boundary = open_target(target)
  try:
    return observe_descriptor(descriptor, target, boundary, options)
  finally:
    os.close(descriptor)


def analyze_sources(path: str, options: AnalysisOptions, rotated: int) -> AnalysisResult:
  results = [analyze(path, options)]
  missing = []
  for index in range(1, rotated + 1):
    candidate = f"{path}.{index}"
    try:
      results.append(analyze(candidate, options))
    except InvalidTargetError:
      missing.append(candidate)
  merged: dict[str, list[int]] = {}
  offset = 0
  severity = {name: 0 for name in SEVERITIES}
  for result in results:
    for pattern in result.patterns:
      values = merged.setdefault(pattern.key, [0, pattern.first_line + offset, pattern.last_line + offset])
      values[0] += pattern.count
      values[2] = pattern.last_line + offset
    for name, count in result.severity_counts:
      severity[name] += count
    offset += result.physical_lines
  warnings = [item.incomplete_warning for item in results if item.incomplete_warning]
  if missing:
    warnings.append(f"{len(missing)} requested rotated files were unavailable")
  durations = [item.duration_seconds for item in results if item.duration_seconds is not None]
  peaks = [item.peak_messages_per_minute for item in results if item.peak_messages_per_minute is not None]
  return AnalysisResult(
    target=results[0].target,
    boundary_bytes=sum(item.boundary_bytes for item in results),
    consumed_bytes=sum(item.consumed_bytes for item in results),
    physical_lines=sum(item.physical_lines for item in results),
    analyzable_lines=sum(item.analyzable_lines for item in results),
    patterns=tuple(PatternEvidence(key, *values) for key, values in merged.items()),
    incomplete_warning="; ".join(warnings) if warnings else None,
    severity_counts=tuple((name, severity[name]) for name in SEVERITIES),
    filtered_lines=sum(item.filtered_lines for item in results),
    timestamped_lines=sum(item.timestamped_lines for item in results),
    duration_seconds=sum(durations) if durations else None,
    peak_messages_per_minute=max(peaks, default=None),
    sources=tuple(item.target for item in results),
    stack_trace_groups=sum(item.stack_trace_groups for item in results),
    stack_trace_lines=sum(item.stack_trace_lines for item in results),
    earlier_period_messages=(sum(item.earlier_period_messages or 0 for item in results) if any(item.earlier_period_messages is not None for item in results) else None),
    later_period_messages=(sum(item.later_period_messages or 0 for item in results) if any(item.later_period_messages is not None for item in results) else None),
  )


def rank_recurring(patterns: Sequence[PatternEvidence]) -> list[PatternEvidence]:
  recurring = [pattern for pattern in patterns if pattern.count >= 2]
  return sorted(recurring, key=lambda pattern: (
    -pattern.count,
    pattern.first_line,
    pattern.last_line,
    pattern.key.encode("utf-8", errors="surrogateescape"),
  ))


def render_result(result: AnalysisResult, *, top: int = RESULT_LIMIT) -> str:
  recurring = rank_recurring(result.patterns)
  displayed = recurring[:top]
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
    f"  Filtered physical lines: {result.filtered_lines}",
    f"  Timestamped analyzed lines: {result.timestamped_lines}",
    f"  Observed timestamp span: {result.duration_seconds if result.duration_seconds is not None else 'unavailable'} seconds",
    f"  Peak messages in one timestamp minute: {result.peak_messages_per_minute if result.peak_messages_per_minute is not None else 'unavailable'}",
    f"  Bounded stack-trace groups: {result.stack_trace_groups} ({result.stack_trace_lines} recognized lines)",
    f"  Earlier/later timestamp-period messages: {result.earlier_period_messages if result.earlier_period_messages is not None else 'unavailable'} / {result.later_period_messages if result.later_period_messages is not None else 'unavailable'}",
    "Severity classification",
    *[f"  {name}: {count}" for name, count in result.severity_counts],
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
  validate_output_arguments(parser, arguments)
  if len(arguments.include) > MAX_FILTERS or len(arguments.exclude) > MAX_FILTERS:
    parser.error(f"include/exclude filters may each be repeated at most {MAX_FILTERS} times")
  filters = (*arguments.include, *arguments.exclude)
  if any(not value or len(value) > 256 or display_safe(value) != value for value in filters):
    parser.error("filters must be printable literal text of at most 256 characters")
  options = AnalysisOptions(tuple(arguments.include), tuple(arguments.exclude), arguments.window_seconds)
  started = time.monotonic()
  try:
    result = analyze_sources(arguments.path, options, arguments.rotated)
    output = render_result(result, top=arguments.top)
    warning = None
    if result.incomplete_warning is not None:
      warning = f"loghound: warning: incomplete observation: {result.incomplete_warning}"
    exit_code = 1 if result.incomplete else 0
  except InvalidTargetError as error:
    print_safe(f"loghound: {display_safe(error)}", file=sys.stderr)
    return 2
  except ObservationError as error:
    print_safe(f"loghound: {display_safe(error)}", file=sys.stderr)
    return 3
  except KeyboardInterrupt:
    print_safe("loghound: interrupted", file=sys.stderr)
    return 130
  except Exception:
    print_safe("loghound: internal execution failure", file=sys.stderr)
    return 3
  if warning is not None:
    print_safe(warning, file=sys.stderr)
  recurring = rank_recurring(result.patterns)
  errors = dict(result.severity_counts).get("error", 0) + dict(result.severity_counts).get("critical", 0)
  status = "PARTIAL" if result.incomplete else "OBSERVED"
  finding = f"{len(recurring)} recurring patterns and {errors} error/critical messages were observed"
  next_action = (
    "resolve the incomplete read before relying on absence evidence" if result.incomplete
    else "review the highest-frequency patterns and timestamp bursts in context"
  )
  conclusion = make_conclusion(status, result.target, finding, next_action)
  rate = None
  if result.duration_seconds is not None and result.duration_seconds > 0:
    rate = result.analyzable_lines / result.duration_seconds
  record = OutputRecord(
    tool="loghound",
    status=status,
    target=result.target,
    observations={
      "sources": result.sources,
      "physical_lines": result.physical_lines,
      "analyzable_lines": result.analyzable_lines,
      "filtered_lines": result.filtered_lines,
      "patterns": rank_recurring(result.patterns)[:arguments.top],
      "severity_counts": dict(result.severity_counts),
      "message_rate_per_second": rate,
      "peak_messages_per_minute": result.peak_messages_per_minute,
      "timestamp_span_seconds": result.duration_seconds,
      "stack_trace_groups": result.stack_trace_groups,
      "stack_trace_lines": result.stack_trace_lines,
      "earlier_period_messages": result.earlier_period_messages,
      "later_period_messages": result.later_period_messages,
    },
    conclusion=conclusion,
    next_action=next_action + ".",
    warnings=(warning,) if warning else (),
    elapsed_seconds=time.monotonic() - started,
  )
  brief = "\n".join([
    f"Target: {display_safe(result.target)}",
    f"Analyzed lines: {result.analyzable_lines}",
    f"Recurring patterns: {len(recurring)}",
    f"Error/critical messages: {errors}",
    f"Peak per minute: {result.peak_messages_per_minute if result.peak_messages_per_minute is not None else 'unavailable'}",
  ])
  try:
    emit_output(
      record,
      detailed=output,
      brief=brief,
      json_mode=arguments.json,
      brief_mode=arguments.brief,
      quiet=arguments.quiet,
      output_path=arguments.output,
      force=arguments.force,
      stdout=sys.stdout,
    )
  except OutputError as error:
    print_safe(f"loghound: {display_safe(error)}", file=sys.stderr)
    return 3
  return exit_code


if __name__ == "__main__":
  raise SystemExit(main())
