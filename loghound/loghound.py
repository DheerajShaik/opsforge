#!/usr/bin/env python3
"""Summarize recurring messages in one bounded local log file."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import functools
import hashlib
import heapq
import ipaddress
import os
import re
import stat
import sys
import time
from typing import Callable, Sequence

from opsforge_common import (
  OutputError,
  OutputRecord,
  add_output_arguments,
  emit_output,
  has_unsafe_characters,
  make_conclusion,
  print_safe,
  sanitize_text as display_safe,
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
# 32 days of minutes, so a monthly log keeps its peak and period evidence.
MAX_MINUTE_BUCKETS = 32 * 24 * 60
MAX_PATTERNS = 100_000
LEVEL_SEARCH_CODEPOINTS = 128
RFC3164_FUTURE_TOLERANCE = timedelta(days=1)
COMPRESSED_SIGNATURES = (
  (b"\x1f\x8b", "gzip"),
  (b"BZh", "bzip2"),
  (b"\xfd7zXZ\x00", "xz"),
  (b"PK\x03\x04", "ZIP"),
  (b"PK\x05\x06", "ZIP"),
  (b"PK\x07\x08", "ZIP"),
  (b"\x28\xb5\x2f\xfd", "Zstandard"),
)
ISO_TIMESTAMP = re.compile(
  r"(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})"
  r"[Tt ](?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
  r"(?:[.,](?P<fraction>[0-9]{1,9}))?"
  r"(?P<zone>[Zz]|(?P<sign>[+-])(?P<zone_hour>[0-9]{2}):?(?P<zone_minute>[0-9]{2}))?"
  r"(?:[ \t]+|$)"
)
RFC3164_TIMESTAMP = re.compile(
  r"(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (?P<day>[ 0-9]?[0-9]) "
  r"(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})(?:[ \t]+|$)"
)
MONTHS = {name: number for number, name in enumerate(
  ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1,
)}
UUID_TOKEN = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
IPV6_TOKEN = re.compile(
  r"(?<![0-9A-Za-z:.])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[0-9A-Fa-f]{1,4})?"
  r"(?:%[0-9A-Za-z_.-]{1,32})?(?![0-9A-Za-z:]|\.[0-9])"
)
IPV4_TOKEN = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9]|\.[0-9])")
# The syslog tag is the first token, or the second after a hostname: "host sshd[4242]: ...".
SYSLOG_TAG_PID = re.compile(r"^((?:\S+ )?[^\s\[\]:]{1,64})\[[0-9]{1,10}\]:")
PID_TOKEN = re.compile(r'(?i)\b(pid|process_id)("?[=: ]+"?)[0-9]{1,10}\b')
PORT_TOKEN = re.compile(r'(?i)\b(port)("?[=: ]+"?)[0-9]{1,5}\b')
IDENTIFIER_TOKEN = re.compile(r'(?i)\b(request[_-]?id|trace[_-]?id|user[_-]?id|job[_-]?id)("?[=: ]+"?)[A-Za-z0-9._-]{1,128}')
SEVERITIES = ("critical", "error", "warning", "info", "debug")
LEVELS = {
  "emerg": "critical", "emergency": "critical", "alert": "critical", "crit": "critical",
  "critical": "critical", "fatal": "critical", "panic": "critical",
  "err": "error", "error": "error", "severe": "error",
  "warn": "warning", "warning": "warning",
  "notice": "info", "info": "info",
  "debug": "debug", "trace": "debug",
}
SYSLOG_PRIORITY = re.compile(r"<([0-9]{1,3})>")
SYSLOG_SEVERITIES = ("critical", "critical", "critical", "error", "warning", "info", "info", "debug")
GLOG_PREFIX = re.compile(r"([IWEF])[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2}")
GLOG_SEVERITIES = {"I": "info", "W": "warning", "E": "error", "F": "critical"}
LEVEL_FIELD = re.compile(r'(?i)\b(?:level|severity|lvl|loglevel)"?[=:] ?"?([a-z]{3,9})\b')
LEVEL_WORD = re.compile(
  r"(?<![\w/.-])(EMERG|EMERGENCY|ALERT|CRIT|CRITICAL|FATAL|PANIC|SEVERE|ERR|ERROR|WARN|WARNING|NOTICE|INFO|DEBUG|TRACE)"
  r"(?![\w/-]|\.\w)|\[(?i:(emerg|alert|crit|error|warn|notice|info|debug))\]"
)
SEVERITY_KEYWORD = re.compile(
  r"(?<![\w/.-])(?:(fatal|panic|critical|crit)|(errors?|exceptions?|failed|failures?|failing)|(warn|warnings?)|(debug))"
  r"(?![\w/-]|\.\w)",
  re.IGNORECASE,
)
KEYWORD_SEVERITIES = ("info", "critical", "error", "warning", "debug")
ZERO_VALUE = re.compile(r'"?\s*[=:]\s*"?(?:0+|false|no|none|null)\b', re.IGNORECASE)
NEGATION = re.compile(r"(?:^|\W)(?:no|0|zero|without)\s+$", re.IGNORECASE)
PYTHON_TRACEBACK = re.compile(r"Traceback \(most recent call last\):")
PYTHON_FRAME = re.compile(r'\s+File ".{0,512}", line [0-9]+')
PYTHON_CHAIN = re.compile(r"During handling of the above exception|The above exception was the direct cause")
PYTHON_EXCEPTION = re.compile(r"[A-Za-z_][\w.]{0,255}(?::|$)")
JAVA_THREAD_HEADER = re.compile(r'Exception in thread "')
JAVA_EXCEPTION = re.compile(r"(?:[\w$]+\.)+[\w$]*(?:Exception|Error|Throwable)\b")
JAVA_FRAME = re.compile(r"\s+(?:at [\w$.@/<>-]{1,512}\(.{0,512}\)|\.\.\. [0-9]+ (?:more|common frames omitted))")
JAVA_CHAIN = re.compile(r"\s*(?:Caused by|Suppressed): ")


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
  # KEY holds at most EXCERPT_CODEPOINTS of the normalized text; length and BLAKE2b-128 digest identify the whole.
  key_length: int | None = None
  key_digest: str | None = None

  @property
  def key_truncated(self) -> bool:
    return self.key_length is not None and self.key_length > len(self.key)


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
  first_timestamp: datetime | None = None
  last_timestamp: datetime | None = None
  minute_counts: tuple[tuple[int, int], ...] = ()
  minute_counts_complete: bool = True
  untracked_lines: int = 0
  truncated_lines: int = 0
  nul_bytes_removed: int = 0
  undated_lines_excluded: int = 0
  local_time_lines: int = 0
  unavailable_sources: tuple[tuple[str, str], ...] = ()

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
  local_time: int = 0
  undated_excluded: int = 0
  truncated: int = 0
  first_timestamp: datetime | None = None
  last_timestamp: datetime | None = None
  # Undated lines such as stack frames inherit the latest timestamp for window filtering.
  inherited_timestamp: datetime | None = None
  minute_counts: dict[int, int] = field(default_factory=dict)
  minute_counts_complete: bool = True
  stack_groups: int = 0
  stack_lines: int = 0
  stack_state: str | None = None
  stack_last_line: int = 0
  current_stack_lines: int = 0
  last_nonblank_line: int = 0
  java_header_line: int = 0


class PatternStore:
  """Distinct normalized patterns keyed by digest; at most MAX_PATTERNS are tracked."""

  def __init__(self) -> None:
    self.entries: dict[bytes, list] = {}
    self.untracked_lines = 0

  def add(self, normalized: str, line: int) -> None:
    digest = hashlib.blake2b(normalized.encode("utf-8", "surrogateescape"), digest_size=16).digest()
    entry = self.entries.get(digest)
    if entry is not None:
      entry[0] += 1
      entry[2] = line
    elif len(self.entries) < MAX_PATTERNS:
      self.entries[digest] = [1, line, line, normalized[:EXCERPT_CODEPOINTS], len(normalized)]
    else:
      self.untracked_lines += 1

  def evidence(self) -> tuple[PatternEvidence, ...]:
    return tuple(
      PatternEvidence(excerpt, count, first, last, length, digest.hex())
      for digest, (count, first, last, excerpt, length) in self.entries.items()
    )


class Parser(argparse.ArgumentParser):
  def error(self, message):
    self.print_usage(sys.stderr)
    self.exit(2, f"{self.prog}: error: {display_safe(message)}\n")


def build_argument_parser() -> argparse.ArgumentParser:
  parser = Parser(
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


def display_excerpt(value: str) -> str:
  prefix = value[:EXCERPT_CODEPOINTS]
  suffix = "... [truncated]" if len(value) > EXCERPT_CODEPOINTS else ""
  return display_safe(prefix) + suffix


def pattern_excerpt(pattern: PatternEvidence) -> str:
  if pattern.key_truncated:
    return display_safe(pattern.key[:EXCERPT_CODEPOINTS]) + "... [truncated]"
  return display_excerpt(pattern.key)


@functools.lru_cache(maxsize=4096)
def _iso_timestamp(groups: tuple[str | None, ...]) -> tuple[datetime, bool] | None:
  year, month, day, hour, minute, second, fraction, zone, sign, zone_hour, zone_minute = groups
  try:
    if zone is None:
      zone_info = None
    elif zone in ("Z", "z"):
      zone_info = timezone.utc
    else:
      hours, minutes = int(zone_hour, 10), int(zone_minute, 10)
      if hours > 23 or minutes > 59:
        return None
      offset = timedelta(hours=hours, minutes=minutes)
      zone_info = timezone(-offset if sign == "-" else offset)
    parsed = datetime(
      int(year, 10), int(month, 10), int(day, 10), int(hour, 10), int(minute, 10), int(second, 10),
      int((fraction or "0")[:6].ljust(6, "0"), 10), tzinfo=zone_info,
    )
    # A zone-less value is read as local time, where the logging host most likely wrote it.
    return parsed.astimezone(timezone.utc), zone_info is None
  except (ValueError, OverflowError, OSError):
    return None


@functools.lru_cache(maxsize=4096)
def _rfc3164_timestamp(groups: tuple[str, ...], reference: datetime) -> datetime | None:
  month, day, hour, minute, second = groups
  try:
    limit = reference + RFC3164_FUTURE_TOLERANCE
  except OverflowError:
    limit = reference
  # RFC 3164 omits the year: take the latest year that does not place the entry after the file was written.
  for year in range(reference.year, reference.year - 8, -1):
    try:
      candidate = datetime(
        year, MONTHS[month], int(day, 10), int(hour, 10), int(minute, 10), int(second, 10),
      ).astimezone(timezone.utc)
    except (ValueError, OverflowError, OSError):
      continue
    if candidate <= limit:
      return candidate
  return None


def extract_timestamp(message: str, reference: datetime | None = None) -> tuple[datetime | None, str, bool]:
  """Return (UTC time, remaining text, local time assumed) for a supported leading timestamp."""
  match = ISO_TIMESTAMP.match(message)
  if match is not None:
    parsed = _iso_timestamp(match.groups())
    if parsed is None:
      return None, message, False
    return parsed[0], message[match.end():], parsed[1]
  match = RFC3164_TIMESTAMP.match(message)
  if match is not None:
    parsed = _rfc3164_timestamp(match.groups(), reference or datetime.now(timezone.utc))
    if parsed is not None:
      return parsed, message[match.end():], True
  return None, message, False


def _replace_address(match: re.Match[str]) -> str:
  try:
    ipaddress.ip_address(match.group(0))
  except ValueError:
    return match.group(0)
  return "<ip>"


def normalize_content(text: str) -> str:
  """Replace well-delimited operational identifiers in text whose timestamp was already removed."""
  if "-" in text:
    text = UUID_TOKEN.sub("<uuid>", text)
  if "::" in text or text.count(":") >= 7:
    text = IPV6_TOKEN.sub(_replace_address, text)
  if "." in text:
    text = IPV4_TOKEN.sub(_replace_address, text)
  if "[" in text:
    text = SYSLOG_TAG_PID.sub(r"\1[<pid>]:", text)
  text = PID_TOKEN.sub(lambda match: f"{match.group(1).lower()}{match.group(2)}<pid>", text)
  text = PORT_TOKEN.sub(lambda match: f"{match.group(1).lower()}{match.group(2)}<port>", text)
  return IDENTIFIER_TOKEN.sub(lambda match: f"{match.group(1).lower()}{match.group(2)}<id>", text)


def normalize_message(message: str) -> str:
  """Conservatively normalize timestamps and well-delimited operational identifiers."""
  return normalize_content(extract_timestamp(message)[1])


def explicit_severity(message: str) -> str | None:
  """Return the level a line states itself: syslog PRI, glog prefix, level field, or level word."""
  match = SYSLOG_PRIORITY.match(message)
  if match is not None and int(match.group(1), 10) <= 191:
    return SYSLOG_SEVERITIES[int(match.group(1), 10) % 8]
  match = GLOG_PREFIX.match(message)
  if match is not None:
    return GLOG_SEVERITIES[match.group(1)]
  match = LEVEL_FIELD.search(message)
  if match is not None and match.group(1).lower() in LEVELS:
    return LEVELS[match.group(1).lower()]
  match = LEVEL_WORD.search(message, 0, LEVEL_SEARCH_CODEPOINTS)
  if match is not None:
    return LEVELS[(match.group(1) or match.group(2)).lower()]
  return None


def classify_severity(message: str) -> str:
  explicit = explicit_severity(message)
  if explicit is not None:
    return explicit
  best = 0
  for match in SEVERITY_KEYWORD.finditer(message):
    rank = match.lastindex
    if best and rank >= best:
      continue
    # "failed=0", "errors: none", "no error", and "0 errors" report the absence of a problem.
    if ZERO_VALUE.match(message, match.end()) or NEGATION.search(message, max(0, match.start() - 16), match.start()):
      continue
    best = rank
    if best == 1:
      break
  return KEYWORD_SEVERITIES[best]


def compressed_format(prefix: bytes) -> str | None:
  for signature, name in COMPRESSED_SIGNATURES:
    if prefix.startswith(signature):
      return name
  return None


def display_target(path: str) -> str:
  """Return an absolute display form without collapsing '..' lexically; the kernel resolves PATH as given."""
  return path if os.path.isabs(path) else os.path.join(os.getcwd(), path)


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


def _track_stack(metrics: LineMetrics, line: int, content: str, dated: bool, previous_nonblank: int) -> None:
  """Group Python and Java stack traces, including source, caret, exception, and cause-chain lines."""
  state = metrics.stack_state
  open_group = state is not None and not dated and metrics.current_stack_lines < MAX_STACK_LINES_PER_GROUP
  adjacent = open_group and metrics.stack_last_line == line - 1
  # Python separates chained tracebacks with blank lines, so only blank lines may intervene there.
  bridged = open_group and metrics.stack_last_line == previous_nonblank
  header = False
  if PYTHON_TRACEBACK.match(content):
    continues, state = bridged and state == "chain", "python"
  elif PYTHON_FRAME.match(content):
    continues, state = adjacent and state == "python", "python"
  elif bridged and state == "ended" and PYTHON_CHAIN.match(content):
    continues, state = True, "chain"
  elif JAVA_THREAD_HEADER.match(content):
    continues, state = False, "java"
  elif JAVA_FRAME.match(content) or JAVA_CHAIN.match(content):
    continues = adjacent and state == "java"
    header = not continues and metrics.java_header_line == line - 1
    state = "java"
  elif adjacent and state == "python" and (content[:1].isspace() or PYTHON_EXCEPTION.match(content)):
    continues, state = True, "python" if content[:1].isspace() else "ended"
  else:
    metrics.stack_state = None
    if JAVA_EXCEPTION.match(content):
      metrics.java_header_line = line
    return
  if not continues:
    metrics.stack_groups += 1
    metrics.current_stack_lines = int(header)
    metrics.stack_lines += int(header)
  metrics.stack_lines += 1
  metrics.current_stack_lines += 1
  metrics.stack_last_line = line
  metrics.stack_state = state


def _record_line(
  record: bytes,
  line: int,
  metrics: LineMetrics,
  store: PatternStore,
  options: AnalysisOptions,
  cutoff: datetime | None,
  reference: datetime,
  *,
  terminated_by_lf: bool,
) -> bool:
  if terminated_by_lf and record.endswith(b"\r"):
    record = record[:-1]
  if len(record) > MAX_LINE_BYTES:
    record = record[:MAX_LINE_BYTES]
    metrics.truncated += 1
  message = record.decode("utf-8", errors="surrogateescape")
  timestamp, content, assumed_local = extract_timestamp(message, reference)
  if timestamp is not None:
    metrics.inherited_timestamp = timestamp
  if not content.strip():
    return False
  previous_nonblank = metrics.last_nonblank_line
  metrics.last_nonblank_line = line
  if cutoff is not None:
    if metrics.inherited_timestamp is None:
      metrics.undated_excluded += 1
      metrics.filtered += 1
      return False
    if metrics.inherited_timestamp < cutoff:
      metrics.filtered += 1
      return False
  if (options.include and not any(value in content for value in options.include)) or (
    options.exclude and any(value in content for value in options.exclude)
  ):
    metrics.filtered += 1
    return False
  store.add(normalize_content(content), line)
  severity = classify_severity(content)
  metrics.severity[severity] = metrics.severity.get(severity, 0) + 1
  if timestamp is not None:
    metrics.timestamped += 1
    metrics.local_time += assumed_local
    if metrics.first_timestamp is None or timestamp < metrics.first_timestamp:
      metrics.first_timestamp = timestamp
    if metrics.last_timestamp is None or timestamp > metrics.last_timestamp:
      metrics.last_timestamp = timestamp
    bucket = int(timestamp.timestamp()) // 60
    if bucket in metrics.minute_counts or len(metrics.minute_counts) < MAX_MINUTE_BUCKETS:
      metrics.minute_counts[bucket] = metrics.minute_counts.get(bucket, 0) + 1
    else:
      metrics.minute_counts_complete = False
  _track_stack(metrics, line, content, timestamp is not None, previous_nonblank)
  return True


def observe_descriptor(
  descriptor: int,
  target: str,
  boundary: int,
  options: AnalysisOptions | None = None,
  clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
  *,
  reference: datetime | None = None,
  store: PatternStore | None = None,
  line_offset: int = 0,
) -> AnalysisResult:
  """Analyze BOUNDARY bytes of DESCRIPTOR; REFERENCE (the file mtime) anchors RFC 3164 years."""
  options = AnalysisOptions() if options is None else options
  now = clock()
  cutoff = None if options.window_seconds is None else now - timedelta(seconds=options.window_seconds)
  reference = now if reference is None else reference
  own_store = store is None
  store = PatternStore() if store is None else store
  untracked_before = store.untracked_lines
  metrics = LineMetrics()
  remaining = boundary
  consumed = 0
  nul_bytes = 0
  pending = b""
  overlong: bytes | None = None
  physical_lines = 0
  analyzable_lines = 0
  checked_signature = False
  signature_prefix = bytearray()
  signature_length = min(boundary, max(len(item[0]) for item in COMPRESSED_SIGNATURES))
  warning = None

  def record(data: bytes, terminated_by_lf: bool) -> None:
    nonlocal physical_lines, analyzable_lines
    physical_lines += 1
    if _record_line(
      data, line_offset + physical_lines, metrics, store, options, cutoff, reference,
      terminated_by_lf=terminated_by_lf,
    ):
      analyzable_lines += 1

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
      nul_bytes += chunk.count(b"\x00")
      chunk = chunk.replace(b"\x00", b"")
    parts = (pending + chunk).split(b"\n")
    pending = parts.pop()
    for part in parts:
      if overlong is None:
        record(part, True)
      else:
        # The overlong line ends at this newline; bytes beyond its retained prefix are dropped.
        record(overlong, False)
        overlong = None
    if overlong is not None:
      pending = b""
    elif len(pending) > MAX_LINE_BYTES + 1 or (len(pending) == MAX_LINE_BYTES + 1 and not pending.endswith(b"\r")):
      overlong, pending = pending[:MAX_LINE_BYTES + 1], b""

  if warning is None:
    if overlong is not None:
      record(overlong, False)
    elif pending:
      record(pending, False)
  if warning is not None and analyzable_lines == 0:
    raise ObservationError(warning)
  warnings = [] if warning is None else [warning]
  if nul_bytes:
    warnings.append(f"removed {nul_bytes} NUL bytes (for example from a zero-filled or sparse region)")
  if metrics.truncated:
    warnings.append(f"{metrics.truncated} lines exceeded {MAX_LINE_BYTES} bytes and were truncated")
  if metrics.undated_excluded:
    warnings.append(
      f"{metrics.undated_excluded} lines had no recognized timestamp before them and were excluded from the time window"
    )
  untracked = store.untracked_lines - untracked_before
  if untracked:
    warnings.append(f"distinct pattern limit of {MAX_PATTERNS} reached; {untracked} lines with new patterns were not tracked")
  earlier = later = None
  if not metrics.minute_counts_complete:
    warnings.append("minute histogram limit reached; peak and period counts unavailable")
  elif metrics.minute_counts:
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
    patterns=store.evidence() if own_store else (),
    incomplete_warning="; ".join(warnings) if warnings else None,
    severity_counts=tuple((name, metrics.severity.get(name, 0)) for name in SEVERITIES),
    filtered_lines=metrics.filtered,
    timestamped_lines=metrics.timestamped,
    duration_seconds=(metrics.last_timestamp - metrics.first_timestamp).total_seconds()
      if metrics.first_timestamp is not None and metrics.last_timestamp is not None else None,
    peak_messages_per_minute=max(metrics.minute_counts.values(), default=None) if metrics.minute_counts_complete else None,
    sources=(target,),
    stack_trace_groups=metrics.stack_groups,
    stack_trace_lines=metrics.stack_lines,
    earlier_period_messages=earlier,
    later_period_messages=later,
    first_timestamp=metrics.first_timestamp,
    last_timestamp=metrics.last_timestamp,
    minute_counts=tuple(sorted(metrics.minute_counts.items())),
    minute_counts_complete=metrics.minute_counts_complete,
    untracked_lines=untracked,
    truncated_lines=metrics.truncated,
    nul_bytes_removed=nul_bytes,
    undated_lines_excluded=metrics.undated_excluded,
    local_time_lines=metrics.local_time,
  )


def analyze(path: str, options: AnalysisOptions | None = None) -> AnalysisResult:
  return analyze_sources(path, AnalysisOptions() if options is None else options, 0)


def analyze_sources(
  path: str,
  options: AnalysisOptions,
  rotated: int,
  clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> AnalysisResult:
  """Analyze PATH and up to ROTATED numbered rotations; only a PATH failure is fatal."""
  if not path:
    raise InvalidTargetError("target path must not be empty")
  now = clock()
  store = PatternStore()
  unavailable: list[tuple[str, str]] = []
  descriptors: list[int] = []
  sources: list[tuple[str, int, int, datetime]] = []
  seen: dict[tuple[int, int], str] = {}
  results: list[AnalysisResult] = []
  try:
    # Every source is opened before any is read, so a rotation during the scan cannot be read twice.
    for index in range(rotated + 1):
      candidate = path if index == 0 else f"{path}.{index}"
      target = display_target(candidate)
      try:
        descriptor, boundary = open_target(candidate)
      except InvalidTargetError as error:
        if index == 0:
          raise
        unavailable.append((target, str(error)))
        continue
      descriptors.append(descriptor)
      metadata = os.fstat(descriptor)
      identity = (metadata.st_dev, metadata.st_ino)
      if identity in seen:
        unavailable.append((target, f"same file as {display_safe(seen[identity])}"))
        continue
      seen[identity] = target
      try:
        reference = datetime.fromtimestamp(metadata.st_mtime, timezone.utc)
      except (OverflowError, OSError, ValueError):
        reference = now
      sources.append((target, descriptor, boundary, reference))
    offset = 0
    for index, (target, descriptor, boundary, reference) in enumerate(sources):
      try:
        result = observe_descriptor(
          descriptor, target, boundary, options, lambda: now,
          reference=reference, store=store, line_offset=offset,
        )
      except (InvalidTargetError, ObservationError) as error:
        if index == 0:
          raise
        unavailable.append((target, str(error)))
        continue
      results.append(result)
      offset += result.physical_lines
  finally:
    for descriptor in descriptors:
      os.close(descriptor)
  multiple = len(sources) > 1
  warnings = [
    f"{display_safe(item.target)}: {item.incomplete_warning}" if multiple else item.incomplete_warning
    for item in results if item.incomplete_warning
  ]
  warnings.extend(f"rotated source {display_safe(target)} unavailable: {reason}" for target, reason in unavailable)
  severity = {name: 0 for name in SEVERITIES}
  for result in results:
    for name, count in result.severity_counts:
      severity[name] += count
  first = min((item.first_timestamp for item in results if item.first_timestamp is not None), default=None)
  last = max((item.last_timestamp for item in results if item.last_timestamp is not None), default=None)
  minutes: dict[int, int] = {}
  complete = all(item.minute_counts_complete for item in results)
  for item in results:
    for bucket, count in item.minute_counts:
      if bucket in minutes or len(minutes) < MAX_MINUTE_BUCKETS:
        minutes[bucket] = minutes.get(bucket, 0) + count
      else:
        complete = False
  earlier = later = peak = None
  if not complete:
    # A per-source overflow was already reported by that source.
    if all(item.minute_counts_complete for item in results):
      warnings.append("global minute histogram limit reached; peak and period counts unavailable")
  elif minutes:
    midpoint = (min(minutes) + max(minutes)) / 2
    earlier = sum(count for bucket, count in minutes.items() if bucket <= midpoint)
    later = sum(count for bucket, count in minutes.items() if bucket > midpoint)
    peak = max(minutes.values())
  return AnalysisResult(
    target=results[0].target,
    boundary_bytes=sum(item.boundary_bytes for item in results),
    consumed_bytes=sum(item.consumed_bytes for item in results),
    physical_lines=sum(item.physical_lines for item in results),
    analyzable_lines=sum(item.analyzable_lines for item in results),
    patterns=store.evidence(),
    incomplete_warning="; ".join(warnings) if warnings else None,
    severity_counts=tuple((name, severity[name]) for name in SEVERITIES),
    filtered_lines=sum(item.filtered_lines for item in results),
    timestamped_lines=sum(item.timestamped_lines for item in results),
    duration_seconds=(last - first).total_seconds() if first is not None and last is not None else None,
    peak_messages_per_minute=peak,
    sources=tuple(item.target for item in results),
    stack_trace_groups=sum(item.stack_trace_groups for item in results),
    stack_trace_lines=sum(item.stack_trace_lines for item in results),
    earlier_period_messages=earlier,
    later_period_messages=later,
    first_timestamp=first,
    last_timestamp=last,
    minute_counts=tuple(sorted(minutes.items())),
    minute_counts_complete=complete,
    untracked_lines=store.untracked_lines,
    truncated_lines=sum(item.truncated_lines for item in results),
    nul_bytes_removed=sum(item.nul_bytes_removed for item in results),
    undated_lines_excluded=sum(item.undated_lines_excluded for item in results),
    local_time_lines=sum(item.local_time_lines for item in results),
    unavailable_sources=tuple(unavailable),
  )


def _rank_key(pattern: PatternEvidence) -> tuple:
  return (
    -pattern.count,
    pattern.first_line,
    pattern.last_line,
    pattern.key.encode("utf-8", errors="surrogateescape"),
    pattern.key_digest or "",
  )


def rank_recurring(patterns: Sequence[PatternEvidence], limit: int | None = None) -> list[PatternEvidence]:
  recurring = [pattern for pattern in patterns if pattern.count >= 2]
  if limit is None:
    return sorted(recurring, key=_rank_key)
  return heapq.nsmallest(limit, recurring, key=_rank_key)


def message_rate(result: AnalysisResult) -> float | None:
  if result.duration_seconds is None or result.duration_seconds <= 0:
    return None
  return result.timestamped_lines / result.duration_seconds


def render_result(result: AnalysisResult, *, top: int = RESULT_LIMIT) -> str:
  recurring = sum(1 for pattern in result.patterns if pattern.count >= 2)
  displayed = rank_recurring(result.patterns, top)
  rate = message_rate(result)
  lines = [
    "Target",
    f"  Path: {display_safe(result.target)}",
    "Observation",
    f"  Status: {'incomplete' if result.incomplete else 'complete'}",
    f"  Initial byte boundary: {result.boundary_bytes}",
    f"  Bytes consumed: {result.consumed_bytes}",
    f"  Completely observed physical lines: {result.physical_lines}",
    f"  Scope: {max(1, len(result.sources))} opened regular file(s); bytes beyond each initial boundary excluded",
    "  Snapshot: no; the file may have changed during observation",
    *[f"  Unavailable source: {display_safe(path)}: {reason}" for path, reason in result.unavailable_sources],
    "Analysis summary",
    f"  Analyzable nonblank normalized lines: {result.analyzable_lines}",
    f"  Distinct normalized patterns: {len(result.patterns)}",
    f"  Recurring patterns: {recurring}",
    f"  Displayed recurring patterns: {len(displayed)} of {recurring}",
    f"  Filtered physical lines: {result.filtered_lines}",
    f"  Timestamped analyzed lines: {result.timestamped_lines}",
    f"  Observed timestamp span: {result.duration_seconds if result.duration_seconds is not None else 'unavailable'} seconds",
    f"  Approximate message rate: {'unavailable' if rate is None else f'{rate:.3f} timestamped messages per second'}",
    f"  Peak messages in one timestamp minute: {result.peak_messages_per_minute if result.peak_messages_per_minute is not None else 'unavailable'}",
    f"  Bounded stack-trace groups: {result.stack_trace_groups} ({result.stack_trace_lines} recognized lines)",
    f"  Earlier/later timestamp-period messages: {result.earlier_period_messages if result.earlier_period_messages is not None else 'unavailable'} / {result.later_period_messages if result.later_period_messages is not None else 'unavailable'}",
  ]
  lines.extend(f"  {label}: {count}" for label, count in (
    ("Zone-less timestamps read as local time", result.local_time_lines),
    ("Undated lines excluded from the time window", result.undated_lines_excluded),
    (f"Lines truncated at {MAX_LINE_BYTES} bytes", result.truncated_lines),
    ("NUL bytes removed", result.nul_bytes_removed),
    (f"Lines with new patterns beyond the {MAX_PATTERNS}-pattern limit", result.untracked_lines),
  ) if count)
  lines.extend((
    "Severity classification",
    *[f"  {name}: {count}" for name, count in result.severity_counts],
    "Recurring patterns",
  ))
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
      f"    Excerpt: {pattern_excerpt(pattern)}",
    ))
  lines.extend((
    "Interpretation limits",
    "  Recurrence is textual evidence only; it does not establish incident, failure, severity, anomaly, health, maliciousness, or root cause.",
    "  Absence of recurrence does not establish health.",
    "  Physical file order is not parsed timestamp chronology.",
    "  This observation is not an atomic snapshot.",
  ))
  return "\n".join(lines)


def pattern_observation(pattern: PatternEvidence) -> dict[str, object]:
  key = pattern.key[:EXCERPT_CODEPOINTS]
  return {
    # Undecodable bytes become \xNN text so strict JSON decoders never receive lone surrogates.
    "key": key.encode("utf-8", "surrogateescape").decode("utf-8", "backslashreplace"),
    "key_truncated": pattern.key_truncated or len(pattern.key) > EXCERPT_CODEPOINTS,
    "key_length": len(pattern.key) if pattern.key_length is None else pattern.key_length,
    "key_digest": pattern.key_digest,
    "count": pattern.count,
    "first_line": pattern.first_line,
    "last_line": pattern.last_line,
  }


def main(argv: Sequence[str] | None = None) -> int:
  parser = build_argument_parser()
  arguments = parser.parse_args(argv)
  validate_output_arguments(parser, arguments)
  if len(arguments.include) > MAX_FILTERS or len(arguments.exclude) > MAX_FILTERS:
    parser.error(f"include/exclude filters may each be repeated at most {MAX_FILTERS} times")
  filters = (*arguments.include, *arguments.exclude)
  if any(not value or len(value) > 256 or has_unsafe_characters(value) for value in filters):
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
  recurring = sum(1 for pattern in result.patterns if pattern.count >= 2)
  errors = dict(result.severity_counts).get("error", 0) + dict(result.severity_counts).get("critical", 0)
  status = "PARTIAL" if result.incomplete else "OBSERVED"
  finding = f"{recurring} recurring patterns and {errors} error/critical messages were observed"
  next_action = (
    "resolve the incomplete read before relying on absence evidence" if result.incomplete
    else "review the highest-frequency patterns and timestamp bursts in context"
  )
  conclusion = make_conclusion(status, result.target, finding, next_action)
  record = OutputRecord(
    tool="loghound",
    status=status,
    target=result.target,
    observations={
      "sources": result.sources,
      "unavailable_sources": [{"path": path, "reason": reason} for path, reason in result.unavailable_sources],
      "physical_lines": result.physical_lines,
      "analyzable_lines": result.analyzable_lines,
      "filtered_lines": result.filtered_lines,
      "distinct_patterns": len(result.patterns),
      "recurring_patterns": recurring,
      "patterns": [pattern_observation(pattern) for pattern in rank_recurring(result.patterns, arguments.top)],
      "severity_counts": dict(result.severity_counts),
      "message_rate_per_second": message_rate(result),
      "peak_messages_per_minute": result.peak_messages_per_minute,
      "timestamp_span_seconds": result.duration_seconds,
      "timestamped_lines": result.timestamped_lines,
      "local_time_lines": result.local_time_lines,
      "undated_lines_excluded": result.undated_lines_excluded,
      "truncated_lines": result.truncated_lines,
      "nul_bytes_removed": result.nul_bytes_removed,
      "untracked_lines": result.untracked_lines,
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
    f"Recurring patterns: {recurring}",
    f"Error/critical messages: {errors}",
    f"Peak per minute: {result.peak_messages_per_minute if result.peak_messages_per_minute is not None else 'unavailable'}",
  ])
  try:
    if warning is not None:
      print_safe(warning, file=sys.stderr)
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
  except KeyboardInterrupt:
    print_safe("loghound: interrupted", file=sys.stderr)
    return 130
  return exit_code


if __name__ == "__main__":
  raise SystemExit(main())
