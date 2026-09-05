#!/usr/bin/env python3
"""Capture a bounded, privacy-minimized local Linux incident snapshot."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP, localcontext
import errno
import os
import re
import stat
import sys
import time
import unicodedata
from typing import Callable, Sequence


UPTIME_PATH = "/proc/uptime"
LOADAVG_PATH = "/proc/loadavg"
MEMINFO_PATH = "/proc/meminfo"
UPTIME_MAX_BYTES = 4096
LOADAVG_MAX_BYTES = 4096
MEMINFO_MAX_BYTES = 65536
MEMINFO_MAX_RECORDS = 256
PLATFORM_MAX_CODEPOINTS = 256
MAX_CALCULATED_BYTES = (1 << 127) - 1
READ_CHUNK_BYTES = 4096
DECIMAL_RE = re.compile(rb"[0-9]{1,20}(?:\.[0-9]{1,9})?\Z", re.ASCII)
INTEGER_RE = re.compile(rb"[0-9]{1,20}\Z", re.ASCII)
MEMINFO_RE = re.compile(rb"([A-Za-z][A-Za-z0-9_()]*):[ \t]*([^\r\n]*)\Z", re.ASCII)
MEMINFO_VALUE_RE = re.compile(rb"([0-9]{1,20})[ \t]+kB\Z", re.ASCII)
REQUIRED_MEMORY_FIELDS = (b"MemTotal", b"MemAvailable", b"SwapTotal", b"SwapFree")
IEC_UNITS = ("B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB")


class ObservationError(Exception):
  """A mandatory observation or report cannot be trusted."""

  def __init__(self, section: str, reason: str):
    super().__init__(reason)
    self.section = section
    self.reason = reason


class SectionUnavailable(Exception):
  """A best-effort section could not be observed trustworthily."""

  def __init__(self, reason: str):
    super().__init__(reason)
    self.reason = reason


class UnsupportedPlatform(Exception):
  """The current platform is outside the Linux-only V1 contract."""


@dataclass(frozen=True)
class ObservationWindow:
  started_utc: datetime
  finished_utc: datetime
  elapsed_ns: int


@dataclass(frozen=True)
class PlatformObservation:
  system: str
  release: str
  machine: str


@dataclass(frozen=True)
class RuntimeObservation:
  uptime: Decimal
  load_1m: Decimal
  load_5m: Decimal
  load_15m: Decimal


@dataclass(frozen=True)
class MemoryObservation:
  total: int
  available: int
  swap_total: int
  swap_free: int


@dataclass(frozen=True)
class FilesystemObservation:
  total: int
  used: int
  available: int


@dataclass(frozen=True)
class OptionalObservation:
  value: object | None = None
  reason: str | None = None

  @property
  def observed(self) -> bool:
    return self.reason is None


@dataclass(frozen=True)
class SnapshotResult:
  window: ObservationWindow
  platform: PlatformObservation
  runtime: RuntimeObservation
  memory: OptionalObservation
  filesystem: OptionalObservation


def build_argument_parser() -> argparse.ArgumentParser:
  return argparse.ArgumentParser(
    prog="incidentsnapshot",
    description="Capture bounded, low-sensitivity local Linux incident context.",
  )


def display_safe(value: object) -> str:
  """Escape controls and presentation characters in externally derived text."""
  rendered = []
  for character in str(value):
    codepoint = ord(character)
    category = unicodedata.category(character)
    if character == "\\":
      rendered.append("\\\\")
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


def write_safe(value: object, *, file: object) -> None:
  file.write(stream_safe(value, file))


def write_best_effort(value: object, *, file: object) -> None:
  """Emit a terminal-safe diagnostic without allowing stream failure to escape."""
  try:
    write_safe(value, file=file)
  except Exception:
    pass


def _reason_for_os_error(error: OSError) -> str:
  if isinstance(error, PermissionError) or error.errno in {errno.EACCES, errno.EPERM}:
    return "permission denied"
  if isinstance(error, FileNotFoundError) or error.errno == errno.ENOENT:
    return "source unavailable"
  return "observation failed"


def _open_flags() -> int:
  flags = os.O_RDONLY
  flags |= getattr(os, "O_CLOEXEC", 0)
  flags |= getattr(os, "O_NOFOLLOW", 0)
  flags |= getattr(os, "O_NONBLOCK", 0)
  return flags


def read_bounded_ascii(path: str, limit: int) -> bytes:
  """Read at most limit + 1 bytes from an allowlisted procfs regular file."""
  try:
    descriptor = os.open(path, _open_flags())
  except OSError as error:
    raise SectionUnavailable(_reason_for_os_error(error)) from error
  try:
    try:
      metadata = os.fstat(descriptor)
    except OSError as error:
      raise SectionUnavailable(_reason_for_os_error(error)) from error
    if not stat.S_ISREG(metadata.st_mode):
      raise SectionUnavailable("unsupported data shape")

    chunks = []
    observed = 0
    while observed <= limit:
      try:
        chunk = os.read(descriptor, min(READ_CHUNK_BYTES, limit + 1 - observed))
      except OSError as error:
        raise SectionUnavailable(_reason_for_os_error(error)) from error
      if not chunk:
        break
      chunks.append(chunk)
      observed += len(chunk)
    if observed > limit:
      raise SectionUnavailable("source exceeds V1 byte limit")
    data = b"".join(chunks)
    if b"\x00" in data:
      raise SectionUnavailable("malformed data")
    try:
      data.decode("ascii")
    except UnicodeDecodeError as error:
      raise SectionUnavailable("malformed data") from error
    return data
  finally:
    try:
      os.close(descriptor)
    except OSError:
      pass


def _parse_decimal(token: bytes) -> Decimal:
  if not DECIMAL_RE.fullmatch(token):
    if re.fullmatch(rb"[0-9]+(?:\.[0-9]+)?", token) and (
      len(token.partition(b".")[0]) > 20 or len(token.partition(b".")[2]) > 9
    ):
      raise SectionUnavailable("numeric value exceeds V1 limit")
    raise SectionUnavailable("malformed data")
  value = Decimal(token.decode("ascii"))
  if not value.is_finite() or value < 0:
    raise SectionUnavailable("malformed data")
  return value


def parse_uptime(data: bytes) -> Decimal:
  tokens = data.split()
  if not tokens:
    raise SectionUnavailable("malformed data")
  return _parse_decimal(tokens[0])


def parse_loadavg(data: bytes) -> tuple[Decimal, Decimal, Decimal]:
  tokens = data.split()
  if len(tokens) < 3:
    raise SectionUnavailable("malformed data")
  return (_parse_decimal(tokens[0]), _parse_decimal(tokens[1]), _parse_decimal(tokens[2]))


def parse_meminfo(data: bytes) -> MemoryObservation:
  records = [record for record in data.splitlines() if record.strip()]
  if len(records) > MEMINFO_MAX_RECORDS:
    raise SectionUnavailable("record count exceeds V1 limit")
  values: dict[bytes, int] = {}
  for record in records:
    match = MEMINFO_RE.fullmatch(record)
    if match is None:
      raise SectionUnavailable("malformed data")
    key, raw_value = match.groups()
    if key not in REQUIRED_MEMORY_FIELDS:
      continue
    if key in values:
      raise SectionUnavailable("malformed data")
    value_match = MEMINFO_VALUE_RE.fullmatch(raw_value)
    if value_match is None:
      digits = raw_value.split(None, 1)[0] if raw_value.split() else b""
      if INTEGER_RE.fullmatch(digits) is None and digits.isdigit() and len(digits) > 20:
        raise SectionUnavailable("numeric value exceeds V1 limit")
      raise SectionUnavailable("malformed data")
    kibibytes = int(value_match.group(1))
    byte_value = kibibytes * 1024
    if byte_value > MAX_CALCULATED_BYTES:
      raise SectionUnavailable("numeric value exceeds V1 limit")
    values[key] = byte_value
  if any(key not in values for key in REQUIRED_MEMORY_FIELDS):
    raise SectionUnavailable("malformed data")
  total = values[b"MemTotal"]
  available = values[b"MemAvailable"]
  swap_total = values[b"SwapTotal"]
  swap_free = values[b"SwapFree"]
  if total <= 0 or available > total or swap_free > swap_total:
    raise SectionUnavailable("malformed data")
  return MemoryObservation(total, available, swap_total, swap_free)


def _platform_field(value: object) -> str:
  if not isinstance(value, str):
    raise ObservationError("platform", "unsupported data shape")
  if not value or "\x00" in value:
    raise ObservationError("platform", "malformed data")
  if len(value) > PLATFORM_MAX_CODEPOINTS:
    raise ObservationError("platform", "numeric value exceeds V1 limit")
  return value


def collect_platform(uname_provider: Callable[[], object] = os.uname) -> PlatformObservation:
  try:
    result = uname_provider()
    system = _platform_field(getattr(result, "sysname"))
    release = _platform_field(getattr(result, "release"))
    machine = _platform_field(getattr(result, "machine"))
  except ObservationError:
    raise
  except (AttributeError, TypeError) as error:
    raise ObservationError("platform", "unsupported data shape") from error
  except OSError as error:
    raise ObservationError("platform", _reason_for_os_error(error)) from error
  if system != "Linux":
    raise UnsupportedPlatform
  return PlatformObservation(system, release, machine)


def collect_runtime(reader: Callable[[str, int], bytes] = read_bounded_ascii) -> RuntimeObservation:
  try:
    uptime = parse_uptime(reader(UPTIME_PATH, UPTIME_MAX_BYTES))
    loads = parse_loadavg(reader(LOADAVG_PATH, LOADAVG_MAX_BYTES))
  except SectionUnavailable as error:
    raise ObservationError("runtime", error.reason) from error
  return RuntimeObservation(uptime, *loads)


def collect_memory(reader: Callable[[str, int], bytes] = read_bounded_ascii) -> MemoryObservation:
  return parse_meminfo(reader(MEMINFO_PATH, MEMINFO_MAX_BYTES))


def collect_root_filesystem(
  statvfs_provider: Callable[[str], object] = os.statvfs,
) -> FilesystemObservation:
  try:
    result = statvfs_provider("/")
  except OSError as error:
    raise SectionUnavailable(_reason_for_os_error(error)) from error
  try:
    fragment_size = result.f_frsize
    block_size = result.f_bsize
    blocks = result.f_blocks
    free_blocks = result.f_bfree
    available_blocks = result.f_bavail
  except AttributeError as error:
    raise SectionUnavailable("unsupported data shape") from error
  fields = (fragment_size, block_size, blocks, free_blocks, available_blocks)
  if any(not isinstance(value, int) or isinstance(value, bool) for value in fields):
    raise SectionUnavailable("unsupported data shape")
  effective_size = fragment_size if fragment_size > 0 else block_size
  if effective_size <= 0 or not (blocks >= free_blocks >= available_blocks >= 0):
    raise SectionUnavailable("malformed data")
  calculated = (blocks * effective_size, free_blocks * effective_size, available_blocks * effective_size)
  if any(value > MAX_CALCULATED_BYTES for value in calculated):
    raise SectionUnavailable("numeric value exceeds V1 limit")
  total, free, available = calculated
  used = total - free
  if used + available == 0:
    raise SectionUnavailable("malformed data")
  return FilesystemObservation(total, used, available)


def _utc_value(value: object) -> datetime:
  if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
    raise ObservationError("observation timing", "unsupported data shape")
  return value.astimezone(timezone.utc)


def _monotonic_value(value: object) -> int:
  if not isinstance(value, int) or isinstance(value, bool):
    raise ObservationError("observation timing", "unsupported data shape")
  return value


def collect_snapshot(
  *,
  reader: Callable[[str, int], bytes] = read_bounded_ascii,
  uname_provider: Callable[[], object] = os.uname,
  statvfs_provider: Callable[[str], object] = os.statvfs,
  utc_clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
  monotonic_clock: Callable[[], int] = time.monotonic_ns,
) -> SnapshotResult:
  started = _utc_value(utc_clock())
  monotonic_start = _monotonic_value(monotonic_clock())
  platform = collect_platform(uname_provider)
  runtime = collect_runtime(reader)
  try:
    memory = OptionalObservation(value=collect_memory(reader))
  except SectionUnavailable as error:
    memory = OptionalObservation(reason=error.reason)
  try:
    filesystem = OptionalObservation(value=collect_root_filesystem(statvfs_provider))
  except SectionUnavailable as error:
    filesystem = OptionalObservation(reason=error.reason)
  monotonic_finish = _monotonic_value(monotonic_clock())
  finished = _utc_value(utc_clock())
  elapsed = monotonic_finish - monotonic_start
  if elapsed < 0:
    raise ObservationError("observation timing", "malformed data")
  return SnapshotResult(
    ObservationWindow(started, finished, elapsed), platform, runtime, memory, filesystem
  )


def _quantized(value: Decimal, places: str) -> str:
  with localcontext() as context:
    context.prec = 100
    return str(value.quantize(Decimal(places), rounding=ROUND_HALF_UP))


def format_timestamp(value: datetime) -> str:
  return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def format_uptime(value: Decimal) -> str:
  seconds = int(value)
  days, remainder = divmod(seconds, 86400)
  hours, remainder = divmod(remainder, 3600)
  minutes, seconds = divmod(remainder, 60)
  return f"{days} d {hours:02d}:{minutes:02d}:{seconds:02d} ({_quantized(value, '0.01')} seconds)"


def format_iec_bytes(value: int) -> str:
  if value < 1024:
    return f"{value} B"
  unit_index = 0
  divisor = 1
  while unit_index + 1 < len(IEC_UNITS) and value >= divisor * 1024:
    divisor *= 1024
    unit_index += 1
  with localcontext() as context:
    context.prec = 100
    amount = Decimal(value) / Decimal(divisor)
  return f"{_quantized(amount, '0.1')} {IEC_UNITS[unit_index]} ({value} bytes)"


def format_percentage(numerator: int, denominator: int) -> str:
  with localcontext() as context:
    context.prec = 100
    value = Decimal(numerator) * Decimal(100) / Decimal(denominator)
  return f"{_quantized(value, '0.1')}%"


def render_report(snapshot: SnapshotResult) -> str:
  elapsed_ms = Decimal(snapshot.window.elapsed_ns) / Decimal(1_000_000)
  sections = [
    "Incident Snapshot",
    "\n".join((
      "Observation",
      "  Status: observed",
      f"  Started UTC: {format_timestamp(snapshot.window.started_utc)}",
      f"  Finished UTC: {format_timestamp(snapshot.window.finished_utc)}",
      f"  Elapsed: {_quantized(elapsed_ms, '0.001')} ms",
      "  Mode: sequential single pass",
    )),
    "\n".join((
      "Platform",
      "  Status: observed",
      f"  System: {display_safe(snapshot.platform.system)}",
      f"  Kernel release: {display_safe(snapshot.platform.release)}",
      f"  Machine: {display_safe(snapshot.platform.machine)}",
    )),
    "\n".join((
      "Runtime",
      "  Status: observed",
      f"  Uptime: {format_uptime(snapshot.runtime.uptime)}",
      f"  Load average 1m: {_quantized(snapshot.runtime.load_1m, '0.01')}",
      f"  Load average 5m: {_quantized(snapshot.runtime.load_5m, '0.01')}",
      f"  Load average 15m: {_quantized(snapshot.runtime.load_15m, '0.01')}",
    )),
  ]
  if snapshot.memory.observed:
    memory = snapshot.memory.value
    assert isinstance(memory, MemoryObservation)
    sections.append("\n".join((
      "Memory",
      "  Status: observed",
      f"  Total: {format_iec_bytes(memory.total)}",
      f"  Available: {format_iec_bytes(memory.available)}",
      f"  Available percent: {format_percentage(memory.available, memory.total)}",
      f"  Swap total: {format_iec_bytes(memory.swap_total)}",
      f"  Swap free: {format_iec_bytes(memory.swap_free)}",
    )))
  else:
    sections.append(f"Memory\n  Status: unavailable\n  Reason: {snapshot.memory.reason}")
  if snapshot.filesystem.observed:
    filesystem = snapshot.filesystem.value
    assert isinstance(filesystem, FilesystemObservation)
    sections.append("\n".join((
      "Root filesystem",
      "  Status: observed",
      "  Scope: current mount namespace, root filesystem",
      f"  Total: {format_iec_bytes(filesystem.total)}",
      f"  Used: {format_iec_bytes(filesystem.used)}",
      f"  Available to caller: {format_iec_bytes(filesystem.available)}",
      f"  Capacity used: {format_percentage(filesystem.used, filesystem.used + filesystem.available)}",
    )))
  else:
    sections.append(f"Root filesystem\n  Status: unavailable\n  Reason: {snapshot.filesystem.reason}")
  warnings = []
  if not snapshot.memory.observed:
    warnings.append(f"Memory: {snapshot.memory.reason}")
  if not snapshot.filesystem.observed:
    warnings.append(f"Root filesystem: {snapshot.filesystem.reason}")
  warning_lines = ["Collection warnings"]
  warning_lines.extend(
    [f"  {index}. {warning}" for index, warning in enumerate(warnings, 1)] if warnings else ["  None"]
  )
  sections.append("\n".join(warning_lines))
  sections.append("\n".join((
    "Interpretation limits",
    "  Collection was sequential, not atomic; values may have changed during or immediately after observation.",
    "  Root-filesystem evidence covers / in the current mount namespace only.",
    "  Load, memory, and capacity values are evidence, not health thresholds.",
    "  Process, network, service, log, and configuration evidence was deliberately not inspected.",
    "  This snapshot does not determine incident severity or identify root cause.",
  )))
  return "\n\n".join(sections) + "\n"


def snapshot_exit_code(snapshot: SnapshotResult) -> int:
  return 0 if snapshot.memory.observed and snapshot.filesystem.observed else 1


def main(argv: Sequence[str] | None = None) -> int:
  args = build_argument_parser().parse_args(argv)
  del args
  try:
    snapshot = collect_snapshot()
    report = render_report(snapshot)
    exit_code = snapshot_exit_code(snapshot)
    write_safe(report, file=sys.stdout)
    if exit_code == 1:
      write_safe("incidentsnapshot: snapshot incomplete; see Collection warnings\n", file=sys.stderr)
    return exit_code
  except UnsupportedPlatform:
    write_best_effort("incidentsnapshot: unsupported platform: Linux is required\n", file=sys.stderr)
    return 3
  except ObservationError as error:
    write_best_effort(
      f"incidentsnapshot: {error.section} observation failed: {error.reason}\n",
      file=sys.stderr,
    )
    return 3
  except KeyboardInterrupt:
    write_best_effort("incidentsnapshot: interrupted\n", file=sys.stderr)
    return 130
  except Exception:
    write_best_effort("incidentsnapshot: internal execution failure\n", file=sys.stderr)
    return 3


if __name__ == "__main__":
  try:
    raise SystemExit(main())
  except KeyboardInterrupt:
    write_best_effort("incidentsnapshot: interrupted\n", file=sys.stderr)
    raise SystemExit(130)
