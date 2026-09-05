#!/usr/bin/env python3
"""Sample one Linux process for bounded CPU and memory evidence."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import math
import os
import stat
import sys
import time
import unicodedata
from typing import Callable, Sequence


DEFAULT_INTERVAL_SECONDS = 1.0
MIN_INTERVAL_SECONDS = 0.1
MAX_INTERVAL_SECONDS = 60.0
MAX_STAT_BYTES = 64 * 1024
READ_CHUNK_BYTES = 4096


class InvalidTargetError(Exception):
  """The requested process cannot be used as the initial observation target."""


class ObservationError(Exception):
  """No trustworthy useful report can be produced."""


class ProcReadError(Exception):
  """A bounded read from the anchored process directory failed."""


@dataclass(frozen=True)
class ProcessSample:
  pid: int
  command: str
  state: str
  ppid: int
  user_ticks: int
  system_ticks: int
  threads: int
  start_ticks: int
  virtual_bytes: int
  rss_pages: int
  observed_at: float

  @property
  def cpu_ticks(self) -> int:
    return self.user_ticks + self.system_ticks


@dataclass(frozen=True)
class AnalysisResult:
  pid: int
  requested_interval: float
  clock_ticks_per_second: int
  page_size_bytes: int
  initial: ProcessSample
  final: ProcessSample | None
  elapsed_seconds: float | None
  incomplete_warning: str | None = None

  @property
  def incomplete(self) -> bool:
    return self.final is None or self.incomplete_warning is not None


def parse_pid(value: str) -> int:
  try:
    pid = int(value, 10)
  except ValueError as error:
    raise argparse.ArgumentTypeError("PID must be a positive decimal integer") from error
  if pid <= 0:
    raise argparse.ArgumentTypeError("PID must be a positive decimal integer")
  return pid


def parse_interval(value: str) -> float:
  try:
    interval = float(value)
  except ValueError as error:
    raise argparse.ArgumentTypeError("interval must be a finite number of seconds") from error
  if not math.isfinite(interval):
    raise argparse.ArgumentTypeError("interval must be a finite number of seconds")
  if interval < MIN_INTERVAL_SECONDS or interval > MAX_INTERVAL_SECONDS:
    raise argparse.ArgumentTypeError(
      f"interval must be from {MIN_INTERVAL_SECONDS:g} through {MAX_INTERVAL_SECONDS:g} seconds"
    )
  return interval


def build_argument_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(
    prog="procwatch",
    description=(
      "Sample one Linux process for bounded CPU and memory evidence without judging abnormality."
    ),
  )
  parser.add_argument("pid", type=parse_pid, help="positive process ID to inspect")
  parser.add_argument(
    "--interval",
    type=parse_interval,
    default=DEFAULT_INTERVAL_SECONDS,
    metavar="SECONDS",
    help=(
      f"requested delay between samples; {MIN_INTERVAL_SECONDS:g}-{MAX_INTERVAL_SECONDS:g} "
      f"seconds (default: {DEFAULT_INTERVAL_SECONDS:g})"
    ),
  )
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


def system_parameter(name: str) -> int:
  try:
    value = int(os.sysconf(name))
  except (AttributeError, OSError, TypeError, ValueError) as error:
    raise ObservationError(f"cannot determine required system parameter {name}") from error
  if value <= 0:
    raise ObservationError(f"required system parameter {name} is invalid")
  return value


def open_process_directory(pid: int) -> int:
  flags = os.O_RDONLY
  flags |= getattr(os, "O_CLOEXEC", 0)
  flags |= getattr(os, "O_DIRECTORY", 0)
  flags |= getattr(os, "O_NOFOLLOW", 0)
  path = f"/proc/{pid}"
  try:
    descriptor = os.open(path, flags)
  except OSError as error:
    raise InvalidTargetError(
      f"cannot open process {pid}: {display_safe(error)}"
    ) from error
  try:
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
      raise InvalidTargetError(f"process {pid} target is not a directory")
    return descriptor
  except Exception:
    os.close(descriptor)
    raise


def read_bounded_proc_file(directory_fd: int, name: str, limit: int) -> bytes:
  flags = os.O_RDONLY
  flags |= getattr(os, "O_CLOEXEC", 0)
  flags |= getattr(os, "O_NOFOLLOW", 0)
  flags |= getattr(os, "O_NONBLOCK", 0)
  try:
    descriptor = os.open(name, flags, dir_fd=directory_fd)
  except OSError as error:
    raise ProcReadError(f"cannot open {name}: {display_safe(error)}") from error
  try:
    chunks = []
    total = 0
    while total <= limit:
      try:
        chunk = os.read(descriptor, min(READ_CHUNK_BYTES, limit + 1 - total))
      except OSError as error:
        raise ProcReadError(f"cannot read {name}: {display_safe(error)}") from error
      if not chunk:
        break
      chunks.append(chunk)
      total += len(chunk)
    data = b"".join(chunks)
    if len(data) > limit:
      raise ProcReadError(f"{name} exceeds {limit} bytes")
    if b"\x00" in data:
      raise ProcReadError(f"{name} contains unsupported NUL data")
    return data
  finally:
    os.close(descriptor)


def parse_stat(data: bytes, expected_pid: int, observed_at: float) -> ProcessSample:
  text = data.decode("utf-8", errors="surrogateescape")
  if text.endswith("\n"):
    text = text[:-1]
  first_space = text.find(" ")
  open_paren = text.find("(", first_space + 1)
  close_paren = text.rfind(")")
  if first_space <= 0 or open_paren != first_space + 1 or close_paren <= open_paren:
    raise ProcReadError("stat has an unsupported record shape")
  try:
    pid = int(text[:first_space], 10)
  except ValueError as error:
    raise ProcReadError("stat PID is invalid") from error
  if pid != expected_pid:
    raise ProcReadError(f"stat PID changed from requested PID {expected_pid}")
  command = text[open_paren + 1:close_paren]
  fields = text[close_paren + 1:].strip().split()
  if len(fields) < 22:
    raise ProcReadError("stat does not contain required fields through RSS")
  state = fields[0]
  if len(state) != 1:
    raise ProcReadError("stat process state is invalid")
  try:
    ppid = int(fields[1], 10)
    user_ticks = int(fields[11], 10)
    system_ticks = int(fields[12], 10)
    threads = int(fields[17], 10)
    start_ticks = int(fields[19], 10)
    virtual_bytes = int(fields[20], 10)
    rss_pages = int(fields[21], 10)
  except ValueError as error:
    raise ProcReadError("stat contains a non-integer required field") from error
  if min(ppid, user_ticks, system_ticks, threads, start_ticks, virtual_bytes, rss_pages) < 0:
    raise ProcReadError("stat contains a negative required counter")
  return ProcessSample(
    pid=pid,
    command=command,
    state=state,
    ppid=ppid,
    user_ticks=user_ticks,
    system_ticks=system_ticks,
    threads=threads,
    start_ticks=start_ticks,
    virtual_bytes=virtual_bytes,
    rss_pages=rss_pages,
    observed_at=observed_at,
  )


def capture_sample(
  directory_fd: int,
  pid: int,
  *,
  monotonic_fn: Callable[[], float] = time.monotonic,
) -> ProcessSample:
  data = read_bounded_proc_file(directory_fd, "stat", MAX_STAT_BYTES)
  observed_at = monotonic_fn()
  return parse_stat(data, pid, observed_at)


def observe(
  pid: int,
  interval: float = DEFAULT_INTERVAL_SECONDS,
  *,
  sleep_fn: Callable[[float], None] = time.sleep,
  monotonic_fn: Callable[[], float] = time.monotonic,
) -> AnalysisResult:
  clock_ticks = system_parameter("SC_CLK_TCK")
  page_size = system_parameter("SC_PAGE_SIZE")
  directory_fd = open_process_directory(pid)
  try:
    try:
      initial = capture_sample(directory_fd, pid, monotonic_fn=monotonic_fn)
    except ProcReadError as error:
      raise InvalidTargetError(
        f"cannot read initial process state for {pid}: {display_safe(error)}"
      ) from error

    sleep_fn(interval)

    try:
      final = capture_sample(directory_fd, pid, monotonic_fn=monotonic_fn)
    except ProcReadError as error:
      return AnalysisResult(
        pid=pid,
        requested_interval=interval,
        clock_ticks_per_second=clock_ticks,
        page_size_bytes=page_size,
        initial=initial,
        final=None,
        elapsed_seconds=None,
        incomplete_warning=f"second sample unavailable: {display_safe(error)}",
      )

    if final.start_ticks != initial.start_ticks:
      return AnalysisResult(
        pid=pid,
        requested_interval=interval,
        clock_ticks_per_second=clock_ticks,
        page_size_bytes=page_size,
        initial=initial,
        final=None,
        elapsed_seconds=None,
        incomplete_warning="process identity changed between samples",
      )
    if (
      final.user_ticks < initial.user_ticks
      or final.system_ticks < initial.system_ticks
    ):
      return AnalysisResult(
        pid=pid,
        requested_interval=interval,
        clock_ticks_per_second=clock_ticks,
        page_size_bytes=page_size,
        initial=initial,
        final=None,
        elapsed_seconds=None,
        incomplete_warning="cumulative CPU counters moved backwards between samples",
      )
    elapsed = final.observed_at - initial.observed_at
    if not math.isfinite(elapsed) or elapsed <= 0:
      raise ObservationError("monotonic sample interval is not positive and finite")
    return AnalysisResult(
      pid=pid,
      requested_interval=interval,
      clock_ticks_per_second=clock_ticks,
      page_size_bytes=page_size,
      initial=initial,
      final=final,
      elapsed_seconds=elapsed,
    )
  finally:
    os.close(directory_fd)


def kibibytes(byte_count: int) -> float:
  return byte_count / 1024


def signed_kibibytes(byte_count: int) -> str:
  return f"{byte_count / 1024:+.2f} KiB"


def render_result(result: AnalysisResult) -> str:
  initial = result.initial
  initial_rss = initial.rss_pages * result.page_size_bytes
  lines = [
    "Target",
    f"  PID: {result.pid}",
    f"  Command name: {display_safe(initial.command)}",
    f"  Process start ticks: {initial.start_ticks}",
    "Observation",
    f"  Status: {'incomplete' if result.incomplete else 'complete'}",
    f"  Requested sample interval: {result.requested_interval:.3f} s",
    "  Scope: one anchored Linux /proc process directory; two bounded stat reads",
    "  Snapshot: no; fields within and across samples may change during observation",
  ]
  if result.incomplete:
    lines.extend((
      "Initial process evidence",
      f"  State: {display_safe(initial.state)}",
      f"  Parent PID: {initial.ppid}",
      f"  Threads: {initial.threads}",
      f"  Cumulative CPU time: {initial.cpu_ticks / result.clock_ticks_per_second:.6f} s",
      f"  Resident set size: {kibibytes(initial_rss):.2f} KiB",
      f"  Virtual memory size: {kibibytes(initial.virtual_bytes):.2f} KiB",
      "Delta evidence",
      "  Unavailable: a trustworthy second sample was not obtained for the same process identity.",
    ))
  else:
    assert result.final is not None
    assert result.elapsed_seconds is not None
    final = result.final
    final_rss = final.rss_pages * result.page_size_bytes
    cpu_delta_ticks = final.cpu_ticks - initial.cpu_ticks
    user_delta_ticks = final.user_ticks - initial.user_ticks
    system_delta_ticks = final.system_ticks - initial.system_ticks
    cpu_seconds = cpu_delta_ticks / result.clock_ticks_per_second
    user_seconds = user_delta_ticks / result.clock_ticks_per_second
    system_seconds = system_delta_ticks / result.clock_ticks_per_second
    utilization = cpu_seconds / result.elapsed_seconds * 100
    lines.extend((
      f"  Observed sample interval: {result.elapsed_seconds:.6f} s",
      "Process evidence",
      f"  State: {display_safe(initial.state)} -> {display_safe(final.state)}",
      f"  Parent PID: {initial.ppid} -> {final.ppid}",
      f"  Threads: {initial.threads} -> {final.threads}",
      "CPU evidence",
      f"  User CPU delta: {user_seconds:.6f} s",
      f"  System CPU delta: {system_seconds:.6f} s",
      f"  Total CPU delta: {cpu_seconds:.6f} s",
      f"  Utilization relative to one logical CPU: {utilization:.2f}%",
      "Memory evidence",
      f"  Resident set size: {kibibytes(initial_rss):.2f} KiB -> {kibibytes(final_rss):.2f} KiB",
      f"  Resident set delta: {signed_kibibytes(final_rss - initial_rss)}",
      f"  Virtual memory size: {kibibytes(initial.virtual_bytes):.2f} KiB -> {kibibytes(final.virtual_bytes):.2f} KiB",
      f"  Virtual memory delta: {signed_kibibytes(final.virtual_bytes - initial.virtual_bytes)}",
    ))
  lines.extend((
    "Interpretation limits",
    "  These measurements are evidence, not a judgment that the process is healthy, unhealthy, anomalous, leaking memory, or causing an incident.",
    "  CPU utilization is sampled against one logical CPU and may exceed 100% for multithreaded work.",
    "  No historical baseline, cgroup or quota context, host load, I/O, network, file-descriptor, scheduler-delay, or root-cause analysis is performed.",
    "  Command-line arguments and environment variables are intentionally not read.",
  ))
  return "\n".join(lines)


def inspect(pid: int, interval: float) -> tuple[str, str | None, int]:
  result = observe(pid, interval)
  warning = None
  if result.incomplete_warning is not None:
    warning = f"procwatch: warning: incomplete observation: {result.incomplete_warning}"
  return render_result(result), warning, 1 if result.incomplete else 0


def main(argv: Sequence[str] | None = None) -> int:
  parser = build_argument_parser()
  arguments = parser.parse_args(argv)
  try:
    output, warning, exit_code = inspect(arguments.pid, arguments.interval)
  except InvalidTargetError as error:
    print_safe(f"procwatch: {display_safe(error)}", file=sys.stderr)
    return 2
  except ObservationError as error:
    print_safe(f"procwatch: {display_safe(error)}", file=sys.stderr)
    return 3
  except KeyboardInterrupt:
    print_safe("procwatch: interrupted", file=sys.stderr)
    return 130
  except Exception:
    print_safe("procwatch: internal execution failure", file=sys.stderr)
    return 3
  print_safe(output, file=sys.stdout)
  if warning is not None:
    print_safe(warning, file=sys.stderr)
  return exit_code


if __name__ == "__main__":
  raise SystemExit(main())
