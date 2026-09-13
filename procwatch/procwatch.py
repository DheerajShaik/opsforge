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

from opsforge_common import (
  OutputError,
  OutputRecord,
  add_output_arguments,
  emit_output,
  make_conclusion,
  validate_output_arguments,
)


DEFAULT_INTERVAL_SECONDS = 1.0
MIN_INTERVAL_SECONDS = 0.1
MAX_INTERVAL_SECONDS = 60.0
MAX_STAT_BYTES = 64 * 1024
READ_CHUNK_BYTES = 4096
MAX_SAMPLES = 100
MAX_DURATION_SECONDS = 3600.0
MAX_AUX_ENTRIES = 100_000


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
  samples: tuple[ProcessSample, ...] = ()

  @property
  def incomplete(self) -> bool:
    return self.final is None or self.incomplete_warning is not None


@dataclass(frozen=True)
class AuxiliarySample:
  file_descriptors: int | None
  sockets: int | None
  read_bytes: int | None
  write_bytes: int | None
  voluntary_context_switches: int | None
  nonvoluntary_context_switches: int | None
  children: tuple[int, ...]
  thread_cpu_ticks: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class ExtendedResult:
  analysis: AnalysisResult
  auxiliary_initial: AuxiliarySample | None
  auxiliary_final: AuxiliarySample | None
  cgroup: str | None
  cpu_constraint: str | None
  memory_constraint: str | None
  warnings: tuple[str, ...]


def parse_pid(value: str) -> int:
  if not value.isascii() or not value.isdecimal():
    raise argparse.ArgumentTypeError("PID must be a positive decimal integer")
  pid = int(value, 10)
  if not 1 <= pid <= 2_147_483_647:
    raise argparse.ArgumentTypeError("PID must be a positive decimal integer in the supported range")
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


def parse_sample_count(value: str) -> int:
  if not value.isascii() or not value.isdecimal() or not 2 <= int(value, 10) <= MAX_SAMPLES:
    raise argparse.ArgumentTypeError(f"sample count must be from 2 through {MAX_SAMPLES}")
  return int(value, 10)


def parse_duration(value: str) -> float:
  try:
    duration = float(value)
  except ValueError as error:
    raise argparse.ArgumentTypeError("duration must be finite and positive") from error
  if not math.isfinite(duration) or not MIN_INTERVAL_SECONDS <= duration <= MAX_DURATION_SECONDS:
    raise argparse.ArgumentTypeError(f"duration must be from {MIN_INTERVAL_SECONDS:g} through {MAX_DURATION_SECONDS:g} seconds")
  return duration


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
  sampling = parser.add_mutually_exclusive_group()
  sampling.add_argument("--samples", type=parse_sample_count, default=2, metavar="N", help="bounded sample count (2-100)")
  sampling.add_argument("--duration", type=parse_duration, metavar="SECONDS", help="bounded total duration (0.1-3600 seconds)")
  sampling.add_argument("--continuous", type=parse_sample_count, metavar="COUNT", help="bounded continuous-mode sample count (2-100)")
  add_output_arguments(parser)
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


def observe_samples(
  pid: int,
  interval: float = DEFAULT_INTERVAL_SECONDS,
  *,
  sample_count: int = 2,
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

    samples = [initial]
    final = None
    for index in range(1, sample_count):
      sleep_fn(interval)
      try:
        candidate = capture_sample(directory_fd, pid, monotonic_fn=monotonic_fn)
      except ProcReadError as error:
        label = "second sample" if index == 1 else f"sample {index + 1}"
        return AnalysisResult(
          pid, interval, clock_ticks, page_size, initial, None, None,
          f"{label} unavailable: {display_safe(error)}", tuple(samples),
        )
      previous = samples[-1]
      if candidate.start_ticks != initial.start_ticks:
        return AnalysisResult(
          pid, interval, clock_ticks, page_size, initial, None, None,
          "process identity changed between samples", tuple(samples),
        )
      if candidate.user_ticks < previous.user_ticks or candidate.system_ticks < previous.system_ticks:
        return AnalysisResult(
          pid, interval, clock_ticks, page_size, initial, None, None,
          "cumulative CPU counters moved backwards between samples", tuple(samples),
        )
      samples.append(candidate)
      final = candidate
    assert final is not None
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
      samples=tuple(samples),
    )
  finally:
    os.close(directory_fd)


def observe(
  pid: int,
  interval: float = DEFAULT_INTERVAL_SECONDS,
  *,
  sleep_fn: Callable[[float], None] = time.sleep,
  monotonic_fn: Callable[[], float] = time.monotonic,
) -> AnalysisResult:
  return observe_samples(
    pid, interval, sample_count=2, sleep_fn=sleep_fn, monotonic_fn=monotonic_fn,
  )


def _parse_proc_mapping(data: bytes) -> dict[str, int]:
  values = {}
  for raw_line in data.decode("ascii", "strict").splitlines():
    if ":" not in raw_line:
      continue
    name, raw_value = raw_line.split(":", 1)
    token = raw_value.strip().split()[0] if raw_value.strip() else ""
    if token.isdecimal():
      values[name] = int(token, 10)
  return values


def _open_proc_subdirectory(directory_fd: int, name: str) -> int:
  flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
  flags |= getattr(os, "O_NOFOLLOW", 0)
  return os.open(name, flags, dir_fd=directory_fd)


def _bounded_directory_names(directory_fd: int, limit: int) -> list[str] | None:
  names = []
  with os.scandir(directory_fd) as entries:
    for entry in entries:
      if len(names) >= limit:
        return None
      names.append(entry.name)
  return names


def capture_auxiliary(directory_fd: int, pid: int) -> AuxiliarySample:
  try:
    io_values = _parse_proc_mapping(read_bounded_proc_file(directory_fd, "io", MAX_STAT_BYTES))
  except (ProcReadError, UnicodeDecodeError):
    io_values = {}
  try:
    status_values = _parse_proc_mapping(read_bounded_proc_file(directory_fd, "status", MAX_STAT_BYTES))
  except (ProcReadError, UnicodeDecodeError):
    status_values = {}
  fd_count = None
  socket_count = None
  try:
    fd_directory = _open_proc_subdirectory(directory_fd, "fd")
    try:
      names = _bounded_directory_names(fd_directory, MAX_AUX_ENTRIES)
      if names is not None:
        fd_count = len(names)
        socket_count = 0
        for name in names:
          try:
            if os.readlink(name, dir_fd=fd_directory).startswith("socket:["):
              socket_count += 1
          except OSError:
            continue
    finally:
      os.close(fd_directory)
  except OSError:
    pass
  children = ()
  try:
    raw_children = read_bounded_proc_file(directory_fd, f"task/{pid}/children", MAX_STAT_BYTES)
    children = tuple(int(token, 10) for token in raw_children.decode("ascii").split() if token.isdecimal())[:256]
  except (ProcReadError, UnicodeDecodeError):
    pass
  thread_ticks = []
  try:
    task_directory = _open_proc_subdirectory(directory_fd, "task")
    try:
      names = _bounded_directory_names(task_directory, 256)
      for name in sorted((name for name in (names or ()) if name.isdecimal()), key=int):
        thread_directory = None
        try:
          thread_directory = _open_proc_subdirectory(task_directory, name)
          sample = parse_stat(read_bounded_proc_file(thread_directory, "stat", MAX_STAT_BYTES), int(name), 0.0)
          thread_ticks.append((int(name), sample.cpu_ticks))
        except (OSError, ProcReadError):
          continue
        finally:
          if thread_directory is not None:
            os.close(thread_directory)
    finally:
      os.close(task_directory)
  except OSError:
    pass
  return AuxiliarySample(
    fd_count, socket_count, io_values.get("read_bytes"), io_values.get("write_bytes"),
    status_values.get("voluntary_ctxt_switches"), status_values.get("nonvoluntary_ctxt_switches"),
    children, tuple(thread_ticks),
  )


def collect_cgroup_context(directory_fd: int) -> tuple[str | None, str | None, str | None]:
  try:
    text = read_bounded_proc_file(directory_fd, "cgroup", MAX_STAT_BYTES).decode("utf-8", "strict")
  except (ProcReadError, UnicodeDecodeError):
    return None, None, None
  path = next((line.split("::", 1)[1] for line in text.splitlines() if line.startswith("0::")), None)
  if path is None or ".." in path.split("/"):
    return path, None, None
  root = os.path.join("/sys/fs/cgroup", path.lstrip("/"))
  def read_constraint(name: str) -> str | None:
    try:
      with open(os.path.join(root, name), "rb") as handle:
        value = handle.read(257)
    except (OSError, UnicodeDecodeError):
      return None
    if len(value) > 256:
      return None
    return display_safe(value.decode("ascii", "strict").strip())
  return path, read_constraint("cpu.max"), read_constraint("memory.max")


def observe_extended(pid: int, interval: float, sample_count: int) -> ExtendedResult:
  warnings = []
  initial_aux = None
  cgroup = cpu_constraint = memory_constraint = None
  try:
    descriptor = open_process_directory(pid)
    try:
      initial_aux = capture_auxiliary(descriptor, pid)
      cgroup, cpu_constraint, memory_constraint = collect_cgroup_context(descriptor)
    finally:
      os.close(descriptor)
  except (InvalidTargetError, OSError) as error:
    warnings.append(f"initial auxiliary evidence unavailable: {display_safe(error)}")
  analysis = observe_samples(pid, interval, sample_count=sample_count)
  final_aux = None
  if not analysis.incomplete:
    try:
      descriptor = open_process_directory(pid)
      try:
        current = capture_sample(descriptor, pid)
        if current.start_ticks == analysis.initial.start_ticks:
          final_aux = capture_auxiliary(descriptor, pid)
        else:
          warnings.append("auxiliary evidence discarded because process identity changed")
      finally:
        os.close(descriptor)
    except (InvalidTargetError, ProcReadError, OSError) as error:
      warnings.append(f"final auxiliary evidence unavailable: {display_safe(error)}")
  return ExtendedResult(analysis, initial_aux, final_aux, cgroup, cpu_constraint, memory_constraint, tuple(warnings))


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
    "  No historical baseline, host load, scheduler-delay, or root-cause analysis is performed.",
    "  Command-line arguments and environment variables are intentionally not read.",
  ))
  return "\n".join(lines)


def _delta(initial: int | None, final: int | None) -> str:
  if initial is None or final is None:
    return "unavailable"
  return f"{initial} -> {final} (delta {final - initial:+d})"


def render_extended(result: ExtendedResult) -> str:
  analysis = result.analysis
  lines = [render_result(analysis), "Auxiliary evidence"]
  initial, final = result.auxiliary_initial, result.auxiliary_final
  if initial is None:
    lines.append("  unavailable")
  else:
    lines.extend([
      f"  File descriptors: {_delta(initial.file_descriptors, final.file_descriptors if final else None)}",
      f"  Sockets: {_delta(initial.sockets, final.sockets if final else None)}",
      f"  Read bytes: {_delta(initial.read_bytes, final.read_bytes if final else None)}",
      f"  Write bytes: {_delta(initial.write_bytes, final.write_bytes if final else None)}",
      f"  Voluntary context switches: {_delta(initial.voluntary_context_switches, final.voluntary_context_switches if final else None)}",
      f"  Nonvoluntary context switches: {_delta(initial.nonvoluntary_context_switches, final.nonvoluntary_context_switches if final else None)}",
      f"  Child PIDs: {', '.join(map(str, initial.children)) or 'none observed'}",
      f"  Observed threads: {len(initial.thread_cpu_ticks)}",
    ])
    if final is not None:
      initial_threads = dict(initial.thread_cpu_ticks)
      deltas = sorted(
        ((ticks - initial_threads[tid], tid) for tid, ticks in final.thread_cpu_ticks if tid in initial_threads),
        reverse=True,
      )[:10]
      lines.append("  Top per-thread CPU tick deltas: " + (
        ", ".join(f"{tid}:{ticks:+d}" for ticks, tid in deltas) or "unavailable"
      ))
  lines.extend([
    "Cgroup context",
    f"  Path: {display_safe(result.cgroup) if result.cgroup else 'unavailable'}",
    f"  CPU constraint: {display_safe(result.cpu_constraint) if result.cpu_constraint else 'unavailable'}",
    f"  Memory constraint: {display_safe(result.memory_constraint) if result.memory_constraint else 'unavailable'}",
  ])
  if analysis.samples:
    lines.append(f"Sampling: {len(analysis.samples)} samples were captured")
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
  validate_output_arguments(parser, arguments)
  interval = arguments.interval
  if arguments.duration is not None:
    sample_count = min(MAX_SAMPLES, max(2, int(arguments.duration / interval) + 1))
    interval = arguments.duration / (sample_count - 1)
  else:
    sample_count = arguments.continuous or arguments.samples
  started = time.monotonic()
  try:
    extended = observe_extended(arguments.pid, interval, sample_count)
    result = extended.analysis
    output = render_extended(extended)
    warning_items = list(extended.warnings)
    if result.incomplete_warning is not None:
      warning_items.insert(0, f"incomplete observation: {result.incomplete_warning}")
    exit_code = 1 if result.incomplete else 0
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
  for warning in warning_items:
    print_safe(f"procwatch: warning: {warning}", file=sys.stderr)
  if result.incomplete:
    status = "PARTIAL"
    finding = "the requested process could not be sampled completely with stable identity"
    next_action = "repeat the bounded observation if the same process instance is still running"
  else:
    status = "OBSERVED"
    assert result.final is not None
    rss_delta = (result.final.rss_pages - result.initial.rss_pages) * result.page_size_bytes
    fd_delta = None
    if extended.auxiliary_initial and extended.auxiliary_final:
      if extended.auxiliary_initial.file_descriptors is not None and extended.auxiliary_final.file_descriptors is not None:
        fd_delta = extended.auxiliary_final.file_descriptors - extended.auxiliary_initial.file_descriptors
    finding = f"{sample_count} bounded samples captured; resident memory changed by {signed_kibibytes(rss_delta)}"
    if fd_delta is not None:
      finding += f" and file descriptors changed by {fd_delta:+d}"
    next_action = "correlate observed growth with workload; this sample does not establish a leak"
  conclusion = make_conclusion(status, f"PID {arguments.pid}", finding, next_action)
  record = OutputRecord(
    tool="procwatch",
    status=status,
    target=str(arguments.pid),
    observations={
      "sample_count": len(result.samples) if result.samples else 1 + int(result.final is not None),
      "requested_interval_seconds": interval,
      "observed_interval_seconds": result.elapsed_seconds,
      "initial": result.initial,
      "final": result.final,
      "auxiliary_initial": extended.auxiliary_initial,
      "auxiliary_final": extended.auxiliary_final,
      "cgroup": result.cgroup if hasattr(result, "cgroup") else extended.cgroup,
      "cpu_constraint": extended.cpu_constraint,
      "memory_constraint": extended.memory_constraint,
    },
    conclusion=conclusion,
    next_action=next_action + ".",
    warnings=warning_items,
    elapsed_seconds=time.monotonic() - started,
  )
  brief = "\n".join([
    f"PID: {arguments.pid}",
    f"Samples: {len(result.samples) if result.samples else 1 + int(result.final is not None)}",
    f"State: {display_safe(result.initial.state)}" + (f" -> {display_safe(result.final.state)}" if result.final else ""),
    f"Observation: {'partial' if result.incomplete else 'complete'}",
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
    print_safe(f"procwatch: {display_safe(error)}", file=sys.stderr)
    return 3
  return exit_code


if __name__ == "__main__":
  raise SystemExit(main())
