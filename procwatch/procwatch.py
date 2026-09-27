#!/usr/bin/env python3
"""Sample one Linux process for bounded CPU and memory evidence."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from fractions import Fraction
import math
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
  make_conclusion,
  print_safe,
  sanitize_text as display_safe,
  validate_output_arguments,
)
from opsforge_common.procfs import unified_cgroup_path


DEFAULT_INTERVAL_SECONDS = 1.0
MIN_INTERVAL_SECONDS = 0.1
MAX_INTERVAL_SECONDS = 60.0
MAX_STAT_BYTES = 64 * 1024
READ_CHUNK_BYTES = 4096
MAX_SAMPLES = 100
MAX_DURATION_SECONDS = 3600.0
MAX_AUX_ENTRIES = 100_000
MAX_THREAD_SAMPLES = 256
MAX_CHILD_PIDS = 256
MAX_CGROUP_VALUE_BYTES = 256
MAX_MOUNTINFO_BYTES = 1024 * 1024
DEFAULT_CGROUP_MOUNT = ("/sys/fs/cgroup", "/")
EXITED_STATES = frozenset({"Z", "X"})
MOUNTINFO_ESCAPE = re.compile(r"\\([0-7]{3})")


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
  requested_samples: int = 2

  @property
  def incomplete(self) -> bool:
    return self.final is None or self.incomplete_warning is not None

  @property
  def captured_samples(self) -> int:
    return len(self.samples) if self.samples else 1 + int(self.final is not None)

  @property
  def cpu_utilization_percent(self) -> float | None:
    if self.final is None or not self.elapsed_seconds:
      return None
    cpu_seconds = (self.final.cpu_ticks - self.initial.cpu_ticks) / self.clock_ticks_per_second
    return cpu_seconds / self.elapsed_seconds * 100


@dataclass(frozen=True)
class AuxiliarySample:
  file_descriptors: int | None
  sockets: int | None
  read_bytes: int | None
  write_bytes: int | None
  voluntary_context_switches: int | None
  nonvoluntary_context_switches: int | None
  children: tuple[int, ...] | None
  # (thread ID, cumulative CPU ticks, thread start ticks); start ticks detect a reused thread ID.
  thread_cpu_ticks: tuple[tuple[int, int, int], ...] | None
  children_truncated: bool = False
  thread_count: int | None = None
  threads_truncated: bool = False


@dataclass(frozen=True)
class CgroupContext:
  path: str | None = None
  cpu_constraint: str | None = None
  cpu_constraint_source: str | None = None
  memory_constraint: str | None = None
  memory_constraint_source: str | None = None


@dataclass(frozen=True)
class ExtendedResult:
  analysis: AnalysisResult
  auxiliary_initial: AuxiliarySample | None
  auxiliary_final: AuxiliarySample | None
  cgroup: CgroupContext | None
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


class Parser(argparse.ArgumentParser):
  def error(self, message):
    self.print_usage(sys.stderr)
    self.exit(2, f"{self.prog}: error: {display_safe(message)}\n")


def build_argument_parser() -> argparse.ArgumentParser:
  parser = Parser(
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


def read_bounded_proc_file(directory_fd: int | None, name: str, limit: int) -> bytes:
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

    if initial.state in EXITED_STATES:
      return AnalysisResult(
        pid, interval, clock_ticks, page_size, initial, None, None,
        f"process had already exited at the first sample (state {initial.state})", (initial,), sample_count,
      )
    samples = [initial]
    stop_reason = None
    for index in range(1, sample_count):
      sleep_fn(interval)
      label = "second sample" if index == 1 else f"sample {index + 1}"
      try:
        candidate = capture_sample(directory_fd, pid, monotonic_fn=monotonic_fn)
      except ProcReadError as error:
        stop_reason = f"{label} unavailable: {display_safe(error)}"
        break
      previous = samples[-1]
      if candidate.start_ticks != initial.start_ticks:
        problem = "process identity changed"
      elif candidate.state in EXITED_STATES:
        problem = f"process exited (state {candidate.state})"
      elif candidate.user_ticks < previous.user_ticks or candidate.system_ticks < previous.system_ticks:
        problem = "cumulative CPU counters moved backwards"
      else:
        samples.append(candidate)
        continue
      stop_reason = f"{label} unavailable: {problem}"
      break
    if len(samples) < 2:
      return AnalysisResult(
        pid, interval, clock_ticks, page_size, initial, None, None, stop_reason, tuple(samples), sample_count,
      )
    final = samples[-1]
    elapsed = final.observed_at - initial.observed_at
    if not math.isfinite(elapsed) or elapsed <= 0:
      raise ObservationError("monotonic sample interval is not positive and finite")
    if stop_reason is not None:
      stop_reason += f"; results cover samples 1-{len(samples)} ({elapsed:.3f} s)"
    return AnalysisResult(
      pid=pid,
      requested_interval=interval,
      clock_ticks_per_second=clock_ticks,
      page_size_bytes=page_size,
      initial=initial,
      final=final,
      elapsed_seconds=elapsed,
      incomplete_warning=stop_reason,
      samples=tuple(samples),
      requested_samples=sample_count,
    )
  finally:
    os.close(directory_fd)


def _parse_proc_mapping(data: bytes) -> dict[str, int]:
  values = {}
  # Only numeric fields are used, so undecodable Name bytes must not discard the rest.
  for raw_line in data.decode("ascii", "replace").split("\n"):
    if ":" not in raw_line:
      continue
    name, raw_value = raw_line.split(":", 1)
    tokens = raw_value.split()
    if tokens and tokens[0].isascii() and tokens[0].isdecimal():
      values[name] = int(tokens[0], 10)
  return values


def _read_counters(
  directory_fd: int, name: str, keys: tuple[str, ...], label: str, gaps: list[str],
) -> tuple[int | None, ...]:
  try:
    values = _parse_proc_mapping(read_bounded_proc_file(directory_fd, name, MAX_STAT_BYTES))
  except ProcReadError as error:
    gaps.append(f"{label} unavailable: {display_safe(error)}")
    return (None,) * len(keys)
  missing = [key for key in keys if key not in values]
  if missing:
    gaps.append(f"{label} unavailable: {name} has no valid {' or '.join(missing)}")
  return tuple(values.get(key) for key in keys)


def _open_proc_subdirectory(directory_fd: int, name: str) -> int:
  flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
  flags |= getattr(os, "O_NOFOLLOW", 0)
  return os.open(name, flags, dir_fd=directory_fd)


def _bounded_directory_names(directory_fd: int, limit: int) -> list[str]:
  names = []
  with os.scandir(directory_fd) as entries:
    for entry in entries:
      if len(names) >= limit:
        raise ProcReadError(f"more than {limit} directory entries")
      names.append(entry.name)
  return names


def capture_auxiliary(directory_fd: int) -> tuple[AuxiliarySample, list[str]]:
  gaps = []
  read_bytes, write_bytes = _read_counters(directory_fd, "io", ("read_bytes", "write_bytes"), "I/O byte counters", gaps)
  voluntary, nonvoluntary = _read_counters(
    directory_fd, "status", ("voluntary_ctxt_switches", "nonvoluntary_ctxt_switches"), "context switch counters", gaps,
  )
  fd_count = None
  socket_count = None
  try:
    fd_directory = _open_proc_subdirectory(directory_fd, "fd")
    try:
      names = _bounded_directory_names(fd_directory, MAX_AUX_ENTRIES)
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
  except (OSError, ProcReadError) as error:
    gaps.append(f"file descriptor counts unavailable: {display_safe(error)}")
  thread_ticks = None
  thread_count = None
  threads_truncated = False
  children = None
  children_truncated = False
  try:
    task_directory = _open_proc_subdirectory(directory_fd, "task")
    try:
      tids = sorted(int(name, 10) for name in _bounded_directory_names(task_directory, MAX_AUX_ENTRIES) if name.isdecimal())
      thread_count = len(tids)
      threads_truncated = thread_count > MAX_THREAD_SAMPLES
      thread_ticks = []
      found_children = set()
      children_read = False
      children_error = "no thread children list was readable"
      for tid in tids[:MAX_THREAD_SAMPLES]:
        try:
          thread_directory = _open_proc_subdirectory(task_directory, str(tid))
        except OSError:
          continue
        try:
          try:
            thread = parse_stat(read_bounded_proc_file(thread_directory, "stat", MAX_STAT_BYTES), tid, 0.0)
            thread_ticks.append((tid, thread.cpu_ticks, thread.start_ticks))
          except ProcReadError:
            pass
          try:
            raw_children = read_bounded_proc_file(thread_directory, "children", MAX_STAT_BYTES)
            found_children.update(int(token, 10) for token in raw_children.split() if token.isdigit())
            children_read = True
          except ProcReadError as error:
            children_error = display_safe(error)
        finally:
          os.close(thread_directory)
      if children_read:
        ordered = sorted(found_children)
        children = tuple(ordered[:MAX_CHILD_PIDS])
        # Children of threads beyond the thread cap were never read.
        children_truncated = threads_truncated or len(ordered) > MAX_CHILD_PIDS
      else:
        gaps.append(f"child PIDs unavailable: {children_error}")
    finally:
      os.close(task_directory)
  except (OSError, ProcReadError) as error:
    gaps.append(f"thread and child PID evidence unavailable: {display_safe(error)}")
  sample = AuxiliarySample(
    fd_count, socket_count, read_bytes, write_bytes, voluntary, nonvoluntary,
    children, None if thread_ticks is None else tuple(thread_ticks),
    children_truncated, thread_count, threads_truncated,
  )
  return sample, gaps


def parse_cgroup2_mount(mountinfo: str) -> tuple[str, str] | None:
  """Return (mount point, hierarchy root) of the first cgroup2 mount in mountinfo text."""
  for line in mountinfo.split("\n"):
    head, separator, tail = line.partition(" - ")
    fields = head.split(" ")
    if separator and len(fields) >= 5 and tail.split(" ", 1)[0] == "cgroup2":
      point, root = (MOUNTINFO_ESCAPE.sub(lambda match: chr(int(match.group(1), 8)), value) for value in (fields[4], fields[3]))
      return point, root
  return None


def _read_cgroup_value(path: str) -> str | None:
  """Return the stripped ASCII value, or None when this level does not expose the file."""
  flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
  try:
    descriptor = os.open(path, flags)
  except FileNotFoundError:
    return None
  try:
    data = os.read(descriptor, MAX_CGROUP_VALUE_BYTES + 1)
  finally:
    os.close(descriptor)
  if len(data) > MAX_CGROUP_VALUE_BYTES:
    raise ValueError("value is too long")
  return data.decode("ascii").strip()


def _cgroup_limit(name: str, value: str) -> int | Fraction | None:
  """Return a comparable limit, None for "max", or raise ValueError."""
  tokens = value.split()
  if name == "memory.max" and len(tokens) == 1 and (tokens[0] == "max" or tokens[0].isdecimal()):
    return None if tokens[0] == "max" else int(tokens[0], 10)
  if name == "cpu.max" and len(tokens) == 2 and tokens[1].isdecimal() and int(tokens[1], 10) > 0:
    if tokens[0] == "max":
      return None
    if tokens[0].isdecimal():
      return Fraction(int(tokens[0], 10), int(tokens[1], 10))
  raise ValueError(f"unsupported {name} value")


def collect_cgroup_context(
  directory_fd: int, mount: tuple[str, str] | None = None,
) -> tuple[CgroupContext, list[str]]:
  """Report the tightest cpu.max and memory.max from the process cgroup up to the cgroup2 mount root."""
  try:
    text = read_bounded_proc_file(directory_fd, "cgroup", MAX_STAT_BYTES).decode("utf-8", "surrogateescape")
  except ProcReadError as error:
    return CgroupContext(), [f"cgroup context unavailable: {display_safe(error)}"]
  path = unified_cgroup_path(text)
  if path is None or not path.startswith("/"):
    return CgroupContext(), ["cgroup context unavailable: no cgroup v2 path is listed"]
  if ".." in path.split("/"):
    return CgroupContext(path), ["cgroup constraints unavailable: the cgroup is outside this cgroup namespace"]
  if mount is None:
    try:
      mountinfo = read_bounded_proc_file(None, "/proc/self/mountinfo", MAX_MOUNTINFO_BYTES)
    except ProcReadError:
      mountinfo = b""
    mount = parse_cgroup2_mount(mountinfo.decode("utf-8", "surrogateescape")) or DEFAULT_CGROUP_MOUNT
  mount_point, mount_root = mount
  prefix = mount_root.rstrip("/")
  if path != prefix and not path.startswith(prefix + "/"):
    return CgroupContext(path), [f"cgroup constraints unavailable: the cgroup is not below cgroup2 mount root {display_safe(mount_root)}"]
  parts = [part for part in path[len(prefix):].split("/") if part]
  gaps = []
  found = {}
  for depth in range(len(parts), -1, -1):
    level = "/".join([prefix, *parts[:depth]]) or "/"
    for name in ("cpu.max", "memory.max"):
      try:
        value = _read_cgroup_value(os.path.join(mount_point, *parts[:depth], name))
        if value is None:
          continue
        limit = _cgroup_limit(name, value)
      except OSError as error:
        gaps.append(f"cgroup {name} unreadable at {display_safe(level)}: {display_safe(error.strerror or error)}")
        continue
      except ValueError:
        gaps.append(f"cgroup {name} at {display_safe(level)} has an unsupported value")
        continue
      best = found.get(name)
      if best is None or (limit is not None and (best[2] is None or limit < best[2])):
        found[name] = (value, None if limit is None else level, limit)
  for name, label in (("cpu.max", "CPU"), ("memory.max", "memory")):
    if name not in found:
      gaps.append(f"cgroup {label} constraint unavailable: no readable {name} at {display_safe(path)} or its ancestors")
  cpu = found.get("cpu.max", (None, None))
  memory = found.get("memory.max", (None, None))
  return CgroupContext(path, cpu[0], cpu[1], memory[0], memory[1]), gaps


def observe_extended(pid: int, interval: float, sample_count: int) -> ExtendedResult:
  warnings = []
  gaps = []
  initial_aux = None
  initial_identity = None
  cgroup = None
  try:
    descriptor = open_process_directory(pid)
    try:
      initial_identity = capture_sample(descriptor, pid).start_ticks
      initial_aux, aux_gaps = capture_auxiliary(descriptor)
      cgroup, cgroup_gaps = collect_cgroup_context(descriptor)
      if capture_sample(descriptor, pid).start_ticks != initial_identity:
        raise ProcReadError("process identity mismatch during initial auxiliary collection")
      gaps = aux_gaps + cgroup_gaps
    finally:
      os.close(descriptor)
  except (InvalidTargetError, ProcReadError, OSError) as error:
    initial_aux = None
    initial_identity = None
    cgroup = None
    warnings.append(f"initial auxiliary evidence unavailable: {display_safe(error)}")
  analysis = observe_samples(pid, interval, sample_count=sample_count)
  if initial_identity is not None and initial_identity != analysis.initial.start_ticks:
    initial_aux = None
    cgroup = None
    gaps = []
    warnings.append("initial auxiliary evidence discarded because of process identity mismatch")
  warnings.extend(gaps)
  final_aux = None
  if analysis.incomplete:
    if initial_aux is not None:
      warnings.append("final auxiliary evidence not collected because sampling ended early")
  else:
    try:
      descriptor = open_process_directory(pid)
      try:
        current = capture_sample(descriptor, pid)
        if current.start_ticks == analysis.initial.start_ticks:
          final_aux, final_gaps = capture_auxiliary(descriptor)
          if capture_sample(descriptor, pid).start_ticks != analysis.initial.start_ticks:
            raise ProcReadError("process identity mismatch during final auxiliary collection")
          warnings.extend([gap for gap in final_gaps if gap not in warnings])
        else:
          warnings.append("final auxiliary evidence discarded because of process identity mismatch")
      finally:
        os.close(descriptor)
    except (InvalidTargetError, ProcReadError, OSError) as error:
      final_aux = None
      warnings.append(f"final auxiliary evidence unavailable: {display_safe(error)}")
  return ExtendedResult(analysis, initial_aux, final_aux, cgroup, tuple(warnings))


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
    f"  Sample interval: {result.requested_interval:.3f} s",
    (
      "  Scope: one anchored Linux /proc process directory; "
      f"{result.captured_samples} of {result.requested_samples} requested bounded stat samples used"
    ),
    "  Snapshot: no; fields within and across samples may change during observation",
  ]
  final = result.final
  if final is None or result.elapsed_seconds is None:
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
    final_rss = final.rss_pages * result.page_size_bytes
    cpu_delta_ticks = final.cpu_ticks - initial.cpu_ticks
    user_delta_ticks = final.user_ticks - initial.user_ticks
    system_delta_ticks = final.system_ticks - initial.system_ticks
    cpu_seconds = cpu_delta_ticks / result.clock_ticks_per_second
    user_seconds = user_delta_ticks / result.clock_ticks_per_second
    system_seconds = system_delta_ticks / result.clock_ticks_per_second
    utilization = result.cpu_utilization_percent
    lines.extend((
      f"  Observation window: {result.elapsed_seconds:.6f} s",
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


def _constraint_text(value: str | None, source: str | None) -> str:
  if value is None:
    return "unavailable"
  if source is None:
    return f"{display_safe(value)} (no limit at any readable level)"
  return f"{display_safe(value)} (tightest; set by {display_safe(source)})"


def render_extended(result: ExtendedResult) -> str:
  analysis = result.analysis
  lines = [render_result(analysis), "Auxiliary evidence"]
  initial, final = result.auxiliary_initial, result.auxiliary_final
  if initial is None:
    lines.append("  unavailable")
  else:
    if initial.children is None:
      children = "unavailable"
    else:
      children = ", ".join(map(str, initial.children)) or "none observed"
      if initial.children_truncated:
        children += " (truncated)"
    if initial.thread_cpu_ticks is None:
      threads = "unavailable"
    else:
      threads = str(len(initial.thread_cpu_ticks))
      if initial.thread_count is not None and initial.thread_count != len(initial.thread_cpu_ticks):
        threads += f" of {initial.thread_count}"
      if initial.threads_truncated:
        threads += " (truncated)"
    lines.extend([
      f"  File descriptors: {_delta(initial.file_descriptors, final.file_descriptors if final else None)}",
      f"  Sockets: {_delta(initial.sockets, final.sockets if final else None)}",
      f"  Read bytes: {_delta(initial.read_bytes, final.read_bytes if final else None)}",
      f"  Write bytes: {_delta(initial.write_bytes, final.write_bytes if final else None)}",
      f"  Voluntary context switches: {_delta(initial.voluntary_context_switches, final.voluntary_context_switches if final else None)}",
      f"  Nonvoluntary context switches: {_delta(initial.nonvoluntary_context_switches, final.nonvoluntary_context_switches if final else None)}",
      f"  Child PIDs: {children}",
      f"  Observed threads: {threads}",
    ])
    if final is not None:
      deltas = []
      if initial.thread_cpu_ticks is not None and final.thread_cpu_ticks is not None:
        initial_threads = {(tid, start): ticks for tid, ticks, start in initial.thread_cpu_ticks}
        deltas = sorted(
          (
            (ticks - initial_threads[tid, start], tid)
            for tid, ticks, start in final.thread_cpu_ticks if (tid, start) in initial_threads
          ),
          reverse=True,
        )[:10]
      lines.append("  Top per-thread CPU tick deltas: " + (
        ", ".join(f"{tid}:{ticks:+d}" for ticks, tid in deltas) or "unavailable"
      ))
  cgroup = result.cgroup or CgroupContext()
  lines.extend([
    "Cgroup context",
    f"  Path: {'unavailable' if cgroup.path is None else display_safe(cgroup.path)}",
    f"  CPU constraint: {_constraint_text(cgroup.cpu_constraint, cgroup.cpu_constraint_source)}",
    f"  Memory constraint: {_constraint_text(cgroup.memory_constraint, cgroup.memory_constraint_source)}",
  ])
  if analysis.samples:
    lines.append(f"Sampling: {len(analysis.samples)} samples were captured")
  return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
  parser = build_argument_parser()
  arguments = parser.parse_args(argv)
  validate_output_arguments(parser, arguments)
  interval = arguments.interval
  if arguments.duration is not None:
    # 1e-9 absorbs float error such as 0.3 / 0.1 == 2.9999999999999996.
    steps = max(
      1,
      math.floor(arguments.duration / interval + 1e-9),
      math.ceil(arguments.duration / MAX_INTERVAL_SECONDS - 1e-9),
    )
    sample_count = min(MAX_SAMPLES, steps + 1)
    interval = round(arguments.duration / (sample_count - 1), 6)
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
  initial_rss = result.initial.rss_pages * result.page_size_bytes
  final_rss = None if result.final is None else result.final.rss_pages * result.page_size_bytes
  utilization = result.cpu_utilization_percent
  if final_rss is None:
    status = "PARTIAL"
    finding = "the requested process could not be sampled completely with stable identity"
    next_action = "repeat the bounded observation if the same process instance is still running"
  else:
    fd_delta = None
    if extended.auxiliary_initial and extended.auxiliary_final:
      if extended.auxiliary_initial.file_descriptors is not None and extended.auxiliary_final.file_descriptors is not None:
        fd_delta = extended.auxiliary_final.file_descriptors - extended.auxiliary_initial.file_descriptors
    if result.incomplete:
      status = "PARTIAL"
      finding = f"{result.captured_samples} of {sample_count} bounded samples captured before sampling stopped"
      next_action = "repeat the bounded observation if the same process instance is still running"
    else:
      status = "OBSERVED"
      finding = f"{sample_count} bounded samples captured"
      next_action = "correlate observed growth with workload; this sample does not establish a leak"
    finding += f"; resident memory changed by {signed_kibibytes(final_rss - initial_rss)}"
    if fd_delta is not None:
      finding += f" and file descriptors changed by {fd_delta:+d}"
  cgroup = extended.cgroup or CgroupContext()
  conclusion = make_conclusion(status, f"PID {arguments.pid}", finding, next_action)
  record = OutputRecord(
    tool="procwatch",
    status=status,
    target=str(arguments.pid),
    observations={
      "sample_count": result.captured_samples,
      "requested_sample_count": sample_count,
      "requested_interval_seconds": arguments.interval,
      "effective_interval_seconds": interval,
      "observed_interval_seconds": result.elapsed_seconds,
      "clock_ticks_per_second": result.clock_ticks_per_second,
      "page_size_bytes": result.page_size_bytes,
      "cpu_utilization_percent": None if utilization is None else round(utilization, 2),
      "initial_rss_bytes": initial_rss,
      "final_rss_bytes": final_rss,
      "rss_delta_bytes": None if final_rss is None else final_rss - initial_rss,
      "initial": result.initial,
      "final": result.final,
      "auxiliary_initial": extended.auxiliary_initial,
      "auxiliary_final": extended.auxiliary_final,
      "cgroup": cgroup.path,
      "cpu_constraint": cgroup.cpu_constraint,
      "cpu_constraint_source": cgroup.cpu_constraint_source,
      "memory_constraint": cgroup.memory_constraint,
      "memory_constraint_source": cgroup.memory_constraint_source,
    },
    conclusion=conclusion,
    next_action=next_action + ".",
    warnings=warning_items,
    elapsed_seconds=time.monotonic() - started,
  )
  brief = "\n".join([
    f"PID: {arguments.pid}",
    f"Samples: {result.captured_samples}",
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
