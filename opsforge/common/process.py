"""Bounded, shell-free child processes shared by OpsForge utilities."""

from __future__ import annotations

from dataclasses import dataclass
import os
import selectors
import signal
import stat
import subprocess
import time
from typing import Mapping, Sequence


TRUSTED_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
READ_CHUNK_BYTES = 64 * 1024


class ProcessError(Exception):
  """A child process could not be run within its bounds."""


class ProcessSpawnError(ProcessError):
  """The child process could not be started."""


class ProcessNotFoundError(ProcessSpawnError):
  """The requested executable does not exist."""


class ProcessTimeoutError(ProcessError):
  """The child process did not finish before its deadline."""


class ProcessOutputLimitError(ProcessError):
  """A child output stream exceeded its byte bound."""

  def __init__(self, stream: str):
    super().__init__(f"child {stream} exceeded its byte limit")
    self.stream = stream


@dataclass(frozen=True)
class ProcessResult:
  returncode: int
  stdout: bytes
  stderr: bytes
  stdout_truncated: bool = False


def _modifiable_only_by_root_or_caller(metadata: os.stat_result) -> bool:
  return metadata.st_uid in {0, os.geteuid()} and not metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)


def resolve_executable(name: str, search_path: str | None = None) -> str | None:
  """Find NAME on absolute PATH entries whose directory and file only root or the caller can modify."""
  path = os.environ.get("PATH", TRUSTED_PATH) if search_path is None else search_path
  for directory in path.split(os.pathsep):
    if not directory or not os.path.isabs(directory):
      continue
    candidate = os.path.join(directory, name)
    try:
      real = os.path.realpath(candidate)
      metadata = os.stat(real)
      trusted = all(
        _modifiable_only_by_root_or_caller(os.stat(item))
        for item in (directory, os.path.dirname(real))
      )
    except OSError:
      continue
    if trusted and stat.S_ISREG(metadata.st_mode) and os.access(real, os.X_OK) and _modifiable_only_by_root_or_caller(metadata):
      return candidate
  return None


def child_environment(**overrides: str) -> dict[str, str]:
  """Return a minimal locale-stable environment that ignores ambient tool configuration."""
  environment = {"PATH": TRUSTED_PATH, "LC_ALL": "C", "LANG": "C"}
  environment.update(overrides)
  return environment


def stop_process_group(process: subprocess.Popen) -> None:
  """Kill an unreaped child's process group, then reap it; a zombie leader keeps the group ID reserved."""
  pid = getattr(process, "pid", None)
  if process.returncode is None and isinstance(pid, int):
    try:
      os.killpg(pid, signal.SIGKILL)
    except OSError:
      try:
        process.kill()
      except OSError:
        pass
  try:
    process.wait(timeout=1.0)
  except (OSError, subprocess.TimeoutExpired):
    pass


def run_bounded(
  arguments: Sequence[str],
  *,
  timeout: float,
  max_output_bytes: int,
  stdin_data: bytes | None = None,
  environment: Mapping[str, str] | None = None,
  truncate_stdout: bool = False,
  capture: bool = True,
) -> ProcessResult:
  """Run ARGUMENTS without a shell under one monotonic deadline and per-stream byte bounds."""
  deadline = time.monotonic() + timeout
  output = subprocess.PIPE if capture else subprocess.DEVNULL
  try:
    process = subprocess.Popen(
      list(arguments),
      stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
      stdout=output,
      stderr=output,
      env=dict(environment) if environment is not None else child_environment(),
      start_new_session=True,
    )
  except FileNotFoundError as error:
    raise ProcessNotFoundError(str(error)) from error
  except OSError as error:
    raise ProcessSpawnError(str(error)) from error
  captured: dict[int, bytearray] = {}
  stdout_fd = process.stdout.fileno() if process.stdout is not None else -1
  truncated = False
  selector = selectors.DefaultSelector()
  try:
    for handle in (process.stdout, process.stderr):
      if handle is not None:
        os.set_blocking(handle.fileno(), False)
        selector.register(handle, selectors.EVENT_READ)
        captured[handle.fileno()] = bytearray()
    pending = memoryview(stdin_data or b"")
    if process.stdin is not None:
      if pending:
        os.set_blocking(process.stdin.fileno(), False)
        selector.register(process.stdin, selectors.EVENT_WRITE)
      else:
        process.stdin.close()
    while selector.get_map() and not truncated:
      remaining = deadline - time.monotonic()
      if remaining <= 0:
        raise ProcessTimeoutError("child process timed out")
      for key, _ in selector.select(remaining):
        if key.fileobj is process.stdin:
          try:
            written = os.write(key.fd, pending[:READ_CHUNK_BYTES])
          except BlockingIOError:
            continue
          except BrokenPipeError:
            written = len(pending)
          pending = pending[written:]
          if not pending:
            selector.unregister(key.fileobj)
            process.stdin.close()
          continue
        try:
          chunk = os.read(key.fd, READ_CHUNK_BYTES)
        except BlockingIOError:
          continue
        if not chunk:
          selector.unregister(key.fileobj)
          continue
        buffer = captured[key.fd]
        buffer.extend(chunk)
        if len(buffer) > max_output_bytes:
          if not (truncate_stdout and key.fd == stdout_fd):
            raise ProcessOutputLimitError("stdout" if key.fd == stdout_fd else "stderr")
          del buffer[max_output_bytes:]
          truncated = True
          break
    if truncated:
      stop_process_group(process)
      returncode = process.returncode if process.returncode is not None else -signal.SIGKILL
    else:
      remaining = deadline - time.monotonic()
      if remaining <= 0:
        raise ProcessTimeoutError("child process timed out")
      try:
        returncode = process.wait(timeout=remaining)
      except subprocess.TimeoutExpired as error:
        raise ProcessTimeoutError("child process timed out") from error
  except BaseException:
    stop_process_group(process)
    raise
  finally:
    selector.close()
    for handle in (process.stdin, process.stdout, process.stderr):
      if handle is not None:
        try:
          handle.close()
        except OSError:
          pass
  stderr_fd = next((fd for fd in captured if fd != stdout_fd), None)
  return ProcessResult(
    returncode,
    bytes(captured.get(stdout_fd, b"")),
    bytes(captured.get(stderr_fd, b"")) if stderr_fd is not None else b"",
    truncated,
  )
