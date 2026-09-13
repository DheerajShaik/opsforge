#!/usr/bin/env python3
"""Inspect TCP listening sockets for one local port."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
import pwd
import re
import selectors
import shutil
import subprocess
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


UNAVAILABLE = "-"
SS_COMMANDS = (("ipv4", ("-H", "-4", "-ltnp")), ("ipv6", ("-H", "-6", "-ltnp")))
PROCESS_REFERENCE = re.compile(r'\("((?:\\.|[^"\\])*)",pid=(\d+)(?:,fd=(\d+))?')
MAX_WATCH_COUNT = 100
MAX_WATCH_INTERVAL = 60.0
MAX_PROC_FIELD_BYTES = 4096
MAX_PROC_ENTRIES = 100_000
MAX_SS_STREAM_BYTES = 8 * 1024 * 1024
SS_TIMEOUT_SECONDS = 30.0


class PortLensError(Exception):
  """A failure that prevents a reliable inspection."""


@dataclass(frozen=True)
class ProcessReference:
  pid: int
  ss_name: str
  fd: int | None = None


@dataclass(frozen=True)
class SocketObservation:
  protocol: str
  state: str
  family: str
  local_address: str
  local_port: int
  processes: tuple[ProcessReference, ...] = ()


@dataclass(frozen=True)
class DisplayObservation:
  protocol: str
  state: str
  family: str
  local_address: str
  local_port: int
  pid: str
  user: str
  process: str
  uid: str = UNAVAILABLE
  executable: str = UNAVAILABLE
  file_descriptors: str = UNAVAILABLE
  cgroup: str = UNAVAILABLE
  socket_fds: str = UNAVAILABLE
  exposure: str = UNAVAILABLE


@dataclass(frozen=True)
class PortSelection:
  start: int
  end: int

  def contains(self, port: int) -> bool:
    return self.start <= port <= self.end

  def label(self) -> str:
    return str(self.start) if self.start == self.end else f"{self.start}-{self.end}"


def parse_port(value: str) -> int:
  """Parse a strict decimal TCP port."""
  if not value or not value.isascii() or not value.isdecimal():
    raise argparse.ArgumentTypeError("port must be a decimal integer from 1 through 65535")
  port = int(value, 10)
  if not 1 <= port <= 65535:
    raise argparse.ArgumentTypeError("port must be from 1 through 65535")
  return port


def parse_port_selection(value: str) -> PortSelection:
  if "-" not in value:
    port = parse_port(value)
    return PortSelection(port, port)
  if value.count("-") != 1:
    raise argparse.ArgumentTypeError("port range must be START-END")
  start_text, end_text = value.split("-", 1)
  start = parse_port(start_text)
  end = parse_port(end_text)
  if start > end:
    raise argparse.ArgumentTypeError("port range start must not exceed its end")
  return PortSelection(start, end)


def bounded_int(value: str) -> int:
  if not value.isascii() or not value.isdecimal():
    raise argparse.ArgumentTypeError("value must be a decimal integer from 1 through 100")
  result = int(value, 10)
  if not 1 <= result <= MAX_WATCH_COUNT:
    raise argparse.ArgumentTypeError("value must be from 1 through 100")
  return result


def bounded_interval(value: str) -> float:
  try:
    result = float(value)
  except ValueError as error:
    raise argparse.ArgumentTypeError("interval must be from 0.1 through 60 seconds") from error
  if not 0.1 <= result <= MAX_WATCH_INTERVAL:
    raise argparse.ArgumentTypeError("interval must be from 0.1 through 60 seconds")
  return result


def parse_pid(value: str) -> int:
  if not value.isascii() or not value.isdecimal() or int(value, 10) < 1:
    raise argparse.ArgumentTypeError("PID must be a positive decimal integer")
  result = int(value, 10)
  if result > 2_147_483_647:
    raise argparse.ArgumentTypeError("PID is outside the supported range")
  return result


class Parser(argparse.ArgumentParser):
  def parse_args(self, args=None, namespace=None):
    parsed = super().parse_args(args, namespace)
    if parsed.all == (parsed.port is not None):
      self.error("specify exactly one PORT/RANGE or --all")
    return parsed


def build_argument_parser() -> argparse.ArgumentParser:
  parser = Parser(
    prog="portlens",
    description=(
      "Inspect TCP listeners or UDP sockets matching a local port in the current network "
      "namespace. A no-match result does not prove that the port is bindable."
    ),
  )
  parser.add_argument("port", nargs="?", type=parse_port_selection, help="local port or inclusive START-END range")
  parser.add_argument("--all", action="store_true", help="show every visible local listener")
  parser.add_argument("--udp", action="store_true", help="inspect UDP sockets instead of TCP listeners")
  family = parser.add_mutually_exclusive_group()
  family.add_argument("--ipv4", action="store_true", help="inspect IPv4 only")
  family.add_argument("--ipv6", action="store_true", help="inspect IPv6 only")
  parser.add_argument("--pid", type=parse_pid, metavar="PID", help="show only sockets owned by PID")
  parser.add_argument("--process", metavar="NAME", help="show only an exact process name")
  parser.add_argument("--watch", type=bounded_int, metavar="COUNT", help="repeat a bounded number of times (1-100)")
  parser.add_argument("--watch-interval", type=bounded_interval, default=1.0, metavar="SECONDS")
  add_output_arguments(parser)
  return parser


def parse_endpoint(endpoint: str, *, allow_wildcard_port: bool = False) -> tuple[str, int | None]:
  """Parse an ss local endpoint without splitting IPv6 address colons."""
  address, separator, port_text = endpoint.rpartition(":")
  if not separator or not address:
    raise PortLensError(f"cannot parse local endpoint {endpoint!r}")
  if allow_wildcard_port and port_text == "*":
    port = None
  else:
    if not port_text.isascii() or not port_text.isdecimal():
      raise PortLensError(f"cannot parse local endpoint {endpoint!r}")
    port = int(port_text, 10)
    if not 0 <= port <= 65535:
      raise PortLensError(f"local endpoint has invalid port {port_text!r}")
  if address.startswith("[") or address.endswith("]"):
    if not (address.startswith("[") and address.endswith("]")):
      raise PortLensError(f"cannot parse local endpoint {endpoint!r}")
    address = address[1:-1]
  if not address:
    raise PortLensError(f"cannot parse local endpoint {endpoint!r}")
  return address, port


def _unescape_ss_name(value: str) -> str:
  """Decode only simple ss backslash escapes; never evaluate the value."""
  return re.sub(r"\\(.)", r"\1", value)


def parse_process_references(metadata: str) -> tuple[ProcessReference, ...]:
  """Return every parseable process reference; malformed metadata is optional."""
  references = []
  for name, pid_text, fd_text in PROCESS_REFERENCE.findall(metadata):
    references.append(ProcessReference(
      pid=int(pid_text, 10),
      ss_name=_unescape_ss_name(name),
      fd=int(fd_text, 10) if fd_text else None,
    ))
  return tuple(references)


def parse_ss_row(row: str, family: str, protocol: str = "tcp") -> SocketObservation:
  """Parse one headerless ss TCP listening row conservatively."""
  if family not in {"ipv4", "ipv6"}:
    raise PortLensError(f"unsupported address family {family!r}")
  fields = row.split(None, 5)
  if len(fields) < 5:
    raise PortLensError("ss returned a malformed socket row")
  state, receive_queue, send_queue, local_endpoint, peer_endpoint = fields[:5]
  if protocol == "tcp" and state != "LISTEN":
    raise PortLensError(f"ss returned unexpected TCP state {state!r}")
  if protocol not in {"tcp", "udp"}:
    raise PortLensError(f"unsupported protocol {protocol!r}")
  if not receive_queue.isdecimal() or not send_queue.isdecimal():
    raise PortLensError("ss returned malformed TCP queue values")
  parse_endpoint(peer_endpoint, allow_wildcard_port=True)
  local_address, local_port = parse_endpoint(local_endpoint)
  if local_port is None:
    raise PortLensError("ss returned a local endpoint without a numeric port")
  metadata = fields[5] if len(fields) == 6 else ""
  return SocketObservation(
    protocol=protocol,
    state=state,
    family=family,
    local_address=local_address,
    local_port=local_port,
    processes=parse_process_references(metadata),
  )


def parse_ss_output(output: str, family: str, protocol: str = "tcp") -> list[SocketObservation]:
  observations = []
  for line in output.splitlines():
    if not line.strip():
      continue
    observations.append(parse_ss_row(line, family, protocol))
  return observations


def find_ss() -> str:
  executable = shutil.which("ss")
  if executable is None:
    raise PortLensError("required command 'ss' was not found")
  return executable


def run_ss_query(executable: str, arguments: Sequence[str]) -> str:
  try:
    process = subprocess.Popen(
      [executable, *arguments],
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
    )
  except OSError as error:
    raise PortLensError(f"could not execute 'ss': {error}") from error
  if process.stdout is None or process.stderr is None:
    process.kill()
    process.wait()
    raise PortLensError("could not execute 'ss'")
  streams = {process.stdout: bytearray(), process.stderr: bytearray()}
  selector = selectors.DefaultSelector()
  selector.register(process.stdout, selectors.EVENT_READ)
  selector.register(process.stderr, selectors.EVENT_READ)
  deadline = time.monotonic() + SS_TIMEOUT_SECONDS
  try:
    while selector.get_map():
      remaining = deadline - time.monotonic()
      if remaining <= 0:
        raise PortLensError("'ss' timed out")
      events = selector.select(remaining)
      if not events:
        raise PortLensError("'ss' timed out")
      for key, _ in events:
        chunk = os.read(key.fileobj.fileno(), 64 * 1024)
        if not chunk:
          selector.unregister(key.fileobj)
          continue
        streams[key.fileobj].extend(chunk)
        if len(streams[key.fileobj]) > MAX_SS_STREAM_BYTES:
          raise PortLensError("'ss' output exceeded the 8 MiB limit")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
      raise PortLensError("'ss' timed out")
    try:
      returncode = process.wait(timeout=remaining)
    except subprocess.TimeoutExpired as error:
      raise PortLensError("'ss' timed out") from error
  except PortLensError:
    if process.poll() is None:
      process.kill()
    process.wait()
    raise
  finally:
    selector.close()
    process.stdout.close()
    process.stderr.close()
  try:
    stdout = bytes(streams[process.stdout]).decode("utf-8", "strict")
    stderr = bytes(streams[process.stderr]).decode("utf-8", "replace")
  except UnicodeDecodeError as error:
    raise PortLensError("'ss' returned non-UTF-8 output") from error
  if returncode != 0:
    detail = sanitize_display(stderr.strip())[:200]
    suffix = f": {detail}" if detail else ""
    raise PortLensError(f"'ss' exited with status {returncode}{suffix}")
  return stdout


def discover_sockets(
  executable: str,
  runner: Callable[[str, Sequence[str]], str] = run_ss_query,
  *,
  protocol: str = "tcp",
  families: Sequence[str] = ("ipv4", "ipv6"),
) -> list[SocketObservation]:
  observations = []
  flag = "-lunp" if protocol == "udp" else "-ltnp"
  for family in families:
    family_flag = "-4" if family == "ipv4" else "-6"
    arguments = ("-H", family_flag, flag)
    observations.extend(parse_ss_output(runner(executable, arguments), family, protocol))
  return observations


def enrich_process(reference: ProcessReference) -> tuple[str, str]:
  proc_path = f"/proc/{reference.pid}"
  try:
    uid = os.stat(proc_path).st_uid
  except OSError:
    user = UNAVAILABLE
  else:
    try:
      user = pwd.getpwuid(uid).pw_name
    except KeyError:
      user = str(uid)

  process = _read_proc_text(f"{proc_path}/comm")
  if process == UNAVAILABLE:
    process = reference.ss_name or UNAVAILABLE
  if not process:
    process = reference.ss_name or UNAVAILABLE
  return user, process


def _read_proc_text(path: str) -> str:
  try:
    with open(path, "rb") as handle:
      data = handle.read(MAX_PROC_FIELD_BYTES + 1)
  except OSError:
    return UNAVAILABLE
  if len(data) > MAX_PROC_FIELD_BYTES:
    return UNAVAILABLE
  return data.decode("utf-8", "replace").strip() or UNAVAILABLE


def process_details(reference: ProcessReference) -> tuple[str, str, str, str, str, str, str]:
  """Read bounded, non-command-line process metadata from procfs."""
  user, process = enrich_process(reference)
  proc_path = f"/proc/{reference.pid}"
  try:
    uid = str(os.stat(proc_path).st_uid)
  except OSError:
    uid = UNAVAILABLE
  try:
    executable = os.path.basename(os.readlink(f"{proc_path}/exe")) or UNAVAILABLE
  except OSError:
    executable = UNAVAILABLE
  try:
    with os.scandir(f"{proc_path}/fd") as entries:
      count = 0
      for count, _ in enumerate(entries, 1):
        if count > MAX_PROC_ENTRIES:
          raise OverflowError
    fd_count = str(count)
  except (OSError, OverflowError):
    fd_count = UNAVAILABLE
  cgroup_text = _read_proc_text(f"{proc_path}/cgroup")
  if cgroup_text != UNAVAILABLE:
    first = cgroup_text.splitlines()[0]
    cgroup = first.rsplit(":", 1)[-1][:256] or "/"
  else:
    cgroup = UNAVAILABLE
  fd = str(reference.fd) if reference.fd is not None else UNAVAILABLE
  return user, process, uid, executable, fd_count, cgroup, fd


def classify_bind(address: str) -> str:
  if address in {"0.0.0.0", "::", "*"}:
    return "wildcard (all local interfaces in this namespace)"
  if address == "127.0.0.1" or address == "::1" or address.startswith("127."):
    return "loopback only"
  return "specific local address"


def to_display(observation: SocketObservation) -> DisplayObservation:
  if not observation.processes:
    return DisplayObservation(
      observation.protocol, observation.state, observation.family,
      observation.local_address, observation.local_port,
      UNAVAILABLE, UNAVAILABLE, UNAVAILABLE,
      exposure=classify_bind(observation.local_address),
    )
  users = []
  names = []
  uids = []
  executables = []
  fd_counts = []
  cgroups = []
  socket_fds = []
  for reference in observation.processes:
    user, name, uid, executable, fd_count, cgroup, socket_fd = process_details(reference)
    users.append(user)
    names.append(name)
    uids.append(uid)
    executables.append(executable)
    fd_counts.append(fd_count)
    cgroups.append(cgroup)
    socket_fds.append(socket_fd)
  return DisplayObservation(
    observation.protocol,
    observation.state,
    observation.family,
    observation.local_address,
    observation.local_port,
    ",".join(str(reference.pid) for reference in observation.processes),
    ",".join(users),
    ",".join(names),
    ",".join(uids),
    ",".join(executables),
    ",".join(fd_counts),
    ",".join(cgroups),
    ",".join(socket_fds),
    classify_bind(observation.local_address),
  )


def sanitize_display(value: object) -> str:
  text = str(value)
  return "".join(
    "?" if character == "\x1b" or unicodedata.category(character) == "Cc" else character
    for character in text
  )


def sort_observations(observations: Sequence[DisplayObservation]) -> list[DisplayObservation]:
  family_order = {"ipv4": 0, "ipv6": 1}

  def key(item: DisplayObservation) -> tuple[object, ...]:
    pid_key = (1, 0) if item.pid == UNAVAILABLE else (0, int(item.pid.split(",", 1)[0]))
    return (family_order[item.family], item.local_address, pid_key, item.process)

  return sorted(observations, key=key)


def render_result(port: int | str, observations: Sequence[DisplayObservation], *, protocol: str = "tcp") -> str:
  lines = [
    f"PortLens: local port {port}",
    f"Scope: {protocol.upper()} local sockets visible in the current network namespace",
    "",
  ]
  if not observations:
    lines.extend([
      f"No matching {protocol.upper()} socket was observed.",
      "This result does not prove that the port is available or bindable.",
    ])
    return "\n".join(lines)

  count = len(observations)
  noun = "socket" if count == 1 else "sockets"
  lines.extend([f"Found {count} matching {noun}.", ""])
  headings = ("PROTO", "STATE", "FAMILY", "LOCAL ADDRESS", "PORT", "PID", "USER", "PROCESS", "EXPOSURE")
  rows = [headings]
  for item in observations:
    rows.append(tuple(sanitize_display(value) for value in (
      item.protocol, item.state, item.family, item.local_address, item.local_port,
      item.pid, item.user, item.process, item.exposure,
    )))
  widths = [max(len(row[index]) for row in rows) for index in range(len(headings))]
  for row in rows:
    lines.append("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)).rstrip())
  shared = likely_shared_bind_count(observations)
  lines.extend((
    "",
    f"Likely shared/reused bind groups: {shared}",
    "Multiple rows on one protocol/family/address/port can reflect socket reuse or multiple owners; it does not by itself prove a conflict.",
  ))
  return "\n".join(lines)


def likely_shared_bind_count(observations: Sequence[DisplayObservation]) -> int:
  counts: dict[tuple[str, str, str, int], int] = {}
  for item in observations:
    key = (item.protocol, item.family, item.local_address, item.local_port)
    counts[key] = counts.get(key, 0) + 1
  return sum(count > 1 for count in counts.values())


def inspect(port: int) -> tuple[str, int]:
  executable = find_ss()
  observations = discover_sockets(executable)
  matches = [observation for observation in observations if observation.local_port == port]
  displayed = sort_observations([to_display(observation) for observation in matches])
  return render_result(port, displayed), 0 if displayed else 1


def inspect_selection(
  selection: PortSelection | None,
  *,
  all_ports: bool,
  protocol: str,
  families: Sequence[str],
  pid: int | None,
  process: str | None,
) -> tuple[str, list[DisplayObservation], int]:
  executable = find_ss()
  observed = discover_sockets(executable, protocol=protocol, families=families)
  matches = []
  for item in observed:
    if not all_ports and selection is not None and not selection.contains(item.local_port):
      continue
    if pid is not None and all(reference.pid != pid for reference in item.processes):
      continue
    display = to_display(item)
    if process is not None and process not in display.process.split(","):
      continue
    matches.append(display)
  displayed = sort_observations(matches)
  label = "all" if all_ports else selection.label() if selection is not None else "-"
  return render_result(label, displayed, protocol=protocol), displayed, 0 if displayed else 1


def observation_dict(item: DisplayObservation) -> dict[str, object]:
  return {
    "protocol": item.protocol,
    "state": item.state,
    "family": item.family,
    "local_address": item.local_address,
    "local_port": item.local_port,
    "pid": None if item.pid == UNAVAILABLE else item.pid,
    "uid": None if item.uid == UNAVAILABLE else item.uid,
    "user": None if item.user == UNAVAILABLE else item.user,
    "process": None if item.process == UNAVAILABLE else item.process,
    "executable": None if item.executable == UNAVAILABLE else item.executable,
    "file_descriptor_count": None if item.file_descriptors == UNAVAILABLE else item.file_descriptors,
    "cgroup": None if item.cgroup == UNAVAILABLE else item.cgroup,
    "socket_file_descriptor": None if item.socket_fds == UNAVAILABLE else item.socket_fds,
    "exposure": item.exposure,
  }


def main(argv: Sequence[str] | None = None) -> int:
  parser = build_argument_parser()
  arguments = parser.parse_args(argv)
  validate_output_arguments(parser, arguments)
  if arguments.process is not None:
    if not arguments.process or len(arguments.process) > 128 or sanitize_display(arguments.process) != arguments.process:
      parser.error("--process must be a printable process name of at most 128 characters")
  protocol = "udp" if arguments.udp else "tcp"
  families = ("ipv4",) if arguments.ipv4 else ("ipv6",) if arguments.ipv6 else ("ipv4", "ipv6")
  watch_count = arguments.watch or 1
  started = time.monotonic()
  try:
    output = ""
    displayed: list[DisplayObservation] = []
    exit_code = 1
    snapshots = []
    for index in range(watch_count):
      output, displayed, exit_code = inspect_selection(
        arguments.port,
        all_ports=arguments.all,
        protocol=protocol,
        families=families,
        pid=arguments.pid,
        process=arguments.process,
      )
      snapshots.append([observation_dict(item) for item in displayed])
      if index + 1 < watch_count:
        time.sleep(arguments.watch_interval)
  except PortLensError as error:
    print(f"portlens: {sanitize_display(error)}", file=sys.stderr)
    return 2
  except KeyboardInterrupt:
    print("portlens: interrupted", file=sys.stderr)
    return 130
  except Exception:
    print("portlens: internal execution failure", file=sys.stderr)
    return 2
  elapsed = time.monotonic() - started
  target = "all local ports" if arguments.all else f"local port {arguments.port.label()}"
  if displayed:
    status = "FOUND"
    shared = likely_shared_bind_count(displayed)
    finding = f"{len(displayed)} matching {protocol.upper()} socket{'s were' if len(displayed) != 1 else ' was'} observed"
    finding += f" with {shared} likely shared/reused bind group(s)." if shared else "."
    next_action = "review bind exposure and owning-process evidence"
  else:
    status = "NOT_FOUND"
    finding = f"no matching {protocol.upper()} socket was observed."
    next_action = "do not infer that the port is bindable from this observation alone"
  conclusion = make_conclusion(status, target, finding, next_action)
  brief = f"Target: {target}\nObserved sockets: {len(displayed)}"
  record = OutputRecord(
    tool="portlens",
    status=status,
    target=target,
    observations={
      "protocol": protocol,
      "families": list(families),
      "watch_count": watch_count,
      "likely_shared_bind_groups": likely_shared_bind_count(displayed),
      "snapshots": snapshots,
    },
    conclusion=conclusion,
    next_action=next_action + ".",
    warnings=("Process metadata may be unavailable without sufficient procfs permissions.",),
    elapsed_seconds=elapsed,
  )
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
    )
  except OutputError as error:
    print(f"portlens: {sanitize_display(error)}", file=sys.stderr)
    return 2
  return exit_code


if __name__ == "__main__":
  raise SystemExit(main())
