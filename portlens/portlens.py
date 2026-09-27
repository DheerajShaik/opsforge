#!/usr/bin/env python3
"""Inspect TCP listeners and UDP sockets for local ports."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
import ipaddress
import os
import pwd
import sys
import time
from typing import Callable, NamedTuple, Sequence

from opsforge_common import (
  OutputError,
  OutputRecord,
  add_output_arguments,
  emit_output,
  has_unsafe_characters,
  make_conclusion,
  sanitize_text,
  validate_output_arguments,
)
from opsforge_common.process import (
  ProcessOutputLimitError,
  ProcessSpawnError,
  ProcessTimeoutError,
  resolve_executable,
  run_bounded,
)
from opsforge_common.procfs import unified_cgroup_path


UNAVAILABLE = "-"
MAX_WATCH_COUNT = 100
MAX_WATCH_INTERVAL = 60.0
MAX_PROC_FIELD_BYTES = 4096
MAX_PROC_ENTRIES = 100_000
MAX_SS_STREAM_BYTES = 8 * 1024 * 1024
SS_TIMEOUT_SECONDS = 30.0
COMM_BYTES = 15
MAX_REPORTED_WARNINGS = 20
ENRICHMENT_NOTE = (
  "socket owners are matched by socket inode through /proc/PID/fd, never by ss process-name text; "
  "process metadata is live, non-atomic, and best-effort, and PID reuse can make it refer to another process"
)


class PortLensError(Exception):
  """A failure that prevents a reliable inspection."""


@dataclass(frozen=True)
class ProcessReference:
  pid: int
  fd: int | None = None


@dataclass(frozen=True)
class SocketObservation:
  protocol: str
  state: str
  family: str
  local_address: str
  local_port: int
  processes: tuple[ProcessReference, ...] = ()
  interface: str | None = None
  inode: int | None = None


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
  interface: str = UNAVAILABLE


class Inspection(NamedTuple):
  report: str
  observations: list[DisplayObservation]
  exit_code: int
  warnings: tuple[str, ...] = ()
  shared_groups: int = 0


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


def split_endpoint(endpoint: str, *, allow_wildcard_port: bool = False) -> tuple[str, str | None, int | None]:
  """Parse an ss endpoint such as [fe80::1]%eth0:546 into address, bound interface, and port."""
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
  interface = None
  if address.startswith("["):
    closing = address.find("]")
    suffix = address[closing + 1:]
    if closing < 0 or (suffix and not suffix.startswith("%")):
      raise PortLensError(f"cannot parse local endpoint {endpoint!r}")
    interface = suffix[1:] if suffix else None
    address = address[1:closing]
  elif address.endswith("]"):
    raise PortLensError(f"cannot parse local endpoint {endpoint!r}")
  elif "%" in address:
    address, _, interface = address.partition("%")
  if not address or interface == "":
    raise PortLensError(f"cannot parse local endpoint {endpoint!r}")
  if address != "*":
    try:
      ipaddress.ip_address(address)
    except ValueError as error:
      raise PortLensError(f"cannot parse local endpoint {endpoint!r}") from error
  return address, interface, port


def parse_endpoint(endpoint: str, *, allow_wildcard_port: bool = False) -> tuple[str, int | None]:
  """Parse an ss endpoint without splitting IPv6 address colons."""
  address, _, port = split_endpoint(endpoint, allow_wildcard_port=allow_wildcard_port)
  return address, port


def parse_ss_row(row: str, family: str, protocol: str = "tcp") -> SocketObservation:
  """Parse one headerless `ss -e` row; ownership is resolved later from the socket inode."""
  if family not in {"ipv4", "ipv6"}:
    raise PortLensError(f"unsupported address family {family!r}")
  if protocol not in {"tcp", "udp"}:
    raise PortLensError(f"unsupported protocol {protocol!r}")
  fields = row.split(None, 5)
  if len(fields) < 5:
    raise PortLensError("ss returned a malformed socket row")
  state, receive_queue, send_queue, local_endpoint, peer_endpoint = fields[:5]
  if protocol == "tcp" and state != "LISTEN":
    raise PortLensError(f"ss returned unexpected TCP state {state!r}")
  if not receive_queue.isdecimal() or not send_queue.isdecimal():
    raise PortLensError("ss returned malformed TCP queue values")
  split_endpoint(peer_endpoint, allow_wildcard_port=True)
  local_address, interface, local_port = split_endpoint(local_endpoint)
  inode = None
  # The kernel-reported inode precedes free-form fields such as cgroup paths.
  for token in (fields[5] if len(fields) == 6 else "").split():
    if token.startswith("ino:"):
      value = token[4:]
      inode = int(value, 10) if value.isascii() and value.isdecimal() else None
      break
  return SocketObservation(
    protocol=protocol,
    state=state,
    family=family,
    local_address=local_address,
    local_port=local_port,
    interface=interface,
    inode=inode,
  )


def parse_ss_output(
  output: str, family: str, protocol: str = "tcp", malformed: list[str] | None = None,
) -> list[SocketObservation]:
  """Parse ss rows; with MALFORMED, collect unparseable rows as warnings instead of failing."""
  observations = []
  for line in output.split("\n"):
    if not line.strip():
      continue
    try:
      observations.append(parse_ss_row(line, family, protocol))
    except PortLensError as error:
      if malformed is None:
        raise
      malformed.append(f"skipped an unparseable ss row: {error}")
  return observations


def find_ss() -> str:
  executable = resolve_executable("ss")
  if executable is None:
    raise PortLensError("required command 'ss' was not found in a trusted PATH directory")
  return executable


def run_ss_query(executable: str, arguments: Sequence[str]) -> str:
  try:
    result = run_bounded(
      [executable, *arguments], timeout=SS_TIMEOUT_SECONDS, max_output_bytes=MAX_SS_STREAM_BYTES,
    )
  except ProcessTimeoutError as error:
    raise PortLensError("'ss' timed out") from error
  except ProcessOutputLimitError as error:
    raise PortLensError("'ss' output exceeded the 8 MiB limit") from error
  except ProcessSpawnError as error:
    raise PortLensError(f"could not execute 'ss': {sanitize_text(error)}") from error
  if result.returncode != 0:
    detail = sanitize_text(result.stderr.decode("utf-8", "replace").strip())[:200]
    suffix = f": {detail}" if detail else ""
    raise PortLensError(f"'ss' exited with status {result.returncode}{suffix}")
  return result.stdout.decode("utf-8", "surrogateescape")


def port_filter(selection: PortSelection | None) -> tuple[str, ...]:
  """Build an ss kernel-side filter from already validated integer ports."""
  if selection is None:
    return ()
  if selection.start == selection.end:
    return ("sport", "=", f":{selection.start}")
  return ("(", "sport", ">=", f":{selection.start}", "and", "sport", "<=", f":{selection.end}", ")")


def discover_sockets(
  executable: str,
  runner: Callable[[str, Sequence[str]], str] = run_ss_query,
  *,
  protocol: str = "tcp",
  families: Sequence[str] = ("ipv4", "ipv6"),
  selection: PortSelection | None = None,
  warnings: list[str] | None = None,
) -> list[SocketObservation]:
  observations = []
  flag = "-lune" if protocol == "udp" else "-ltne"
  for family in families:
    family_flag = "-4" if family == "ipv4" else "-6"
    arguments = ("-H", family_flag, flag, *port_filter(selection))
    observations.extend(parse_ss_output(runner(executable, arguments), family, protocol, warnings))
  return observations


def find_socket_owners(
  inodes: set[int], proc_root: str = "/proc",
) -> tuple[dict[int, tuple[ProcessReference, ...]], dict[int, int | None]]:
  """Map socket inodes to (PID, FD) owners and count FDs by reading /proc/PID/fd links, as ss -p does."""
  if not inodes:
    return {}, {}
  targets = {f"socket:[{inode}]": inode for inode in inodes}
  owners: dict[int, list[ProcessReference]] = {}
  counts: dict[int, int | None] = {}
  try:
    processes = os.scandir(proc_root)
  except OSError:
    return {}, {}
  with processes:
    for process_entry in processes:
      if not process_entry.name.isascii() or not process_entry.name.isdecimal():
        continue
      pid = int(process_entry.name, 10)
      count: int | None = 0
      found = False
      try:
        with os.scandir(f"{proc_root}/{process_entry.name}/fd") as descriptors:
          for count, descriptor in enumerate(descriptors, 1):
            if count > MAX_PROC_ENTRIES:
              count = None
              break
            try:
              inode = targets.get(os.readlink(descriptor.path))
            except OSError:
              continue
            if inode is not None and descriptor.name.isdecimal():
              owners.setdefault(inode, []).append(ProcessReference(pid, int(descriptor.name, 10)))
              found = True
      except OSError:
        continue
      if found:
        counts[pid] = count
  return {inode: tuple(references) for inode, references in owners.items()}, counts


@dataclass(frozen=True)
class ProcessDetails:
  user: str
  process: str
  uid: str
  executable: str
  cgroup: str


def _user_name(uid: int, cache: dict[int, str]) -> str:
  if uid not in cache:
    try:
      cache[uid] = pwd.getpwuid(uid).pw_name
    except KeyError:
      cache[uid] = str(uid)
  return cache[uid]


def enrich_process(reference: ProcessReference, user_cache: dict[int, str] | None = None) -> tuple[str, str]:
  proc_path = f"/proc/{reference.pid}"
  process = _read_proc_text(f"{proc_path}/comm")
  try:
    uid = os.stat(proc_path).st_uid
  except OSError:
    return UNAVAILABLE, process
  return _user_name(uid, {} if user_cache is None else user_cache), process


def _read_proc_text(path: str) -> str:
  try:
    with open(path, "rb") as handle:
      data = handle.read(MAX_PROC_FIELD_BYTES + 1)
  except OSError:
    return UNAVAILABLE
  if len(data) > MAX_PROC_FIELD_BYTES:
    return UNAVAILABLE
  return data.decode("utf-8", "replace").strip() or UNAVAILABLE


def process_details(pid: int, user_cache: dict[int, str] | None = None) -> ProcessDetails:
  """Collect live, non-atomic metadata for one socket-owning PID."""
  proc_path = f"/proc/{pid}"
  try:
    uid_number = os.stat(proc_path).st_uid
  except OSError:
    uid = user = UNAVAILABLE
  else:
    uid = str(uid_number)
    user = _user_name(uid_number, {} if user_cache is None else user_cache)
  process = _read_proc_text(f"{proc_path}/comm")
  try:
    executable = os.path.basename(os.readlink(f"{proc_path}/exe")) or UNAVAILABLE
  except OSError:
    executable = UNAVAILABLE
  cgroup_text = _read_proc_text(f"{proc_path}/cgroup")
  cgroup = UNAVAILABLE if cgroup_text == UNAVAILABLE else (unified_cgroup_path(cgroup_text) or UNAVAILABLE)[:256]
  return ProcessDetails(user, process, uid, executable, cgroup)


def classify_bind(address: str, interface: str | None = None) -> str:
  if address == "*":
    scope = "wildcard (all local IPv4 and IPv6 interfaces in this namespace)"
  else:
    try:
      parsed = ipaddress.ip_address(address)
    except ValueError:
      parsed = None
    mapped = getattr(parsed, "ipv4_mapped", None)
    if mapped is not None:
      parsed = mapped
    if parsed is None:
      scope = "specific local address"
    elif parsed.is_unspecified:
      scope = "wildcard (all local interfaces in this namespace)"
    elif parsed.is_loopback:
      scope = "loopback only"
    elif parsed.is_link_local:
      scope = "link-local address"
    else:
      scope = "specific local address"
  return f"{scope}; bound to interface {interface}" if interface else scope


def to_display(
  observation: SocketObservation,
  details: Callable[[int], ProcessDetails] | None = None,
  fd_counts: dict[int, int | None] | None = None,
) -> DisplayObservation:
  exposure = classify_bind(observation.local_address, observation.interface)
  interface = observation.interface or UNAVAILABLE
  if not observation.processes:
    return DisplayObservation(
      observation.protocol, observation.state, observation.family,
      observation.local_address, observation.local_port,
      UNAVAILABLE, UNAVAILABLE, UNAVAILABLE,
      exposure=exposure, interface=interface,
    )
  lookup = details or process_details
  counts = fd_counts or {}
  owners = [(reference, lookup(reference.pid)) for reference in observation.processes]

  def joined(values: Sequence[str]) -> str:
    return ",".join(values)

  return DisplayObservation(
    observation.protocol,
    observation.state,
    observation.family,
    observation.local_address,
    observation.local_port,
    joined([str(reference.pid) for reference, _ in owners]),
    joined([info.user for _, info in owners]),
    joined([info.process for _, info in owners]),
    joined([info.uid for _, info in owners]),
    joined([info.executable for _, info in owners]),
    joined([UNAVAILABLE if counts.get(reference.pid) is None else str(counts[reference.pid]) for reference, _ in owners]),
    joined([info.cgroup for _, info in owners]),
    joined([str(reference.fd) if reference.fd is not None else UNAVAILABLE for reference, _ in owners]),
    exposure,
    interface,
  )


def _address_sort_key(address: str) -> tuple[int, int]:
  if address == "*":
    return (0, 0)
  try:
    parsed = ipaddress.ip_address(address)
  except ValueError:
    return (9, 0)
  return (parsed.version, int(parsed))


def sort_observations(observations: Sequence[DisplayObservation]) -> list[DisplayObservation]:
  family_order = {"ipv4": 0, "ipv6": 1}

  def key(item: DisplayObservation) -> tuple[object, ...]:
    pid_key = (1, 0) if item.pid == UNAVAILABLE else (0, int(item.pid.split(",", 1)[0]))
    return (family_order[item.family], _address_sort_key(item.local_address), item.local_port, pid_key, item.process)

  return sorted(observations, key=key)


def _display_address(item: DisplayObservation) -> str:
  return item.local_address if item.interface == UNAVAILABLE else f"{item.local_address}%{item.interface}"


def render_result(
  port: int | str,
  observations: Sequence[DisplayObservation],
  *,
  protocol: str = "tcp",
  shared: int | None = None,
  warnings: Sequence[str] = (),
) -> str:
  lines = [
    f"PortLens: local port {port}",
    f"Scope: {protocol.upper()} local sockets visible in the current network namespace",
    f"Process enrichment: {ENRICHMENT_NOTE}.",
    "",
  ]
  if not observations:
    lines.extend([
      f"No matching {protocol.upper()} socket was observed.",
      "This result does not prove that the port is available or bindable.",
    ])
  else:
    count = len(observations)
    noun = "socket" if count == 1 else "sockets"
    lines.extend([f"Found {count} matching {noun}.", ""])
    headings = ("PROTO", "STATE", "FAMILY", "LOCAL ADDRESS", "PORT", "PID", "USER", "PROCESS", "EXPOSURE")
    rows = [headings]
    for item in observations:
      rows.append(tuple(sanitize_text(value) for value in (
        item.protocol, item.state, item.family, _display_address(item), item.local_port,
        item.pid, item.user, item.process, item.exposure,
      )))
    widths = [max(len(row[index]) for row in rows) for index in range(len(headings))]
    for row in rows:
      lines.append("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)).rstrip())
    lines.extend((
      "",
      f"Likely shared/reused bind groups: {likely_shared_bind_count(observations) if shared is None else shared}",
      "Multiple rows on one protocol/family/address/port can reflect socket reuse or multiple owners; it does not by itself prove a conflict.",
    ))
  if warnings:
    lines.extend(("", "Warnings:"))
    lines.extend(f"  {sanitize_text(item)}" for item in warnings[:MAX_REPORTED_WARNINGS])
  return "\n".join(lines)


def likely_shared_bind_count(observations: Sequence[DisplayObservation]) -> int:
  counts: dict[tuple[str, str, str, str, int], int] = {}
  for item in observations:
    key = (item.protocol, item.family, item.local_address, item.interface, item.local_port)
    counts[key] = counts.get(key, 0) + 1
  return sum(count > 1 for count in counts.values())


def accepts_ipv4(address: str) -> bool:
  """Return whether an IPv6-family ss row can also accept IPv4 connections (dual-stack or mapped)."""
  if address == "*":
    return True
  try:
    parsed = ipaddress.ip_address(address)
  except ValueError:
    return False
  return getattr(parsed, "ipv4_mapped", None) is not None


def process_name_matches(requested: str, comm: str, executable: str) -> bool:
  """Match a name against /proc comm, which the kernel truncates to 15 bytes, or the executable name."""
  if requested in (comm, executable):
    return True
  encoded = requested.encode("utf-8", "surrogateescape")
  return len(encoded) > COMM_BYTES and comm == encoded[:COMM_BYTES].decode("utf-8", "replace")


def inspect_selection(
  selection: PortSelection | None,
  *,
  all_ports: bool,
  protocol: str,
  families: Sequence[str],
  pid: int | None,
  process: str | None,
) -> Inspection:
  executable = find_ss()
  warnings: list[str] = []
  ipv4_only = tuple(families) == ("ipv4",)
  # Dual-stack IPv6 wildcard sockets accept IPv4 but appear only in `ss -6` output.
  query_families = ("ipv4", "ipv6") if ipv4_only else tuple(families)
  scope = None if all_ports else selection
  observed = discover_sockets(executable, protocol=protocol, families=query_families, selection=scope, warnings=warnings)
  in_scope = [
    item for item in observed
    if (scope is None or scope.contains(item.local_port))
    and (not ipv4_only or item.family == "ipv4" or accepts_ipv4(item.local_address))
  ]
  owners, fd_counts = find_socket_owners({item.inode for item in in_scope if item.inode is not None})
  without_inode = sum(item.inode is None for item in in_scope)
  if without_inode:
    warnings.append(f"{without_inode} ss row(s) lacked a socket inode, so their owners are unavailable")
  user_cache: dict[int, str] = {}
  details_cache: dict[int, ProcessDetails] = {}

  def details(owner_pid: int) -> ProcessDetails:
    if owner_pid not in details_cache:
      details_cache[owner_pid] = process_details(owner_pid, user_cache)
    return details_cache[owner_pid]

  rows = []
  for item in in_scope:
    item = replace(item, processes=owners.get(item.inode, ()) if item.inode is not None else ())
    rows.append((item, to_display(item, details, fd_counts)))
  shared = likely_shared_bind_count([display for _, display in rows])
  matches = []
  for item, display in rows:
    if pid is not None and all(reference.pid != pid for reference in item.processes):
      continue
    if process is not None and not any(
      process_name_matches(process, details(reference.pid).process, details(reference.pid).executable)
      for reference in item.processes
    ):
      continue
    matches.append(display)
  displayed = sort_observations(matches)
  label = "all" if all_ports else selection.label() if selection is not None else "-"
  report = render_result(label, displayed, protocol=protocol, shared=shared, warnings=warnings)
  return Inspection(report, displayed, 0 if displayed else 1, tuple(warnings), shared)


def observation_dict(item: DisplayObservation) -> dict[str, object]:
  return {
    "protocol": item.protocol,
    "state": item.state,
    "family": item.family,
    "local_address": item.local_address,
    "interface": None if item.interface == UNAVAILABLE else item.interface,
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
    if not arguments.process or len(arguments.process) > 128 or has_unsafe_characters(arguments.process):
      parser.error("--process must be a printable process name of at most 128 characters")
  protocol = "udp" if arguments.udp else "tcp"
  families = ("ipv4",) if arguments.ipv4 else ("ipv6",) if arguments.ipv6 else ("ipv4", "ipv6")
  watch_count = arguments.watch or 1
  started = time.monotonic()
  inspections: list[Inspection] = []
  try:
    for index in range(watch_count):
      inspections.append(inspect_selection(
        arguments.port,
        all_ports=arguments.all,
        protocol=protocol,
        families=families,
        pid=arguments.pid,
        process=arguments.process,
      ))
      if index + 1 < watch_count:
        time.sleep(arguments.watch_interval)
  except PortLensError as error:
    print(f"portlens: {sanitize_text(error)}", file=sys.stderr)
    return 2
  except KeyboardInterrupt:
    print("portlens: interrupted", file=sys.stderr)
    return 130
  except Exception:
    print("portlens: internal execution failure", file=sys.stderr)
    return 2
  elapsed = time.monotonic() - started
  target = "all local ports" if arguments.all else f"local port {arguments.port.label()}"
  matched = [inspection for inspection in inspections if inspection.observations]
  latest = matched[-1] if matched else inspections[-1]
  displayed = latest.observations
  if watch_count == 1:
    output = latest.report
  else:
    output = "\n\n".join(
      f"Snapshot {number} of {watch_count}\n{inspection.report}"
      for number, inspection in enumerate(inspections, 1)
    )
  if displayed:
    status = "FOUND"
    shared = latest.shared_groups
    finding = f"{len(displayed)} matching {protocol.upper()} socket{'s were' if len(displayed) != 1 else ' was'} observed"
    if watch_count > 1:
      finding += f" in the latest matching snapshot ({len(matched)} of {watch_count} snapshots matched)"
    finding += f" with {shared} likely shared/reused bind group(s)." if shared else "."
    next_action = "review bind exposure and owning-process evidence"
  else:
    status = "NOT_FOUND"
    finding = f"no matching {protocol.upper()} socket was observed" + (f" in any of {watch_count} snapshots." if watch_count > 1 else ".")
    next_action = "do not infer that the port is bindable from this observation alone"
  conclusion = make_conclusion(status, target, finding, next_action)
  brief = f"Target: {target}\nObserved sockets: {len(displayed)}"
  if watch_count > 1:
    brief += f"\nSnapshots with matches: {len(matched)} of {watch_count}"
  warnings = ["Process metadata is live, non-atomic, and best-effort; PID reuse or procfs permissions can invalidate enrichment."]
  for inspection in inspections:
    warnings.extend(item for item in inspection.warnings if item not in warnings)
  record = OutputRecord(
    tool="portlens",
    status=status,
    target=target,
    observations={
      "process_enrichment": ENRICHMENT_NOTE,
      "protocol": protocol,
      "families": list(families),
      "watch_count": watch_count,
      "snapshots_with_matches": len(matched),
      "likely_shared_bind_groups": latest.shared_groups,
      "snapshots": [[observation_dict(item) for item in inspection.observations] for inspection in inspections],
    },
    conclusion=conclusion,
    next_action=next_action + ".",
    warnings=tuple(warnings[:MAX_REPORTED_WARNINGS + 1]),
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
    print(f"portlens: {sanitize_text(error)}", file=sys.stderr)
    return 2
  return 0 if matched else 1


if __name__ == "__main__":
  raise SystemExit(main())
