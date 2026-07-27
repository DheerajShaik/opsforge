#!/usr/bin/env python3
"""Inspect TCP listening sockets for one local port."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
import pwd
import re
import shutil
import subprocess
import sys
import unicodedata
from typing import Callable, Sequence


UNAVAILABLE = "-"
SS_COMMANDS = (("ipv4", ("-H", "-4", "-ltnp")), ("ipv6", ("-H", "-6", "-ltnp")))
PROCESS_REFERENCE = re.compile(r'\("((?:\\.|[^"\\])*)",pid=(\d+)')


class PortLensError(Exception):
  """A failure that prevents a reliable inspection."""


@dataclass(frozen=True)
class ProcessReference:
  pid: int
  ss_name: str


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


def parse_port(value: str) -> int:
  """Parse a strict decimal TCP port."""
  if not value or not value.isascii() or not value.isdecimal():
    raise argparse.ArgumentTypeError("port must be a decimal integer from 1 through 65535")
  port = int(value, 10)
  if not 1 <= port <= 65535:
    raise argparse.ArgumentTypeError("port must be from 1 through 65535")
  return port


def build_argument_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(
    prog="portlens",
    description=(
      "Inspect TCP LISTEN sockets matching a local port in the current network "
      "namespace. A no-match result does not prove that the port is bindable."
    ),
  )
  parser.add_argument("port", type=parse_port, help="decimal local TCP port (1-65535)")
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
  for name, pid_text in PROCESS_REFERENCE.findall(metadata):
    references.append(ProcessReference(pid=int(pid_text, 10), ss_name=_unescape_ss_name(name)))
  return tuple(references)


def parse_ss_row(row: str, family: str) -> SocketObservation:
  """Parse one headerless ss TCP listening row conservatively."""
  if family not in {"ipv4", "ipv6"}:
    raise PortLensError(f"unsupported address family {family!r}")
  fields = row.split(None, 5)
  if len(fields) < 5:
    raise PortLensError("ss returned a malformed socket row")
  state, receive_queue, send_queue, local_endpoint, peer_endpoint = fields[:5]
  if state != "LISTEN":
    raise PortLensError(f"ss returned unexpected TCP state {state!r}")
  if not receive_queue.isdecimal() or not send_queue.isdecimal():
    raise PortLensError("ss returned malformed TCP queue values")
  parse_endpoint(peer_endpoint, allow_wildcard_port=True)
  local_address, local_port = parse_endpoint(local_endpoint)
  if local_port is None:
    raise PortLensError("ss returned a local endpoint without a numeric port")
  metadata = fields[5] if len(fields) == 6 else ""
  return SocketObservation(
    protocol="tcp",
    state=state,
    family=family,
    local_address=local_address,
    local_port=local_port,
    processes=parse_process_references(metadata),
  )


def parse_ss_output(output: str, family: str) -> list[SocketObservation]:
  observations = []
  for line in output.splitlines():
    if not line.strip():
      continue
    observations.append(parse_ss_row(line, family))
  return observations


def find_ss() -> str:
  executable = shutil.which("ss")
  if executable is None:
    raise PortLensError("required command 'ss' was not found")
  return executable


def run_ss_query(executable: str, arguments: Sequence[str]) -> str:
  try:
    result = subprocess.run(
      [executable, *arguments],
      check=False,
      capture_output=True,
      text=True,
      timeout=30,
    )
  except (OSError, subprocess.SubprocessError) as error:
    raise PortLensError(f"could not execute 'ss': {error}") from error
  if result.returncode != 0:
    detail = sanitize_display(result.stderr.strip())[:200]
    suffix = f": {detail}" if detail else ""
    raise PortLensError(f"'ss' exited with status {result.returncode}{suffix}")
  return result.stdout


def discover_sockets(
  executable: str,
  runner: Callable[[str, Sequence[str]], str] = run_ss_query,
) -> list[SocketObservation]:
  observations = []
  for family, arguments in SS_COMMANDS:
    observations.extend(parse_ss_output(runner(executable, arguments), family))
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

  try:
    with open(f"{proc_path}/comm", encoding="utf-8", errors="replace") as handle:
      process = handle.read().rstrip("\n")
  except OSError:
    process = reference.ss_name or UNAVAILABLE
  if not process:
    process = reference.ss_name or UNAVAILABLE
  return user, process


def to_display(observation: SocketObservation) -> DisplayObservation:
  if not observation.processes:
    return DisplayObservation(
      observation.protocol, observation.state, observation.family,
      observation.local_address, observation.local_port,
      UNAVAILABLE, UNAVAILABLE, UNAVAILABLE,
    )
  users = []
  names = []
  for reference in observation.processes:
    user, name = enrich_process(reference)
    users.append(user)
    names.append(name)
  return DisplayObservation(
    observation.protocol,
    observation.state,
    observation.family,
    observation.local_address,
    observation.local_port,
    ",".join(str(reference.pid) for reference in observation.processes),
    ",".join(users),
    ",".join(names),
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


def render_result(port: int, observations: Sequence[DisplayObservation]) -> str:
  lines = [
    f"PortLens: local port {port}",
    "Scope: TCP LISTEN sockets visible in the current network namespace",
    "",
  ]
  if not observations:
    lines.extend([
      "No matching TCP listening socket was observed.",
      "This result does not prove that the port is available or bindable.",
    ])
    return "\n".join(lines)

  count = len(observations)
  noun = "socket" if count == 1 else "sockets"
  lines.extend([f"Found {count} matching {noun}.", ""])
  headings = ("PROTO", "STATE", "FAMILY", "LOCAL ADDRESS", "PORT", "PID", "USER", "PROCESS")
  rows = [headings]
  for item in observations:
    rows.append(tuple(sanitize_display(value) for value in (
      item.protocol, item.state, item.family, item.local_address, item.local_port,
      item.pid, item.user, item.process,
    )))
  widths = [max(len(row[index]) for row in rows) for index in range(len(headings))]
  for row in rows:
    lines.append("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)).rstrip())
  return "\n".join(lines)


def inspect(port: int) -> tuple[str, int]:
  executable = find_ss()
  observations = discover_sockets(executable)
  matches = [observation for observation in observations if observation.local_port == port]
  displayed = sort_observations([to_display(observation) for observation in matches])
  return render_result(port, displayed), 0 if displayed else 1


def main(argv: Sequence[str] | None = None) -> int:
  parser = build_argument_parser()
  arguments = parser.parse_args(argv)
  try:
    output, exit_code = inspect(arguments.port)
  except PortLensError as error:
    print(f"portlens: {sanitize_display(error)}", file=sys.stderr)
    return 2
  except Exception:
    print("portlens: internal execution failure", file=sys.stderr)
    return 2
  print(output)
  return exit_code


if __name__ == "__main__":
  raise SystemExit(main())
