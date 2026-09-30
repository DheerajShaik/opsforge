#!/usr/bin/env python3
"""Diagnose name resolution and TCP connectivity for one explicit endpoint."""

from __future__ import annotations

import argparse
import contextlib
from dataclasses import asdict, dataclass, replace
import ipaddress
import os
import re
import socket
import ssl
import sys
import time
from typing import Callable, Sequence

from opsforge.common import (
  OutputError,
  OutputRecord,
  add_output_arguments,
  emit_output,
  make_conclusion,
  net,
  print_safe,
  sanitize_text as display_safe,
  validate_output_arguments,
)
from opsforge.common.fs import open_regular_file
from opsforge.common.procfs import DefaultRoute, parse_ipv4_default_routes, parse_ipv6_default_routes
from opsforge.common.status import EXIT_FAILURE, EXIT_FINDING, EXIT_INTERRUPTED, EXIT_OK, EXIT_USAGE, INCOMPLETE


CONNECT_TIMEOUT_SECONDS = 3.0
RESOLVE_TIMEOUT_SECONDS = 10.0
MAX_RETRIES = 3
MAX_CONTEXT_BYTES = 64 * 1024
# glibc's resolver ignores nameserver lines after the third (MAXNS).
MAX_NAMESERVERS = 3
RESOLV_CONF = "/etc/resolv.conf"
RESOLVED_STUB = "127.0.0.53"
TIMEOUT_TEXT = re.compile(r"(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)\Z", re.ASCII)


class ObservationError(Exception):
  """No trustworthy structured network diagnostic can be produced."""


@dataclass(frozen=True)
class Target:
  original_host: str
  host: str
  port: int
  kind: str

  @property
  def endpoint(self) -> str:
    return net.format_endpoint(self.host, self.port)


@dataclass(frozen=True)
class ConnectionAttempt(net.Attempt):
  local_endpoint: str | None = None
  peer_endpoint: str | None = None


@dataclass(frozen=True)
class DiagnosticResult:
  target: Target
  resolution_status: str
  resolution_detail: str | None
  candidates: tuple[net.Candidate, ...]
  attempts: tuple[ConnectionAttempt, ...]
  resolution_seconds: float = 0.0
  connect_timeout: float = CONNECT_TIMEOUT_SECONDS
  resolver_servers: tuple[str, ...] = ()
  default_route: str | None = None
  ipv6_default_route: str | None = None
  proxy_variables: tuple[str, ...] = ()
  retries: int = 0
  tls_status: str | None = None
  tls_version: str | None = None
  tls_cipher: str | None = None
  tls_seconds: float | None = None
  notes: tuple[str, ...] = ()

  @property
  def connected(self) -> bool:
    return any(attempt.connected for attempt in self.attempts)


def parse_port(value: str) -> int:
  if not value or not value.isascii() or not value.isdecimal():
    raise argparse.ArgumentTypeError("port must be an ASCII decimal integer from 1 through 65535")
  try:
    port = int(value, 10)
  except ValueError as error:
    raise argparse.ArgumentTypeError(
      "port must be an ASCII decimal integer from 1 through 65535"
    ) from error
  if not 1 <= port <= 65535:
    raise argparse.ArgumentTypeError("port must be from 1 through 65535")
  return port


def build_argument_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(
    prog="netdoctor",
    description=(
      "Diagnose OS name resolution and TCP connection establishment for one explicit endpoint."
    ),
  )
  parser.add_argument("host", help="ASCII hostname or unbracketed IPv4/IPv6 literal")
  parser.add_argument("port", type=parse_port, help="TCP port from 1 through 65535")
  parser.add_argument("--timeout", type=parse_timeout, default=CONNECT_TIMEOUT_SECONDS, metavar="SECONDS", help="per-attempt timeout from 0.1 through 30 seconds")
  parser.add_argument("--retries", type=parse_retries, default=0, metavar="N", help="additional bounded candidate rounds (0-3)")
  parser.add_argument("--compare-families", action="store_true", help="attempt all resolved IPv4 and IPv6 candidates")
  parser.add_argument("--tls", action="store_true", help="perform one targeted TLS handshake after TCP connectivity")
  parser.add_argument("--sni", metavar="HOST", help="explicit TLS SNI name (requires --tls)")
  add_output_arguments(parser)
  return parser


def parse_timeout(value: str) -> float:
  if TIMEOUT_TEXT.fullmatch(value) is None or not 0.1 <= float(value) <= 30.0:
    raise argparse.ArgumentTypeError("timeout must be an ASCII decimal number of seconds from 0.1 through 30")
  return float(value)


def parse_retries(value: str) -> int:
  if not value.isascii() or not value.isdecimal() or not 0 <= int(value, 10) <= MAX_RETRIES:
    raise argparse.ArgumentTypeError(f"retries must be from 0 through {MAX_RETRIES}")
  return int(value, 10)


def socket_endpoint(family: int, method: Callable[[], object]) -> str | None:
  try:
    return net.normalize_sockaddr(family, method())[1]
  except (OSError, net.NetworkAPIError):
    return None


def attempt_connections(
  candidates: Sequence[net.Candidate],
  *,
  socket_factory: Callable[[int, int, int], socket.socket] = socket.socket,
  timeout: float = CONNECT_TIMEOUT_SECONDS,
  stop_on_success: bool = True,
  monotonic_fn: Callable[[], float] = time.monotonic,
) -> tuple[ConnectionAttempt, ...]:
  """Try each candidate in order (all of them unless stop_on_success) and close every connection immediately."""
  attempts = []
  for candidate in candidates:
    client, (attempt,) = net.connect_first(
      (candidate,), timeout=timeout, socket_factory=socket_factory, clock=monotonic_fn,
    )
    local_endpoint = peer_endpoint = None
    if client is not None:
      try:
        local_endpoint = socket_endpoint(candidate.family, client.getsockname)
        peer_endpoint = socket_endpoint(candidate.family, client.getpeername) or candidate.endpoint
      finally:
        with contextlib.suppress(OSError):
          client.close()
    attempts.append(ConnectionAttempt(
      candidate, attempt.outcome, attempt.error_number, attempt.duration_seconds, local_endpoint, peer_endpoint,
    ))
    if client is not None and stop_on_success:
      break
  return tuple(attempts)


def diagnose(
  target: Target,
  *,
  resolver: Callable[..., object] = socket.getaddrinfo,
  socket_factory: Callable[[int, int, int], socket.socket] = socket.socket,
  timeout: float = CONNECT_TIMEOUT_SECONDS,
  retries: int = 0,
  compare_families: bool = False,
  monotonic_fn: Callable[[], float] = time.monotonic,
) -> DiagnosticResult:
  resolution_started = monotonic_fn()
  resolution = net.resolve_tcp(target.host, target.port, target.kind, resolver=resolver, timeout=RESOLVE_TIMEOUT_SECONDS)
  resolution_seconds = max(0.0, monotonic_fn() - resolution_started)
  if resolution.failure is not None:
    return DiagnosticResult(target, "failed", resolution.failure, (), (), resolution_seconds, timeout)
  notes = ()
  if resolution.truncated:
    notes = (
      f"the resolver returned more than {net.MAX_CANDIDATES} candidates; only the first {net.MAX_CANDIDATES} were considered",
    )
  attempts = []
  for retry in range(retries + 1):
    attempts.extend(attempt_connections(
      resolution.candidates, socket_factory=socket_factory, timeout=timeout,
      stop_on_success=not compare_families, monotonic_fn=monotonic_fn,
    ))
    if any(item.connected for item in attempts):
      break
  return DiagnosticResult(
    target, "resolved", None, resolution.candidates, tuple(attempts), resolution_seconds,
    timeout, retries=retry, notes=notes,
  )


def read_bounded_text(path: str) -> str | None:
  """Read a small root-managed context file; symlinks are followed (resolv.conf commonly is one)."""
  try:
    descriptor, _ = open_regular_file(path, follow_symlinks=True)
  except OSError:
    return None
  data = bytearray()
  try:
    # procfs returns about one page per read(), so read until end of file.
    while len(data) <= MAX_CONTEXT_BYTES:
      chunk = os.read(descriptor, MAX_CONTEXT_BYTES + 1 - len(data))
      if not chunk:
        break
      data.extend(chunk)
  except OSError:
    return None
  finally:
    os.close(descriptor)
  if len(data) > MAX_CONTEXT_BYTES:
    return None
  return data.decode("ascii", "replace")


def resolver_context(path: str = RESOLV_CONF) -> tuple[str, ...]:
  """Return the distinct nameservers among the first MAX_NAMESERVERS valid nameserver lines."""
  text = read_bounded_text(path)
  if text is None:
    return ()
  servers = []
  for line in text.splitlines():
    fields = line.split()
    if len(fields) < 2 or fields[0] != "nameserver":
      continue
    try:
      servers.append(str(ipaddress.ip_address(fields[1].split("%", 1)[0])))
    except ValueError:
      continue
    if len(servers) == MAX_NAMESERVERS:
      break
  return tuple(dict.fromkeys(servers))


def default_route_context(path: str, parse: Callable[[str], list[DefaultRoute]]) -> str | None:
  """Describe the lowest-metric usable default route in a procfs route table, or None."""
  text = read_bounded_text(path)
  routes = parse(text) if text is not None else []
  if not routes:
    return None
  route = routes[0]
  return f"{route.gateway} via {route.interface}" if route.gateway else f"direct via {route.interface} (no gateway)"


def proxy_context(environment: dict[str, str] | None = None) -> tuple[str, ...]:
  source = os.environ if environment is None else environment
  names = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy")
  return tuple(name for name in names if source.get(name))


def tls_handshake(
  candidate: net.Candidate,
  *,
  timeout: float,
  sni_name: str | None,
  socket_factory=socket.socket,
  context_factory=lambda: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT),
  monotonic_fn=time.monotonic,
) -> tuple[str, str | None, str | None, float]:
  """Reconnect to the connected candidate and time only the TLS handshake."""
  tcp, (attempt,) = net.connect_first(
    (candidate,), timeout=timeout, socket_factory=socket_factory, clock=monotonic_fn,
  )
  if tcp is None:
    if attempt.socket_unavailable:
      raise ObservationError(f"could not reconnect for the TLS stage: {attempt.outcome}")
    return f"failed: TCP reconnect for TLS failed ({attempt.outcome})", None, None, 0.0
  tls = None
  started = monotonic_fn()
  try:
    context = context_factory()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    tls = context.wrap_socket(tcp, server_hostname=sni_name)
    version = tls.version()
    cipher_value = tls.cipher()
    cipher = cipher_value[0] if cipher_value else None
    return "connected", version, cipher, max(0.0, monotonic_fn() - started)
  except OSError as error:
    return f"failed: {net.classify_connect_error(error)[0]}", None, None, max(0.0, monotonic_fn() - started)
  finally:
    with contextlib.suppress(OSError):
      (tls or tcp).close()


def render_result(result: DiagnosticResult) -> str:
  status = "connected" if result.connected else "not connected"
  if result.target.kind == "hostname":
    resolution_label = "Name resolution"
    resolution_scope = "OS resolver lookup was requested for the hostname."
  else:
    resolution_label = "Address expansion"
    resolution_scope = "The target was numeric; AI_NUMERICHOST requested no hostname lookup."

  servers = ", ".join(
    f"{server} (systemd-resolved stub)" if server == RESOLVED_STUB else server for server in result.resolver_servers
  )
  lines = [
    "NetDoctor: TCP connectivity diagnostic",
    "",
    "Target",
    f"  Requested host: {display_safe(result.target.original_host)}",
    f"  Parsed endpoint: {display_safe(result.target.endpoint)}",
    f"  Target kind: {result.target.kind}",
    "  Transport: TCP",
    "",
    "Observation",
    f"  Status: {status}",
    f"  {resolution_label}: {result.resolution_status}",
    f"  Resolver candidates: {len(result.candidates)}",
    f"  Connection attempts: {len(result.attempts)}",
    f"  Per-candidate connect timeout: {result.connect_timeout:.3f} s",
    f"  Resolution duration: {result.resolution_seconds:.6f} s",
    f"  Retry rounds used: {result.retries}",
    f"  Resolution scope: {resolution_scope}",
    f"  Resolver servers: {servers or '-'}",
    f"  IPv4 default-route context: {display_safe(result.default_route or 'unavailable')}",
    f"  IPv6 default-route context: {display_safe(result.ipv6_default_route or 'unavailable')}",
    "  Connection interface: unavailable (not established)",
    f"  Proxy variables present: {', '.join(result.proxy_variables) or 'none'}",
  ]
  if result.resolution_detail is not None:
    lines.append(f"  Resolution detail: {display_safe(result.resolution_detail)}")

  lines.extend(("", "Resolution candidates"))
  if not result.candidates:
    lines.append("  No TCP resolver candidate was available.")
  else:
    for index, candidate in enumerate(result.candidates, 1):
      lines.append(
        f"  {index}. {candidate.family_name} {display_safe(candidate.endpoint)}"
      )

  lines.extend(("", "Connection attempts"))
  if not result.attempts:
    lines.append("  No TCP connection attempt was made.")
  else:
    for index, attempt in enumerate(result.attempts, 1):
      lines.extend((
        f"  Attempt {index}",
        f"    Candidate: {attempt.candidate.family_name} {display_safe(attempt.candidate.endpoint)}",
        f"    Outcome: {attempt.outcome}",
        f"    Duration: {attempt.duration_seconds:.6f} s",
      ))
      if attempt.error_number is not None:
        lines.append(f"    OS error number: {attempt.error_number}")
      if attempt.connected:
        lines.append(
          f"    Local endpoint: {display_safe(attempt.local_endpoint or '-')}"
      )
        lines.append(
          f"    Peer endpoint: {display_safe(attempt.peer_endpoint or attempt.candidate.endpoint)}"
        )

  if result.tls_status is not None:
    lines.extend((
      "",
      "TLS stage",
      f"  Status: {display_safe(result.tls_status)}",
      f"  Version: {display_safe(result.tls_version or '-')}",
      f"  Cipher: {display_safe(result.tls_cipher or '-')}",
      f"  Duration: {result.tls_seconds:.6f} s" if result.tls_seconds is not None else "  Duration: -",
      "  Certificate trust, hostname identity, revocation, and application readiness were not assessed.",
    ))

  tls_completed = result.tls_status == "connected"
  lines.extend((
    "",
    "Interpretation limits",
    "  A successful result proves only that one TCP connection handshake completed to one resolved candidate during this invocation."
    if not tls_completed else
    "  A successful result proves only that TCP and an unverified TLS handshake completed to one resolved candidate during this invocation.",
    "  It does not establish certificate trust, HTTP, service, readiness, or end-to-end health."
    if tls_completed else
    "  It does not establish application, TLS, HTTP, service, readiness, or end-to-end health.",
    "  A failed connection does not by itself identify whether routing, firewall policy, listener state, remote policy, or another network condition caused the outcome.",
    "  Name-resolution and connection observations are live and non-atomic; network state may change immediately after the report.",
    "  NetDoctor sends no application data and closes a successful TCP connection immediately.",
  ))
  return "\n".join(lines)


def classify(result: DiagnosticResult, tls_requested: bool) -> tuple[str, str, str, str]:
  """Return (status, stage, finding, next action); attempts without a socket are gaps that never decide a verdict."""
  if result.connected and (not tls_requested or result.tls_status == "connected"):
    stage = "TLS" if tls_requested else "TCP"
    return (
      "CONNECTED", stage, f"{stage} connection succeeded after {len(result.attempts)} TCP attempt(s)",
      "no transport-layer issue was detected; application behavior was not tested",
    )
  tested = [attempt for attempt in result.attempts if not attempt.socket_unavailable]
  if result.resolution_status == "failed":
    stage = "resolution"
  elif not tested:
    return (
      INCOMPLETE, "TCP", "no candidate was tested because no socket could be created for any of them",
      "check local support for the candidates' address families and the open-file limit",
    )
  elif tls_requested and result.connected:
    stage = "TLS"
  elif all(attempt.outcome in {"network unreachable", "host unreachable"} for attempt in tested):
    stage = "route"
  else:
    stage = "TCP"
  return (
    "UNREACHABLE", stage, f"the targeted connection did not complete at the {stage} stage",
    f"review the {stage} evidence and target-specific network policy",
  )


def candidate_record(candidate: net.Candidate) -> dict[str, object]:
  return {**asdict(candidate), "family_name": candidate.family_name}


def main(argv: Sequence[str] | None = None) -> int:
  parser = build_argument_parser()
  arguments = parser.parse_args(argv)
  validate_output_arguments(parser, arguments)
  if arguments.sni is not None and not arguments.tls:
    parser.error("--sni requires --tls")
  started = time.monotonic()
  try:
    normalized_host, kind = net.parse_host(arguments.host)
    target = Target(arguments.host, normalized_host, arguments.port, kind)
    sni_name = net.sni_name(normalized_host, kind)
    if arguments.sni is not None:
      sni_name = net.parse_sni(arguments.sni, "--sni")
    result = diagnose(
      target,
      timeout=arguments.timeout,
      retries=arguments.retries,
      compare_families=arguments.compare_families,
    )
    connected_attempt = next((item for item in result.attempts if item.connected), None)
    tls_status = tls_version = tls_cipher = None
    tls_seconds = None
    if arguments.tls and connected_attempt is not None:
      tls_status, tls_version, tls_cipher, tls_seconds = tls_handshake(
        connected_attempt.candidate, timeout=arguments.timeout, sni_name=sni_name,
      )
    result = replace(
      result,
      resolver_servers=resolver_context(),
      default_route=default_route_context("/proc/net/route", parse_ipv4_default_routes),
      ipv6_default_route=default_route_context("/proc/net/ipv6_route", parse_ipv6_default_routes),
      proxy_variables=proxy_context(),
      tls_status=tls_status,
      tls_version=tls_version,
      tls_cipher=tls_cipher,
      tls_seconds=tls_seconds,
    )
    output = render_result(result)
  except net.HostError as error:
    print_safe(f"netdoctor: {display_safe(error)}", file=sys.stderr)
    return EXIT_USAGE
  except (ObservationError, net.NetworkAPIError) as error:
    print_safe(f"netdoctor: {display_safe(error)}", file=sys.stderr)
    return EXIT_FAILURE
  except KeyboardInterrupt:
    print_safe("netdoctor: interrupted", file=sys.stderr)
    return EXIT_INTERRUPTED
  except Exception:
    print_safe("netdoctor: internal execution failure", file=sys.stderr)
    return EXIT_FAILURE
  status, stage, finding, next_action = classify(result, arguments.tls)
  conclusion = make_conclusion(status, target.endpoint, finding, next_action)
  warnings = list(result.notes)
  unavailable = sum(attempt.socket_unavailable for attempt in result.attempts)
  if unavailable:
    warnings.append(
      f"{unavailable} of {len(result.attempts)} connection attempts could not create a socket; those candidates were not tested"
    )
  if not result.resolver_servers:
    warnings.append("no nameserver was read from /etc/resolv.conf; resolver context is unavailable")
  record = OutputRecord(
    tool="netdoctor",
    status=status,
    target=target.endpoint,
    observations={
      "stage": stage.lower(),
      "target_kind": target.kind,
      "resolution_status": result.resolution_status,
      "resolution_detail": result.resolution_detail,
      "resolution_seconds": result.resolution_seconds,
      "candidates": [candidate_record(candidate) for candidate in result.candidates],
      "attempts": [{**asdict(attempt), "candidate": candidate_record(attempt.candidate)} for attempt in result.attempts],
      "connect_timeout_seconds": result.connect_timeout,
      "retry_rounds_used": result.retries,
      "resolver_servers": result.resolver_servers,
      "ipv4_default_route_context": result.default_route,
      "ipv6_default_route_context": result.ipv6_default_route,
      "selected_interface": None,
      "proxy_variables_present": result.proxy_variables,
      "tls": {"status": result.tls_status, "version": result.tls_version, "cipher": result.tls_cipher, "seconds": result.tls_seconds},
    },
    conclusion=conclusion,
    next_action=next_action + ".",
    warnings=tuple(warnings),
    elapsed_seconds=time.monotonic() - started,
  )
  brief = "\n".join([
    f"Target: {display_safe(target.endpoint)}",
    f"Resolution: {result.resolution_status} ({result.resolution_seconds:.3f} s)",
    f"TCP attempts: {len(result.attempts)}",
    f"Stage: {stage}",
  ])
  try:
    emit_output(
      record, detailed=output, brief=brief, json_mode=arguments.json,
      brief_mode=arguments.brief, quiet=arguments.quiet,
      output_path=arguments.output, force=arguments.force, stdout=sys.stdout,
    )
  except (OutputError, OSError) as error:
    print_safe(f"netdoctor: {display_safe(error)}", file=sys.stderr)
    return EXIT_FAILURE
  except KeyboardInterrupt:
    print_safe("netdoctor: interrupted", file=sys.stderr)
    return EXIT_INTERRUPTED
  if status == "CONNECTED":
    return EXIT_OK
  return EXIT_FAILURE if status == INCOMPLETE else EXIT_FINDING


if __name__ == "__main__":
  raise SystemExit(main())
