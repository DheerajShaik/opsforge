#!/usr/bin/env python3
"""Diagnose name resolution and TCP connectivity for one explicit endpoint."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
import errno
import ipaddress
import os
import re
import socket
import ssl
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


CONNECT_TIMEOUT_SECONDS = 3.0
MAX_RESOLVER_CANDIDATES = 16
MAX_RETRIES = 3
MAX_CONTEXT_BYTES = 64 * 1024


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
    if self.kind == "ipv6":
      return f"[{self.host}]:{self.port}"
    return f"{self.host}:{self.port}"


@dataclass(frozen=True)
class ConnectionCandidate:
  family: int
  socket_type: int
  protocol: int
  sockaddr: tuple
  endpoint: str

  @property
  def family_name(self) -> str:
    return "ipv4" if self.family == socket.AF_INET else "ipv6"


@dataclass(frozen=True)
class ConnectionAttempt:
  candidate: ConnectionCandidate
  outcome: str
  error_number: int | None = None
  local_endpoint: str | None = None
  peer_endpoint: str | None = None
  duration_seconds: float = 0.0

  @property
  def connected(self) -> bool:
    return self.outcome == "connected"


@dataclass(frozen=True)
class DiagnosticResult:
  target: Target
  resolution_status: str
  resolution_detail: str | None
  candidates: tuple[ConnectionCandidate, ...]
  attempts: tuple[ConnectionAttempt, ...]
  resolution_seconds: float = 0.0
  connect_timeout: float = CONNECT_TIMEOUT_SECONDS
  resolver_servers: tuple[str, ...] = ()
  default_route: str | None = None
  selected_interface: str | None = None
  proxy_variables: tuple[str, ...] = ()
  retries: int = 0
  tls_status: str | None = None
  tls_version: str | None = None
  tls_cipher: str | None = None
  tls_seconds: float | None = None

  @property
  def connected(self) -> bool:
    return any(attempt.connected for attempt in self.attempts)


HOST_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z", re.ASCII)


def parse_host(value: str) -> tuple[str, str]:
  if not value:
    raise argparse.ArgumentTypeError("host must not be empty")
  if value.startswith("[") or value.endswith("]"):
    raise argparse.ArgumentTypeError(
      "IPv6 host must be supplied without brackets because PORT is a separate argument"
    )
  if "%" in value:
    raise argparse.ArgumentTypeError("scoped IPv6 zone identifiers are not supported in V1")
  if any(character.isspace() for character in value):
    raise argparse.ArgumentTypeError("host must not contain whitespace")
  if any(unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"} for character in value):
    raise argparse.ArgumentTypeError("host must not contain control or presentation characters")

  try:
    return str(ipaddress.IPv4Address(value)), "ipv4"
  except ipaddress.AddressValueError:
    pass
  try:
    return str(ipaddress.IPv6Address(value)), "ipv6"
  except ipaddress.AddressValueError:
    pass

  try:
    value.encode("ascii")
  except UnicodeEncodeError as error:
    raise argparse.ArgumentTypeError("hostname must contain ASCII characters only") from error
  if len(value) > 253:
    raise argparse.ArgumentTypeError("hostname exceeds the 253-character V1 limit")
  rooted = value.endswith(".")
  body = value[:-1] if rooted else value
  if not body:
    raise argparse.ArgumentTypeError("hostname must contain at least one label")
  labels = body.split(".")
  if any(HOST_LABEL.fullmatch(label) is None for label in labels):
    raise argparse.ArgumentTypeError("hostname contains an invalid label")
  return value, "hostname"


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
  try:
    result = float(value)
  except ValueError as error:
    raise argparse.ArgumentTypeError("timeout must be from 0.1 through 30 seconds") from error
  if not 0.1 <= result <= 30.0:
    raise argparse.ArgumentTypeError("timeout must be from 0.1 through 30 seconds")
  return result


def parse_retries(value: str) -> int:
  if not value.isascii() or not value.isdecimal() or not 0 <= int(value, 10) <= MAX_RETRIES:
    raise argparse.ArgumentTypeError(f"retries must be from 0 through {MAX_RETRIES}")
  return int(value, 10)


def display_safe(value: object) -> str:
  """Escape terminal controls, presentation controls, surrogates, and backslashes."""
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


def format_endpoint(address: str, port: int, scope_id: int = 0) -> str:
  try:
    parsed = ipaddress.ip_address(address)
  except ValueError as error:
    raise ObservationError("network API returned a non-IP socket address") from error
  if parsed.version == 6:
    suffix = f"%{scope_id}" if scope_id else ""
    return f"[{parsed}{suffix}]:{port}"
  return f"{parsed}:{port}"


def format_sockaddr(family: int, sockaddr: object) -> str:
  if not isinstance(sockaddr, tuple):
    raise ObservationError("network API returned an unsupported socket address")
  if family == socket.AF_INET:
    if len(sockaddr) < 2:
      raise ObservationError("network API returned an incomplete IPv4 socket address")
    address, port = sockaddr[:2]
    scope_id = 0
  elif family == socket.AF_INET6:
    if len(sockaddr) < 4:
      raise ObservationError("network API returned an incomplete IPv6 socket address")
    address, port, _flow_info, scope_id = sockaddr[:4]
  else:
    raise ObservationError("network API returned an unsupported address family")
  if not isinstance(address, str) or not isinstance(port, int) or isinstance(port, bool):
    raise ObservationError("network API returned malformed socket address fields")
  if not 1 <= port <= 65535:
    raise ObservationError("network API returned an invalid TCP port")
  if not isinstance(scope_id, int) or isinstance(scope_id, bool) or scope_id < 0:
    raise ObservationError("network API returned an invalid IPv6 scope identifier")
  return format_endpoint(address, port, scope_id)


def make_candidate(record: object, expected_port: int) -> ConnectionCandidate:
  if not isinstance(record, tuple) or len(record) != 5:
    raise ObservationError("resolver returned an unsupported candidate record")
  family, socket_type, protocol, _canonical_name, sockaddr = record
  if family not in {socket.AF_INET, socket.AF_INET6}:
    raise ObservationError("resolver returned an unsupported address family")
  if socket_type != socket.SOCK_STREAM:
    raise ObservationError("resolver returned a non-TCP candidate")
  if not isinstance(protocol, int) or isinstance(protocol, bool):
    raise ObservationError("resolver returned an invalid protocol value")
  endpoint = format_sockaddr(family, sockaddr)
  resolved_port = sockaddr[1]
  if resolved_port != expected_port:
    raise ObservationError("resolver returned a candidate for an unexpected port")
  return ConnectionCandidate(family, socket_type, protocol, sockaddr, endpoint)


def resolver_failure_detail(error: socket.gaierror) -> str:
  code = getattr(error, "errno", None)
  known = (
    (getattr(socket, "EAI_NONAME", None), "name or address was not known"),
    (getattr(socket, "EAI_AGAIN", None), "temporary resolver failure"),
    (getattr(socket, "EAI_FAIL", None), "non-recoverable resolver failure"),
    (getattr(socket, "EAI_FAMILY", None), "resolver did not support the requested address family"),
    (getattr(socket, "EAI_SERVICE", None), "resolver did not support the requested service"),
  )
  for expected, detail in known:
    if expected is not None and code == expected:
      return detail
  return f"resolver error {code}" if isinstance(code, int) else "resolver error"


def resolve_candidates(
  target: Target,
  *,
  resolver: Callable[..., object] = socket.getaddrinfo,
) -> tuple[tuple[ConnectionCandidate, ...], str | None]:
  flags = getattr(socket, "AI_NUMERICHOST", 0) if target.kind in {"ipv4", "ipv6"} else 0
  try:
    records = resolver(
      target.host,
      target.port,
      socket.AF_UNSPEC,
      socket.SOCK_STREAM,
      0,
      flags,
    )
  except socket.gaierror as error:
    return (), resolver_failure_detail(error)
  except OSError as error:
    raise ObservationError("OS resolver call failed unexpectedly") from error
  except (TypeError, ValueError) as error:
    raise ObservationError("OS resolver call failed unexpectedly") from error

  if not isinstance(records, (list, tuple)):
    raise ObservationError("resolver returned an unsupported result container")
  if not records:
    return (), "resolver returned no TCP candidates"

  candidates = []
  seen = set()
  for record in records:
    candidate = make_candidate(record, target.port)
    identity = (
      candidate.family,
      candidate.socket_type,
      candidate.protocol,
      candidate.sockaddr,
    )
    if identity in seen:
      continue
    seen.add(identity)
    candidates.append(candidate)
    if len(candidates) > MAX_RESOLVER_CANDIDATES:
      raise ObservationError(
        f"resolver returned more than the {MAX_RESOLVER_CANDIDATES}-candidate V1 limit"
      )
  return tuple(candidates), None


def classify_connect_error(error: OSError) -> tuple[str, int | None]:
  number = getattr(error, "errno", None)
  if isinstance(error, (socket.timeout, TimeoutError)) or number == errno.ETIMEDOUT:
    return "timed out", number
  if number == errno.ECONNREFUSED:
    return "connection refused", number
  if number == errno.EHOSTUNREACH:
    return "host unreachable", number
  if number == errno.ENETUNREACH:
    return "network unreachable", number
  if number in {errno.EACCES, errno.EPERM}:
    return "permission denied", number
  return "connection error", number if isinstance(number, int) else None


def attempt_connections(
  candidates: Sequence[ConnectionCandidate],
  *,
  socket_factory: Callable[[int, int, int], socket.socket] = socket.socket,
  timeout: float = CONNECT_TIMEOUT_SECONDS,
  stop_on_success: bool = True,
  monotonic_fn: Callable[[], float] = time.monotonic,
) -> tuple[ConnectionAttempt, ...]:
  attempts = []
  for candidate in candidates:
    try:
      client = socket_factory(candidate.family, candidate.socket_type, candidate.protocol)
    except OSError as error:
      raise ObservationError("could not create a TCP socket for a resolver candidate") from error
    try:
      try:
        client.settimeout(timeout)
      except (OSError, ValueError) as error:
        raise ObservationError("could not apply the TCP connection timeout") from error
      attempt_started = monotonic_fn()
      try:
        client.connect(candidate.sockaddr)
      except OSError as error:
        outcome, error_number = classify_connect_error(error)
        attempts.append(ConnectionAttempt(
          candidate, outcome, error_number, duration_seconds=max(0.0, monotonic_fn() - attempt_started),
        ))
        continue

      local_endpoint = None
      peer_endpoint = candidate.endpoint
      try:
        local_endpoint = format_sockaddr(candidate.family, client.getsockname())
      except (OSError, ObservationError):
        local_endpoint = None
      try:
        peer_endpoint = format_sockaddr(candidate.family, client.getpeername())
      except (OSError, ObservationError):
        peer_endpoint = candidate.endpoint
      attempts.append(
        ConnectionAttempt(
          candidate,
          "connected",
          local_endpoint=local_endpoint,
          peer_endpoint=peer_endpoint,
          duration_seconds=max(0.0, monotonic_fn() - attempt_started),
        )
      )
      if stop_on_success:
        break
    finally:
      try:
        client.close()
      except OSError:
        pass
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
  candidates, resolution_error = resolve_candidates(target, resolver=resolver)
  resolution_seconds = max(0.0, monotonic_fn() - resolution_started)
  if resolution_error is not None:
    return DiagnosticResult(target, "failed", resolution_error, (), (), resolution_seconds, timeout)
  attempts = []
  for retry in range(retries + 1):
    attempts.extend(attempt_connections(
      candidates, socket_factory=socket_factory, timeout=timeout,
      stop_on_success=not compare_families, monotonic_fn=monotonic_fn,
    ))
    if any(item.connected for item in attempts):
      break
  return DiagnosticResult(
    target, "resolved", None, candidates, tuple(attempts), resolution_seconds,
    timeout, retries=retry,
  )


def read_bounded_text(path: str) -> str | None:
  flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
  try:
    descriptor = os.open(path, flags)
  except OSError:
    return None
  try:
    data = os.read(descriptor, MAX_CONTEXT_BYTES + 1)
  except OSError:
    return None
  finally:
    os.close(descriptor)
  if len(data) > MAX_CONTEXT_BYTES:
    return None
  return data.decode("ascii", "replace")


def resolver_context() -> tuple[str, ...]:
  text = read_bounded_text("/etc/resolv.conf")
  if text is None:
    return ()
  servers = []
  for line in text.splitlines():
    fields = line.split()
    if len(fields) >= 2 and fields[0] == "nameserver":
      try:
        value = str(ipaddress.ip_address(fields[1].split("%", 1)[0]))
      except ValueError:
        continue
      if value not in servers:
        servers.append(value)
      if len(servers) >= 8:
        break
  return tuple(servers)


def default_route_context() -> tuple[str | None, str | None]:
  text = read_bounded_text("/proc/net/route")
  if text is None:
    return None, None
  for line in text.splitlines()[1:]:
    fields = line.split()
    if len(fields) < 4 or fields[1] != "00000000":
      continue
    try:
      flags = int(fields[3], 16)
      raw = bytes.fromhex(fields[2])
      gateway = str(ipaddress.IPv4Address(raw[::-1]))
    except (ValueError, IndexError):
      continue
    if flags & 0x1:
      return fields[0][:64], gateway
  return None, None


def proxy_context(environment: dict[str, str] | None = None) -> tuple[str, ...]:
  source = os.environ if environment is None else environment
  names = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy")
  return tuple(name for name in names if source.get(name))


def tls_handshake(
  target: Target,
  candidate: ConnectionCandidate,
  *,
  timeout: float,
  sni_name: str | None,
  socket_factory=socket.socket,
  context_factory=lambda: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT),
  monotonic_fn=time.monotonic,
) -> tuple[str, str | None, str | None, float]:
  started = monotonic_fn()
  tcp = socket_factory(candidate.family, candidate.socket_type, candidate.protocol)
  tls = None
  try:
    tcp.settimeout(timeout)
    tcp.connect(candidate.sockaddr)
    context = context_factory()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    tls = context.wrap_socket(tcp, server_hostname=sni_name)
    version = tls.version()
    cipher_value = tls.cipher()
    cipher = cipher_value[0] if cipher_value else None
    return "connected", version, cipher, max(0.0, monotonic_fn() - started)
  except (OSError, ssl.SSLError, TimeoutError) as error:
    return f"failed: {classify_connect_error(error)[0]}", None, None, max(0.0, monotonic_fn() - started)
  finally:
    if tls is not None:
      tls.close()
    else:
      tcp.close()


def render_result(result: DiagnosticResult) -> str:
  status = "connected" if result.connected else "not connected"
  if result.target.kind == "hostname":
    resolution_label = "Name resolution"
    resolution_scope = "OS resolver lookup was requested for the hostname."
  else:
    resolution_label = "Address expansion"
    resolution_scope = "The target was numeric; AI_NUMERICHOST requested no hostname lookup."

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
    f"  Candidates attempted: {len(result.attempts)}",
    f"  Per-candidate connect timeout: {result.connect_timeout:.3f} s",
    f"  Resolution duration: {result.resolution_seconds:.6f} s",
    f"  Retry rounds used: {result.retries}",
    f"  Resolution scope: {resolution_scope}",
    f"  Resolver servers: {', '.join(result.resolver_servers) or '-'}",
    f"  Default route: {display_safe(result.default_route or '-')}",
    f"  Selected interface: {display_safe(result.selected_interface or '-')}",
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

  lines.extend((
    "",
    "Interpretation limits",
    "  A successful result proves only that one TCP connection handshake completed to one resolved candidate during this invocation.",
    "  It does not establish application, TLS, HTTP, service, readiness, or end-to-end health.",
    "  A failed connection does not by itself identify whether routing, firewall policy, listener state, remote policy, or another network condition caused the outcome.",
    "  Name-resolution and connection observations are live and non-atomic; network state may change immediately after the report.",
    "  NetDoctor sends no application data and closes a successful TCP connection immediately.",
  ))
  return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
  parser = build_argument_parser()
  arguments = parser.parse_args(argv)
  validate_output_arguments(parser, arguments)
  if arguments.sni is not None and not arguments.tls:
    parser.error("--sni requires --tls")
  started = time.monotonic()
  try:
    normalized_host, kind = parse_host(arguments.host)
    target = Target(arguments.host, normalized_host, arguments.port, kind)
    sni_name = normalized_host.rstrip(".") if kind == "hostname" else None
    if arguments.sni is not None:
      sni_name, sni_kind = parse_host(arguments.sni)
      if sni_kind != "hostname":
        raise argparse.ArgumentTypeError("--sni must be an ASCII hostname")
    result = diagnose(
      target,
      timeout=arguments.timeout,
      retries=arguments.retries,
      compare_families=arguments.compare_families,
    )
    route_interface, gateway = default_route_context()
    connected_attempt = next((item for item in result.attempts if item.connected), None)
    selected_interface = None
    if connected_attempt and connected_attempt.local_endpoint:
      if connected_attempt.local_endpoint.startswith("127.") or connected_attempt.local_endpoint.startswith("[::1]"):
        selected_interface = "lo"
      else:
        selected_interface = route_interface
    tls_status = tls_version = tls_cipher = None
    tls_seconds = None
    if arguments.tls and connected_attempt is not None:
      tls_status, tls_version, tls_cipher, tls_seconds = tls_handshake(
        target, connected_attempt.candidate, timeout=arguments.timeout, sni_name=sni_name,
      )
    result = replace(
      result,
      resolver_servers=resolver_context(),
      default_route=(f"{gateway} via {route_interface}" if gateway and route_interface else None),
      selected_interface=selected_interface,
      proxy_variables=proxy_context(),
      tls_status=tls_status,
      tls_version=tls_version,
      tls_cipher=tls_cipher,
      tls_seconds=tls_seconds,
    )
    output = render_result(result)
  except argparse.ArgumentTypeError as error:
    print_safe(f"netdoctor: {display_safe(error)}", file=sys.stderr)
    return 2
  except ObservationError as error:
    print_safe(f"netdoctor: {display_safe(error)}", file=sys.stderr)
    return 3
  except KeyboardInterrupt:
    print_safe("netdoctor: interrupted", file=sys.stderr)
    return 130
  except Exception:
    print_safe("netdoctor: internal execution failure", file=sys.stderr)
    return 3
  if result.connected and (not arguments.tls or result.tls_status == "connected"):
    status = "CONNECTED"
    stage = "TLS" if arguments.tls else "TCP"
    finding = f"{stage} connection succeeded after {len(result.attempts)} TCP attempt(s)"
    next_action = "no transport-layer issue was detected; application behavior was not tested"
  else:
    status = "UNREACHABLE"
    if result.resolution_status == "failed":
      stage = "resolution"
    elif arguments.tls and result.connected:
      stage = "TLS"
    else:
      stage = "TCP"
    finding = f"the targeted connection did not complete at the {stage} stage"
    next_action = f"review the {stage} evidence and target-specific network policy"
  conclusion = make_conclusion(status, target.endpoint, finding, next_action)
  record = OutputRecord(
    tool="netdoctor",
    status=status,
    target=target.endpoint,
    observations={
      "stage": stage.lower(),
      "resolution_status": result.resolution_status,
      "resolution_detail": result.resolution_detail,
      "resolution_seconds": result.resolution_seconds,
      "candidates": result.candidates,
      "attempts": result.attempts,
      "resolver_servers": result.resolver_servers,
      "default_route": result.default_route,
      "selected_interface": result.selected_interface,
      "proxy_variables_present": result.proxy_variables,
      "tls": {"status": result.tls_status, "version": result.tls_version, "cipher": result.tls_cipher, "seconds": result.tls_seconds},
    },
    conclusion=conclusion,
    next_action=next_action + ".",
    warnings=(),
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
  except OutputError as error:
    print_safe(f"netdoctor: {display_safe(error)}", file=sys.stderr)
    return 3
  return 0 if status == "CONNECTED" else 1


if __name__ == "__main__":
  raise SystemExit(main())
