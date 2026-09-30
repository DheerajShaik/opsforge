"""Host parsing, bounded TCP resolution, and first-reachable connection shared by OpsForge utilities."""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
import errno
import ipaddress
import queue
import re
import socket
import ssl
import threading
import time
from typing import Callable, Sequence

from .text import has_unsafe_characters


MAX_CANDIDATES = 16
CONNECTED = "connected"
SOCKET_UNAVAILABLE = "socket unavailable"
HOST_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z", re.ASCII)
# glibc's inet_aton() reads a name ending in such a label as a lenient IPv4 literal (127.1 is 127.0.0.1, 010.0.0.1 is 8.0.0.1).
NUMERIC_LABEL = re.compile(r"(?:[0-9]+|0[Xx][0-9A-Fa-f]*)\Z", re.ASCII)
NEGATIVE_RESOLVER_ANSWERS = {
  socket.EAI_NONAME: "name or address was not known",
  socket.EAI_NODATA: "name has no address records",
}


class HostError(ValueError):
  """A host name, address literal, or SNI name is not acceptable."""


class NetworkAPIError(Exception):
  """The OS resolver or socket API failed or returned data that gives no trustworthy answer."""


@dataclass(frozen=True)
class Candidate:
  family: int
  socket_type: int
  protocol: int
  sockaddr: tuple
  endpoint: str

  @property
  def family_name(self) -> str:
    return "ipv4" if self.family == socket.AF_INET else "ipv6"


@dataclass(frozen=True)
class Resolution:
  candidates: tuple[Candidate, ...] = ()
  failure: str | None = None
  truncated: bool = False


@dataclass(frozen=True)
class Attempt:
  candidate: Candidate
  outcome: str
  error_number: int | None = None
  duration_seconds: float = 0.0

  @property
  def connected(self) -> bool:
    return self.outcome == CONNECTED

  @property
  def socket_unavailable(self) -> bool:
    return self.outcome.startswith(SOCKET_UNAVAILABLE)


def parse_host(value: str, label: str = "host") -> tuple[str, str]:
  """Return (host, kind): a canonical unbracketed IPv4/IPv6 literal, or a strict ASCII DNS name as given."""
  if not value:
    raise HostError(f"{label} must not be empty")
  if value.startswith("[") or value.endswith("]"):
    raise HostError(f"{label} must use an unbracketed IPv6 literal")
  if "%" in value:
    raise HostError(f"{label} does not support scoped IPv6 zone identifiers")
  if any(character.isspace() for character in value):
    raise HostError(f"{label} must not contain whitespace")
  if has_unsafe_characters(value):
    raise HostError(f"{label} must not contain control or presentation characters")
  for kind, parse in (("ipv4", ipaddress.IPv4Address), ("ipv6", ipaddress.IPv6Address)):
    try:
      return str(parse(value)), kind
    except ipaddress.AddressValueError:
      pass
  if not value.isascii():
    # The stdlib IDNA codec is IDNA 2003, which maps some IDNA 2008 names to other domains (faß.de to fass.de).
    raise HostError(f"{label} must contain ASCII characters only; give internationalized names in their xn-- form")
  if len(value) > 253:
    raise HostError(f"{label} exceeds the 253-character hostname limit")
  body = value[:-1] if value.endswith(".") else value
  if not body:
    raise HostError(f"{label} must contain at least one hostname label")
  labels = body.split(".")
  if any(HOST_LABEL.fullmatch(part) is None for part in labels):
    raise HostError(f"{label} contains an invalid hostname label")
  if NUMERIC_LABEL.fullmatch(labels[-1]):
    raise HostError(f"{label} ends in a numeric label; give an IPv4 address as a canonical dotted quad")
  return value, "hostname"


def sni_name(host: str, kind: str) -> str | None:
  """Return the SNI a client sends for a parsed host: the name without its root dot (RFC 6066), or None for an IP."""
  return host.rstrip(".") if kind == "hostname" else None


def parse_sni(value: str, label: str = "SNI name") -> str:
  """Validate an explicit SNI name and return it without a root dot."""
  host, kind = parse_host(value, label)
  if kind != "hostname":
    raise HostError(f"{label} must be a hostname; TLS clients do not send IP literals as SNI")
  return host.rstrip(".")


def format_endpoint(host: str, port: int, scope_id: int = 0) -> str:
  """Return HOST:PORT, bracketing an IPv6 literal and showing a nonzero IPv6 scope as %N."""
  if ":" not in host:
    return f"{host}:{port}"
  return f"[{host}%{scope_id}]:{port}" if scope_id else f"[{host}]:{port}"


def _is_int(value: object) -> bool:
  return isinstance(value, int) and not isinstance(value, bool)


def normalize_sockaddr(family: int, sockaddr: object) -> tuple[tuple, str]:
  """Validate an AF_INET/AF_INET6 socket address from the OS; return (canonical sockaddr, endpoint text)."""
  if family == socket.AF_INET:
    size, version = 2, 4
  elif family == socket.AF_INET6:
    size, version = 4, 6
  else:
    raise NetworkAPIError("network API returned an unsupported address family")
  if not isinstance(sockaddr, tuple) or len(sockaddr) != size:
    raise NetworkAPIError(f"network API returned an unsupported IPv{version} socket address shape")
  address, port, *extra = sockaddr
  if not isinstance(address, str) or not all(_is_int(item) and item >= 0 for item in (port, *extra)):
    raise NetworkAPIError("network API returned malformed socket address fields")
  if not 1 <= port <= 65535:
    raise NetworkAPIError("network API returned an invalid TCP port")
  try:
    parsed = ipaddress.ip_address(address)
  except ValueError as error:
    raise NetworkAPIError("network API returned a non-IP socket address") from error
  if parsed.version != version:
    raise NetworkAPIError("network API returned an address that did not match its declared address family")
  canonical = str(parsed)
  return (canonical, port, *extra), format_endpoint(canonical, port, extra[1] if extra else 0)


def _make_candidate(record: object, port: int) -> Candidate:
  if not isinstance(record, tuple) or len(record) != 5:
    raise NetworkAPIError("resolver returned an unsupported candidate record")
  family, socket_type, protocol, _canonical_name, sockaddr = record
  if socket_type != socket.SOCK_STREAM:
    raise NetworkAPIError("resolver returned a non-TCP candidate")
  if not _is_int(protocol):
    raise NetworkAPIError("resolver returned an invalid protocol value")
  normalized, endpoint = normalize_sockaddr(family, sockaddr)
  if normalized[1] != port:
    raise NetworkAPIError("resolver returned a candidate for an unexpected port")
  return Candidate(family, socket_type, protocol, normalized, endpoint)


def _call_bounded(function: Callable[[], object], timeout: float) -> object:
  """Run FUNCTION on a daemon thread and give up waiting after TIMEOUT seconds (the lookup itself cannot be cancelled)."""
  outcome: queue.Queue[tuple[bool, object]] = queue.Queue(maxsize=1)

  def work() -> None:
    try:
      outcome.put((True, function()))
    except BaseException as error:
      outcome.put((False, error))

  threading.Thread(target=work, name="opsforge-resolver", daemon=True).start()
  try:
    succeeded, value = outcome.get(timeout=timeout)
  except queue.Empty:
    raise NetworkAPIError(f"OS resolver did not answer within {timeout:g} s") from None
  if not succeeded:
    raise value  # type: ignore[misc]
  return value


def resolve_tcp(
  host: str,
  port: int,
  kind: str,
  *,
  resolver: Callable[..., object] = socket.getaddrinfo,
  timeout: float | None = None,
) -> Resolution:
  """Resolve HOST for TCP (no DNS query for an IP-literal KIND), keeping the first MAX_CANDIDATES distinct results.

  A negative answer is returned as `failure`; other resolver failures, timeouts, and malformed results raise NetworkAPIError.
  """
  flags = socket.AI_NUMERICHOST if kind in {"ipv4", "ipv6"} else 0
  try:
    if timeout is None:
      records = resolver(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, flags)
    else:
      records = _call_bounded(lambda: resolver(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, flags), timeout)
  except socket.gaierror as error:
    if error.errno in NEGATIVE_RESOLVER_ANSWERS:
      return Resolution(failure=NEGATIVE_RESOLVER_ANSWERS[error.errno])
    raise NetworkAPIError(f"OS resolver failed ({error.strerror or 'unknown error'})") from error
  except (OSError, TypeError, ValueError) as error:
    raise NetworkAPIError("OS resolver call failed unexpectedly") from error
  if not isinstance(records, (list, tuple)) or not records:
    raise NetworkAPIError("resolver returned an unsupported or empty result")
  candidates: list[Candidate] = []
  seen = set()
  for record in records:
    candidate = _make_candidate(record, port)
    key = (candidate.family, candidate.socket_type, candidate.protocol, candidate.sockaddr)
    if key in seen:
      continue
    if len(candidates) == MAX_CANDIDATES:
      return Resolution(tuple(candidates), truncated=True)
    seen.add(key)
    candidates.append(candidate)
  return Resolution(tuple(candidates))


def classify_connect_error(error: OSError) -> tuple[str, int | None]:
  """Return (outcome, OS errno) for a connect or TLS error."""
  if isinstance(error, ssl.SSLError):
    # SSL errors carry SSL_ERROR_* codes in errno (SSL_ERROR_SSL == 1 == EPERM), not OS errno values.
    return f"TLS protocol error ({getattr(error, 'reason', None) or type(error).__name__})", None
  number = error.errno
  if isinstance(error, TimeoutError) or number == errno.ETIMEDOUT:
    return "timed out", number
  if number == errno.ECONNREFUSED:
    return "connection refused", number
  if number == errno.ECONNRESET:
    return "connection reset", number
  if number == errno.EHOSTUNREACH:
    return "host unreachable", number
  if number == errno.ENETUNREACH:
    return "network unreachable", number
  if number in {errno.EACCES, errno.EPERM}:
    return "permission denied", number
  return "connection error", number if _is_int(number) else None


def connect_first(
  candidates: Sequence[Candidate],
  *,
  timeout: float | None = None,
  deadline: float | None = None,
  socket_factory: Callable[[int, int, int], socket.socket] = socket.socket,
  clock: Callable[[], float] = time.monotonic,
) -> tuple[socket.socket | None, tuple[Attempt, ...]]:
  """Return the first reachable candidate's open socket (or None) and one Attempt per candidate tried.

  Each connect gets `timeout` seconds, cut short by the absolute `deadline` on `clock`; a socket that cannot be
  created or connected is recorded and the next candidate is tried. Raises TimeoutError when the deadline passes
  before a remaining candidate is tried, and NetworkAPIError when a socket timeout cannot be applied.
  """
  if timeout is None and deadline is None:
    raise ValueError("a per-candidate timeout or an overall deadline is required")
  attempts: list[Attempt] = []
  now = clock()
  for candidate in candidates:
    limit = timeout
    if deadline is not None:
      remaining = deadline - now
      if remaining <= 0:
        raise TimeoutError("the connection deadline passed before every candidate was tried")
      limit = remaining if limit is None else min(limit, remaining)
    try:
      client = socket_factory(candidate.family, candidate.socket_type, candidate.protocol)
    except OSError as error:
      name = errno.errorcode.get(error.errno, "unknown error")
      attempts.append(Attempt(candidate, f"{SOCKET_UNAVAILABLE} ({name})", error.errno))
      continue
    try:
      try:
        client.settimeout(limit)
      except OSError as error:
        raise NetworkAPIError("could not apply the connection timeout") from error
      try:
        client.connect(candidate.sockaddr)
        failure = None
      except OSError as error:
        failure = error
      finished = clock()
    except BaseException:
      with contextlib.suppress(OSError):
        client.close()
      raise
    duration, now = finished - now, finished
    if failure is None:
      attempts.append(Attempt(candidate, CONNECTED, None, duration))
      return client, tuple(attempts)
    with contextlib.suppress(OSError):
      client.close()
    outcome, number = classify_connect_error(failure)
    attempts.append(Attempt(candidate, outcome, number, duration))
  return None, tuple(attempts)
