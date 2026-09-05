#!/usr/bin/env python3
"""Evaluate a bounded set of explicit host and service health criteria."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import errno
import ipaddress
import json
import math
import os
import re
import shutil
import socket
import stat
import sys
import unicodedata
from typing import Callable, Mapping, Sequence


CONFIG_MAX_BYTES = 64 * 1024
MAX_CHECKS = 32
MAX_RESOLVER_CANDIDATES = 16
DEFAULT_TCP_TIMEOUT_SECONDS = 1.0
MIN_TCP_TIMEOUT_SECONDS = 0.1
MAX_TCP_TIMEOUT_SECONDS = 5.0
CHECK_NAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,63})\Z", re.ASCII)
HOST_LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z", re.ASCII)


class ConfigError(Exception):
  """The requested configuration cannot be trusted or accepted."""


class ObservationError(Exception):
  """A configured check could not produce trustworthy evidence."""


@dataclass(frozen=True)
class DiskFreeCheck:
  name: str
  path: str
  minimum_free_percent: float
  type: str = "disk_free_percent"


@dataclass(frozen=True)
class TcpConnectCheck:
  name: str
  host: str
  host_kind: str
  port: int
  timeout_seconds: float
  type: str = "tcp_connect"


HealthCheck = DiskFreeCheck | TcpConnectCheck


@dataclass(frozen=True)
class HealthConfig:
  path: str
  checks: tuple[HealthCheck, ...]


@dataclass(frozen=True)
class CheckResult:
  name: str
  type: str
  status: str
  target: str
  evidence: str


@dataclass(frozen=True)
class TcpCandidate:
  family: int
  socket_type: int
  protocol: int
  sockaddr: tuple
  endpoint: str


@dataclass(frozen=True)
class TcpAttempt:
  outcome: str
  endpoint: str
  error_number: int | None = None


def display_safe(value: object) -> str:
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


def _metadata_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
  return (
    metadata.st_dev,
    metadata.st_ino,
    metadata.st_size,
    metadata.st_mtime_ns,
    metadata.st_ctime_ns,
  )


def read_config_bytes(path: str) -> bytes:
  flags = os.O_RDONLY
  for name in ("O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK"):
    flags |= getattr(os, name, 0)
  try:
    descriptor = os.open(path, flags)
  except (FileNotFoundError, NotADirectoryError) as error:
    raise ConfigError("configuration file was not found") from error
  except PermissionError as error:
    raise ConfigError("configuration file is not readable with current permissions") from error
  except OSError as error:
    if error.errno == errno.ELOOP:
      raise ConfigError("configuration file must not be a final-component symlink") from error
    raise ConfigError("configuration file could not be opened") from error

  try:
    try:
      before = os.fstat(descriptor)
    except OSError as error:
      raise ConfigError("configuration file metadata could not be inspected") from error
    if not stat.S_ISREG(before.st_mode):
      raise ConfigError("configuration target must be a regular file")
    if before.st_size < 0 or before.st_size > CONFIG_MAX_BYTES:
      raise ConfigError(f"configuration file exceeds the {CONFIG_MAX_BYTES}-byte V1 limit")

    remaining = before.st_size
    chunks = []
    while remaining:
      try:
        chunk = os.read(descriptor, min(remaining, 8192))
      except OSError as error:
        raise ConfigError("configuration file could not be read") from error
      if not chunk:
        raise ConfigError("configuration file changed during observation")
      chunks.append(chunk)
      remaining -= len(chunk)

    try:
      extra = os.read(descriptor, 1)
    except OSError as error:
      raise ConfigError("configuration file could not be verified") from error
    if extra:
      raise ConfigError("configuration file changed during observation")

    try:
      after = os.fstat(descriptor)
    except OSError as error:
      raise ConfigError("configuration file metadata could not be rechecked") from error
    if _metadata_identity(before) != _metadata_identity(after):
      raise ConfigError("configuration file changed during observation")
    return b"".join(chunks)
  finally:
    try:
      os.close(descriptor)
    except OSError:
      pass


def _expect_mapping(value: object, context: str) -> Mapping[str, object]:
  if not isinstance(value, dict):
    raise ConfigError(f"{context} must be a JSON object")
  if any(not isinstance(key, str) for key in value):
    raise ConfigError(f"{context} contains a non-string key")
  return value


def _reject_unknown_keys(mapping: Mapping[str, object], allowed: set[str], context: str) -> None:
  unknown = sorted(set(mapping) - allowed)
  if unknown:
    raise ConfigError(f"{context} contains unsupported field: {display_safe(unknown[0])}")


def _require_string(mapping: Mapping[str, object], key: str, context: str) -> str:
  value = mapping.get(key)
  if not isinstance(value, str):
    raise ConfigError(f"{context}.{key} must be a string")
  return value


def _parse_check_name(value: str, context: str) -> str:
  if CHECK_NAME_RE.fullmatch(value) is None:
    raise ConfigError(
      f"{context}.name must be 1-64 ASCII letters, digits, '.', '_' or '-', starting with a letter or digit"
    )
  return value


def _parse_percent(value: object, context: str) -> float:
  if isinstance(value, bool) or not isinstance(value, (int, float)):
    raise ConfigError(f"{context} must be a JSON number from 0 through 100")
  number = float(value)
  if not math.isfinite(number) or not 0.0 <= number <= 100.0:
    raise ConfigError(f"{context} must be a finite number from 0 through 100")
  return number


def _parse_timeout(value: object, context: str) -> float:
  if isinstance(value, bool) or not isinstance(value, (int, float)):
    raise ConfigError(
      f"{context} must be a JSON number from {MIN_TCP_TIMEOUT_SECONDS} through {MAX_TCP_TIMEOUT_SECONDS}"
    )
  number = float(value)
  if not math.isfinite(number) or not MIN_TCP_TIMEOUT_SECONDS <= number <= MAX_TCP_TIMEOUT_SECONDS:
    raise ConfigError(
      f"{context} must be a finite number from {MIN_TCP_TIMEOUT_SECONDS} through {MAX_TCP_TIMEOUT_SECONDS}"
    )
  return number


def _parse_port(value: object, context: str) -> int:
  if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
    raise ConfigError(f"{context} must be a JSON integer from 1 through 65535")
  return value


def parse_host(value: str, context: str) -> tuple[str, str]:
  if not value:
    raise ConfigError(f"{context} must not be empty")
  if value.startswith("[") or value.endswith("]"):
    raise ConfigError(f"{context} must use an unbracketed IPv6 literal")
  if "%" in value:
    raise ConfigError(f"{context} does not support scoped IPv6 zone identifiers in V1")
  if any(character.isspace() for character in value):
    raise ConfigError(f"{context} must not contain whitespace")
  if any(unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"} for character in value):
    raise ConfigError(f"{context} must not contain control or presentation characters")

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
    raise ConfigError(f"{context} hostname must contain ASCII characters only") from error
  if len(value) > 253:
    raise ConfigError(f"{context} hostname exceeds the 253-character V1 limit")
  rooted = value.endswith(".")
  body = value[:-1] if rooted else value
  if not body:
    raise ConfigError(f"{context} hostname must contain at least one label")
  if any(HOST_LABEL_RE.fullmatch(label) is None for label in body.split(".")):
    raise ConfigError(f"{context} hostname contains an invalid label")
  return value, "hostname"


def parse_config_document(document: object, *, path: str) -> HealthConfig:
  root = _expect_mapping(document, "configuration")
  _reject_unknown_keys(root, {"version", "checks"}, "configuration")
  if root.get("version") != 1 or isinstance(root.get("version"), bool):
    raise ConfigError("configuration.version must be the JSON integer 1")
  checks_value = root.get("checks")
  if not isinstance(checks_value, list):
    raise ConfigError("configuration.checks must be a JSON array")
  if not checks_value:
    raise ConfigError("configuration.checks must contain at least one check")
  if len(checks_value) > MAX_CHECKS:
    raise ConfigError(f"configuration.checks exceeds the {MAX_CHECKS}-check V1 limit")

  checks = []
  names = set()
  for index, raw_check in enumerate(checks_value, 1):
    context = f"configuration.checks[{index}]"
    check = _expect_mapping(raw_check, context)
    name = _parse_check_name(_require_string(check, "name", context), context)
    if name in names:
      raise ConfigError(f"configuration contains duplicate check name: {name}")
    names.add(name)
    check_type = _require_string(check, "type", context)

    if check_type == "disk_free_percent":
      _reject_unknown_keys(check, {"name", "type", "path", "minimum_free_percent"}, context)
      check_path = _require_string(check, "path", context)
      if not check_path:
        raise ConfigError(f"{context}.path must not be empty")
      if "\x00" in check_path:
        raise ConfigError(f"{context}.path must not contain NUL")
      minimum = _parse_percent(check.get("minimum_free_percent"), f"{context}.minimum_free_percent")
      checks.append(DiskFreeCheck(name, check_path, minimum))
    elif check_type == "tcp_connect":
      _reject_unknown_keys(check, {"name", "type", "host", "port", "timeout_seconds"}, context)
      host, host_kind = parse_host(_require_string(check, "host", context), f"{context}.host")
      port = _parse_port(check.get("port"), f"{context}.port")
      timeout = _parse_timeout(
        check.get("timeout_seconds", DEFAULT_TCP_TIMEOUT_SECONDS),
        f"{context}.timeout_seconds",
      )
      checks.append(TcpConnectCheck(name, host, host_kind, port, timeout))
    else:
      raise ConfigError(f"{context}.type is unsupported in V1: {display_safe(check_type)}")

  return HealthConfig(os.path.abspath(path), tuple(checks))


def _strict_json_object(pairs: Sequence[tuple[str, object]]) -> dict[str, object]:
  result = {}
  for key, value in pairs:
    if key in result:
      raise ConfigError(f"configuration JSON contains duplicate object field: {display_safe(key)}")
    result[key] = value
  return result


def load_config(path: str) -> HealthConfig:
  raw = read_config_bytes(path)
  try:
    text = raw.decode("utf-8", errors="strict")
  except UnicodeDecodeError as error:
    raise ConfigError("configuration file must be valid UTF-8 JSON") from error
  try:
    document = json.loads(text, object_pairs_hook=_strict_json_object)
  except json.JSONDecodeError as error:
    raise ConfigError(
      f"configuration file is not valid JSON at line {error.lineno}, column {error.colno}"
    ) from error
  return parse_config_document(document, path=path)


def _normalize_sockaddr(
  family: int,
  sockaddr: object,
  expected_port: int,
) -> tuple[tuple, str]:
  if not isinstance(sockaddr, tuple):
    raise ObservationError("resolver returned an unsupported socket address")
  if family == socket.AF_INET:
    if len(sockaddr) != 2:
      raise ObservationError("resolver returned an unsupported IPv4 socket address shape")
    address, port = sockaddr
    flow_info = 0
    scope_id = 0
    expected_version = 4
  elif family == socket.AF_INET6:
    if len(sockaddr) != 4:
      raise ObservationError("resolver returned an unsupported IPv6 socket address shape")
    address, port, flow_info, scope_id = sockaddr
    expected_version = 6
  else:
    raise ObservationError("resolver returned an unsupported address family")
  if not isinstance(address, str) or not isinstance(port, int) or isinstance(port, bool):
    raise ObservationError("resolver returned malformed socket address fields")
  if port != expected_port:
    raise ObservationError("resolver returned a candidate for an unexpected port")
  if family == socket.AF_INET6:
    if not isinstance(flow_info, int) or isinstance(flow_info, bool) or flow_info < 0:
      raise ObservationError("resolver returned an invalid IPv6 flow identifier")
    if not isinstance(scope_id, int) or isinstance(scope_id, bool) or scope_id < 0:
      raise ObservationError("resolver returned an invalid IPv6 scope identifier")
  try:
    parsed = ipaddress.ip_address(address)
  except ValueError as error:
    raise ObservationError("resolver returned a non-IP socket address") from error
  if parsed.version != expected_version:
    raise ObservationError("resolver address did not match its declared address family")

  canonical_address = str(parsed)
  if family == socket.AF_INET6:
    normalized = (canonical_address, port, flow_info, scope_id)
    suffix = f"%{scope_id}" if scope_id else ""
    endpoint = f"[{canonical_address}{suffix}]:{port}"
  else:
    normalized = (canonical_address, port)
    endpoint = f"{canonical_address}:{port}"
  return normalized, endpoint


def _make_candidate(record: object, expected_port: int) -> TcpCandidate:
  if not isinstance(record, tuple) or len(record) != 5:
    raise ObservationError("resolver returned an unsupported candidate record")
  family, socket_type, protocol, _canonical_name, sockaddr = record
  if family not in {socket.AF_INET, socket.AF_INET6}:
    raise ObservationError("resolver returned an unsupported address family")
  if socket_type != socket.SOCK_STREAM:
    raise ObservationError("resolver returned a non-TCP candidate")
  if not isinstance(protocol, int) or isinstance(protocol, bool):
    raise ObservationError("resolver returned an invalid protocol value")
  normalized_sockaddr, endpoint = _normalize_sockaddr(family, sockaddr, expected_port)
  return TcpCandidate(family, socket_type, protocol, normalized_sockaddr, endpoint)


def resolve_tcp_candidates(
  check: TcpConnectCheck,
  *,
  resolver: Callable[..., object] = socket.getaddrinfo,
) -> tuple[TcpCandidate, ...] | None:
  flags = getattr(socket, "AI_NUMERICHOST", 0) if check.host_kind in {"ipv4", "ipv6"} else 0
  try:
    records = resolver(check.host, check.port, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, flags)
  except socket.gaierror:
    return None
  except (OSError, TypeError, ValueError) as error:
    raise ObservationError("OS resolver call failed unexpectedly") from error
  if not isinstance(records, (list, tuple)):
    raise ObservationError("resolver returned an unsupported result container")
  if not records:
    return None

  candidates = []
  seen = set()
  for record in records:
    candidate = _make_candidate(record, check.port)
    identity = (candidate.family, candidate.socket_type, candidate.protocol, candidate.sockaddr)
    if identity in seen:
      continue
    seen.add(identity)
    candidates.append(candidate)
    if len(candidates) > MAX_RESOLVER_CANDIDATES:
      raise ObservationError(
        f"resolver returned more than the {MAX_RESOLVER_CANDIDATES}-candidate V1 limit"
      )
  return tuple(candidates)


def _classify_connect_error(error: OSError) -> tuple[str, int | None]:
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


def attempt_tcp_candidates(
  check: TcpConnectCheck,
  candidates: Sequence[TcpCandidate],
  *,
  socket_factory: Callable[[int, int, int], socket.socket] = socket.socket,
) -> tuple[bool, tuple[TcpAttempt, ...]]:
  attempts = []
  for candidate in candidates:
    try:
      client = socket_factory(candidate.family, candidate.socket_type, candidate.protocol)
    except OSError as error:
      raise ObservationError("could not create a TCP socket") from error
    try:
      try:
        client.settimeout(check.timeout_seconds)
      except (OSError, ValueError) as error:
        raise ObservationError("could not apply the TCP connection timeout") from error
      try:
        client.connect(candidate.sockaddr)
      except OSError as error:
        outcome, number = _classify_connect_error(error)
        attempts.append(TcpAttempt(outcome, candidate.endpoint, number))
        continue
      attempts.append(TcpAttempt("connected", candidate.endpoint))
      return True, tuple(attempts)
    finally:
      try:
        client.close()
      except OSError:
        pass
  return False, tuple(attempts)


def run_disk_check(
  check: DiskFreeCheck,
  *,
  disk_usage: Callable[[str], object] = shutil.disk_usage,
) -> CheckResult:
  target = os.path.abspath(check.path)
  try:
    usage = disk_usage(check.path)
  except (OSError, ValueError):
    return CheckResult(check.name, check.type, "ERROR", target, "filesystem capacity could not be observed")
  try:
    total = int(usage.total)
    free = int(usage.free)
  except (AttributeError, TypeError, ValueError, OverflowError) as error:
    raise ObservationError("filesystem capacity API returned unsupported values") from error
  if total <= 0 or free < 0 or free > total:
    raise ObservationError("filesystem capacity API returned invalid values")
  percent = (free * 100.0) / total
  status = "PASS" if percent >= check.minimum_free_percent else "FAIL"
  evidence = (
    f"free {percent:.2f}% ({free} of {total} bytes); "
    f"required >= {check.minimum_free_percent:.2f}%"
  )
  return CheckResult(check.name, check.type, status, target, evidence)


def run_tcp_check(
  check: TcpConnectCheck,
  *,
  resolver: Callable[..., object] = socket.getaddrinfo,
  socket_factory: Callable[[int, int, int], socket.socket] = socket.socket,
) -> CheckResult:
  target = f"[{check.host}]:{check.port}" if check.host_kind == "ipv6" else f"{check.host}:{check.port}"
  candidates = resolve_tcp_candidates(check, resolver=resolver)
  if candidates is None:
    return CheckResult(check.name, check.type, "FAIL", target, "OS resolution produced no usable TCP candidate")
  connected, attempts = attempt_tcp_candidates(check, candidates, socket_factory=socket_factory)
  if connected:
    endpoint = attempts[-1].endpoint
    return CheckResult(
      check.name,
      check.type,
      "PASS",
      target,
      f"TCP handshake completed to {endpoint} after {len(attempts)} attempt(s)",
    )
  if not attempts:
    raise ObservationError("no TCP candidate was attempted")
  last = attempts[-1]
  detail = last.outcome
  if last.error_number is not None and last.outcome == "connection error":
    detail += f" (errno {last.error_number})"
  return CheckResult(
    check.name,
    check.type,
    "FAIL",
    target,
    f"no TCP handshake completed across {len(attempts)} candidate(s); last outcome: {detail}",
  )


def run_check(check: HealthCheck) -> CheckResult:
  if isinstance(check, DiskFreeCheck):
    return run_disk_check(check)
  if isinstance(check, TcpConnectCheck):
    return run_tcp_check(check)
  raise ObservationError("configuration produced an unsupported check type")


def evaluate_config(
  config: HealthConfig,
  *,
  executor: Callable[[HealthCheck], CheckResult] = run_check,
) -> tuple[CheckResult, ...]:
  results = []
  for check in config.checks:
    try:
      result = executor(check)
    except ObservationError as error:
      result = CheckResult(check.name, check.type, "ERROR", _check_target(check), str(error))
    except OSError:
      result = CheckResult(check.name, check.type, "ERROR", _check_target(check), "operating-system observation failed")
    if result.name != check.name or result.type != check.type or result.status not in {"PASS", "FAIL", "ERROR"}:
      raise ObservationError("check executor returned an invalid result")
    results.append(result)
  return tuple(results)


def _check_target(check: HealthCheck) -> str:
  if isinstance(check, DiskFreeCheck):
    return os.path.abspath(check.path)
  if isinstance(check, TcpConnectCheck):
    return f"[{check.host}]:{check.port}" if check.host_kind == "ipv6" else f"{check.host}:{check.port}"
  return "unknown"


def render_report(config: HealthConfig, results: Sequence[CheckResult]) -> str:
  passes = sum(result.status == "PASS" for result in results)
  failures = sum(result.status == "FAIL" for result in results)
  errors = sum(result.status == "ERROR" for result in results)
  lines = [
    "HealthCtl: configured health criteria",
    "",
    "Configuration",
    f"  File: {display_safe(config.path)}",
    f"  Checks: {len(results)}",
    "",
    "Results",
  ]
  for index, result in enumerate(results, 1):
    lines.extend((
      f"  {index}. [{result.status}] {display_safe(result.name)}",
      f"     Type: {result.type}",
      f"     Target: {display_safe(result.target)}",
      f"     Evidence: {display_safe(result.evidence)}",
    ))
  lines.extend((
    "",
    "Summary",
    f"  PASS: {passes}",
    f"  FAIL: {failures}",
    f"  ERROR: {errors}",
    "",
    "Interpretation limits",
    "  PASS means only that the caller-configured criterion was satisfied during this invocation.",
    "  FAIL means the configured criterion was observed and was not satisfied.",
    "  ERROR means that criterion could not be evaluated trustworthily.",
    "  These results do not prove overall host, application, or service health or identify root cause.",
  ))
  return "\n".join(lines)


def result_exit_code(results: Sequence[CheckResult]) -> int:
  if any(result.status == "ERROR" for result in results):
    return 3
  if any(result.status == "FAIL" for result in results):
    return 1
  return 0


def build_argument_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(
    prog="healthctl",
    description="Evaluate bounded host and TCP service criteria from one explicit JSON configuration file.",
  )
  parser.add_argument("config", help="path to a HealthCtl V1 JSON configuration file")
  return parser


def main(argv: Sequence[str] | None = None) -> int:
  parser = build_argument_parser()
  args = parser.parse_args(argv)
  try:
    config = load_config(args.config)
    results = evaluate_config(config)
    report = render_report(config, results)
  except ConfigError as error:
    print_safe(f"healthctl: configuration error: {display_safe(error)}", file=sys.stderr)
    return 2
  except KeyboardInterrupt:
    print_safe("healthctl: interrupted", file=sys.stderr)
    return 130
  except ObservationError as error:
    print_safe(f"healthctl: observation error: {display_safe(error)}", file=sys.stderr)
    return 3
  except Exception:
    print_safe("healthctl: internal error: unexpected failure", file=sys.stderr)
    return 3
  print_safe(report, file=sys.stdout)
  return result_exit_code(results)


if __name__ == "__main__":
  try:
    raise SystemExit(main())
  except KeyboardInterrupt:
    print_safe("healthctl: interrupted", file=sys.stderr)
    raise SystemExit(130)
