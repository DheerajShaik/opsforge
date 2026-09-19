#!/usr/bin/env python3
"""Evaluate a bounded set of explicit host and service health criteria."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import errno
import ipaddress
import json
import hashlib
import math
import os
import re
import signal
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Mapping, Sequence

from opsforge_common import (
  OutputError,
  OutputRecord,
  add_output_arguments,
  emit_output,
  make_conclusion,
  validate_output_arguments,
)


CONFIG_MAX_BYTES = 64 * 1024
MAX_CHECKS = 32
MAX_RESOLVER_CANDIDATES = 16
DEFAULT_TCP_TIMEOUT_SECONDS = 1.0
MIN_TCP_TIMEOUT_SECONDS = 0.1
MAX_TCP_TIMEOUT_SECONDS = 5.0
MAX_RETRIES = 3
MAX_WORKERS = 8
MAX_HTTP_REDIRECTS = 3
MAX_HTTP_HEADER_BYTES = 64 * 1024
MAX_HASH_BYTES = 64 * 1024 * 1024
CHECK_NAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,63})\Z", re.ASCII)
HOST_LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z", re.ASCII)


class ConfigError(Exception):
  """The requested configuration cannot be trusted or accepted."""


class ObservationError(Exception):
  """A configured check could not produce trustworthy evidence."""


class RedirectPolicyError(urllib.error.URLError):
  """An HTTP redirect exceeded the configured target boundary."""


@dataclass(frozen=True)
class DiskFreeCheck:
  name: str
  path: str
  minimum_free_percent: float
  type: str = "disk_free_percent"
  severity: str = "CRITICAL"
  group: str = "default"
  profile: str = "default"
  depends_on: tuple[str, ...] = ()
  retries: int = 0


@dataclass(frozen=True)
class TcpConnectCheck:
  name: str
  host: str
  host_kind: str
  port: int
  timeout_seconds: float
  type: str = "tcp_connect"
  severity: str = "CRITICAL"
  group: str = "default"
  profile: str = "default"
  depends_on: tuple[str, ...] = ()
  retries: int = 0


@dataclass(frozen=True)
class GenericCheck:
  name: str
  type: str
  target: str
  timeout_seconds: float = DEFAULT_TCP_TIMEOUT_SECONDS
  severity: str = "CRITICAL"
  group: str = "default"
  profile: str = "default"
  depends_on: tuple[str, ...] = ()
  retries: int = 0
  options: tuple[tuple[str, object], ...] = ()


HealthCheck = DiskFreeCheck | TcpConnectCheck | GenericCheck


@dataclass(frozen=True)
class HealthConfig:
  path: str
  checks: tuple[HealthCheck, ...]
  max_workers: int = 4


@dataclass(frozen=True)
class CheckResult:
  name: str
  type: str
  status: str
  target: str
  evidence: str
  severity: str = "OK"
  elapsed_seconds: float = 0.0
  attempts: int = 1


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


def _parse_nonnegative_int(value: object, context: str, maximum: int) -> int:
  if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
    raise ConfigError(f"{context} must be a JSON integer from 0 through {maximum}")
  return value


COMMON_CHECK_FIELDS = {"severity", "group", "profile", "depends_on", "retries"}


def _common_check_fields(check: Mapping[str, object], context: str) -> dict[str, object]:
  severity = check.get("severity", "CRITICAL")
  if not isinstance(severity, str) or severity not in {"WARN", "CRITICAL"}:
    raise ConfigError(f"{context}.severity must be WARN or CRITICAL")
  group_value = check.get("group", "default")
  profile_value = check.get("profile", "default")
  if not isinstance(group_value, str) or not isinstance(profile_value, str):
    raise ConfigError(f"{context}.group and profile must be strings")
  group = _parse_check_name(group_value, f"{context}.group")
  profile = _parse_check_name(profile_value, f"{context}.profile")
  raw_dependencies = check.get("depends_on", [])
  if not isinstance(raw_dependencies, list) or len(raw_dependencies) > MAX_CHECKS:
    raise ConfigError(f"{context}.depends_on must be a bounded JSON array")
  dependencies = tuple(_parse_check_name(value, f"{context}.depends_on") for value in raw_dependencies if isinstance(value, str))
  if len(dependencies) != len(raw_dependencies) or len(set(dependencies)) != len(dependencies):
    raise ConfigError(f"{context}.depends_on must contain unique check names")
  retries = _parse_nonnegative_int(check.get("retries", 0), f"{context}.retries", MAX_RETRIES)
  return {"severity": severity, "group": group, "profile": profile, "depends_on": dependencies, "retries": retries}


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
  _reject_unknown_keys(root, {"version", "checks", "max_workers"}, "configuration")
  if root.get("version") != 1 or isinstance(root.get("version"), bool):
    raise ConfigError("configuration.version must be the JSON integer 1")
  checks_value = root.get("checks")
  if not isinstance(checks_value, list):
    raise ConfigError("configuration.checks must be a JSON array")
  if not checks_value:
    raise ConfigError("configuration.checks must contain at least one check")
  if len(checks_value) > MAX_CHECKS:
    raise ConfigError(f"configuration.checks exceeds the {MAX_CHECKS}-check V1 limit")

  max_workers = _parse_nonnegative_int(root.get("max_workers", 4), "configuration.max_workers", MAX_WORKERS)
  if max_workers < 1:
    raise ConfigError("configuration.max_workers must be at least 1")
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
    common = _common_check_fields(check, context)

    if check_type == "disk_free_percent":
      _reject_unknown_keys(check, {"name", "type", "path", "minimum_free_percent"} | COMMON_CHECK_FIELDS, context)
      check_path = _require_string(check, "path", context)
      if not check_path:
        raise ConfigError(f"{context}.path must not be empty")
      if "\x00" in check_path:
        raise ConfigError(f"{context}.path must not contain NUL")
      minimum = _parse_percent(check.get("minimum_free_percent"), f"{context}.minimum_free_percent")
      checks.append(DiskFreeCheck(name, check_path, minimum, **common))
    elif check_type == "tcp_connect":
      _reject_unknown_keys(check, {"name", "type", "host", "port", "timeout_seconds"} | COMMON_CHECK_FIELDS, context)
      host, host_kind = parse_host(_require_string(check, "host", context), f"{context}.host")
      port = _parse_port(check.get("port"), f"{context}.port")
      timeout = _parse_timeout(
        check.get("timeout_seconds", DEFAULT_TCP_TIMEOUT_SECONDS),
        f"{context}.timeout_seconds",
      )
      checks.append(TcpConnectCheck(name, host, host_kind, port, timeout, **common))
    elif check_type in {"http", "https"}:
      _reject_unknown_keys(check, {"name", "type", "url", "timeout_seconds", "expected_status"} | COMMON_CHECK_FIELDS, context)
      url = _require_string(check, "url", context)
      if len(url) > 2048 or not url.isascii() or display_safe(url) != url:
        raise ConfigError(f"{context}.url must be printable ASCII of at most 2048 characters")
      try:
        parsed = urllib.parse.urlsplit(url)
        parsed.port
      except ValueError as error:
        raise ConfigError(f"{context}.url is malformed") from error
      if (
        parsed.scheme != check_type or not parsed.hostname or parsed.username is not None or parsed.password is not None
        or parsed.port == 0
        or parsed.fragment or parsed.query
      ):
        raise ConfigError(f"{context}.url must be a credential-free {check_type} URL without query or fragment")
      parse_host(parsed.hostname, f"{context}.url host")
      timeout = _parse_timeout(check.get("timeout_seconds", DEFAULT_TCP_TIMEOUT_SECONDS), f"{context}.timeout_seconds")
      expected = _parse_nonnegative_int(check.get("expected_status", 200), f"{context}.expected_status", 599)
      if expected < 100:
        raise ConfigError(f"{context}.expected_status must be from 100 through 599")
      checks.append(GenericCheck(name, check_type, url, timeout, options=(("expected_status", expected),), **common))
    elif check_type == "dns":
      _reject_unknown_keys(check, {"name", "type", "host"} | COMMON_CHECK_FIELDS, context)
      host, _ = parse_host(_require_string(check, "host", context), f"{context}.host")
      checks.append(GenericCheck(name, check_type, host, **common))
    elif check_type == "certificate_expiry":
      _reject_unknown_keys(check, {"name", "type", "host", "port", "timeout_seconds", "warn_days", "critical_days"} | COMMON_CHECK_FIELDS, context)
      host, _ = parse_host(_require_string(check, "host", context), f"{context}.host")
      port = _parse_port(check.get("port", 443), f"{context}.port")
      timeout = _parse_timeout(check.get("timeout_seconds", DEFAULT_TCP_TIMEOUT_SECONDS), f"{context}.timeout_seconds")
      warn = _parse_nonnegative_int(check.get("warn_days", 30), f"{context}.warn_days", 36500)
      critical = _parse_nonnegative_int(check.get("critical_days", 7), f"{context}.critical_days", 36500)
      if critical > warn:
        raise ConfigError(f"{context}.critical_days must not exceed warn_days")
      checks.append(GenericCheck(name, check_type, f"{host}:{port}", timeout, options=(("host", host), ("port", port), ("warn_days", warn), ("critical_days", critical)), **common))
    elif check_type == "process":
      _reject_unknown_keys(check, {"name", "type", "pid"} | COMMON_CHECK_FIELDS, context)
      pid = _parse_nonnegative_int(check.get("pid"), f"{context}.pid", 2_147_483_647)
      if pid < 1:
        raise ConfigError(f"{context}.pid must be positive")
      checks.append(GenericCheck(name, check_type, str(pid), options=(("pid", pid),), **common))
    elif check_type == "systemd_service":
      _reject_unknown_keys(check, {"name", "type", "service", "timeout_seconds"} | COMMON_CHECK_FIELDS, context)
      service = _require_string(check, "service", context)
      if not service or service.startswith("-") or "/" in service or any(value.isspace() for value in service):
        raise ConfigError(f"{context}.service is invalid")
      service = service if service.endswith(".service") else service + ".service"
      timeout = _parse_timeout(check.get("timeout_seconds", DEFAULT_TCP_TIMEOUT_SECONDS), f"{context}.timeout_seconds")
      checks.append(GenericCheck(name, check_type, service, timeout, **common))
    elif check_type in {"file_exists", "file_metadata", "config_hash"}:
      allowed = {"name", "type", "path", "minimum_bytes", "maximum_bytes", "sha256"} | COMMON_CHECK_FIELDS
      _reject_unknown_keys(check, allowed, context)
      check_path = _require_string(check, "path", context)
      if not check_path or "\x00" in check_path:
        raise ConfigError(f"{context}.path is invalid")
      options = []
      if check_type == "file_metadata":
        options.extend((
          ("minimum_bytes", _parse_nonnegative_int(check.get("minimum_bytes", 0), f"{context}.minimum_bytes", (1 << 63) - 1)),
          ("maximum_bytes", _parse_nonnegative_int(check.get("maximum_bytes", (1 << 63) - 1), f"{context}.maximum_bytes", (1 << 63) - 1)),
        ))
        if options[0][1] > options[1][1]:
          raise ConfigError(f"{context}.minimum_bytes must not exceed maximum_bytes")
      if check_type == "config_hash":
        digest = _require_string(check, "sha256", context).lower()
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
          raise ConfigError(f"{context}.sha256 must be 64 hexadecimal digits")
        options.append(("sha256", digest))
      checks.append(GenericCheck(name, check_type, check_path, options=tuple(options), **common))
    else:
      raise ConfigError(f"{context}.type is unsupported in V1: {display_safe(check_type)}")

  for check in checks:
    for dependency in check.depends_on:
      if dependency not in names or dependency == check.name:
        raise ConfigError(f"check {check.name} has an invalid dependency: {dependency}")
  dependency_map = {check.name: check.depends_on for check in checks}
  visiting: set[str] = set()
  visited: set[str] = set()

  def visit(check_name: str) -> None:
    if check_name in visiting:
      raise ConfigError("check dependency graph contains a cycle")
    if check_name in visited:
      return
    visiting.add(check_name)
    for dependency in dependency_map[check_name]:
      visit(dependency)
    visiting.remove(check_name)
    visited.add(check_name)

  for check_name in dependency_map:
    visit(check_name)
  return HealthConfig(os.path.abspath(path), tuple(checks), max_workers)


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


class LimitedRedirectHandler(urllib.request.HTTPRedirectHandler):
  def __init__(self):
    self.redirects = 0

  def redirect_request(self, req, fp, code, msg, headers, newurl):
    self.redirects += 1
    if self.redirects > MAX_HTTP_REDIRECTS:
      raise RedirectPolicyError("redirect limit exceeded")
    destination = validate_redirect_url(req.full_url, newurl)
    return super().redirect_request(req, fp, code, msg, headers, destination)


def validate_redirect_url(current_url: str, new_url: str) -> str:
  """Resolve and validate a same-origin redirect without consulting proxy state."""
  destination = urllib.parse.urljoin(current_url, new_url)
  if len(destination) > 2048 or not destination.isascii() or display_safe(destination) != destination:
    raise RedirectPolicyError("redirect URL is malformed")
  try:
    old = urllib.parse.urlsplit(current_url)
    new = urllib.parse.urlsplit(destination)
    old_port = old.port or (443 if old.scheme == "https" else 80)
    new_port = new.port or (443 if new.scheme == "https" else 80)
  except ValueError as exc:
    raise RedirectPolicyError("redirect URL is malformed") from exc
  if (
    new.scheme != old.scheme or new.hostname != old.hostname or new_port != old_port
    or new.username is not None or new.password is not None or new.query or new.fragment
    or new.port == 0 or old.port == 0
  ):
    raise RedirectPolicyError("redirect left the configured origin or transport")
  return destination


def _deadline_remaining(deadline: float, clock: Callable[[], float]) -> float:
  remaining = deadline - clock()
  if remaining <= 0:
    raise TimeoutError("network check exceeded its total deadline")
  return remaining


def _connect_tcp_target(
  host: str,
  host_kind: str,
  port: int,
  deadline: float,
  *,
  resolver: Callable[..., object],
  socket_factory: Callable[[int, int, int], socket.socket],
  clock: Callable[[], float],
) -> socket.socket:
  check = TcpConnectCheck("network", host, host_kind, port, 0.1)
  candidates = resolve_tcp_candidates(check, resolver=resolver)
  if not candidates:
    raise socket.gaierror("name resolution returned no usable address")
  last_error: OSError | None = None
  for candidate in candidates:
    remaining = _deadline_remaining(deadline, clock)
    client = socket_factory(candidate.family, candidate.socket_type, candidate.protocol)
    try:
      client.settimeout(remaining)
      client.connect(candidate.sockaddr)
      return client
    except BaseException as error:
      try:
        client.close()
      except OSError:
        pass
      if not isinstance(error, OSError):
        raise
      last_error = error
  if last_error is not None:
    raise last_error
  raise OSError("no TCP candidate was attempted")


def _parse_http_head(data: bytes) -> tuple[int, str | None]:
  head, separator, _remainder = data.partition(b"\r\n\r\n")
  if not separator or b"\n" in head.replace(b"\r\n", b"") or b"\r" in head.replace(b"\r\n", b""):
    raise ObservationError("HTTP response headers were malformed")
  lines = head.split(b"\r\n")
  match = re.fullmatch(rb"HTTP/1\.[01] ([0-9]{3})(?: [\x20-\x7e]*)?", lines[0])
  if match is None:
    raise ObservationError("HTTP status line was malformed")
  status = int(match.group(1))
  locations = []
  for line in lines[1:]:
    if not line or line[:1] in b" \t" or b":" not in line:
      raise ObservationError("HTTP response headers were malformed")
    name, value = line.split(b":", 1)
    if re.fullmatch(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", name) is None:
      raise ObservationError("HTTP response headers were malformed")
    if name.lower() == b"location":
      locations.append(value.strip().decode("latin-1"))
  if len(locations) > 1:
    raise ObservationError("HTTP response contained multiple Location headers")
  return status, locations[0] if locations else None


def _one_http_head(
  url: str,
  deadline: float,
  *,
  resolver: Callable[..., object],
  socket_factory: Callable[[int, int, int], socket.socket],
  context_factory: Callable[[], ssl.SSLContext],
  clock: Callable[[], float],
) -> tuple[int, str | None]:
  parsed = urllib.parse.urlsplit(url)
  assert parsed.hostname is not None
  host, host_kind = parse_host(parsed.hostname, "HTTP URL host")
  port = parsed.port or (443 if parsed.scheme == "https" else 80)
  client = _connect_tcp_target(
    host, host_kind, port, deadline,
    resolver=resolver, socket_factory=socket_factory, clock=clock,
  )
  stream = client
  try:
    if parsed.scheme == "https":
      client.settimeout(_deadline_remaining(deadline, clock))
      stream = context_factory().wrap_socket(client, server_hostname=host)
    path = parsed.path or "/"
    if not path.startswith("/"):
      path = "/" + path
    default_port = 443 if parsed.scheme == "https" else 80
    host_value = f"[{host}]" if host_kind == "ipv6" else host
    if port != default_port:
      host_value += f":{port}"
    request = (
      f"HEAD {path} HTTP/1.1\r\nHost: {host_value}\r\n"
      "User-Agent: OpsForge-HealthCtl/0.2\r\nConnection: close\r\n\r\n"
    ).encode("ascii")
    stream.settimeout(_deadline_remaining(deadline, clock))
    stream.sendall(request)
    response = bytearray()
    while b"\r\n\r\n" not in response:
      stream.settimeout(_deadline_remaining(deadline, clock))
      chunk = stream.recv(min(4096, MAX_HTTP_HEADER_BYTES + 1 - len(response)))
      if not chunk:
        raise ObservationError("HTTP response ended before complete headers")
      response.extend(chunk)
      if len(response) > MAX_HTTP_HEADER_BYTES:
        raise ObservationError("HTTP response headers exceeded the 64 KiB limit")
    return _parse_http_head(bytes(response))
  finally:
    try:
      stream.close()
    except OSError:
      pass
    if stream is not client:
      try:
        client.close()
      except OSError:
        pass


def run_http_head(
  check: GenericCheck,
  *,
  resolver: Callable[..., object] = socket.getaddrinfo,
  socket_factory: Callable[[int, int, int], socket.socket] = socket.socket,
  context_factory: Callable[[], ssl.SSLContext] = ssl.create_default_context,
  clock: Callable[[], float] = time.monotonic,
) -> int:
  deadline = clock() + check.timeout_seconds
  current = check.target
  for redirects in range(MAX_HTTP_REDIRECTS + 1):
    status, location = _one_http_head(
      current, deadline, resolver=resolver, socket_factory=socket_factory,
      context_factory=context_factory, clock=clock,
    )
    if status not in {301, 302, 303, 307, 308} or location is None:
      return status
    if redirects >= MAX_HTTP_REDIRECTS:
      raise RedirectPolicyError("redirect limit exceeded")
    current = validate_redirect_url(current, location)
  raise RedirectPolicyError("redirect limit exceeded")


def _options(check: GenericCheck) -> dict[str, object]:
  return dict(check.options)


def hash_regular_file(path: str, expected_metadata: os.stat_result) -> str:
  flags = os.O_RDONLY
  for flag_name in ("O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK"):
    flags |= getattr(os, flag_name, 0)
  try:
    descriptor = os.open(path, flags)
  except OSError as error:
    raise ObservationError("file could not be opened safely for hashing") from error
  try:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or _metadata_identity(before) != _metadata_identity(expected_metadata):
      raise ObservationError("file identity changed before hashing")
    if before.st_size > MAX_HASH_BYTES:
      raise ObservationError(f"file exceeds {MAX_HASH_BYTES}-byte hash limit")
    digest = hashlib.sha256()
    remaining = before.st_size
    while remaining:
      chunk = os.read(descriptor, min(remaining, 64 * 1024))
      if not chunk:
        raise ObservationError("file changed during hashing")
      digest.update(chunk)
      remaining -= len(chunk)
    if os.read(descriptor, 1):
      raise ObservationError("file changed during hashing")
    after = os.fstat(descriptor)
    if _metadata_identity(before) != _metadata_identity(after):
      raise ObservationError("file changed during hashing")
    return digest.hexdigest()
  except OSError as error:
    raise ObservationError("file could not be hashed") from error
  finally:
    os.close(descriptor)


def _stop_process_group(process: subprocess.Popen[bytes]) -> None:
  running = process.poll() is None
  try:
    os.killpg(process.pid, signal.SIGKILL)
  except OSError:
    if running:
      try:
        process.kill()
      except OSError:
        pass
  try:
    process.wait(timeout=1.0)
  except (OSError, subprocess.SubprocessError):
    pass


def run_silent_command(arguments: Sequence[str], timeout_seconds: float) -> int:
  process = subprocess.Popen(
    list(arguments), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    env={**os.environ, "LC_ALL": "C", "SYSTEMD_PAGER": "", "SYSTEMD_COLORS": "0"},
    start_new_session=True,
  )
  try:
    return process.wait(timeout=timeout_seconds)
  except subprocess.TimeoutExpired as error:
    _stop_process_group(process)
    raise ObservationError("command exceeded its deadline") from error
  except BaseException:
    _stop_process_group(process)
    raise


def run_generic_check(check: GenericCheck) -> CheckResult:
  options = _options(check)
  if check.type in {"http", "https"}:
    try:
      status_code = run_http_head(check)
    except urllib.error.URLError as error:
      reason = error.reason
      if isinstance(reason, ssl.SSLError):
        layer = "TLS"
      elif isinstance(reason, socket.gaierror):
        layer = "resolution"
      elif isinstance(reason, (ConnectionError, TimeoutError, socket.timeout, OSError)):
        layer = "TCP"
      else:
        layer = "HTTP"
      return CheckResult(check.name, check.type, "FAIL", check.target, f"{layer} layer failed: {type(reason).__name__}", check.severity)
    except ssl.SSLError as error:
      return CheckResult(check.name, check.type, "FAIL", check.target, f"TLS layer failed: {type(error).__name__}", check.severity)
    except socket.gaierror as error:
      return CheckResult(check.name, check.type, "FAIL", check.target, f"resolution layer failed: {type(error).__name__}", check.severity)
    except (OSError, TimeoutError) as error:
      return CheckResult(check.name, check.type, "FAIL", check.target, f"TCP layer failed: {type(error).__name__}", check.severity)
    expected = int(options["expected_status"])
    status = "PASS" if status_code == expected else "FAIL"
    return CheckResult(check.name, check.type, status, check.target, f"HTTP status {status_code}; required {expected}", "OK" if status == "PASS" else check.severity)
  if check.type == "dns":
    try:
      records = socket.getaddrinfo(check.target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
      return CheckResult(check.name, check.type, "FAIL", check.target, "OS resolution returned no usable address", check.severity)
    addresses = set()
    try:
      for record in records:
        addresses.add(str(ipaddress.ip_address(record[4][0].split("%", 1)[0])))
        if len(addresses) > MAX_RESOLVER_CANDIDATES:
          return CheckResult(check.name, check.type, "ERROR", check.target, "OS resolution exceeded the 16-address limit", "CRITICAL")
    except (IndexError, TypeError, ValueError):
      return CheckResult(check.name, check.type, "ERROR", check.target, "OS resolution returned malformed address evidence", "CRITICAL")
    addresses = sorted(addresses)
    status = "PASS" if addresses else "FAIL"
    return CheckResult(check.name, check.type, status, check.target, f"resolved addresses: {', '.join(addresses) or 'none'}", "OK" if status == "PASS" else check.severity)
  if check.type == "certificate_expiry":
    host, port = str(options["host"]), int(options["port"])
    try:
      deadline = time.monotonic() + check.timeout_seconds
      context = ssl.create_default_context()
      _, host_kind = parse_host(host, "certificate host")
      with _connect_tcp_target(
        host, host_kind, port, deadline, resolver=socket.getaddrinfo,
        socket_factory=socket.socket, clock=time.monotonic,
      ) as tcp:
        tcp.settimeout(_deadline_remaining(deadline, time.monotonic))
        with context.wrap_socket(tcp, server_hostname=host) as tls:
          certificate = tls.getpeercert()
          _deadline_remaining(deadline, time.monotonic)
      not_after = certificate.get("notAfter")
      if not isinstance(not_after, str):
        raise ValueError
      remaining = ssl.cert_time_to_seconds(not_after) - time.time()
    except (OSError, ssl.SSLError, ValueError, ObservationError):
      return CheckResult(check.name, check.type, "ERROR", check.target, "trusted TLS certificate observation failed; revocation not checked", "CRITICAL")
    days = remaining / 86400
    critical, warn = int(options["critical_days"]), int(options["warn_days"])
    if days < critical:
      status, severity = "FAIL", "CRITICAL"
    elif days < warn:
      status, severity = "FAIL", "WARN"
    else:
      status, severity = "PASS", "OK"
    return CheckResult(check.name, check.type, status, check.target, f"trusted certificate expires in {days:.2f} days; revocation not checked", severity)
  if check.type == "process":
    pid = int(options["pid"])
    try:
      metadata = os.stat(f"/proc/{pid}", follow_symlinks=False)
      exists = stat.S_ISDIR(metadata.st_mode)
    except OSError:
      exists = False
    return CheckResult(check.name, check.type, "PASS" if exists else "FAIL", check.target, "process directory exists" if exists else "process directory was not observed", "OK" if exists else check.severity)
  if check.type == "systemd_service":
    try:
      return_code = run_silent_command(
        ["systemctl", "is-active", "--system", "--quiet", "--", check.target],
        check.timeout_seconds,
      )
    except (OSError, subprocess.SubprocessError, ObservationError):
      return CheckResult(check.name, check.type, "ERROR", check.target, "systemd state could not be observed", "CRITICAL")
    active = return_code == 0
    return CheckResult(check.name, check.type, "PASS" if active else "FAIL", check.target, "service is active" if active else f"service is not active (status {return_code})", "OK" if active else check.severity)
  if check.type in {"file_exists", "file_metadata", "config_hash"}:
    path = os.path.abspath(check.target)
    try:
      metadata = os.lstat(path)
    except OSError:
      return CheckResult(check.name, check.type, "FAIL", path, "path was not observed", check.severity)
    if stat.S_ISLNK(metadata.st_mode):
      return CheckResult(check.name, check.type, "ERROR", path, "final-component symlinks are not followed", "CRITICAL")
    if check.type == "file_exists":
      return CheckResult(check.name, check.type, "PASS", path, "path exists", "OK")
    if not stat.S_ISREG(metadata.st_mode):
      return CheckResult(check.name, check.type, "FAIL", path, "path is not a regular file", check.severity)
    if check.type == "file_metadata":
      minimum, maximum = int(options["minimum_bytes"]), int(options["maximum_bytes"])
      passed = minimum <= metadata.st_size <= maximum
      return CheckResult(check.name, check.type, "PASS" if passed else "FAIL", path, f"size {metadata.st_size} bytes; required {minimum}-{maximum}", "OK" if passed else check.severity)
    try:
      observed_digest = hash_regular_file(path, metadata)
    except ObservationError as error:
      return CheckResult(check.name, check.type, "ERROR", path, str(error), "CRITICAL")
    passed = observed_digest == options["sha256"]
    return CheckResult(check.name, check.type, "PASS" if passed else "FAIL", path, f"SHA-256 {'matched' if passed else 'did not match'}", "OK" if passed else check.severity)
  raise ObservationError("configuration produced an unsupported generic check type")


def run_check(check: HealthCheck) -> CheckResult:
  started = time.monotonic()
  result = None
  attempts = 0
  for attempts in range(1, check.retries + 2):
    if isinstance(check, DiskFreeCheck):
      result = run_disk_check(check)
    elif isinstance(check, TcpConnectCheck):
      result = run_tcp_check(check)
    elif isinstance(check, GenericCheck):
      result = run_generic_check(check)
    else:
      raise ObservationError("configuration produced an unsupported check type")
    if result.status == "PASS":
      break
  assert result is not None
  severity = "OK" if result.status == "PASS" else result.severity if result.severity in {"WARN", "CRITICAL"} else check.severity
  return replace(result, severity=severity, elapsed_seconds=time.monotonic() - started, attempts=attempts)


def evaluate_config(
  config: HealthConfig,
  *,
  executor: Callable[[HealthCheck], CheckResult] = run_check,
) -> tuple[CheckResult, ...]:
  pending = {check.name: check for check in config.checks}
  completed: dict[str, CheckResult] = {}
  order = {check.name: index for index, check in enumerate(config.checks)}
  while pending:
    ready = [check for check in pending.values() if all(name in completed for name in check.depends_on)]
    if not ready:
      raise ObservationError("check dependency graph contains a cycle")
    runnable = []
    for check in ready:
      failed_dependencies = [name for name in check.depends_on if completed[name].status != "PASS"]
      if failed_dependencies:
        completed[check.name] = CheckResult(
          check.name, check.type, "FAIL", _check_target(check),
          f"dependency did not pass: {', '.join(failed_dependencies)}", check.severity,
        )
      else:
        runnable.append(check)
    if runnable:
      with ThreadPoolExecutor(max_workers=min(config.max_workers, len(runnable))) as pool:
        futures = {pool.submit(executor, check): check for check in runnable}
        for future in as_completed(futures):
          check = futures[future]
          try:
            result = future.result()
          except ObservationError as error:
            result = CheckResult(check.name, check.type, "ERROR", _check_target(check), str(error), "CRITICAL")
          except OSError:
            result = CheckResult(check.name, check.type, "ERROR", _check_target(check), "operating-system observation failed", "CRITICAL")
          if result.name != check.name or result.type != check.type or result.status not in {"PASS", "FAIL", "ERROR"}:
            raise ObservationError("check executor returned an invalid result")
          completed[check.name] = result
    for check in ready:
      pending.pop(check.name)
  return tuple(sorted(completed.values(), key=lambda result: order[result.name]))


def _check_target(check: HealthCheck) -> str:
  if isinstance(check, DiskFreeCheck):
    return os.path.abspath(check.path)
  if isinstance(check, TcpConnectCheck):
    return f"[{check.host}]:{check.port}" if check.host_kind == "ipv6" else f"{check.host}:{check.port}"
  if isinstance(check, GenericCheck):
    return os.path.abspath(check.target) if check.type.startswith("file_") or check.type == "config_hash" else check.target
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
      f"     Severity: {result.severity}",
      f"     Type: {result.type}",
      f"     Target: {display_safe(result.target)}",
      f"     Evidence: {display_safe(result.evidence)}",
      f"     Attempts: {result.attempts}",
      f"     Elapsed: {result.elapsed_seconds:.6f} s",
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
    description="Evaluate bounded dependency-aware criteria from one strict JSON configuration file.",
  )
  parser.add_argument("config", help="path to a HealthCtl V1 JSON configuration file")
  parser.add_argument("--profile", metavar="NAME", help="run only a named profile")
  parser.add_argument("--group", metavar="NAME", help="run only a named check group")
  parser.add_argument("--workers", type=lambda value: _cli_workers(value), metavar="N", help="override bounded parallel workers (1-8)")
  add_output_arguments(parser)
  return parser


def _cli_workers(value: str) -> int:
  if not value.isascii() or not value.isdecimal() or not 1 <= int(value, 10) <= MAX_WORKERS:
    raise argparse.ArgumentTypeError(f"workers must be from 1 through {MAX_WORKERS}")
  return int(value, 10)


def main(argv: Sequence[str] | None = None) -> int:
  parser = build_argument_parser()
  args = parser.parse_args(argv)
  validate_output_arguments(parser, args)
  started = time.monotonic()
  try:
    config = load_config(args.config)
    selected = tuple(
      check for check in config.checks
      if (args.profile is None or check.profile == args.profile)
      and (args.group is None or check.group == args.group)
    )
    if not selected:
      raise ConfigError("selected profile/group contains no checks")
    selected_names = {check.name for check in selected}
    if any(any(dependency not in selected_names for dependency in check.depends_on) for check in selected):
      raise ConfigError("selected profile/group omits a required check dependency")
    config = HealthConfig(config.path, selected, args.workers or config.max_workers)
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
  exit_code = result_exit_code(results)
  errors = sum(result.status == "ERROR" for result in results)
  critical = sum(result.status != "PASS" and result.severity == "CRITICAL" for result in results)
  warnings = sum(result.status != "PASS" and result.severity == "WARN" for result in results)
  status = "CRITICAL" if errors or critical else "WARN" if warnings else "OK"
  finding = f"{sum(result.status == 'PASS' for result in results)} of {len(results)} checks passed; {warnings} warning and {critical} critical/error results"
  next_action = "review failed checks in dependency order" if exit_code else "all selected criteria passed during this invocation"
  conclusion = make_conclusion(status, config.path, finding, next_action)
  record = OutputRecord(
    tool="healthctl", status=status, target=config.path,
    observations={
      "checks": results,
      "summary": {"ok": sum(result.status == "PASS" for result in results), "warn": warnings, "critical": critical, "error": errors},
      "profile": args.profile, "group": args.group, "max_workers": config.max_workers,
    },
    conclusion=conclusion, next_action=next_action + ".", warnings=(),
    elapsed_seconds=time.monotonic() - started,
  )
  brief = "\n".join([
    f"Configuration: {display_safe(config.path)}",
    f"Checks: {len(results)}",
    f"OK/WARN/CRITICAL: {sum(result.status == 'PASS' for result in results)}/{warnings}/{critical}",
  ])
  try:
    emit_output(
      record, detailed=report, brief=brief, json_mode=args.json,
      brief_mode=args.brief, quiet=args.quiet,
      output_path=args.output, force=args.force, stdout=sys.stdout,
    )
  except OutputError as error:
    print_safe(f"healthctl: output error: {display_safe(error)}", file=sys.stderr)
    return 3
  return exit_code


if __name__ == "__main__":
  try:
    raise SystemExit(main())
  except KeyboardInterrupt:
    print_safe("healthctl: interrupted", file=sys.stderr)
    raise SystemExit(130)
