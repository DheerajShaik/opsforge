#!/usr/bin/env python3
"""Evaluate a bounded set of explicit host and service health criteria."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
import errno
import functools
import json
import hashlib
import os
import queue
import re
import shutil
import socket
import ssl
import stat
import sys
import threading
import time
import urllib.parse
from typing import Callable, Mapping, Sequence, TypeVar

from opsforge.common import (
  OutputError,
  OutputRecord,
  add_output_arguments,
  emit_output,
  make_conclusion,
  print_safe,
  sanitize_text as display_safe,
  validate_output_arguments,
)
from opsforge.common.fs import FileIdentityError, NotRegularFileError, open_regular_file
from opsforge.common.net import (
  Attempt,
  Candidate,
  HostError,
  MAX_CANDIDATES,
  NetworkAPIError,
  classify_connect_error,
  connect_first,
  parse_host as parse_net_host,
  resolve_tcp,
  sni_name,
)
from opsforge.common.process import (
  ProcessSpawnError,
  ProcessTimeoutError,
  child_environment,
  resolve_executable,
  run_bounded,
)
from opsforge.common.status import (
  CRITICAL,
  ERROR,
  EXIT_FAILURE,
  EXIT_FINDING,
  EXIT_INTERRUPTED,
  EXIT_OK,
  EXIT_USAGE,
  INCOMPLETE,
  SKIPPED,
  WARNING,
)
from opsforge.common.systemd import UnitNameError, normalize_service_name


PASS = "PASS"
FAIL = "FAIL"
OK = "OK"
# "WARN" is the V1 spelling, still accepted in configuration files.
SEVERITY_NAMES = {"WARN": WARNING, WARNING: WARNING, CRITICAL: CRITICAL}
AGGREGATE_EXIT_CODES = {
  OK: EXIT_OK, WARNING: EXIT_FINDING, CRITICAL: EXIT_FINDING, INCOMPLETE: EXIT_FAILURE, ERROR: EXIT_FAILURE,
}
CONFIG_MAX_BYTES = 64 * 1024
MAX_CHECKS = 32
DEFAULT_TIMEOUT_SECONDS = 1.0
MIN_TIMEOUT_SECONDS = 0.1
MAX_TIMEOUT_SECONDS = 5.0
FILESYSTEM_TIMEOUT_SECONDS = 5.0
RESOLVER_TIMEOUT_SECONDS = 5.0
# getaddrinfo returns TCP candidates only for a port; a DNS check resolves with this one and never connects to it.
DNS_PROBE_PORT = 80
CONNECT_ATTEMPT_FLOOR_SECONDS = 0.25
MAX_RETRIES = 3
MAX_WORKERS = 8
MAX_URL_CHARACTERS = 2048
MAX_HTTP_REDIRECTS = 3
MAX_HTTP_HEADER_BYTES = 64 * 1024
MAX_HASH_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = (1 << 63) - 1
MAX_CERTIFICATE_DAYS = 36500
MAX_PID = (1 << 31) - 1
PROC_STATUS_MAX_BYTES = 64 * 1024
RETRY_BACKOFF_SECONDS = 0.1
MAX_RETRY_BACKOFF_SECONDS = 0.5
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
X509_V_ERR_CERT_NOT_YET_VALID = 9
X509_V_ERR_CERT_HAS_EXPIRED = 10
# OpenSSL's X509_V_FLAG_NO_CHECK_TIME, which the ssl module does not export.
X509_V_FLAG_NO_CHECK_TIME = 0x200000
CHECK_NAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,63})\Z", re.ASCII)
# RFC 3986 unreserved, reserved, and percent characters; anything else would corrupt the request line.
URL_RE = re.compile(r"[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%%]{1,%d}\Z" % MAX_URL_CHARACTERS, re.ASCII)
T = TypeVar("T")


class ConfigError(Exception):
  """The requested configuration cannot be trusted or accepted."""


class ObservationError(Exception):
  """A configured check could not produce trustworthy evidence."""


class RedirectPolicyError(ObservationError):
  """An HTTP redirect exceeded the configured target boundary."""


class ProbeTimeoutError(ObservationError):
  """A blocking operating-system call did not return within its bound."""


class NetworkFailure(Exception):
  """A configured endpoint was reached for, and it refused, failed, or did not answer in time."""


@dataclass(frozen=True)
class DiskFreeCheck:
  name: str
  path: str
  minimum_free_percent: float
  type: str = "disk_free_percent"
  severity: str = CRITICAL
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
  severity: str = CRITICAL
  group: str = "default"
  profile: str = "default"
  depends_on: tuple[str, ...] = ()
  retries: int = 0


@dataclass(frozen=True)
class GenericCheck:
  name: str
  type: str
  target: str
  timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
  severity: str = CRITICAL
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
  # OK for PASS, WARNING or CRITICAL for FAIL; None for ERROR and SKIPPED, which established nothing.
  severity: str | None = None
  elapsed_seconds: float = 0.0
  attempts: int = 1


def _metadata_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
  return (
    metadata.st_dev,
    metadata.st_ino,
    metadata.st_size,
    metadata.st_mtime_ns,
    metadata.st_ctime_ns,
  )


def read_config_bytes(path: str) -> bytes:
  try:
    descriptor, before = open_regular_file(path)
  except (FileNotFoundError, NotADirectoryError) as error:
    raise ConfigError("configuration file was not found") from error
  except PermissionError as error:
    raise ConfigError("configuration file is not readable with current permissions") from error
  except NotRegularFileError as error:
    if os.path.islink(path):
      raise ConfigError("configuration file must not be a final-component symlink") from error
    raise ConfigError("configuration target must be a regular file") from error
  except FileIdentityError as error:
    raise ConfigError("configuration file changed during observation") from error
  except OSError as error:
    if error.errno == errno.ELOOP:
      raise ConfigError("configuration file must not be a final-component symlink") from error
    raise ConfigError("configuration file could not be opened") from error

  try:
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
  return value


def _reject_unknown_keys(mapping: Mapping[str, object], allowed: set[str], context: str) -> None:
  unknown = sorted(set(mapping) - allowed)
  if unknown:
    raise ConfigError(f"{context} contains unsupported field: {unknown[0]}")


def _require_string(mapping: Mapping[str, object], key: str, context: str) -> str:
  value = mapping.get(key)
  if not isinstance(value, str):
    raise ConfigError(f"{context}.{key} must be a string")
  return value


def _parse_check_name(value: str, field: str) -> str:
  if CHECK_NAME_RE.fullmatch(value) is None:
    raise ConfigError(
      f"{field} must be 1-64 ASCII letters, digits, '.', '_' or '-', starting with a letter or digit"
    )
  return value


def _parse_percent(value: object, context: str) -> float:
  if isinstance(value, bool) or not isinstance(value, (int, float)):
    raise ConfigError(f"{context} must be a JSON number from 0 through 100")
  # Comparing before float() rejects NaN and infinities and cannot overflow on huge integers.
  if not 0.0 <= value <= 100.0:
    raise ConfigError(f"{context} must be a finite number from 0 through 100")
  return float(value)


def _parse_timeout(value: object, context: str) -> float:
  if isinstance(value, bool) or not isinstance(value, (int, float)):
    raise ConfigError(
      f"{context} must be a JSON number from {MIN_TIMEOUT_SECONDS} through {MAX_TIMEOUT_SECONDS}"
    )
  if not MIN_TIMEOUT_SECONDS <= value <= MAX_TIMEOUT_SECONDS:
    raise ConfigError(
      f"{context} must be a finite number from {MIN_TIMEOUT_SECONDS} through {MAX_TIMEOUT_SECONDS}"
    )
  return float(value)


def _parse_port(value: object, context: str) -> int:
  if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
    raise ConfigError(f"{context} must be a JSON integer from 1 through 65535")
  return value


def _parse_nonnegative_int(value: object, context: str, maximum: int) -> int:
  if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
    raise ConfigError(f"{context} must be a JSON integer from 0 through {maximum}")
  return value


def _parse_path(check: Mapping[str, object], context: str) -> str:
  path = _require_string(check, "path", context)
  if not path:
    raise ConfigError(f"{context}.path must not be empty")
  if "\x00" in path:
    raise ConfigError(f"{context}.path must not contain NUL")
  try:
    os.fsencode(path)
  except UnicodeEncodeError as error:
    raise ConfigError(f"{context}.path cannot be encoded as a file-system path") from error
  return path


COMMON_CHECK_FIELDS = {"severity", "group", "profile", "depends_on", "retries"}


def _common_check_fields(check: Mapping[str, object], context: str) -> dict[str, object]:
  severity = check.get("severity", CRITICAL)
  if not isinstance(severity, str) or severity not in SEVERITY_NAMES:
    raise ConfigError(f"{context}.severity must be WARNING (or WARN) or CRITICAL")
  group_value = check.get("group", "default")
  profile_value = check.get("profile", "default")
  if not isinstance(group_value, str) or not isinstance(profile_value, str):
    raise ConfigError(f"{context}.group and profile must be strings")
  group = _parse_check_name(group_value, f"{context}.group")
  profile = _parse_check_name(profile_value, f"{context}.profile")
  raw_dependencies = check.get("depends_on", [])
  if not isinstance(raw_dependencies, list) or len(raw_dependencies) > MAX_CHECKS:
    raise ConfigError(f"{context}.depends_on must be a bounded JSON array")
  if not all(isinstance(value, str) for value in raw_dependencies):
    raise ConfigError(f"{context}.depends_on must contain only check-name strings")
  dependencies = tuple(_parse_check_name(value, f"{context}.depends_on entry") for value in raw_dependencies)
  if len(set(dependencies)) != len(dependencies):
    raise ConfigError(f"{context}.depends_on must not repeat a check name")
  retries = _parse_nonnegative_int(check.get("retries", 0), f"{context}.retries", MAX_RETRIES)
  return {
    "severity": SEVERITY_NAMES[severity], "group": group, "profile": profile, "depends_on": dependencies,
    "retries": retries,
  }


def parse_host(value: str, context: str) -> tuple[str, str]:
  try:
    return parse_net_host(value, context)
  except HostError as error:
    raise ConfigError(str(error)) from error


def _parse_disk_check(check: Mapping[str, object], context: str, name: str, check_type: str, common: dict[str, object]) -> HealthCheck:
  check_path = _parse_path(check, context)
  minimum = _parse_percent(check.get("minimum_free_percent"), f"{context}.minimum_free_percent")
  return DiskFreeCheck(name, check_path, minimum, **common)


def _parse_tcp_check(check: Mapping[str, object], context: str, name: str, check_type: str, common: dict[str, object]) -> HealthCheck:
  host, host_kind = parse_host(_require_string(check, "host", context), f"{context}.host")
  port = _parse_port(check.get("port"), f"{context}.port")
  timeout = _parse_timeout(check.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS), f"{context}.timeout_seconds")
  return TcpConnectCheck(name, host, host_kind, port, timeout, **common)


def _parse_http_check(check: Mapping[str, object], context: str, name: str, check_type: str, common: dict[str, object]) -> HealthCheck:
  url = _require_string(check, "url", context)
  if URL_RE.fullmatch(url) is None:
    raise ConfigError(
      f"{context}.url must be 1-{MAX_URL_CHARACTERS} ASCII characters allowed in a URL (no spaces or controls)"
    )
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
  timeout = _parse_timeout(check.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS), f"{context}.timeout_seconds")
  expected = _parse_nonnegative_int(check.get("expected_status", 200), f"{context}.expected_status", 599)
  if expected < 100:
    raise ConfigError(f"{context}.expected_status must be from 100 through 599")
  return GenericCheck(name, check_type, url, timeout, options=(("expected_status", expected),), **common)


def _parse_dns_check(check: Mapping[str, object], context: str, name: str, check_type: str, common: dict[str, object]) -> HealthCheck:
  host, _ = parse_host(_require_string(check, "host", context), f"{context}.host")
  return GenericCheck(name, check_type, host, **common)


def _parse_certificate_check(check: Mapping[str, object], context: str, name: str, check_type: str, common: dict[str, object]) -> HealthCheck:
  host, host_kind = parse_host(_require_string(check, "host", context), f"{context}.host")
  port = _parse_port(check.get("port", 443), f"{context}.port")
  timeout = _parse_timeout(check.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS), f"{context}.timeout_seconds")
  warn = _parse_nonnegative_int(check.get("warn_days", 30), f"{context}.warn_days", MAX_CERTIFICATE_DAYS)
  critical = _parse_nonnegative_int(check.get("critical_days", 7), f"{context}.critical_days", MAX_CERTIFICATE_DAYS)
  if critical > warn:
    raise ConfigError(f"{context}.critical_days must not exceed warn_days")
  options = (("host", host), ("port", port), ("warn_days", warn), ("critical_days", critical))
  target = f"[{host}]:{port}" if host_kind == "ipv6" else f"{host}:{port}"
  return GenericCheck(name, check_type, target, timeout, options=options, **common)


def _parse_process_check(check: Mapping[str, object], context: str, name: str, check_type: str, common: dict[str, object]) -> HealthCheck:
  pid = _parse_nonnegative_int(check.get("pid"), f"{context}.pid", MAX_PID)
  if pid < 1:
    raise ConfigError(f"{context}.pid must be positive")
  return GenericCheck(name, check_type, str(pid), options=(("pid", pid),), **common)


def _parse_service_check(check: Mapping[str, object], context: str, name: str, check_type: str, common: dict[str, object]) -> HealthCheck:
  try:
    service = normalize_service_name(_require_string(check, "service", context))
  except UnitNameError as error:
    raise ConfigError(f"{context}.service is invalid: {error}") from error
  timeout = _parse_timeout(check.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS), f"{context}.timeout_seconds")
  return GenericCheck(name, check_type, service, timeout, **common)


def _parse_file_check(check: Mapping[str, object], context: str, name: str, check_type: str, common: dict[str, object]) -> HealthCheck:
  check_path = _parse_path(check, context)
  options = []
  if check_type == "file_metadata":
    options.extend((
      ("minimum_bytes", _parse_nonnegative_int(check.get("minimum_bytes", 0), f"{context}.minimum_bytes", MAX_FILE_BYTES)),
      ("maximum_bytes", _parse_nonnegative_int(check.get("maximum_bytes", MAX_FILE_BYTES), f"{context}.maximum_bytes", MAX_FILE_BYTES)),
    ))
    if options[0][1] > options[1][1]:
      raise ConfigError(f"{context}.minimum_bytes must not exceed maximum_bytes")
  if check_type == "config_hash":
    digest = _require_string(check, "sha256", context).lower()
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
      raise ConfigError(f"{context}.sha256 must be 64 hexadecimal digits")
    options.append(("sha256", digest))
  return GenericCheck(name, check_type, check_path, options=tuple(options), **common)


# Each type's own fields; name, type, and COMMON_CHECK_FIELDS are allowed for every type.
CHECK_TYPES: dict[str, tuple[frozenset[str], Callable[..., HealthCheck]]] = {
  "disk_free_percent": (frozenset({"path", "minimum_free_percent"}), _parse_disk_check),
  "tcp_connect": (frozenset({"host", "port", "timeout_seconds"}), _parse_tcp_check),
  "http": (frozenset({"url", "timeout_seconds", "expected_status"}), _parse_http_check),
  "https": (frozenset({"url", "timeout_seconds", "expected_status"}), _parse_http_check),
  "dns": (frozenset({"host"}), _parse_dns_check),
  "certificate_expiry": (frozenset({"host", "port", "timeout_seconds", "warn_days", "critical_days"}), _parse_certificate_check),
  "process": (frozenset({"pid"}), _parse_process_check),
  "systemd_service": (frozenset({"service", "timeout_seconds"}), _parse_service_check),
  "file_exists": (frozenset({"path"}), _parse_file_check),
  "file_metadata": (frozenset({"path", "minimum_bytes", "maximum_bytes"}), _parse_file_check),
  "config_hash": (frozenset({"path", "sha256"}), _parse_file_check),
}


def _validate_dependencies(checks: Sequence[HealthCheck], names: set[str]) -> None:
  """Reject unknown, self, and cyclic dependencies."""
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


def parse_config_document(document: object, *, path: str) -> HealthConfig:
  root = _expect_mapping(document, "configuration")
  _reject_unknown_keys(root, {"version", "checks", "max_workers"}, "configuration")
  version = root.get("version")
  if type(version) is not int or version != 1:
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
    name = _parse_check_name(_require_string(check, "name", context), f"{context}.name")
    if name in names:
      raise ConfigError(f"configuration contains duplicate check name: {name}")
    names.add(name)
    check_type = _require_string(check, "type", context)
    common = _common_check_fields(check, context)
    spec = CHECK_TYPES.get(check_type)
    if spec is None:
      raise ConfigError(f"{context}.type is unsupported in V1: {check_type}")
    fields, parse_check = spec
    _reject_unknown_keys(check, {"name", "type"} | fields | COMMON_CHECK_FIELDS, context)
    checks.append(parse_check(check, context, name, check_type, common))
  _validate_dependencies(checks, names)
  return HealthConfig(os.path.abspath(path), tuple(checks), max_workers)


def _strict_json_object(pairs: Sequence[tuple[str, object]]) -> dict[str, object]:
  result = {}
  for key, value in pairs:
    if key in result:
      raise ConfigError(f"configuration JSON contains duplicate object field: {key}")
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
  except ValueError as error:
    raise ConfigError("configuration file contains a JSON value that cannot be parsed safely") from error
  except RecursionError as error:
    raise ConfigError("configuration JSON is nested too deeply") from error
  return parse_config_document(document, path=path)


def call_with_timeout(function: Callable[[], T], timeout: float, description: str) -> T:
  """Run FUNCTION on a daemon thread and wait at most TIMEOUT seconds; a call still blocked is abandoned."""
  outcome: queue.Queue = queue.Queue(maxsize=1)

  def target() -> None:
    try:
      outcome.put((True, function()))
    except BaseException as error:
      outcome.put((False, error))

  threading.Thread(target=target, name=f"healthctl {description}", daemon=True).start()
  try:
    succeeded, value = outcome.get(timeout=timeout)
  except queue.Empty:
    raise ProbeTimeoutError(f"{description} timed out after {timeout:g} s") from None
  if not succeeded:
    raise value
  return value


def resolve_tcp_candidates(
  host: str,
  host_kind: str,
  port: int,
  *,
  resolver: Callable[..., object] = socket.getaddrinfo,
  timeout: float = RESOLVER_TIMEOUT_SECONDS,
  notes: list[str] | None = None,
) -> tuple[Candidate, ...]:
  """Resolve within TIMEOUT; a negative answer raises NetworkFailure and any other failure ObservationError."""
  try:
    resolution = call_with_timeout(
      lambda: resolve_tcp(host, port, host_kind, resolver=resolver), timeout, "name resolution",
    )
  except NetworkAPIError as error:
    raise ObservationError(str(error)) from error
  if resolution.failure is not None:
    raise NetworkFailure(f"name did not resolve ({resolution.failure})")
  if resolution.truncated and notes is not None:
    notes.append(f"resolver returned more than {MAX_CANDIDATES} candidates; only the first {MAX_CANDIDATES} were used")
  return resolution.candidates


def connect_candidates(
  candidates: Sequence[Candidate],
  *,
  timeout: float | None = None,
  deadline: float | None = None,
  socket_factory: Callable[[int, int, int], socket.socket] = socket.socket,
  clock: Callable[[], float] = time.monotonic,
) -> tuple[socket.socket | None, tuple[Attempt, ...]]:
  """Connect to the first reachable candidate, reporting a failure to apply a timeout as an ObservationError."""
  try:
    return connect_first(candidates, timeout=timeout, deadline=deadline, socket_factory=socket_factory, clock=clock)
  except NetworkAPIError as error:
    raise ObservationError(str(error)) from error


def _attempt_detail(outcome: str, number: int | None) -> str:
  return f"{outcome} (errno {number})" if number is not None and outcome == "connection error" else outcome


def _close(client: socket.socket) -> None:
  try:
    client.close()
  except OSError:
    pass


def _errno_name(error: OSError) -> str:
  number = error.errno
  return errno.errorcode.get(number, f"errno {number}") if isinstance(number, int) else type(error).__name__


def _display_path(path: str) -> str:
  """Return PATH made absolute without collapsing '..', which the kernel resolves after symlinks."""
  if os.path.isabs(path):
    return path
  try:
    return os.path.join(os.getcwd(), path)
  except OSError:
    return path


def _percent_text(value: float, threshold: float) -> str:
  """Format VALUE with enough digits that the displayed number does not contradict the threshold comparison."""
  for digits in (2, 4, 6):
    shown = f"{value:.{digits}f}"
    if (float(shown) >= threshold) == (value >= threshold):
      return shown
  return repr(value)


def run_disk_check(
  check: DiskFreeCheck,
  *,
  disk_usage: Callable[[str], object] = shutil.disk_usage,
) -> CheckResult:
  target = _display_path(check.path)
  try:
    usage = call_with_timeout(lambda: disk_usage(check.path), FILESYSTEM_TIMEOUT_SECONDS, "filesystem capacity probe")
  except (OSError, ValueError) as error:
    detail = _errno_name(error) if isinstance(error, OSError) else type(error).__name__
    return CheckResult(check.name, check.type, ERROR, target, f"filesystem capacity could not be observed ({detail})")
  try:
    total = int(usage.total)
    free = int(usage.free)
  except (AttributeError, TypeError, ValueError, OverflowError) as error:
    raise ObservationError("filesystem capacity API returned unsupported values") from error
  if total <= 0 or free < 0 or free > total:
    raise ObservationError("filesystem capacity API returned invalid values")
  percent = (free * 100.0) / total
  passed = percent >= check.minimum_free_percent
  evidence = (
    f"free {_percent_text(percent, check.minimum_free_percent)}% ({free} of {total} bytes); "
    f"required >= {check.minimum_free_percent:g}%"
  )
  return CheckResult(check.name, check.type, PASS if passed else FAIL, target, evidence, OK if passed else check.severity)


def _with_notes(evidence: str, notes: Sequence[str]) -> str:
  return "; ".join((evidence, *notes))


def run_tcp_check(
  check: TcpConnectCheck,
  *,
  resolver: Callable[..., object] = socket.getaddrinfo,
  socket_factory: Callable[[int, int, int], socket.socket] = socket.socket,
) -> CheckResult:
  target = f"[{check.host}]:{check.port}" if check.host_kind == "ipv6" else f"{check.host}:{check.port}"
  notes: list[str] = []
  try:
    candidates = resolve_tcp_candidates(check.host, check.host_kind, check.port, resolver=resolver, notes=notes)
  except NetworkFailure as failure:
    return CheckResult(check.name, check.type, FAIL, target, _with_notes(str(failure), notes), check.severity)
  client, attempts = connect_candidates(candidates, timeout=check.timeout_seconds, socket_factory=socket_factory)
  if client is not None:
    _close(client)
    return CheckResult(
      check.name,
      check.type,
      PASS,
      target,
      _with_notes(
        f"TCP handshake completed to {attempts[-1].candidate.endpoint} after {len(attempts)} attempt(s)", notes,
      ),
      OK,
    )
  if all(attempt.socket_unavailable for attempt in attempts):
    raise ObservationError("could not create a TCP socket for any resolved candidate")
  last = attempts[-1]
  return CheckResult(
    check.name,
    check.type,
    FAIL,
    target,
    _with_notes(
      f"no TCP handshake completed across {len(attempts)} candidate(s); "
      f"last outcome: {_attempt_detail(last.outcome, last.error_number)}",
      notes,
    ),
    check.severity,
  )


def validate_redirect_url(current_url: str, new_url: str) -> str:
  """Resolve and validate a same-origin redirect without consulting proxy state."""
  try:
    destination = urllib.parse.urljoin(current_url, new_url)
    old = urllib.parse.urlsplit(current_url)
    new = urllib.parse.urlsplit(destination)
    old_port = old.port or (443 if old.scheme == "https" else 80)
    new_port = new.port or (443 if new.scheme == "https" else 80)
  except ValueError as exc:
    raise RedirectPolicyError("redirect URL is malformed") from exc
  if URL_RE.fullmatch(destination) is None:
    raise RedirectPolicyError("redirect URL is malformed")
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


def _failure_detail(error: OSError) -> str:
  if isinstance(error, ssl.SSLCertVerificationError):
    return f"certificate verification failed ({error.verify_message or 'no reason given'})"
  outcome, number = classify_connect_error(error)
  return _attempt_detail(outcome, number)


def _connect_tcp_target(
  host: str,
  host_kind: str,
  port: int,
  deadline: float,
  *,
  resolver: Callable[..., object],
  socket_factory: Callable[[int, int, int], socket.socket],
  clock: Callable[[], float],
  notes: list[str] | None = None,
) -> tuple[socket.socket, str]:
  """Connect within DEADLINE, giving each remaining candidate an equal share (at least a floor) of the time left."""
  remaining = deadline - clock()
  if remaining <= 0:
    raise NetworkFailure("the check deadline passed before name resolution")
  candidates = resolve_tcp_candidates(
    host, host_kind, port, resolver=resolver, timeout=min(RESOLVER_TIMEOUT_SECONDS, remaining), notes=notes,
  )
  attempts: list[Attempt] = []
  for index, candidate in enumerate(candidates):
    remaining = deadline - clock()
    if remaining <= 0:
      break
    budget = min(remaining, max(remaining / (len(candidates) - index), CONNECT_ATTEMPT_FLOOR_SECONDS))
    try:
      client, tried = connect_candidates(
        (candidate,), timeout=budget, deadline=deadline, socket_factory=socket_factory, clock=clock,
      )
    except TimeoutError:
      break
    attempts.extend(tried)
    if client is not None:
      return client, candidate.endpoint
  if len(attempts) == len(candidates) and all(attempt.socket_unavailable for attempt in attempts):
    raise ObservationError("could not create a TCP socket for any resolved candidate")
  detail = f"no TCP connection completed across {len(attempts)} of {len(candidates)} candidate(s)"
  if attempts:
    last = attempts[-1]
    detail += f"; last outcome: {_attempt_detail(last.outcome, last.error_number)} at {last.candidate.endpoint}"
  if len(attempts) < len(candidates):
    detail += "; the check deadline passed"
  raise NetworkFailure(detail)


def _parse_http_head(data: bytes) -> tuple[int, str | None]:
  head, separator, _remainder = data.partition(b"\r\n\r\n")
  if not separator or b"\n" in head.replace(b"\r\n", b"") or b"\r" in head.replace(b"\r\n", b""):
    raise ObservationError("HTTP response headers were malformed")
  lines = head.split(b"\r\n")
  # RFC 9112 reason-phrase: HTAB, SP, VCHAR, and obs-text.
  match = re.fullmatch(rb"HTTP/1\.[01] ([0-9]{3})(?: [\t\x20-\x7e\x80-\xff]*)?", lines[0])
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


@functools.lru_cache(maxsize=1)
def default_tls_context() -> ssl.SSLContext:
  """Load the default CA store once; every HTTPS hop and certificate check shares this context."""
  context = ssl.create_default_context()
  # Never write TLS session secrets to a file named by an inherited SSLKEYLOGFILE.
  context.keylog_filename = None
  return context


def _read_http_head(stream: socket.socket, deadline: float, clock: Callable[[], float]) -> tuple[int, str | None]:
  response = bytearray()
  received = 0
  while True:
    while b"\r\n\r\n" not in response:
      stream.settimeout(_deadline_remaining(deadline, clock))
      chunk = stream.recv(min(4096, MAX_HTTP_HEADER_BYTES + 1 - received))
      if not chunk:
        raise ObservationError("HTTP response ended before complete headers")
      response.extend(chunk)
      received += len(chunk)
      if received > MAX_HTTP_HEADER_BYTES:
        raise ObservationError("HTTP response headers exceeded the 64 KiB limit")
    status, location = _parse_http_head(bytes(response))
    # Interim 1xx responses precede the final one (RFC 9110 section 15.2); 101 would be final but is never requested.
    if not 100 <= status <= 199 or status == 101:
      return status, location
    del response[:response.index(b"\r\n\r\n") + 4]


def _one_http_head(
  url: str,
  deadline: float,
  *,
  resolver: Callable[..., object],
  socket_factory: Callable[[int, int, int], socket.socket],
  context_factory: Callable[[], ssl.SSLContext],
  clock: Callable[[], float],
  notes: list[str] | None = None,
) -> tuple[int, str | None]:
  parsed = urllib.parse.urlsplit(url)
  assert parsed.hostname is not None
  host, host_kind = parse_host(parsed.hostname, "HTTP URL host")
  port = parsed.port or (443 if parsed.scheme == "https" else 80)
  client, endpoint = _connect_tcp_target(
    host, host_kind, port, deadline,
    resolver=resolver, socket_factory=socket_factory, clock=clock, notes=notes,
  )
  stream = client
  phase = "TLS handshake"
  try:
    try:
      if parsed.scheme == "https":
        client.settimeout(_deadline_remaining(deadline, clock))
        stream = context_factory().wrap_socket(client, server_hostname=sni_name(host, host_kind) or host)
      phase = "HTTP exchange"
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
      return _read_http_head(stream, deadline, clock)
    except OSError as error:
      raise NetworkFailure(f"{phase} with {endpoint} failed: {_failure_detail(error)}") from error
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
  context_factory: Callable[[], ssl.SSLContext] = default_tls_context,
  clock: Callable[[], float] = time.monotonic,
  notes: list[str] | None = None,
) -> int:
  expected = int(dict(check.options).get("expected_status", 200))
  # Following redirects would hide the 3xx status that the check expects.
  follow_redirects = not 300 <= expected <= 399
  deadline = clock() + check.timeout_seconds
  current = check.target
  redirects = 0
  while True:
    status, location = _one_http_head(
      current, deadline, resolver=resolver, socket_factory=socket_factory,
      context_factory=context_factory, clock=clock, notes=notes,
    )
    if not follow_redirects or status not in REDIRECT_STATUSES or location is None:
      if redirects and notes is not None:
        notes.append(f"followed {redirects} same-origin redirect(s) to {urllib.parse.urlsplit(current).path or '/'}")
      return status
    if redirects == MAX_HTTP_REDIRECTS:
      raise RedirectPolicyError("redirect limit exceeded")
    current = validate_redirect_url(current, location)
    redirects += 1


def _options(check: GenericCheck) -> dict[str, object]:
  return dict(check.options)


def hash_regular_file(path: str, expected_metadata: os.stat_result) -> str:
  try:
    descriptor, before = open_regular_file(path)
  except OSError as error:
    raise ObservationError("file could not be opened safely for hashing") from error
  try:
    if _metadata_identity(before) != _metadata_identity(expected_metadata):
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


def run_silent_command(arguments: Sequence[str], timeout_seconds: float) -> int:
  try:
    result = run_bounded(
      arguments, timeout=timeout_seconds, max_output_bytes=0, capture=False,
      environment=child_environment(SYSTEMD_PAGER="", SYSTEMD_COLORS="0"),
    )
  except ProcessTimeoutError as error:
    raise ObservationError("command exceeded its deadline") from error
  except ProcessSpawnError as error:
    raise ObservationError("command could not be started") from error
  return result.returncode


def _http_check(check: GenericCheck, options: Mapping[str, object]) -> CheckResult:
  notes: list[str] = []
  try:
    status_code = run_http_head(check, notes=notes)
  except NetworkFailure as failure:
    return CheckResult(check.name, check.type, FAIL, check.target, _with_notes(str(failure), notes), check.severity)
  expected = int(options["expected_status"])
  passed = status_code == expected
  evidence = _with_notes(f"HTTP status {status_code}; required {expected}", notes)
  return CheckResult(check.name, check.type, PASS if passed else FAIL, check.target, evidence, OK if passed else check.severity)


def _dns_check(check: GenericCheck, options: Mapping[str, object]) -> CheckResult:
  notes: list[str] = []
  try:
    _, host_kind = parse_host(check.target, "DNS host")
    candidates = resolve_tcp_candidates(
      check.target, host_kind, DNS_PROBE_PORT, resolver=socket.getaddrinfo, notes=notes,
    )
  except NetworkFailure as failure:
    return CheckResult(check.name, check.type, FAIL, check.target, _with_notes(str(failure), notes), check.severity)
  addresses = sorted({candidate.sockaddr[0] for candidate in candidates})
  evidence = _with_notes(f"resolved addresses: {', '.join(addresses)}", notes)
  return CheckResult(check.name, check.type, PASS, check.target, evidence, OK)


def _certificate_check(check: GenericCheck, options: Mapping[str, object]) -> CheckResult:
  host, port = str(options["host"]), int(options["port"])
  notes: list[str] = []
  try:
    deadline = time.monotonic() + check.timeout_seconds
    context = default_tls_context()
    _, host_kind = parse_host(host, "certificate host")
    tcp, _endpoint = _connect_tcp_target(
      host, host_kind, port, deadline, resolver=socket.getaddrinfo,
      socket_factory=socket.socket, clock=time.monotonic, notes=notes,
    )
    with tcp:
      tcp.settimeout(_deadline_remaining(deadline, time.monotonic))
      with context.wrap_socket(tcp, server_hostname=sni_name(host, host_kind) or host) as tls:
        certificate = tls.getpeercert()
    not_after = certificate.get("notAfter")
    if not isinstance(not_after, str):
      raise ValueError
    remaining = ssl.cert_time_to_seconds(not_after) - time.time()
  except ssl.SSLCertVerificationError as error:
    code = getattr(error, "verify_code", None)
    message = getattr(error, "verify_message", None) or type(error).__name__
    if code == X509_V_ERR_CERT_HAS_EXPIRED:
      finding, severity = f"certificate has expired ({message})", CRITICAL
    elif code == X509_V_ERR_CERT_NOT_YET_VALID:
      finding, severity = f"certificate is not yet valid ({message})", CRITICAL
    else:
      finding, severity = f"certificate verification failed ({message})", check.severity
    return CheckResult(check.name, check.type, FAIL, check.target, _with_notes(f"{finding}; revocation not checked", notes), severity)
  except (NetworkFailure, ObservationError) as error:
    evidence = f"trusted TLS certificate observation failed: {error}; revocation not checked"
    return CheckResult(check.name, check.type, ERROR, check.target, _with_notes(evidence, notes))
  except (OSError, ValueError) as error:
    detail = _failure_detail(error) if isinstance(error, OSError) else type(error).__name__
    evidence = f"trusted TLS certificate observation failed: {detail}; revocation not checked"
    return CheckResult(check.name, check.type, ERROR, check.target, _with_notes(evidence, notes))
  days = remaining / 86400
  critical, warn = int(options["critical_days"]), int(options["warn_days"])
  if days < critical:
    status, severity = FAIL, CRITICAL
  elif days < warn:
    status, severity = FAIL, WARNING
  else:
    status, severity = PASS, OK
  evidence = _with_notes(f"trusted certificate expires in {days:.2f} days; revocation not checked", notes)
  return CheckResult(check.name, check.type, status, check.target, evidence, severity)


def read_process_status(pid: int) -> dict[bytes, bytes]:
  """Return the fields of /proc/PID/status, read through one bounded no-follow descriptor."""
  descriptor = os.open(f"/proc/{pid}/status", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
  try:
    chunks = []
    size = 0
    while True:
      chunk = os.read(descriptor, 8192)
      if not chunk:
        break
      size += len(chunk)
      if size > PROC_STATUS_MAX_BYTES:
        raise ObservationError(f"process status exceeded the {PROC_STATUS_MAX_BYTES}-byte limit")
      chunks.append(chunk)
  finally:
    os.close(descriptor)
  fields: dict[bytes, bytes] = {}
  for line in b"".join(chunks).split(b"\n"):
    name, separator, value = line.partition(b":")
    if separator:
      fields.setdefault(name, value.strip())
  return fields


def _process_check(check: GenericCheck, options: Mapping[str, object]) -> CheckResult:
  pid = int(options["pid"])
  try:
    fields = read_process_status(pid)
  except OSError as error:
    if error.errno in {errno.ENOENT, errno.ESRCH}:
      return CheckResult(check.name, check.type, FAIL, check.target, "no process with this PID was observed", check.severity)
    return CheckResult(check.name, check.type, ERROR, check.target, f"process status could not be read ({_errno_name(error)})")
  thread_group, state = fields.get(b"Tgid", b""), fields.get(b"State", b"")
  if not thread_group.isdigit() or not state[:1].isalpha():
    raise ObservationError("process status lacked a valid Tgid or State field")
  if int(thread_group) != pid:
    return CheckResult(check.name, check.type, FAIL, check.target, f"PID is a thread of process {int(thread_group)}, not a process", check.severity)
  if state[:1] in {b"Z", b"X"}:
    return CheckResult(check.name, check.type, FAIL, check.target, "process has exited and was not yet reaped (zombie)", check.severity)
  return CheckResult(check.name, check.type, PASS, check.target, f"process is alive (state {state[:1].decode('ascii')})", OK)


def _service_check(check: GenericCheck, options: Mapping[str, object]) -> CheckResult:
  systemctl = resolve_executable("systemctl")
  if systemctl is None:
    return CheckResult(check.name, check.type, ERROR, check.target, "systemctl was not found in a trusted PATH directory")
  try:
    return_code = run_silent_command(
      [systemctl, "is-active", "--system", "--quiet", "--", check.target],
      check.timeout_seconds,
    )
  except ObservationError as error:
    return CheckResult(check.name, check.type, ERROR, check.target, f"systemd state could not be observed: {error}")
  if return_code == 0:
    return CheckResult(check.name, check.type, PASS, check.target, "service is active", OK)
  if return_code in {3, 4}:
    return CheckResult(check.name, check.type, FAIL, check.target, f"service is not active (status {return_code})", check.severity)
  return CheckResult(check.name, check.type, ERROR, check.target, f"systemctl could not determine the service state (status {return_code})")


def _file_check(check: GenericCheck, options: Mapping[str, object]) -> CheckResult:
  path = _display_path(check.target)
  try:
    metadata = call_with_timeout(lambda: os.lstat(check.target), FILESYSTEM_TIMEOUT_SECONDS, "file metadata probe")
  except OSError as error:
    if error.errno in {errno.ENOENT, errno.ENOTDIR}:
      return CheckResult(check.name, check.type, FAIL, path, "path does not exist", check.severity)
    return CheckResult(check.name, check.type, ERROR, path, f"path could not be observed ({_errno_name(error)})")
  if stat.S_ISLNK(metadata.st_mode):
    return CheckResult(check.name, check.type, ERROR, path, "final-component symlinks are not followed")
  if check.type == "file_exists":
    return CheckResult(check.name, check.type, PASS, path, "path exists", OK)
  if not stat.S_ISREG(metadata.st_mode):
    return CheckResult(check.name, check.type, FAIL, path, "path is not a regular file", check.severity)
  if check.type == "file_metadata":
    minimum, maximum = int(options["minimum_bytes"]), int(options["maximum_bytes"])
    passed = minimum <= metadata.st_size <= maximum
    return CheckResult(check.name, check.type, PASS if passed else FAIL, path, f"size {metadata.st_size} bytes; required {minimum}-{maximum}", OK if passed else check.severity)
  try:
    observed_digest = call_with_timeout(
      lambda: hash_regular_file(check.target, metadata), FILESYSTEM_TIMEOUT_SECONDS, "file hash probe",
    )
  except ObservationError as error:
    return CheckResult(check.name, check.type, ERROR, path, str(error))
  passed = observed_digest == options["sha256"]
  return CheckResult(check.name, check.type, PASS if passed else FAIL, path, f"SHA-256 {'matched' if passed else 'did not match'}", OK if passed else check.severity)


GENERIC_CHECK_RUNNERS = {
  "http": _http_check,
  "https": _http_check,
  "dns": _dns_check,
  "certificate_expiry": _certificate_check,
  "process": _process_check,
  "systemd_service": _service_check,
  "file_exists": _file_check,
  "file_metadata": _file_check,
  "config_hash": _file_check,
}


def run_generic_check(check: GenericCheck) -> CheckResult:
  runner = GENERIC_CHECK_RUNNERS.get(check.type)
  if runner is None:
    raise ObservationError("configuration produced an unsupported generic check type")
  return runner(check, _options(check))


def _error_result(check: HealthCheck, error: Exception) -> CheckResult:
  if isinstance(error, ObservationError):
    evidence = str(error)
  elif isinstance(error, OSError):
    evidence = f"operating-system observation failed ({type(error).__name__})"
  else:
    evidence = f"check could not be evaluated ({type(error).__name__})"
  return CheckResult(check.name, check.type, ERROR, _check_target(check), evidence)


def run_check(check: HealthCheck) -> CheckResult:
  started = time.monotonic()
  result = None
  attempts = 0
  for attempts in range(1, check.retries + 2):
    if attempts > 1:
      time.sleep(min(RETRY_BACKOFF_SECONDS * (attempts - 1), MAX_RETRY_BACKOFF_SECONDS))
    try:
      if isinstance(check, DiskFreeCheck):
        result = run_disk_check(check)
      elif isinstance(check, TcpConnectCheck):
        result = run_tcp_check(check)
      elif isinstance(check, GenericCheck):
        result = run_generic_check(check)
      else:
        raise ObservationError("configuration produced an unsupported check type")
    except Exception as error:
      result = _error_result(check, error)
    if result.status == PASS:
      break
  assert result is not None
  if result.status == PASS:
    severity = OK
  elif result.status == FAIL:
    severity = result.severity if result.severity in {WARNING, CRITICAL} else check.severity
  else:
    severity = None
  return replace(result, severity=severity, elapsed_seconds=time.monotonic() - started, attempts=attempts)


def evaluate_config(
  config: HealthConfig,
  *,
  executor: Callable[[HealthCheck], CheckResult] = run_check,
) -> tuple[CheckResult, ...]:
  """Run each check on a daemon thread once its dependencies finish, at most max_workers at a time.

  The caller's thread only waits for results, so an interrupt stops scheduling at once: queued checks never
  start, and running ones are abandoned rather than joined.
  """
  finished: queue.Queue = queue.Queue()
  completed: dict[str, CheckResult] = {}
  waiting = list(config.checks)
  running = 0

  def work(check: HealthCheck) -> None:
    result = None
    try:
      result = executor(check)
    except Exception as error:
      result = _error_result(check, error)
    finally:
      finished.put((check, result))

  while True:
    progressed = True
    while progressed:
      progressed = False
      for check in list(waiting):
        if not all(name in completed for name in check.depends_on):
          continue
        unmet = [name for name in check.depends_on if completed[name].status != PASS]
        if unmet:
          completed[check.name] = CheckResult(
            check.name, check.type, SKIPPED, _check_target(check),
            f"dependency did not pass: {', '.join(unmet)}", attempts=0,
          )
        elif running < config.max_workers:
          threading.Thread(target=work, args=(check,), name=f"healthctl check {check.name}", daemon=True).start()
          running += 1
        else:
          continue
        waiting.remove(check)
        progressed = True
    if not running:
      break
    check, result = finished.get()
    running -= 1
    if (
      not isinstance(result, CheckResult) or result.name != check.name or result.type != check.type
      or result.status not in {PASS, FAIL, ERROR, SKIPPED}
    ):
      raise ObservationError("check executor returned an invalid result")
    completed[check.name] = result
  if waiting:
    raise ObservationError("check dependency graph contains a cycle")
  order = {check.name: index for index, check in enumerate(config.checks)}
  return tuple(sorted(completed.values(), key=lambda result: order[result.name]))


def _check_target(check: HealthCheck) -> str:
  if isinstance(check, DiskFreeCheck):
    return _display_path(check.path)
  if isinstance(check, TcpConnectCheck):
    return f"[{check.host}]:{check.port}" if check.host_kind == "ipv6" else f"{check.host}:{check.port}"
  if isinstance(check, GenericCheck):
    return _display_path(check.target) if check.type.startswith("file_") or check.type == "config_hash" else check.target
  return "unknown"


def render_report(config: HealthConfig, results: Sequence[CheckResult]) -> str:
  passes = sum(result.status == PASS for result in results)
  failures = sum(result.status == FAIL for result in results)
  errors = sum(result.status == ERROR for result in results)
  skipped = sum(result.status == SKIPPED for result in results)
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
      f"     Severity: {result.severity or '-'}",
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
    f"  SKIPPED: {skipped}",
    "",
    "Interpretation limits",
    "  PASS means only that the caller-configured criterion was satisfied during this invocation.",
    "  FAIL means the configured criterion was observed and was not satisfied; its severity is WARNING or CRITICAL.",
    "  ERROR means that criterion could not be evaluated trustworthily; it carries no severity.",
    "  SKIPPED means the check was not run because a dependency did not pass.",
    "  These results do not prove overall host, application, or service health or identify root cause.",
  ))
  return "\n".join(lines)


def aggregate_status(results: Sequence[CheckResult]) -> str:
  """Return the worst FAIL severity; without a FAIL, OK, INCOMPLETE, or ERROR (when nothing was evaluated)."""
  failed = [result.severity for result in results if result.status == FAIL]
  if failed:
    return WARNING if all(severity == WARNING for severity in failed) else CRITICAL
  if all(result.status == PASS for result in results):
    return OK
  return INCOMPLETE if any(result.status == PASS for result in results) else ERROR


def result_exit_code(results: Sequence[CheckResult]) -> int:
  return AGGREGATE_EXIT_CODES[aggregate_status(results)]


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
    return EXIT_USAGE
  except KeyboardInterrupt:
    print_safe("healthctl: interrupted", file=sys.stderr)
    return EXIT_INTERRUPTED
  except ObservationError as error:
    print_safe(f"healthctl: observation error: {display_safe(error)}", file=sys.stderr)
    return EXIT_FAILURE
  except Exception:
    print_safe("healthctl: internal error: unexpected failure", file=sys.stderr)
    return EXIT_FAILURE
  status = aggregate_status(results)
  summary = {
    "pass": sum(result.status == PASS for result in results),
    "fail_warning": sum(result.status == FAIL and result.severity == WARNING for result in results),
    "fail_critical": sum(result.status == FAIL and result.severity != WARNING for result in results),
    "error": sum(result.status == ERROR for result in results),
    "skipped": sum(result.status == SKIPPED for result in results),
  }
  finding = (
    f"{summary['pass']} of {len(results)} checks passed; {summary['fail_critical']} critical and "
    f"{summary['fail_warning']} warning failure(s); {summary['error']} error(s)"
  )
  if summary["skipped"]:
    finding += f"; {summary['skipped']} skipped"
  next_action = {
    OK: "all selected criteria passed during this invocation",
    WARNING: "review failed checks in dependency order",
    CRITICAL: "review failed checks in dependency order",
    INCOMPLETE: "resolve the errors and rerun; errored and skipped criteria were not evaluated",
    ERROR: "resolve the errors and rerun; no selected criterion could be evaluated",
  }[status]
  conclusion = make_conclusion(status, config.path, finding, next_action)
  record = OutputRecord(
    tool="healthctl", status=status, target=config.path,
    observations={
      "checks": results,
      "summary": summary,
      "profile": args.profile, "group": args.group, "max_workers": config.max_workers,
    },
    conclusion=conclusion, next_action=next_action + ".",
    warnings=tuple(
      f"{result.status} {result.name}: {result.evidence}" for result in results if result.status in {ERROR, SKIPPED}
    ),
    elapsed_seconds=time.monotonic() - started,
  )
  brief = "\n".join([
    f"Configuration: {display_safe(config.path)}",
    f"Checks: {len(results)}",
    f"PASS/FAIL/ERROR/SKIPPED: {summary['pass']}/{summary['fail_warning'] + summary['fail_critical']}/{summary['error']}/{summary['skipped']}",
    *(
      f"  [{result.status}] {display_safe(result.name)}{f' ({result.severity})' if result.status == FAIL else ''}: "
      f"{display_safe(result.evidence)}"
      for result in results if result.status != PASS
    ),
  ])
  try:
    emit_output(
      record, detailed=report, brief=brief, json_mode=args.json,
      brief_mode=args.brief, quiet=args.quiet,
      output_path=args.output, force=args.force, stdout=sys.stdout,
    )
  except OutputError as error:
    print_safe(f"healthctl: output error: {display_safe(error)}", file=sys.stderr)
    return EXIT_FAILURE
  except KeyboardInterrupt:
    print_safe("healthctl: interrupted", file=sys.stderr)
    return EXIT_INTERRUPTED
  return result_exit_code(results)


if __name__ == "__main__":
  try:
    raise SystemExit(main())
  except KeyboardInterrupt:
    print_safe("healthctl: interrupted", file=sys.stderr)
    raise SystemExit(EXIT_INTERRUPTED)
