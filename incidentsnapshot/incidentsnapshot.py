#!/usr/bin/env python3
"""Capture a bounded, privacy-minimized local Linux incident snapshot."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP, localcontext
import errno
import ipaddress
import json
import os
import re
import socket
import stat
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


UPTIME_PATH = "/proc/uptime"
LOADAVG_PATH = "/proc/loadavg"
MEMINFO_PATH = "/proc/meminfo"
PSI_PATHS = (("cpu", "/proc/pressure/cpu"), ("memory", "/proc/pressure/memory"), ("io", "/proc/pressure/io"))
ROUTE_PATH = "/proc/net/route"
IPV6_ROUTE_PATH = "/proc/net/ipv6_route"
SOCKET_PATHS = (("tcp", "/proc/net/tcp"), ("tcp6", "/proc/net/tcp6"), ("udp", "/proc/net/udp"), ("udp6", "/proc/net/udp6"))
PROC_STAT_PATH = "/proc/stat"
KERNEL_TAINT_PATH = "/proc/sys/kernel/tainted"
UPTIME_MAX_BYTES = 4096
LOADAVG_MAX_BYTES = 4096
MEMINFO_MAX_BYTES = 65536
MEMINFO_MAX_RECORDS = 256
PLATFORM_MAX_CODEPOINTS = 256
MAX_CALCULATED_BYTES = (1 << 127) - 1
READ_CHUNK_BYTES = 4096
MAX_INTERFACES = 128
MAX_ROUTES = 256
MAX_LISTENERS = 512
MAX_PROCESSES = 32768
MAX_TOP = 20
SECTION_MAX_BYTES = 128 * 1024
DECIMAL_RE = re.compile(rb"[0-9]{1,20}(?:\.[0-9]{1,9})?\Z", re.ASCII)
INTEGER_RE = re.compile(rb"[0-9]{1,20}\Z", re.ASCII)
MEMINFO_RE = re.compile(rb"([A-Za-z][A-Za-z0-9_()]*):[ \t]*([^\r\n]*)\Z", re.ASCII)
MEMINFO_VALUE_RE = re.compile(rb"([0-9]{1,20})[ \t]+kB\Z", re.ASCII)
REQUIRED_MEMORY_FIELDS = (b"MemTotal", b"MemAvailable", b"SwapTotal", b"SwapFree")
IEC_UNITS = ("B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB")


class ObservationError(Exception):
  """A mandatory observation or report cannot be trusted."""

  def __init__(self, section: str, reason: str):
    super().__init__(reason)
    self.section = section
    self.reason = reason


class SectionUnavailable(Exception):
  """A best-effort section could not be observed trustworthily."""

  def __init__(self, reason: str):
    super().__init__(reason)
    self.reason = reason


class UnsupportedPlatform(Exception):
  """The current platform is outside the Linux-only V1 contract."""


@dataclass(frozen=True)
class ObservationWindow:
  started_utc: datetime
  finished_utc: datetime
  elapsed_ns: int


@dataclass(frozen=True)
class PlatformObservation:
  system: str
  release: str
  machine: str


@dataclass(frozen=True)
class RuntimeObservation:
  uptime: Decimal
  load_1m: Decimal
  load_5m: Decimal
  load_15m: Decimal
  cpu_count: int | None = None


@dataclass(frozen=True)
class MemoryObservation:
  total: int
  available: int
  swap_total: int
  swap_free: int


@dataclass(frozen=True)
class FilesystemObservation:
  total: int
  used: int
  available: int


@dataclass(frozen=True)
class SectionObservation:
  name: str
  status: str
  value: object | None = None
  reason: str | None = None


@dataclass(frozen=True)
class OptionalObservation:
  value: object | None = None
  reason: str | None = None

  @property
  def observed(self) -> bool:
    return self.reason is None


@dataclass(frozen=True)
class SnapshotResult:
  window: ObservationWindow
  platform: PlatformObservation
  runtime: RuntimeObservation
  memory: OptionalObservation
  filesystem: OptionalObservation
  profile: str = "basic"
  sections: tuple[SectionObservation, ...] = ()


def build_argument_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(
    prog="incidentsnapshot",
    description="Capture bounded, low-sensitivity local Linux incident context.",
  )
  parser.add_argument(
    "--profile", choices=("basic", "network", "process", "full"), default="basic",
    help="collection profile (default: basic)",
  )
  parser.add_argument(
    "--top", type=parse_top, default=5, metavar="N",
    help=f"maximum processes per ranking (1-{MAX_TOP}; default: 5)",
  )
  add_output_arguments(parser)
  return parser


def parse_top(value: str) -> int:
  if not value.isascii() or not value.isdecimal() or not 1 <= int(value, 10) <= MAX_TOP:
    raise argparse.ArgumentTypeError(f"top must be from 1 through {MAX_TOP}")
  return int(value, 10)


def display_safe(value: object) -> str:
  """Escape controls and presentation characters in externally derived text."""
  rendered = []
  for character in str(value):
    codepoint = ord(character)
    category = unicodedata.category(character)
    if character == "\\":
      rendered.append("\\\\")
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


def write_safe(value: object, *, file: object) -> None:
  file.write(stream_safe(value, file))


def write_best_effort(value: object, *, file: object) -> None:
  """Emit a terminal-safe diagnostic without allowing stream failure to escape."""
  try:
    write_safe(value, file=file)
  except Exception:
    pass


def _reason_for_os_error(error: OSError) -> str:
  if isinstance(error, PermissionError) or error.errno in {errno.EACCES, errno.EPERM}:
    return "permission denied"
  if isinstance(error, FileNotFoundError) or error.errno == errno.ENOENT:
    return "source unavailable"
  return "observation failed"


def _open_flags() -> int:
  flags = os.O_RDONLY
  flags |= getattr(os, "O_CLOEXEC", 0)
  flags |= getattr(os, "O_NOFOLLOW", 0)
  flags |= getattr(os, "O_NONBLOCK", 0)
  return flags


def read_bounded_ascii(path: str, limit: int) -> bytes:
  """Read at most limit + 1 bytes from an allowlisted procfs regular file."""
  try:
    descriptor = os.open(path, _open_flags())
  except OSError as error:
    raise SectionUnavailable(_reason_for_os_error(error)) from error
  try:
    try:
      metadata = os.fstat(descriptor)
    except OSError as error:
      raise SectionUnavailable(_reason_for_os_error(error)) from error
    if not stat.S_ISREG(metadata.st_mode):
      raise SectionUnavailable("unsupported data shape")

    chunks = []
    observed = 0
    while observed <= limit:
      try:
        chunk = os.read(descriptor, min(READ_CHUNK_BYTES, limit + 1 - observed))
      except OSError as error:
        raise SectionUnavailable(_reason_for_os_error(error)) from error
      if not chunk:
        break
      chunks.append(chunk)
      observed += len(chunk)
    if observed > limit:
      raise SectionUnavailable("source exceeds V1 byte limit")
    data = b"".join(chunks)
    if b"\x00" in data:
      raise SectionUnavailable("malformed data")
    try:
      data.decode("ascii")
    except UnicodeDecodeError as error:
      raise SectionUnavailable("malformed data") from error
    return data
  finally:
    try:
      os.close(descriptor)
    except OSError:
      pass


def _parse_decimal(token: bytes) -> Decimal:
  if not DECIMAL_RE.fullmatch(token):
    if re.fullmatch(rb"[0-9]+(?:\.[0-9]+)?", token) and (
      len(token.partition(b".")[0]) > 20 or len(token.partition(b".")[2]) > 9
    ):
      raise SectionUnavailable("numeric value exceeds V1 limit")
    raise SectionUnavailable("malformed data")
  value = Decimal(token.decode("ascii"))
  if not value.is_finite() or value < 0:
    raise SectionUnavailable("malformed data")
  return value


def parse_uptime(data: bytes) -> Decimal:
  tokens = data.split()
  if not tokens:
    raise SectionUnavailable("malformed data")
  return _parse_decimal(tokens[0])


def parse_loadavg(data: bytes) -> tuple[Decimal, Decimal, Decimal]:
  tokens = data.split()
  if len(tokens) < 3:
    raise SectionUnavailable("malformed data")
  return (_parse_decimal(tokens[0]), _parse_decimal(tokens[1]), _parse_decimal(tokens[2]))


def parse_meminfo(data: bytes) -> MemoryObservation:
  records = [record for record in data.splitlines() if record.strip()]
  if len(records) > MEMINFO_MAX_RECORDS:
    raise SectionUnavailable("record count exceeds V1 limit")
  values: dict[bytes, int] = {}
  for record in records:
    match = MEMINFO_RE.fullmatch(record)
    if match is None:
      raise SectionUnavailable("malformed data")
    key, raw_value = match.groups()
    if key not in REQUIRED_MEMORY_FIELDS:
      continue
    if key in values:
      raise SectionUnavailable("malformed data")
    value_match = MEMINFO_VALUE_RE.fullmatch(raw_value)
    if value_match is None:
      digits = raw_value.split(None, 1)[0] if raw_value.split() else b""
      if INTEGER_RE.fullmatch(digits) is None and digits.isdigit() and len(digits) > 20:
        raise SectionUnavailable("numeric value exceeds V1 limit")
      raise SectionUnavailable("malformed data")
    kibibytes = int(value_match.group(1))
    byte_value = kibibytes * 1024
    if byte_value > MAX_CALCULATED_BYTES:
      raise SectionUnavailable("numeric value exceeds V1 limit")
    values[key] = byte_value
  if any(key not in values for key in REQUIRED_MEMORY_FIELDS):
    raise SectionUnavailable("malformed data")
  total = values[b"MemTotal"]
  available = values[b"MemAvailable"]
  swap_total = values[b"SwapTotal"]
  swap_free = values[b"SwapFree"]
  if total <= 0 or available > total or swap_free > swap_total:
    raise SectionUnavailable("malformed data")
  return MemoryObservation(total, available, swap_total, swap_free)


def _platform_field(value: object) -> str:
  if not isinstance(value, str):
    raise ObservationError("platform", "unsupported data shape")
  if not value or "\x00" in value:
    raise ObservationError("platform", "malformed data")
  if len(value) > PLATFORM_MAX_CODEPOINTS:
    raise ObservationError("platform", "numeric value exceeds V1 limit")
  return value


def collect_platform(uname_provider: Callable[[], object] = os.uname) -> PlatformObservation:
  try:
    result = uname_provider()
    system = _platform_field(getattr(result, "sysname"))
    release = _platform_field(getattr(result, "release"))
    machine = _platform_field(getattr(result, "machine"))
  except ObservationError:
    raise
  except (AttributeError, TypeError) as error:
    raise ObservationError("platform", "unsupported data shape") from error
  except OSError as error:
    raise ObservationError("platform", _reason_for_os_error(error)) from error
  if system != "Linux":
    raise UnsupportedPlatform
  return PlatformObservation(system, release, machine)


def collect_runtime(reader: Callable[[str, int], bytes] = read_bounded_ascii) -> RuntimeObservation:
  try:
    uptime = parse_uptime(reader(UPTIME_PATH, UPTIME_MAX_BYTES))
    loads = parse_loadavg(reader(LOADAVG_PATH, LOADAVG_MAX_BYTES))
  except SectionUnavailable as error:
    raise ObservationError("runtime", error.reason) from error
  cpu_count = os.cpu_count()
  if not isinstance(cpu_count, int) or isinstance(cpu_count, bool) or cpu_count < 1:
    cpu_count = None
  return RuntimeObservation(uptime, *loads, cpu_count)


def collect_memory(reader: Callable[[str, int], bytes] = read_bounded_ascii) -> MemoryObservation:
  return parse_meminfo(reader(MEMINFO_PATH, MEMINFO_MAX_BYTES))


def collect_root_filesystem(
  statvfs_provider: Callable[[str], object] = os.statvfs,
) -> FilesystemObservation:
  try:
    result = statvfs_provider("/")
  except OSError as error:
    raise SectionUnavailable(_reason_for_os_error(error)) from error
  try:
    fragment_size = result.f_frsize
    block_size = result.f_bsize
    blocks = result.f_blocks
    free_blocks = result.f_bfree
    available_blocks = result.f_bavail
  except AttributeError as error:
    raise SectionUnavailable("unsupported data shape") from error
  fields = (fragment_size, block_size, blocks, free_blocks, available_blocks)
  if any(not isinstance(value, int) or isinstance(value, bool) for value in fields):
    raise SectionUnavailable("unsupported data shape")
  effective_size = fragment_size if fragment_size > 0 else block_size
  if effective_size <= 0 or not (blocks >= free_blocks >= available_blocks >= 0):
    raise SectionUnavailable("malformed data")
  calculated = (blocks * effective_size, free_blocks * effective_size, available_blocks * effective_size)
  if any(value > MAX_CALCULATED_BYTES for value in calculated):
    raise SectionUnavailable("numeric value exceeds V1 limit")
  total, free, available = calculated
  used = total - free
  if used + available == 0:
    raise SectionUnavailable("malformed data")
  return FilesystemObservation(total, used, available)


def collect_pressure(reader: Callable[[str, int], bytes] = read_bounded_ascii) -> tuple[dict[str, object], ...]:
  observations = []
  for resource, path in PSI_PATHS:
    data = reader(path, 4096)
    metrics: dict[str, object] = {"resource": resource}
    records = data.decode("ascii").splitlines()
    if not records or len(records) > 4:
      raise SectionUnavailable("malformed pressure data")
    for record in records:
      fields = record.split()
      if not fields or fields[0] not in {"some", "full"}:
        raise SectionUnavailable("malformed pressure data")
      scope = fields[0]
      parsed = {}
      for field in fields[1:]:
        key, separator, raw = field.partition("=")
        if not separator or key not in {"avg10", "avg60", "avg300", "total"}:
          raise SectionUnavailable("malformed pressure data")
        try:
          parsed[key] = int(raw) if key == "total" else float(raw)
        except ValueError as error:
          raise SectionUnavailable("malformed pressure data") from error
      if set(parsed) != {"avg10", "avg60", "avg300", "total"}:
        raise SectionUnavailable("malformed pressure data")
      metrics[scope] = parsed
    observations.append(metrics)
  return tuple(observations)


def collect_inode_summary(statvfs_provider: Callable[[str], object] = os.statvfs) -> dict[str, int]:
  try:
    result = statvfs_provider("/")
    total = result.f_files
    free = result.f_ffree
  except (OSError, AttributeError) as error:
    raise SectionUnavailable(_reason_for_os_error(error) if isinstance(error, OSError) else "unsupported data shape") from error
  if any(not isinstance(value, int) or isinstance(value, bool) for value in (total, free)) or total < 0 or not 0 <= free <= total:
    raise SectionUnavailable("malformed data")
  return {"total": total, "used": total - free, "free": free}


def _safe_interface_name(name: str) -> str:
  if not name or len(name) > 64 or name in {".", ".."} or "/" in name or "\x00" in name:
    raise SectionUnavailable("unsupported interface name")
  return display_safe(name)


def collect_interfaces(reader: Callable[[str, int], bytes] = read_bounded_ascii) -> tuple[dict[str, object], ...]:
  try:
    with os.scandir("/sys/class/net") as entries:
      names = []
      for entry in entries:
        if len(names) >= MAX_INTERFACES:
          raise SectionUnavailable("interface count exceeds limit")
        names.append(entry.name)
      names.sort()
  except OSError as error:
    raise SectionUnavailable(_reason_for_os_error(error)) from error
  observations = []
  for raw_name in names:
    name = _safe_interface_name(raw_name)
    try:
      state = reader(f"/sys/class/net/{raw_name}/operstate", 64).decode("ascii").strip()
      mtu_raw = reader(f"/sys/class/net/{raw_name}/mtu", 64).decode("ascii").strip()
      if state not in {"unknown", "notpresent", "down", "lowerlayerdown", "testing", "dormant", "up"}:
        raise SectionUnavailable("malformed interface state")
      if not mtu_raw.isdecimal() or not 0 <= int(mtu_raw) <= (1 << 31) - 1:
        raise SectionUnavailable("malformed interface MTU")
      observations.append({"name": name, "state": state, "mtu": int(mtu_raw)})
    except SectionUnavailable as error:
      observations.append({"name": name, "status": "unavailable", "reason": error.reason})
  return tuple(observations)


def _ipv4_from_proc_hex(raw: str) -> str:
  if re.fullmatch(r"[0-9A-Fa-f]{8}", raw) is None:
    raise SectionUnavailable("malformed route data")
  return str(ipaddress.IPv4Address(bytes.fromhex(raw)[::-1]))


def collect_routes(reader: Callable[[str, int], bytes] = read_bounded_ascii) -> tuple[dict[str, str], ...]:
  routes = []
  data = reader(ROUTE_PATH, SECTION_MAX_BYTES).decode("ascii")
  lines = data.splitlines()
  if len(lines) > MAX_ROUTES + 1:
    raise SectionUnavailable("route count exceeds limit")
  for line in lines[1:]:
    fields = line.split()
    if len(fields) < 8:
      raise SectionUnavailable("malformed route data")
    if fields[1] == "00000000" and fields[7] == "00000000":
      routes.append({"family": "IPv4", "interface": display_safe(_safe_interface_name(fields[0])), "gateway": _ipv4_from_proc_hex(fields[2])})
  try:
    ipv6_data = reader(IPV6_ROUTE_PATH, SECTION_MAX_BYTES).decode("ascii")
  except SectionUnavailable:
    ipv6_data = ""
  ipv6_lines = ipv6_data.splitlines()
  if len(ipv6_lines) > MAX_ROUTES:
    raise SectionUnavailable("route count exceeds limit")
  for line in ipv6_lines:
    fields = line.split()
    if len(fields) < 10:
      raise SectionUnavailable("malformed IPv6 route data")
    if fields[0] == "0" * 32 and fields[1] == "00":
      try:
        gateway = str(ipaddress.IPv6Address(bytes.fromhex(fields[4])))
      except (ValueError, ipaddress.AddressValueError) as error:
        raise SectionUnavailable("malformed IPv6 route data") from error
      routes.append({"family": "IPv6", "interface": display_safe(_safe_interface_name(fields[-1])), "gateway": gateway})
  unique_routes = []
  seen_routes = set()
  for route in routes:
    identity = (route["family"], route["interface"], route["gateway"])
    if identity not in seen_routes:
      seen_routes.add(identity)
      unique_routes.append(route)
  return tuple(unique_routes[:MAX_ROUTES])


def _bind_scope(raw_address: str, family: str) -> str:
  if set(raw_address) == {"0"}:
    return "wildcard"
  if family == "IPv4" and raw_address.upper() == "0100007F":
    return "loopback"
  if family == "IPv6" and raw_address.upper() == "00000000000000000000000001000000":
    return "loopback"
  return "specific"


def collect_listeners(reader: Callable[[str, int], bytes] = read_bounded_ascii) -> tuple[dict[str, object], ...]:
  listeners = []
  for protocol, path in SOCKET_PATHS:
    lines = reader(path, SECTION_MAX_BYTES).decode("ascii").splitlines()
    for line in lines[1:]:
      fields = line.split()
      if len(fields) < 4:
        raise SectionUnavailable("malformed socket table")
      if protocol.startswith("tcp") and fields[3] != "0A":
        continue
      raw_address, separator, raw_port = fields[1].rpartition(":")
      if not separator or re.fullmatch(r"[0-9A-Fa-f]{4}", raw_port) is None:
        raise SectionUnavailable("malformed socket table")
      family = "IPv6" if protocol.endswith("6") else "IPv4"
      listeners.append({"protocol": protocol.rstrip("6").upper(), "family": family, "port": int(raw_port, 16), "bind_scope": _bind_scope(raw_address, family)})
      if len(listeners) > MAX_LISTENERS:
        raise SectionUnavailable("listener count exceeds limit")
  unique = {
    (str(item["protocol"]), str(item["family"]), int(item["port"]), str(item["bind_scope"]))
    for item in listeners
  }
  return tuple(
    {"protocol": protocol, "family": family, "port": port, "bind_scope": scope}
    for protocol, family, port, scope in sorted(unique, key=lambda item: (item[0], item[2], item[1], item[3]))
  )


def collect_process_rankings(top: int, reader: Callable[[str, int], bytes] = read_bounded_ascii) -> dict[str, object]:
  try:
    with os.scandir("/proc") as entries:
      pids = []
      for entry in entries:
        if not entry.name.isascii() or not entry.name.isdecimal():
          continue
        if len(pids) >= MAX_PROCESSES:
          raise SectionUnavailable("process count exceeds limit")
        pids.append(entry.name)
      pids.sort(key=int)
  except OSError as error:
    raise SectionUnavailable(_reason_for_os_error(error)) from error
  page_size = os.sysconf("SC_PAGE_SIZE")
  if not isinstance(page_size, int) or page_size <= 0:
    raise SectionUnavailable("page size unavailable")
  records = []
  for raw_pid in pids:
    try:
      data = reader(f"/proc/{raw_pid}/stat", 4096).decode("ascii").strip()
      boundary = data.rfind(") ")
      opening = data.find("(")
      if opening < 1 or boundary <= opening:
        raise SectionUnavailable("malformed process stat")
      pid = int(data[:opening].strip())
      name = display_safe(data[opening + 1:boundary][:128])
      fields = data[boundary + 2:].split()
      if len(fields) < 22:
        raise SectionUnavailable("malformed process stat")
      cpu_ticks = int(fields[11]) + int(fields[12])
      rss_bytes = max(0, int(fields[21])) * page_size
      records.append({"pid": pid, "name": name, "cpu_ticks_since_start": cpu_ticks, "rss_bytes": rss_bytes})
    except (SectionUnavailable, OSError, ValueError):
      continue
  return {
    "observed_processes": len(records),
    "top_cpu": tuple(sorted(records, key=lambda item: (-int(item["cpu_ticks_since_start"]), int(item["pid"])))[:top]),
    "top_memory": tuple(sorted(records, key=lambda item: (-int(item["rss_bytes"]), int(item["pid"])))[:top]),
  }


def run_bounded_command(arguments: Sequence[str], *, timeout: float, limit: int) -> tuple[int, bytes]:
  try:
    process = subprocess.Popen(
      list(arguments), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
      env={**os.environ, "LC_ALL": "C", "SYSTEMD_PAGER": "", "SYSTEMD_COLORS": "0"},
    )
  except OSError as error:
    raise SectionUnavailable("command unavailable") from error
  assert process.stdout is not None
  descriptor = process.stdout.fileno()
  os.set_blocking(descriptor, False)
  deadline = time.monotonic() + timeout
  chunks = []
  observed = 0
  try:
    while True:
      if time.monotonic() >= deadline:
        raise SectionUnavailable("command timed out")
      try:
        chunk = os.read(descriptor, min(8192, limit + 1 - observed))
      except BlockingIOError:
        if process.poll() is not None:
          chunk = os.read(descriptor, min(8192, limit + 1 - observed))
        else:
          time.sleep(0.01)
          continue
      if chunk:
        chunks.append(chunk)
        observed += len(chunk)
        if observed > limit:
          raise SectionUnavailable("command output exceeds limit")
        continue
      if process.poll() is not None:
        break
      time.sleep(0.01)
    remaining = max(0.01, deadline - time.monotonic())
    return process.wait(timeout=remaining), b"".join(chunks)
  except subprocess.TimeoutExpired as error:
    raise SectionUnavailable("command timed out") from error
  finally:
    process.stdout.close()
    if process.poll() is None:
      process.kill()
      try:
        process.wait(timeout=1.0)
      except subprocess.TimeoutExpired:
        pass


def collect_failed_services() -> tuple[str, ...]:
  try:
    return_code, stdout = run_bounded_command(
      ["systemctl", "--failed", "--no-legend", "--plain", "--no-pager", "--type=service"],
      timeout=3.0, limit=64 * 1024,
    )
  except SectionUnavailable as error:
    raise SectionUnavailable("systemd observation unavailable") from error
  if return_code not in {0, 1}:
    raise SectionUnavailable("systemd observation failed")
  services = []
  for line in stdout.decode("utf-8", errors="replace").splitlines()[:64]:
    fields = line.split()
    if fields:
      services.append(display_safe(fields[0][:256]))
  return tuple(services)


def collect_kernel_evidence(reader: Callable[[str, int], bytes] = read_bounded_ascii) -> dict[str, int]:
  tainted = reader(KERNEL_TAINT_PATH, 64).decode("ascii").strip()
  if not tainted.isdecimal():
    raise SectionUnavailable("malformed kernel taint state")
  wanted = {"ctxt", "processes", "procs_running", "procs_blocked"}
  metrics: dict[str, int] = {"tainted": int(tainted)}
  for line in reader(PROC_STAT_PATH, SECTION_MAX_BYTES).decode("ascii").splitlines():
    fields = line.split()
    if fields and fields[0] in wanted and len(fields) == 2 and fields[1].isdecimal():
      metrics[fields[0]] = int(fields[1])
  if not wanted.issubset(metrics):
    raise SectionUnavailable("kernel scheduler evidence incomplete")
  return metrics


def _optional_section(name: str, collector: Callable[[], object]) -> SectionObservation:
  try:
    return SectionObservation(name, "observed", collector())
  except SectionUnavailable as error:
    return SectionObservation(name, "unavailable", reason=error.reason)
  except OSError:
    return SectionObservation(name, "error", reason="observation failed")


def _utc_value(value: object) -> datetime:
  if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
    raise ObservationError("observation timing", "unsupported data shape")
  return value.astimezone(timezone.utc)


def _monotonic_value(value: object) -> int:
  if not isinstance(value, int) or isinstance(value, bool):
    raise ObservationError("observation timing", "unsupported data shape")
  return value


def collect_snapshot(
  *,
  profile: str = "basic",
  top: int = 5,
  reader: Callable[[str, int], bytes] = read_bounded_ascii,
  uname_provider: Callable[[], object] = os.uname,
  statvfs_provider: Callable[[str], object] = os.statvfs,
  utc_clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
  monotonic_clock: Callable[[], int] = time.monotonic_ns,
) -> SnapshotResult:
  started = _utc_value(utc_clock())
  monotonic_start = _monotonic_value(monotonic_clock())
  platform = collect_platform(uname_provider)
  runtime = collect_runtime(reader)
  try:
    memory = OptionalObservation(value=collect_memory(reader))
  except SectionUnavailable as error:
    memory = OptionalObservation(reason=error.reason)
  try:
    filesystem = OptionalObservation(value=collect_root_filesystem(statvfs_provider))
  except SectionUnavailable as error:
    filesystem = OptionalObservation(reason=error.reason)
  sections = []
  if profile == "full":
    sections.extend((
      _optional_section("Pressure", lambda: collect_pressure(reader)),
      _optional_section("Filesystem inodes", lambda: collect_inode_summary(statvfs_provider)),
    ))
  if profile in {"network", "full"}:
    sections.extend((
      _optional_section("Network interfaces", lambda: collect_interfaces(reader)),
      _optional_section("Default routes", lambda: collect_routes(reader)),
      _optional_section("Listening ports", lambda: collect_listeners(reader)),
    ))
  if profile in {"process", "full"}:
    sections.append(_optional_section("Process rankings", lambda: collect_process_rankings(top, reader)))
  if profile == "full":
    sections.extend((
      _optional_section("Failed systemd services", collect_failed_services),
      _optional_section("Kernel evidence", lambda: collect_kernel_evidence(reader)),
    ))
  monotonic_finish = _monotonic_value(monotonic_clock())
  finished = _utc_value(utc_clock())
  elapsed = monotonic_finish - monotonic_start
  if elapsed < 0:
    raise ObservationError("observation timing", "malformed data")
  return SnapshotResult(
    ObservationWindow(started, finished, elapsed), platform, runtime, memory, filesystem,
    profile, tuple(sections),
  )


def _quantized(value: Decimal, places: str) -> str:
  with localcontext() as context:
    context.prec = 100
    return str(value.quantize(Decimal(places), rounding=ROUND_HALF_UP))


def format_timestamp(value: datetime) -> str:
  return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def format_uptime(value: Decimal) -> str:
  seconds = int(value)
  days, remainder = divmod(seconds, 86400)
  hours, remainder = divmod(remainder, 3600)
  minutes, seconds = divmod(remainder, 60)
  return f"{days} d {hours:02d}:{minutes:02d}:{seconds:02d} ({_quantized(value, '0.01')} seconds)"


def format_iec_bytes(value: int) -> str:
  if value < 1024:
    return f"{value} B"
  unit_index = 0
  divisor = 1
  while unit_index + 1 < len(IEC_UNITS) and value >= divisor * 1024:
    divisor *= 1024
    unit_index += 1
  with localcontext() as context:
    context.prec = 100
    amount = Decimal(value) / Decimal(divisor)
  return f"{_quantized(amount, '0.1')} {IEC_UNITS[unit_index]} ({value} bytes)"


def format_percentage(numerator: int, denominator: int) -> str:
  with localcontext() as context:
    context.prec = 100
    value = Decimal(numerator) * Decimal(100) / Decimal(denominator)
  return f"{_quantized(value, '0.1')}%"


def render_report(snapshot: SnapshotResult) -> str:
  elapsed_ms = Decimal(snapshot.window.elapsed_ns) / Decimal(1_000_000)
  sections = [
    "Incident Snapshot",
    "\n".join((
      "Observation",
      "  Status: observed",
      f"  Started UTC: {format_timestamp(snapshot.window.started_utc)}",
      f"  Finished UTC: {format_timestamp(snapshot.window.finished_utc)}",
      f"  Elapsed: {_quantized(elapsed_ms, '0.001')} ms",
      "  Mode: sequential single pass",
    )),
    "\n".join((
      "Platform",
      "  Status: observed",
      f"  System: {display_safe(snapshot.platform.system)}",
      f"  Kernel release: {display_safe(snapshot.platform.release)}",
      f"  Machine: {display_safe(snapshot.platform.machine)}",
    )),
    "\n".join((
      "Runtime",
      "  Status: observed",
      f"  Uptime: {format_uptime(snapshot.runtime.uptime)}",
      f"  Load average 1m: {_quantized(snapshot.runtime.load_1m, '0.01')}",
      f"  Load average 5m: {_quantized(snapshot.runtime.load_5m, '0.01')}",
      f"  Load average 15m: {_quantized(snapshot.runtime.load_15m, '0.01')}",
      f"  Logical CPUs visible: {snapshot.runtime.cpu_count if snapshot.runtime.cpu_count is not None else 'unavailable'}",
    )),
  ]
  if snapshot.memory.observed:
    memory = snapshot.memory.value
    assert isinstance(memory, MemoryObservation)
    sections.append("\n".join((
      "Memory",
      "  Status: observed",
      f"  Total: {format_iec_bytes(memory.total)}",
      f"  Available: {format_iec_bytes(memory.available)}",
      f"  Available percent: {format_percentage(memory.available, memory.total)}",
      f"  Swap total: {format_iec_bytes(memory.swap_total)}",
      f"  Swap free: {format_iec_bytes(memory.swap_free)}",
    )))
  else:
    sections.append(f"Memory\n  Status: unavailable\n  Reason: {snapshot.memory.reason}")
  if snapshot.filesystem.observed:
    filesystem = snapshot.filesystem.value
    assert isinstance(filesystem, FilesystemObservation)
    sections.append("\n".join((
      "Root filesystem",
      "  Status: observed",
      "  Scope: current mount namespace, root filesystem",
      f"  Total: {format_iec_bytes(filesystem.total)}",
      f"  Used: {format_iec_bytes(filesystem.used)}",
      f"  Available to caller: {format_iec_bytes(filesystem.available)}",
      f"  Capacity used: {format_percentage(filesystem.used, filesystem.used + filesystem.available)}",
    )))
  else:
    sections.append(f"Root filesystem\n  Status: unavailable\n  Reason: {snapshot.filesystem.reason}")
  for observation in snapshot.sections:
    lines = [display_safe(observation.name), f"  Status: {observation.status}"]
    if observation.status == "observed":
      rendered = json.dumps(observation.value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
      lines.append(f"  Evidence: {display_safe(rendered)}")
    else:
      lines.append(f"  Reason: {display_safe(observation.reason or 'observation unavailable')}")
    sections.append("\n".join(lines))
  warnings = []
  if not snapshot.memory.observed:
    warnings.append(f"Memory: {snapshot.memory.reason}")
  if not snapshot.filesystem.observed:
    warnings.append(f"Root filesystem: {snapshot.filesystem.reason}")
  warnings.extend(
    f"{observation.name}: {observation.reason}"
    for observation in snapshot.sections if observation.status != "observed"
  )
  warning_lines = ["Collection warnings"]
  warning_lines.extend(
    [f"  {index}. {warning}" for index, warning in enumerate(warnings, 1)] if warnings else ["  None"]
  )
  sections.append("\n".join(warning_lines))
  limits = [
    "Interpretation limits",
    "  Collection was sequential, not atomic; values may have changed during or immediately after observation.",
    "  Root-filesystem evidence covers / in the current mount namespace only.",
    "  Load, memory, and capacity values are evidence, not health thresholds.",
    "  This snapshot does not determine incident severity or identify root cause.",
  ]
  if snapshot.profile == "basic":
    limits.insert(-1, "  Process, network, service, log, and configuration evidence was deliberately not inspected.")
  else:
    limits.insert(-1, "  Process names may be shown, but complete command lines, environments, and unrestricted logs are never collected.")
  sections.append("\n".join(limits))
  return "\n\n".join(sections) + "\n"


def snapshot_exit_code(snapshot: SnapshotResult) -> int:
  complete = snapshot.memory.observed and snapshot.filesystem.observed
  complete = complete and all(section.status == "observed" for section in snapshot.sections)
  return 0 if complete else 1


def main(argv: Sequence[str] | None = None) -> int:
  parser = build_argument_parser()
  args = parser.parse_args(argv)
  validate_output_arguments(parser, args)
  started = time.monotonic()
  try:
    snapshot = collect_snapshot(profile=args.profile, top=args.top)
    report = render_report(snapshot)
    exit_code = snapshot_exit_code(snapshot)
    unavailable = sum(section.status != "observed" for section in snapshot.sections)
    unavailable += int(not snapshot.memory.observed) + int(not snapshot.filesystem.observed)
    status = "WARN" if unavailable else "OK"
    finding = f"{snapshot.profile} profile collected with {unavailable} unavailable or error section(s)"
    next_action = "review collection warnings and gather only the missing evidence needed" if unavailable else "correlate this bounded snapshot with incident-specific evidence"
    conclusion = make_conclusion(status, snapshot.profile, finding, next_action)
    record_warnings = []
    if not snapshot.memory.observed:
      record_warnings.append(f"Memory: {snapshot.memory.reason}")
    if not snapshot.filesystem.observed:
      record_warnings.append(f"Root filesystem: {snapshot.filesystem.reason}")
    record_warnings.extend(
      f"{section.name}: {section.reason}" for section in snapshot.sections if section.status != "observed"
    )
    record = OutputRecord(
      tool="incidentsnapshot", status=status, target=snapshot.profile,
      observations=snapshot, conclusion=conclusion, next_action=next_action + ".",
      warnings=tuple(record_warnings),
      elapsed_seconds=time.monotonic() - started,
    )
    brief = "\n".join((
      f"Profile: {snapshot.profile}",
      f"Sections: {5 + len(snapshot.sections)}",
      f"Unavailable/error: {unavailable}",
    ))
    emit_output(
      record, detailed=report, brief=brief, json_mode=args.json,
      brief_mode=args.brief, quiet=args.quiet,
      output_path=args.output, force=args.force, stdout=sys.stdout,
    )
    if exit_code == 1 and not args.quiet:
      write_safe("incidentsnapshot: snapshot incomplete; see Collection warnings\n", file=sys.stderr)
    return exit_code
  except UnsupportedPlatform:
    write_best_effort("incidentsnapshot: unsupported platform: Linux is required\n", file=sys.stderr)
    return 3
  except ObservationError as error:
    write_best_effort(
      f"incidentsnapshot: {error.section} observation failed: {error.reason}\n",
      file=sys.stderr,
    )
    return 3
  except KeyboardInterrupt:
    write_best_effort("incidentsnapshot: interrupted\n", file=sys.stderr)
    return 130
  except OutputError as error:
    write_best_effort(f"incidentsnapshot: output error: {display_safe(error)}\n", file=sys.stderr)
    return 3
  except Exception:
    write_best_effort("incidentsnapshot: internal execution failure\n", file=sys.stderr)
    return 3


if __name__ == "__main__":
  try:
    raise SystemExit(main())
  except KeyboardInterrupt:
    write_best_effort("incidentsnapshot: interrupted\n", file=sys.stderr)
    raise SystemExit(130)
