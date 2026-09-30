"""Small parsers for Linux procfs text shared by OpsForge utilities."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import socket
import struct


RTF_UP = 0x0001
RTF_GATEWAY = 0x0002
RTF_REJECT = 0x0200


@dataclass(frozen=True)
class DefaultRoute:
  interface: str
  gateway: str | None
  metric: int


def split_stat(data: bytes) -> tuple[int, bytes, list[bytes]]:
  """Split /proc/PID/stat at the first "(" and last ")" so any process name bytes are accepted."""
  opening = data.find(b"(")
  closing = data.rfind(b")")
  if opening < 1 or closing <= opening:
    raise ValueError("malformed process stat")
  pid_text = data[:opening].strip()
  if not pid_text.isdigit():
    raise ValueError("malformed process stat")
  return int(pid_text), data[opening + 1:closing], data[closing + 1:].split()


def unified_cgroup_path(text: str) -> str | None:
  """Return the cgroup v2 path from /proc/PID/cgroup text; paths may contain ':'."""
  for line in text.split("\n"):
    if line.startswith("0::"):
      return line[3:]
  return None


def parse_ipv4_default_routes(text: str) -> list[DefaultRoute]:
  """Return usable /proc/net/route default routes ordered by metric."""
  routes = []
  for line in text.splitlines()[1:]:
    fields = line.split()
    if len(fields) < 8:
      continue
    try:
      destination, gateway, flags, metric, mask = (
        int(fields[1], 16), int(fields[2], 16), int(fields[3], 16), int(fields[6], 10), int(fields[7], 16),
      )
      address = socket.inet_ntoa(struct.pack("=I", gateway))
    except (ValueError, struct.error, OSError):
      continue
    if destination or mask or not flags & RTF_UP or flags & RTF_REJECT:
      continue
    routes.append(DefaultRoute(fields[0][:64], address if flags & RTF_GATEWAY else None, metric))
  return sorted(routes, key=lambda route: route.metric)


def parse_ipv6_default_routes(text: str) -> list[DefaultRoute]:
  """Return usable /proc/net/ipv6_route default routes, excluding the kernel's reject placeholder."""
  routes = []
  for line in text.splitlines():
    fields = line.split()
    if len(fields) < 10 or fields[0] != "0" * 32 or fields[1] != "00":
      continue
    try:
      metric, flags = int(fields[5], 16), int(fields[8], 16)
      address = str(ipaddress.IPv6Address(bytes.fromhex(fields[4])))
    except ValueError:
      continue
    if not flags & RTF_UP or flags & RTF_REJECT:
      continue
    routes.append(DefaultRoute(fields[9][:64], address if flags & RTF_GATEWAY else None, metric))
  return sorted(routes, key=lambda route: route.metric)
