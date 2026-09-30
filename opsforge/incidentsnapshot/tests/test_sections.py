import contextlib
import errno
import inspect
import io
import ipaddress
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import types
import unittest
from unittest import mock

from test_incidentsnapshot import incident, reader, snapshot, uname, vfs


SOCKET_HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
ROUTE_HEADER = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
EMPTY_SOCKETS = {path: SOCKET_HEADER for _, path in incident.SOCKET_PATHS}


def proc_address(address):
  """Encode an address the way /proc/net prints it: 32-bit words in host byte order."""
  packed = ipaddress.ip_address(address).packed
  return "".join("%08X" % word for word in struct.unpack(f"={len(packed) // 4}I", packed))


def socket_row(index, address, port, state):
  local = proc_address(address)
  return (
    f"{index:4d}: {local}:{port:04X} {'0' * len(local)}:0000 {state} 00000000:00000000 00:00000000 "
    f"00000000  1000        0 {10000 + index} 1 0000000000000000 100 0 0 10 0\n"
  )


def route_row(interface, *, destination="0.0.0.0", gateway="0.0.0.0", mask="0.0.0.0", flags=0x0003, metric=0):
  return (
    f"{interface}\t{proc_address(destination)}\t{proc_address(gateway)}\t{flags:04X}\t0\t0\t{metric}\t"
    f"{proc_address(mask)}\t0\t0\t0\n"
  )


def stat_line(pid, name, *, utime=0, rss_pages=0):
  fields = [b"S"] + [b"0"] * 10 + [b"%d" % utime, b"0"] + [b"0"] * 8 + [b"%d" % rss_pages] + [b"0"] * 30
  return b"%d (%s) %s\n" % (pid, name, b" ".join(fields))


def table_reader(sources):
  return lambda path, limit: sources[path].encode("ascii")


def file_reader(directory, sources, read=incident.read_bounded_ascii):
  """Serve fixed procfs paths from real files so the production reader and byte limits apply."""
  mapping = {}
  for path, content in sources.items():
    local = Path(directory, path.strip("/").replace("/", "_"))
    local.write_bytes(content.encode("ascii") if isinstance(content, str) else content)
    mapping[path] = str(local)
  missing = str(Path(directory, "absent"))
  return lambda path, limit: read(mapping.get(path, missing), limit)


@contextlib.contextmanager
def _entries(directories, files):
  yield iter(
    [types.SimpleNamespace(name=name, is_dir=lambda: True) for name in directories]
    + [types.SimpleNamespace(name=name, is_dir=lambda: False) for name in files]
  )


def fake_scandir(directories=(), files=()):
  return mock.patch.object(incident.os, "scandir", side_effect=lambda path: _entries(directories, files))


def run_main(argv, result):
  stdout, stderr = io.StringIO(), io.StringIO()
  with mock.patch.object(incident, "collect_snapshot", return_value=result), \
       mock.patch.object(incident.sys, "stdout", stdout), mock.patch.object(incident.sys, "stderr", stderr):
    code = incident.main(argv)
  return code, stdout.getvalue(), stderr.getvalue()


class ProcessRankingTests(unittest.TestCase):
  def rank(self, stat_reader, pids):
    with fake_scandir(directories=[str(pid) for pid in pids] + ["self", "sys"]):
      return incident.collect_process_rankings(5, stat_reader)

  def test_process_with_any_name_bytes_is_ranked(self):
    names = {101: b"memhog-ascii", 102: "memhog-\u00e9".encode(), 103: b"x) (y \xff"}
    stats = {f"/proc/{pid}/stat": stat_line(pid, name, utime=pid, rss_pages=76800) for pid, name in names.items()}
    with tempfile.TemporaryDirectory() as directory:
      result = self.rank(file_reader(directory, stats, read=incident.read_bounded_bytes), names)
    self.assertIsNone(result.partial)
    self.assertEqual(result.value["observed_processes"], 3)
    self.assertEqual([item["name"] for item in result.value["top_cpu"]], ["x) (y \udcff", "memhog-\u00e9", "memhog-ascii"])
    self.assertEqual({item["pid"] for item in result.value["top_memory"]}, set(names))
    section = incident._optional_section("Process rankings", lambda: result)
    report = incident.render_report(snapshot(profile="process", sections=(section,)))
    self.assertIn('- pid=103 name="x) (y \\xff" cpu_ticks_since_start=103 ', report)
    self.assertIn("- pid=102 name=memhog-\u00e9 ", report)
    code, stdout, _ = run_main(["--json"], snapshot(profile="process", sections=(section,)))
    ranked = json.loads(stdout)["observations"]["sections"][0]["value"]["top_cpu"]
    self.assertEqual((code, ranked[0]["pid"], ranked[0]["name"]), (0, 103, "x) (y \\udcff"))

  def test_snapshot_ranks_non_ascii_names_through_the_bytes_reader(self):
    self.assertIs(inspect.signature(incident.collect_snapshot).parameters["stat_reader"].default, incident.read_bounded_bytes)
    with fake_scandir(directories=["7"]):
      result = incident.collect_snapshot(
        profile="process", reader=reader, stat_reader=lambda path, limit: stat_line(7, b"\xe9miner"),
        uname_provider=lambda: uname(), statvfs_provider=lambda path: vfs(), monotonic_clock=iter((0, 10)).__next__,
      )
    self.assertEqual(result.sections[0].value["top_memory"][0]["name"], "\udce9miner")

  def test_bytes_reader_accepts_any_content_and_keeps_os_errors(self):
    with tempfile.NamedTemporaryFile() as handle:
      handle.write(b"1 (\xff) S\n")
      handle.flush()
      self.assertEqual(incident.read_bounded_bytes(handle.name, 64), b"1 (\xff) S\n")
      with self.assertRaises(incident.SectionUnavailable):
        incident.read_bounded_ascii(handle.name, 64)
    with self.assertRaises(FileNotFoundError):
      incident.read_bounded_bytes("/definitely/not/present", 10)

  def test_vanished_processes_are_churn_but_unreadable_ones_make_the_section_partial(self):
    outcomes = {
      1: stat_line(1, b"init", utime=5, rss_pages=10),
      2: FileNotFoundError(errno.ENOENT, "No such file or directory"),
      3: ProcessLookupError(errno.ESRCH, "No such process"),
      4: PermissionError(errno.EACCES, "Permission denied"),
      5: b"5 (truncated",
    }

    def stat_reader(path, limit):
      outcome = outcomes[int(path.split("/")[2])]
      if isinstance(outcome, BaseException):
        raise outcome
      return outcome

    result = self.rank(stat_reader, outcomes)
    counts = {key: result.value[key] for key in ("observed_processes", "vanished_processes", "skipped_processes", "skip_reasons")}
    self.assertEqual(counts, {
      "observed_processes": 1, "vanished_processes": 2, "skipped_processes": 2,
      "skip_reasons": {"malformed process stat": 1, "permission denied": 1},
    })
    section = incident._optional_section("Process rankings", lambda: result)
    self.assertEqual(section.status, "partial")
    self.assertEqual(section.reason, "2 process(es) could not be read: malformed process stat (1), permission denied (1)")
    partial = snapshot(profile="process", sections=(section,))
    self.assertEqual(incident.snapshot_exit_code(partial), 1)
    self.assertIn("1. Process rankings: 2 process(es) could not be read", incident.render_report(partial))

  def test_only_vanished_processes_keep_the_section_observed(self):
    def stat_reader(path, limit):
      if path == "/proc/2/stat":
        raise ProcessLookupError(errno.ESRCH, "No such process")
      return stat_line(1, b"init")

    section = incident._optional_section("Process rankings", lambda: self.rank(stat_reader, (1, 2)))
    self.assertEqual((section.status, section.value["vanished_processes"]), ("observed", 1))
    self.assertEqual(incident.snapshot_exit_code(snapshot(sections=(section,))), 0)


class TableBudgetTests(unittest.TestCase):
  def test_socket_table_larger_than_128_kib_still_yields_listeners(self):
    rows = [socket_row(0, "0.0.0.0", 22, "0A")]
    rows += [socket_row(index, "10.0.0.1", 30000 + index, "01") for index in range(1, 2000)]
    sources = {**EMPTY_SOCKETS, "/proc/net/tcp": SOCKET_HEADER + "".join(rows)}
    self.assertGreater(len(sources["/proc/net/tcp"]), 128 * 1024)
    with tempfile.TemporaryDirectory() as directory:
      result = incident.collect_listeners(file_reader(directory, sources))
    self.assertEqual(result.value, ({"protocol": "TCP", "family": "IPv4", "port": 22, "bind_scope": "wildcard"},))

  def test_proc_stat_larger_than_128_kib_is_still_parsed(self):
    proc_stat = (
      "cpu  1 2 3 4 5 6 7 0 0 0\nintr 1" + " 0" * 100_000
      + "\nctxt 10\nbtime 1\nprocesses 20\nprocs_running 2\nprocs_blocked 0\n"
    )
    self.assertGreater(len(proc_stat), 128 * 1024)
    with tempfile.TemporaryDirectory() as directory:
      bounded = file_reader(directory, {incident.KERNEL_TAINT_PATH: "0\n", incident.PROC_STAT_PATH: proc_stat})
      self.assertEqual(incident.collect_kernel_evidence(bounded), {
        "tainted": 0, "ctxt": 10, "processes": 20, "procs_running": 2, "procs_blocked": 0,
      })


class CapTests(unittest.TestCase):
  def test_interface_cap_truncates_instead_of_dropping_the_section(self):
    names = [f"veth{index:03d}" for index in range(130)]
    with fake_scandir(directories=names, files=["bonding_masters"]):
      result = incident.collect_interfaces(lambda path, limit: b"up\n" if path.endswith("/operstate") else b"1500\n")
    self.assertEqual((len(result.value), result.truncated, result.total_seen), (incident.MAX_INTERFACES, True, 130))
    self.assertEqual(result.value[0], {"name": "veth000", "state": "up", "mtu": 1500})

  def test_bonding_masters_is_not_reported_as_an_interface(self):
    with fake_scandir(directories=["lo"], files=["bonding_masters"]):
      result = incident.collect_interfaces(lambda path, limit: b"unknown\n" if path.endswith("/operstate") else b"65536\n")
    self.assertEqual(result.value, ({"name": "lo", "state": "unknown", "mtu": 65536},))
    self.assertEqual((result.truncated, result.total_seen), (False, 1))

  def test_route_tables_over_the_old_line_cap_are_truncated_not_dropped(self):
    table = ROUTE_HEADER + "".join(
      route_row("eth0", destination=f"10.{index // 256}.{index % 256}.0", gateway="10.0.0.1", mask="255.255.255.0")
      for index in range(300)
    )
    table += "".join(route_row(f"ppp{index}", gateway="192.0.2.1", metric=index) for index in range(300))
    result = incident.collect_routes(table_reader({incident.ROUTE_PATH: table, incident.IPV6_ROUTE_PATH: ""}))
    self.assertEqual((len(result.value), result.truncated, result.total_seen), (incident.MAX_ROUTES, True, 300))
    self.assertEqual(result.value[0], {"family": "IPv4", "interface": "ppp0", "gateway": "192.0.2.1"})

  def test_listener_cap_applies_after_deduplication(self):
    reuseport = "".join(socket_row(index, "0.0.0.0", 443, "0A") for index in range(600))
    result = incident.collect_listeners(table_reader({**EMPTY_SOCKETS, "/proc/net/tcp": SOCKET_HEADER + reuseport}))
    self.assertEqual(result.value, ({"protocol": "TCP", "family": "IPv4", "port": 443, "bind_scope": "wildcard"},))
    self.assertEqual((result.truncated, result.total_seen), (False, 1))
    distinct = "".join(socket_row(index, "0.0.0.0", 1000 + index, "0A") for index in range(600))
    result = incident.collect_listeners(table_reader({**EMPTY_SOCKETS, "/proc/net/tcp": SOCKET_HEADER + distinct}))
    self.assertEqual((len(result.value), result.truncated, result.total_seen), (incident.MAX_LISTENERS, True, 600))
    self.assertEqual(result.value[-1]["port"], 1000 + incident.MAX_LISTENERS - 1)


class RouteAndSocketSemanticsTests(unittest.TestCase):
  def test_missing_ipv6_tables_keep_ipv4_routes_and_listeners(self):
    sources = {
      incident.ROUTE_PATH: ROUTE_HEADER + route_row("eth0", gateway="192.168.1.1", metric=100),
      "/proc/net/tcp": SOCKET_HEADER + socket_row(0, "0.0.0.0", 22, "0A"),
      "/proc/net/udp": SOCKET_HEADER + socket_row(0, "127.0.0.53", 53, "07"),
    }
    with tempfile.TemporaryDirectory() as directory:
      bounded = file_reader(directory, sources)
      routes = incident._optional_section("Default routes", lambda: incident.collect_routes(bounded))
      listeners = incident._optional_section("Listening ports", lambda: incident.collect_listeners(bounded))
    self.assertEqual((routes.status, routes.value), ("observed", ({"family": "IPv4", "interface": "eth0", "gateway": "192.168.1.1"},)))
    self.assertEqual(routes.notes, ("IPv6 not present: /proc/net/ipv6_route is absent",))
    self.assertEqual(listeners.status, "observed")
    self.assertEqual([(item["protocol"], item["port"], item["bind_scope"]) for item in listeners.value], [
      ("TCP", 22, "wildcard"), ("UDP", 53, "loopback"),
    ])
    self.assertEqual(listeners.notes, (
      "IPv6 not present: /proc/net/tcp6 is absent", "IPv6 not present: /proc/net/udp6 is absent",
    ))

  def test_unreadable_ipv6_table_is_a_named_gap_not_an_empty_answer(self):
    def denied(path, limit):
      if path == incident.IPV6_ROUTE_PATH:
        raise incident.SectionUnavailable("permission denied")
      return ROUTE_HEADER.encode("ascii")

    section = incident._optional_section("Default routes", lambda: incident.collect_routes(denied))
    self.assertEqual((section.status, section.reason), ("partial", "/proc/net/ipv6_route: permission denied"))

  def test_default_routes_honour_route_flags(self):
    zero = "0" * 32
    ipv6 = (
      f"{zero} 00 {zero} 00 {zero} ffffffff 00000001 00000000 00200200       lo\n"
      f"{zero} 00 {zero} 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003     eth0\n"
    )
    ipv4 = ROUTE_HEADER + route_row("blackhole0", flags=0x0201) + route_row("wg0", flags=0x0001, metric=50)
    result = incident.collect_routes(table_reader({incident.ROUTE_PATH: ipv4, incident.IPV6_ROUTE_PATH: ipv6}))
    self.assertEqual(result.value, (
      {"family": "IPv4", "interface": "wg0", "gateway": None},
      {"family": "IPv6", "interface": "eth0", "gateway": "fe80::1"},
    ))

  def test_connected_udp_is_ignored_and_loopback_is_classified_by_address(self):
    sources = {
      "/proc/net/tcp": SOCKET_HEADER,
      "/proc/net/tcp6": SOCKET_HEADER + socket_row(0, "::ffff:127.0.0.1", 8443, "0A")
      + socket_row(1, "::1", 631, "0A") + socket_row(2, "2001:db8::1", 80, "0A"),
      "/proc/net/udp": SOCKET_HEADER + socket_row(0, "127.0.0.53", 53, "07") + socket_row(1, "10.0.0.5", 51000, "01"),
      "/proc/net/udp6": SOCKET_HEADER + socket_row(0, "::", 5353, "07"),
    }
    result = incident.collect_listeners(table_reader(sources))
    self.assertEqual([(item["protocol"], item["family"], item["port"], item["bind_scope"]) for item in result.value], [
      ("TCP", "IPv6", 80, "specific"), ("TCP", "IPv6", 631, "loopback"), ("TCP", "IPv6", 8443, "loopback"),
      ("UDP", "IPv4", 53, "loopback"), ("UDP", "IPv6", 5353, "wildcard"),
    ])


class FailedServiceTests(unittest.TestCase):
  def test_failed_service_list_reports_truncation(self):
    output = "".join(f"unit{index:02d}.service loaded failed failed Unit {index}\n" for index in range(70)).encode()
    with mock.patch.object(incident, "run_bounded_command", return_value=(0, output)):
      result = incident.collect_failed_services()
    self.assertEqual((len(result.value), result.truncated, result.total_seen), (incident.MAX_FAILED_SERVICES, True, 70))
    self.assertEqual(result.value[-1], "unit63.service")

  def test_undecodable_descriptions_do_not_hide_failed_services(self):
    output = b"a.service loaded failed failed Caf\xe9 d\xe6mon\nb.service loaded failed failed Next\xc2\x85line\n"
    with mock.patch.object(incident, "run_bounded_command", return_value=(0, output)):
      self.assertEqual(incident.collect_failed_services().value, ("a.service", "b.service"))

  def test_unit_name_backslash_is_not_double_escaped(self):
    unit = "systemd-fsck@dev-disk-by\\x2duuid-0f1e.service"
    output = f"{unit} loaded failed failed File System Check\n".encode()
    with mock.patch.object(incident, "run_bounded_command", return_value=(0, output)):
      section = incident._optional_section("Failed systemd services", incident.collect_failed_services)
    self.assertEqual(section.value, (unit,))
    result = snapshot(profile="full", sections=(section,))
    _, stdout, _ = run_main(["--json"], result)
    self.assertEqual(json.loads(stdout)["observations"]["sections"][0]["value"], [unit])
    self.assertIn('"systemd-fsck@dev-disk-by\\\\x2duuid-0f1e.service"', stdout)
    report = incident.render_report(result)
    self.assertIn("    - systemd-fsck@dev-disk-by\\\\x2duuid-0f1e.service\n", report)
    self.assertNotIn("\\\\\\\\", report)

  def test_systemctl_is_resolved_from_a_trusted_path_with_a_minimal_environment(self):
    with tempfile.TemporaryDirectory() as directory:
      tool = Path(directory, "systemctl")
      tool.write_text(
        f"#!{sys.executable}\n"
        "import os, sys\n"
        "clean = os.environ.get('SYSTEMD_PAGER') == '' and 'OPSFORGE_PROBE' not in os.environ\n"
        "sys.stdout.write('probe.service loaded failed failed Probe\\n' if clean and '--failed' in sys.argv else '')\n",
        encoding="utf-8",
      )
      tool.chmod(0o700)
      with mock.patch.dict(os.environ, {"PATH": directory, "OPSFORGE_PROBE": "leak"}):
        self.assertEqual(incident.collect_failed_services().value, ("probe.service",))
      with mock.patch.dict(os.environ, {"PATH": str(Path(directory, "missing"))}), \
           self.assertRaises(incident.SectionUnavailable) as caught:
        incident.collect_failed_services()
    self.assertEqual(caught.exception.reason, "systemd observation unavailable")


class SectionContainmentTests(unittest.TestCase):
  def test_unexpected_collector_failure_is_an_error_section(self):
    with fake_scandir(directories=["1"]), \
         mock.patch.object(incident.os, "sysconf", side_effect=ValueError("unrecognized configuration name")):
      result = incident.collect_snapshot(
        profile="process", reader=reader, uname_provider=lambda: uname(),
        statvfs_provider=lambda path: vfs(), monotonic_clock=iter((0, 10)).__next__,
      )
    section = result.sections[0]
    self.assertEqual((section.name, section.status, section.reason), ("Process rankings", "error", "observation failed"))
    report = incident.render_report(result)
    self.assertIn("Process rankings\n  Status: error\n  Reason: observation failed\n", report)
    self.assertNotIn("unrecognized", report)
    self.assertEqual(incident.snapshot_exit_code(result), 1)

  def test_interrupt_inside_a_collector_still_propagates(self):
    with self.assertRaises(KeyboardInterrupt):
      incident._optional_section("Pressure", mock.Mock(side_effect=KeyboardInterrupt))


class RenderingTests(unittest.TestCase):
  def test_section_evidence_is_rendered_as_key_value_lines(self):
    sections = (
      incident.SectionObservation("Pressure", "observed", (
        {"resource": "cpu", "some": {"avg10": 0.1, "avg60": 0.2, "avg300": 0.3, "total": 42}},
      )),
      incident.SectionObservation(
        "Listening ports", "observed", ({"protocol": "TCP", "family": "IPv4", "port": 22, "bind_scope": "wildcard"},),
        truncated=True, total_seen=600, notes=("IPv6 not present: /proc/net/tcp6 is absent",),
      ),
      incident.SectionObservation("Failed systemd services", "observed", ()),
    )
    result = snapshot(profile="full", sections=sections)
    report = incident.render_report(result)
    self.assertIn("Pressure\n  Status: observed\n  Evidence:\n    - resource=cpu some=(avg10=0.1 avg60=0.2 avg300=0.3 total=42)\n", report)
    self.assertIn(
      "Listening ports\n  Status: observed\n  Evidence:\n    - protocol=TCP family=IPv4 port=22 bind_scope=wildcard\n"
      "  Truncated: first 1 of 600 shown\n  Note: IPv6 not present: /proc/net/tcp6 is absent\n",
      report,
    )
    self.assertIn("Failed systemd services\n  Status: observed\n  Evidence:\n    none\n", report)
    _, stdout, _ = run_main(["--json"], result)
    listed = json.loads(stdout)["observations"]["sections"][1]
    self.assertEqual((listed["truncated"], listed["total_seen"], listed["notes"]), (True, 600, ["IPv6 not present: /proc/net/tcp6 is absent"]))

  def test_evidence_strings_cannot_forge_fields_or_lines(self):
    lines = incident._evidence_lines({"top_cpu": ({"pid": 9, "name": 'x rss_bytes=1\n"', "rss_bytes": 5},)})
    self.assertEqual(lines, ["top_cpu:", '  - pid=9 name="x rss_bytes=1\\x0a\\"" rss_bytes=5'])


class RuntimeAndPressureTests(unittest.TestCase):
  def test_cpu_count_follows_scheduler_affinity(self):
    with mock.patch.object(incident.os, "sched_getaffinity", return_value={0, 3}, create=True), \
         mock.patch.object(incident.os, "cpu_count", return_value=64):
      self.assertEqual(incident.collect_runtime(reader).cpu_count, 2)
    with mock.patch.object(incident.os, "sched_getaffinity", side_effect=OSError(errno.EINVAL, "unsupported"), create=True), \
         mock.patch.object(incident.os, "cpu_count", return_value=64):
      self.assertEqual(incident.collect_runtime(reader).cpu_count, 64)

  def test_pressure_rejects_non_decimal_numbers(self):
    for key, token in (("avg10", "nan"), ("avg60", "inf"), ("avg300", "1e3"), ("avg10", "-1.00"), ("total", "1.5"), ("total", "NaN")):
      values = {"avg10": "0.00", "avg60": "0.00", "avg300": "0.00", "total": "0", key: token}
      data = ("some " + " ".join(f"{name}={value}" for name, value in values.items()) + "\n").encode("ascii")
      with self.subTest(key=key, token=token), self.assertRaises(incident.SectionUnavailable):
        incident.collect_pressure(lambda path, limit, data=data: data)


class CliTests(unittest.TestCase):
  def test_top_is_rejected_without_a_process_ranking_profile(self):
    for argv in (["--top", "3"], ["--profile", "basic", "--top", "3"], ["--profile", "network", "--top", "3"]):
      with self.subTest(argv=argv):
        with mock.patch.object(incident, "collect_snapshot") as collect, \
             mock.patch.object(incident.sys, "stderr", io.StringIO()) as stderr, self.assertRaises(SystemExit) as caught:
          incident.main(argv)
        self.assertEqual(caught.exception.code, 2)
        self.assertIn("--top requires --profile process or full", stderr.getvalue())
        collect.assert_not_called()

  def test_top_is_passed_through_for_ranking_profiles(self):
    cases = (
      (["--profile", "process", "--top", "3"], "process", 3),
      (["--profile", "full", "--top", "20"], "full", 20),
      (["--profile", "process"], "process", incident.DEFAULT_TOP),
    )
    for argv, profile, top in cases:
      with self.subTest(argv=argv):
        with mock.patch.object(incident, "collect_snapshot", return_value=snapshot()) as collect, \
             mock.patch.object(incident.sys, "stdout", io.StringIO()):
          self.assertEqual(incident.main(argv), 0)
        collect.assert_called_once_with(profile=profile, top=top)

  def test_incomplete_notice_stream_failure_keeps_exit_one(self):
    class FailingStream:
      encoding = "utf-8"

      def write(self, value):
        raise OSError(errno.EIO, "stderr closed")

    partial = snapshot(memory=incident.OptionalObservation(reason="source unavailable"))
    with mock.patch.object(incident, "collect_snapshot", return_value=partial), \
         mock.patch.object(incident.sys, "stdout", io.StringIO()), mock.patch.object(incident.sys, "stderr", FailingStream()):
      self.assertEqual(incident.main([]), 1)


if __name__ == "__main__":
  unittest.main()
