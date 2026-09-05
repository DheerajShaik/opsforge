import errno
import importlib.util
import io
import os
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "incidentsnapshot.py"
SPEC = importlib.util.spec_from_file_location("incidentsnapshot", MODULE_PATH)
incident = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
import sys
sys.modules[SPEC.name] = incident
SPEC.loader.exec_module(incident)


VALID_UPTIME = b"90061.25 12345.00\n"
VALID_LOAD = b"0.01 1.235 2.00 3/100 98765\n"
VALID_MEMORY = (
  b"MemTotal: 16384 kB\n"
  b"MemFree: 1 kB\n"
  b"MemAvailable: 8192 kB\n"
  b"SwapTotal: 4096 kB\n"
  b"SwapFree: 2048 kB\n"
)


def uname(system="Linux", release="6.8.0", machine="x86_64", nodename="secret", version="secret-version"):
  return types.SimpleNamespace(
    sysname=system, nodename=nodename, release=release, version=version, machine=machine
  )


def vfs(**changes):
  values = dict(f_frsize=1024, f_bsize=4096, f_blocks=100, f_bfree=40, f_bavail=30)
  values.update(changes)
  return types.SimpleNamespace(**values)


def reader(path, limit):
  del limit
  return {incident.UPTIME_PATH: VALID_UPTIME, incident.LOADAVG_PATH: VALID_LOAD,
          incident.MEMINFO_PATH: VALID_MEMORY}[path]


def snapshot(**changes):
  values = dict(
    window=incident.ObservationWindow(
      datetime(2026, 1, 2, 3, 4, 5, 6789, tzinfo=timezone.utc),
      datetime(2026, 1, 2, 3, 4, 6, 7890, tzinfo=timezone.utc), 1_234_567_890),
    platform=incident.PlatformObservation("Linux", "6.8.0", "x86_64"),
    runtime=incident.RuntimeObservation(Decimal("90061.25"), Decimal("0.01"), Decimal("1.235"), Decimal("2")),
    memory=incident.OptionalObservation(incident.parse_meminfo(VALID_MEMORY)),
    filesystem=incident.OptionalObservation(incident.collect_root_filesystem(lambda path: vfs())),
  )
  values.update(changes)
  return incident.SnapshotResult(**values)


class PlatformTests(unittest.TestCase):
  def test_valid_platform_retains_only_reduced_fields(self):
    result = incident.collect_platform(lambda: uname(nodename="host-secret", version="version-secret"))
    self.assertEqual(result, incident.PlatformObservation("Linux", "6.8.0", "x86_64"))
    self.assertNotIn("host-secret", repr(result))
    self.assertNotIn("version-secret", repr(result))

  def test_non_linux_is_rejected(self):
    with self.assertRaises(incident.UnsupportedPlatform):
      incident.collect_platform(lambda: uname(system="Darwin"))

  def test_missing_or_wrong_field_shape_is_rejected(self):
    for value in (types.SimpleNamespace(sysname="Linux"), uname(release=7)):
      with self.subTest(value=value), self.assertRaises(incident.ObservationError):
        incident.collect_platform(lambda value=value: value)

  def test_empty_and_nul_fields_are_rejected(self):
    for release in ("", "bad\x00release"):
      with self.subTest(release=release), self.assertRaises(incident.ObservationError):
        incident.collect_platform(lambda release=release: uname(release=release))

  def test_platform_length_bound(self):
    self.assertEqual(len(incident.collect_platform(lambda: uname(release="x" * 256)).release), 256)
    with self.assertRaises(incident.ObservationError):
      incident.collect_platform(lambda: uname(release="x" * 257))

  def test_provider_failure_is_stable(self):
    with self.assertRaises(incident.ObservationError) as caught:
      incident.collect_platform(lambda: (_ for _ in ()).throw(OSError(errno.EIO, "secret")))
    self.assertEqual(caught.exception.reason, "observation failed")


class RuntimeParserTests(unittest.TestCase):
  def test_uptime_valid_integer_and_decimal(self):
    self.assertEqual(incident.parse_uptime(b"12 3"), Decimal("12"))
    self.assertEqual(incident.parse_uptime(b"12.25 malicious-idle"), Decimal("12.25"))

  def test_uptime_grammar_boundaries(self):
    self.assertEqual(
      incident.parse_uptime(b"9" * 20 + b"." + b"8" * 9),
      Decimal("9" * 20 + "." + "8" * 9),
    )
    for token in (b"9" * 21, b"1." + b"9" * 10):
      with self.subTest(token=token), self.assertRaises(incident.SectionUnavailable) as caught:
        incident.parse_uptime(token)
      self.assertEqual(caught.exception.reason, "numeric value exceeds V1 limit")

  def test_uptime_rejects_malformed_forms(self):
    for token in (b"", b".5", b"1.", b"+1", b"-1", b"1e2", b"1_0", b"NaN", b"Infinity"):
      with self.subTest(token=token), self.assertRaises(incident.SectionUnavailable):
        incident.parse_uptime(token)

  def test_loadavg_consumes_only_first_three(self):
    result = incident.parse_loadavg(b"1 2.5 3.00 malicious/tasks secret-pid")
    self.assertEqual(result, (Decimal("1"), Decimal("2.5"), Decimal("3.00")))

  def test_loadavg_requires_three_valid_values(self):
    for data in (b"1 2", b"bad 2 3", b"1 -2 3", b"1 2 Infinity"):
      with self.subTest(data=data), self.assertRaises(incident.SectionUnavailable):
        incident.parse_loadavg(data)

  def test_runtime_converts_section_error_to_fatal(self):
    def failed(path, limit):
      del path, limit
      raise incident.SectionUnavailable("permission denied")
    with self.assertRaises(incident.ObservationError) as caught:
      incident.collect_runtime(failed)
    self.assertEqual((caught.exception.section, caught.exception.reason), ("runtime", "permission denied"))

  def test_uptime_format_boundaries_and_rounding(self):
    self.assertEqual(incident.format_uptime(Decimal("0")), "0 d 00:00:00 (0.00 seconds)")
    self.assertEqual(incident.format_uptime(Decimal("90061.255")), "1 d 01:01:01 (90061.26 seconds)")

  def test_maximum_uptime_token_can_be_rendered(self):
    value = incident.parse_uptime(b"99999999999999999999.999999999")
    self.assertTrue(incident.format_uptime(value).endswith("(100000000000000000000.00 seconds)"))

  def test_load_rounding_is_half_up(self):
    result = incident.render_report(snapshot())
    self.assertIn("Load average 5m: 1.24", result)


class MemoryTests(unittest.TestCase):
  def test_valid_memory_and_unknown_key(self):
    value = incident.parse_meminfo(VALID_MEMORY)
    self.assertEqual(value.total, 16384 * 1024)
    self.assertEqual(value.available, 8192 * 1024)

  def test_arbitrary_order_is_equivalent(self):
    reordered = b"SwapFree: 2048 kB\nSwapTotal: 4096 kB\nMemAvailable: 8192 kB\nMemTotal: 16384 kB\n"
    self.assertEqual(incident.parse_meminfo(reordered), incident.parse_meminfo(VALID_MEMORY))

  def test_missing_and_duplicate_required_fields(self):
    missing = VALID_MEMORY.replace(b"SwapFree: 2048 kB\n", b"")
    duplicate = VALID_MEMORY + b"MemTotal: 1 kB\n"
    for data in (missing, duplicate):
      with self.subTest(data=data), self.assertRaises(incident.SectionUnavailable):
        incident.parse_meminfo(data)

  def test_rejects_bad_value_forms_and_units(self):
    for replacement in (b"-1 kB", b"1.0 kB", b"1e2 kB", b"1 MB", b"1 kB junk"):
      data = VALID_MEMORY.replace(b"16384 kB", replacement)
      with self.subTest(replacement=replacement), self.assertRaises(incident.SectionUnavailable):
        incident.parse_meminfo(data)

  def test_integer_length_bound(self):
    valid = VALID_MEMORY.replace(b"16384", b"9" * 20)
    self.assertGreater(incident.parse_meminfo(valid).total, 0)
    invalid = VALID_MEMORY.replace(b"16384", b"9" * 21)
    with self.assertRaises(incident.SectionUnavailable) as caught:
      incident.parse_meminfo(invalid)
    self.assertEqual(caught.exception.reason, "numeric value exceeds V1 limit")

  def test_memory_relationships_and_zero_total(self):
    variants = (
      VALID_MEMORY.replace(b"MemAvailable: 8192", b"MemAvailable: 20000"),
      VALID_MEMORY.replace(b"SwapFree: 2048", b"SwapFree: 5000"),
      VALID_MEMORY.replace(b"MemTotal: 16384", b"MemTotal: 0"),
    )
    for data in variants:
      with self.subTest(data=data), self.assertRaises(incident.SectionUnavailable):
        incident.parse_meminfo(data)

  def test_zero_swap_and_available_are_valid(self):
    data = b"MemTotal: 1 kB\nMemAvailable: 0 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n"
    value = incident.parse_meminfo(data)
    self.assertEqual((value.available, value.swap_total, value.swap_free), (0, 0, 0))

  def test_record_bound(self):
    prefix = b"Unknown: 1 kB\n" * 252
    self.assertEqual(incident.parse_meminfo(prefix + VALID_MEMORY.replace(b"MemFree: 1 kB\n", b"")).total, 16384 * 1024)
    with self.assertRaises(incident.SectionUnavailable) as caught:
      incident.parse_meminfo(b"Unknown: 1 kB\n" * 253 + VALID_MEMORY.replace(b"MemFree: 1 kB\n", b""))
    self.assertEqual(caught.exception.reason, "record count exceeds V1 limit")


class FilesystemTests(unittest.TestCase):
  def test_valid_calculation_and_single_root_call(self):
    provider = mock.Mock(return_value=vfs())
    result = incident.collect_root_filesystem(provider)
    provider.assert_called_once_with("/")
    self.assertEqual(result, incident.FilesystemObservation(102400, 61440, 30720))

  def test_fragment_size_preferred_and_block_size_fallback(self):
    self.assertEqual(incident.collect_root_filesystem(lambda path: vfs()).total, 100 * 1024)
    self.assertEqual(incident.collect_root_filesystem(lambda path: vfs(f_frsize=0)).total, 100 * 4096)

  def test_rejects_bad_shapes_and_bool(self):
    for result in (types.SimpleNamespace(), vfs(f_blocks=True)):
      with self.subTest(result=result), self.assertRaises(incident.SectionUnavailable) as caught:
        incident.collect_root_filesystem(lambda path, result=result: result)
      self.assertEqual(caught.exception.reason, "unsupported data shape")

  def test_rejects_invalid_size_relationships_and_denominator(self):
    for result in (vfs(f_frsize=0, f_bsize=0), vfs(f_bfree=101), vfs(f_bavail=41),
                   vfs(f_blocks=-1), vfs(f_blocks=0, f_bfree=0, f_bavail=0)):
      with self.subTest(result=result), self.assertRaises(incident.SectionUnavailable):
        incident.collect_root_filesystem(lambda path, result=result: result)

  def test_valid_zero_used(self):
    result = incident.collect_root_filesystem(lambda path: vfs(f_blocks=100, f_bfree=100, f_bavail=90))
    self.assertEqual(result.used, 0)

  def test_arithmetic_bound(self):
    with self.assertRaises(incident.SectionUnavailable) as caught:
      incident.collect_root_filesystem(lambda path: vfs(f_frsize=1 << 126, f_blocks=2, f_bfree=1, f_bavail=1))
    self.assertEqual(caught.exception.reason, "numeric value exceeds V1 limit")

  def test_provider_failure_mapping(self):
    for error, reason in ((PermissionError(), "permission denied"), (FileNotFoundError(), "source unavailable"), (OSError(), "observation failed")):
      with self.subTest(reason=reason), self.assertRaises(incident.SectionUnavailable) as caught:
        incident.collect_root_filesystem(lambda path, error=error: (_ for _ in ()).throw(error))
      self.assertEqual(caught.exception.reason, reason)


class BoundedReaderTests(unittest.TestCase):
  def test_exact_limit_and_limit_plus_one(self):
    with tempfile.NamedTemporaryFile() as handle:
      handle.write(b"a" * 8); handle.flush()
      self.assertEqual(incident.read_bounded_ascii(handle.name, 8), b"a" * 8)
      handle.seek(0); handle.truncate(); handle.write(b"a" * 9); handle.flush()
      with self.assertRaises(incident.SectionUnavailable) as caught:
        incident.read_bounded_ascii(handle.name, 8)
      self.assertEqual(caught.exception.reason, "source exceeds V1 byte limit")

  def test_non_ascii_and_nul_are_rejected(self):
    for data in (b"\xff", b"a\x00b"):
      with tempfile.NamedTemporaryFile() as handle:
        handle.write(data); handle.flush()
        with self.subTest(data=data), self.assertRaises(incident.SectionUnavailable):
          incident.read_bounded_ascii(handle.name, 10)

  def test_missing_source_mapping(self):
    with self.assertRaises(incident.SectionUnavailable) as caught:
      incident.read_bounded_ascii("/definitely/not/present", 10)
    self.assertEqual(caught.exception.reason, "source unavailable")

  def test_rejects_non_regular_descriptor_and_closes_it(self):
    with mock.patch.object(incident.os, "open", return_value=45), \
         mock.patch.object(incident.os, "fstat", return_value=types.SimpleNamespace(st_mode=stat.S_IFDIR)), \
         mock.patch.object(incident.os, "close") as close:
      with self.assertRaises(incident.SectionUnavailable):
        incident.read_bounded_ascii("/proc/uptime", 10)
      close.assert_called_once_with(45)

  def test_procfs_zero_st_size_does_not_suppress_read(self):
    metadata = types.SimpleNamespace(st_mode=stat.S_IFREG, st_size=0)
    with mock.patch.object(incident.os, "open", return_value=44), \
         mock.patch.object(incident.os, "fstat", return_value=metadata), \
         mock.patch.object(incident.os, "read", side_effect=[b"12.5 4\n", b""]) as read_mock, \
         mock.patch.object(incident.os, "close") as close:
      self.assertEqual(incident.read_bounded_ascii("/proc/uptime", 4096), b"12.5 4\n")
      self.assertEqual(read_mock.call_count, 2)
      close.assert_called_once_with(44)

  def test_read_failure_closes_descriptor(self):
    metadata = types.SimpleNamespace(st_mode=stat.S_IFREG, st_size=0)
    with mock.patch.object(incident.os, "open", return_value=43), \
         mock.patch.object(incident.os, "fstat", return_value=metadata), \
         mock.patch.object(incident.os, "read", side_effect=OSError(errno.EIO, "secret")), \
         mock.patch.object(incident.os, "close") as close:
      with self.assertRaises(incident.SectionUnavailable):
        incident.read_bounded_ascii("/proc/uptime", 10)
      close.assert_called_once_with(43)


class SnapshotAndRenderingTests(unittest.TestCase):
  def test_collection_order_and_timing(self):
    calls = []
    def tracked_reader(path, limit):
      calls.append(path); return reader(path, limit)
    times = iter((datetime(2026, 1, 1, tzinfo=timezone.utc), datetime(2026, 1, 2, tzinfo=timezone.utc)))
    monotonic = iter((100, 1_000_100))
    result = incident.collect_snapshot(
      reader=tracked_reader,
      uname_provider=lambda: calls.append("uname") or uname(),
      statvfs_provider=lambda path: calls.append("statvfs:" + path) or vfs(),
      utc_clock=lambda: next(times), monotonic_clock=lambda: next(monotonic))
    self.assertEqual(calls, ["uname", incident.UPTIME_PATH, incident.LOADAVG_PATH, incident.MEMINFO_PATH, "statvfs:/"])
    self.assertEqual(result.window.elapsed_ns, 1_000_000)

  def test_backward_wall_clock_does_not_change_elapsed(self):
    times = iter((datetime(2026, 2, 1, tzinfo=timezone.utc), datetime(2026, 1, 1, tzinfo=timezone.utc)))
    ticks = iter((5, 10))
    result = incident.collect_snapshot(reader=reader, uname_provider=lambda: uname(), statvfs_provider=lambda path: vfs(),
                                      utc_clock=lambda: next(times), monotonic_clock=lambda: next(ticks))
    self.assertEqual(result.window.elapsed_ns, 5)

  def test_negative_monotonic_delta_is_fatal(self):
    ticks = iter((10, 5))
    with self.assertRaises(incident.ObservationError):
      incident.collect_snapshot(reader=reader, uname_provider=lambda: uname(), statvfs_provider=lambda path: vfs(),
                               monotonic_clock=lambda: next(ticks))

  def test_optional_failures_continue_and_are_ordered(self):
    paths = []
    def partial_reader(path, limit):
      paths.append(path)
      if path == incident.MEMINFO_PATH:
        raise incident.SectionUnavailable("permission denied")
      return reader(path, limit)
    result = incident.collect_snapshot(reader=partial_reader, uname_provider=lambda: uname(),
                                      statvfs_provider=lambda path: (_ for _ in ()).throw(FileNotFoundError()),
                                      monotonic_clock=iter((0, 10)).__next__)
    report = incident.render_report(result)
    self.assertIn("1. Memory: permission denied\n  2. Root filesystem: source unavailable", report)
    self.assertIn(incident.MEMINFO_PATH, paths)
    self.assertEqual(incident.snapshot_exit_code(result), 1)

  def test_mandatory_failure_stops_optional_collection(self):
    statvfs_provider = mock.Mock()
    def failed_reader(path, limit):
      del path, limit
      raise incident.SectionUnavailable("malformed data")
    with self.assertRaises(incident.ObservationError):
      incident.collect_snapshot(reader=failed_reader, uname_provider=lambda: uname(), statvfs_provider=statvfs_provider)
    statvfs_provider.assert_not_called()

  def test_report_has_exact_order_and_terminal_newline(self):
    report = incident.render_report(snapshot())
    headings = ["Incident Snapshot", "Observation", "Platform", "Runtime", "Memory", "Root filesystem", "Collection warnings", "Interpretation limits"]
    positions = [report.index(heading) for heading in headings]
    self.assertEqual(positions, sorted(positions))
    self.assertTrue(report.endswith("\n")); self.assertFalse(report.endswith("\n\n"))
    self.assertIn("Collection warnings\n  None", report)

  def test_report_formatting(self):
    report = incident.render_report(snapshot())
    self.assertIn("Started UTC: 2026-01-02T03:04:05.006789Z", report)
    self.assertIn("Elapsed: 1234.568 ms", report)
    self.assertIn("Uptime: 1 d 01:01:01 (90061.25 seconds)", report)
    self.assertIn("Available percent: 50.0%", report)
    self.assertIn("Capacity used: 66.7%", report)

  def test_byte_format_boundaries(self):
    self.assertEqual(incident.format_iec_bytes(512), "512 B")
    self.assertEqual(incident.format_iec_bytes(1024), "1.0 KiB (1024 bytes)")
    for power, unit in enumerate(incident.IEC_UNITS[1:], 1):
      self.assertEqual(incident.format_iec_bytes(1024 ** power), f"1.0 {unit} ({1024 ** power} bytes)")

  def test_display_safe_escapes_controls_formats_surrogates_and_backslash(self):
    value = "a\\\n\t\x1b\x7f\u202e\u2028\udcff"
    rendered = incident.display_safe(value)
    self.assertEqual(rendered, "a\\\\\\x0a\\x09\\x1b\\x7f\\u202e\\u2028\\udcff")

  def test_no_hostname_version_or_ignored_tokens_rendered(self):
    report = incident.render_report(snapshot())
    for forbidden in ("Hostname", "secret", "98765", "3/100"):
      self.assertNotIn(forbidden, report)
    self.assertIn("does not determine incident severity or identify root cause", report)


class MainTests(unittest.TestCase):
  def run_main(self, result):
    stdout, stderr = io.StringIO(), io.StringIO()
    with mock.patch.object(incident, "collect_snapshot", return_value=result), \
         mock.patch.object(incident.sys, "stdout", stdout), mock.patch.object(incident.sys, "stderr", stderr):
      code = incident.main([])
    return code, stdout.getvalue(), stderr.getvalue()

  def test_complete_stream_contract(self):
    code, stdout, stderr = self.run_main(snapshot())
    self.assertEqual(code, 0); self.assertTrue(stdout.startswith("Incident Snapshot\n")); self.assertEqual(stderr, "")

  def test_incomplete_stream_contract(self):
    code, stdout, stderr = self.run_main(snapshot(memory=incident.OptionalObservation(reason="source unavailable")))
    self.assertEqual(code, 1); self.assertIn("Status: unavailable", stdout)
    self.assertEqual(stderr, "incidentsnapshot: snapshot incomplete; see Collection warnings\n")

  def test_help_performs_no_collection(self):
    with mock.patch.object(incident, "collect_snapshot") as collect, self.assertRaises(SystemExit) as caught:
      incident.main(["--help"])
    self.assertEqual(caught.exception.code, 0); collect.assert_not_called()

  def test_invalid_arguments_exit_two_without_collection(self):
    for argv in (["unexpected"], ["--unknown"]):
      with self.subTest(argv=argv), mock.patch.object(incident, "collect_snapshot") as collect, \
           self.assertRaises(SystemExit) as caught:
        incident.main(argv)
      self.assertEqual(caught.exception.code, 2); collect.assert_not_called()

  def test_unsupported_platform_contract(self):
    stdout, stderr = io.StringIO(), io.StringIO()
    with mock.patch.object(incident, "collect_snapshot", side_effect=incident.UnsupportedPlatform), \
         mock.patch.object(incident.sys, "stdout", stdout), mock.patch.object(incident.sys, "stderr", stderr):
      self.assertEqual(incident.main([]), 3)
    self.assertEqual(stdout.getvalue(), "")
    self.assertEqual(stderr.getvalue(), "incidentsnapshot: unsupported platform: Linux is required\n")

  def test_fatal_and_internal_failures_have_no_traceback(self):
    for error, expected in ((incident.ObservationError("runtime", "malformed data"), "incidentsnapshot: runtime observation failed: malformed data\n"),
                            (RuntimeError("secret"), "incidentsnapshot: internal execution failure\n")):
      stdout, stderr = io.StringIO(), io.StringIO()
      with mock.patch.object(incident, "collect_snapshot", side_effect=error), \
           mock.patch.object(incident.sys, "stdout", stdout), mock.patch.object(incident.sys, "stderr", stderr):
        self.assertEqual(incident.main([]), 3)
      self.assertEqual(stdout.getvalue(), ""); self.assertEqual(stderr.getvalue(), expected)
      self.assertNotIn("Traceback", stderr.getvalue())

  def test_interrupt_contract(self):
    stdout, stderr = io.StringIO(), io.StringIO()
    with mock.patch.object(incident, "collect_snapshot", side_effect=KeyboardInterrupt), \
         mock.patch.object(incident.sys, "stdout", stdout), mock.patch.object(incident.sys, "stderr", stderr):
      self.assertEqual(incident.main([]), 130)
    self.assertEqual(stdout.getvalue(), ""); self.assertEqual(stderr.getvalue(), "incidentsnapshot: interrupted\n")

  def test_source_allowlist_and_no_deadline_skipping(self):
    paths = []
    def allowed_reader(path, limit):
      paths.append(path); return reader(path, limit)
    ticks = iter((0, 10 ** 30))
    provider = mock.Mock(return_value=vfs())
    incident.collect_snapshot(reader=allowed_reader, uname_provider=lambda: uname(), statvfs_provider=provider,
                              monotonic_clock=lambda: next(ticks))
    self.assertEqual(paths, [incident.UPTIME_PATH, incident.LOADAVG_PATH, incident.MEMINFO_PATH])
    provider.assert_called_once_with("/")


if __name__ == "__main__":
  unittest.main()
