import contextlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).parents[1] / "procwatch.py"
SPEC = importlib.util.spec_from_file_location("procwatch", MODULE_PATH)
procwatch = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = procwatch
SPEC.loader.exec_module(procwatch)


class StrictAsciiStream(io.StringIO):
  @property
  def encoding(self):
    return "ascii"

  def write(self, value):
    value.encode("ascii", errors="strict")
    return super().write(value)


def make_stat(
  pid=123,
  command="worker",
  state="S",
  ppid=1,
  user_ticks=100,
  system_ticks=50,
  threads=2,
  start_ticks=9000,
  virtual_bytes=1024 * 1024,
  rss_pages=100,
):
  fields = [
    state, str(ppid), "0", "0", "0", "0", "0", "0", "0", "0", "0",
    str(user_ticks), str(system_ticks), "0", "0", "0", "0", str(threads), "0",
    str(start_ticks), str(virtual_bytes), str(rss_pages),
  ]
  return f"{pid} ({command}) " + " ".join(fields) + "\n"


def sample(**overrides):
  values = dict(
    pid=123,
    command="worker",
    state="S",
    ppid=1,
    user_ticks=100,
    system_ticks=50,
    threads=2,
    start_ticks=9000,
    virtual_bytes=1024 * 1024,
    rss_pages=100,
    observed_at=10.0,
  )
  values.update(overrides)
  return procwatch.ProcessSample(**values)


def extended(*, incomplete=None, command="worker"):
  initial = sample(command=command, observed_at=10.0)
  final = None if incomplete else sample(command=command, observed_at=11.0)
  analysis = procwatch.AnalysisResult(
    123, 1.0, 100, 4096, initial, final,
    None if incomplete else 1.0, incomplete, (initial,) if incomplete else (initial, final),
  )
  return procwatch.ExtendedResult(analysis, None, None, None, ())


class CliTests(unittest.TestCase):
  def run_main(self, arguments):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
      code = procwatch.main(arguments)
    return code, stdout.getvalue(), stderr.getvalue()

  def test_help_is_stdout_and_does_not_inspect(self):
    for option in ("-h", "--help"):
      with self.subTest(option=option), mock.patch.object(procwatch, "observe_extended") as observe:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), self.assertRaises(SystemExit) as caught:
          procwatch.main([option])
        self.assertEqual(caught.exception.code, 0)
        self.assertIn("bounded CPU and memory evidence", stdout.getvalue())
        observe.assert_not_called()

  def test_argument_errors_are_terminal_safe(self):
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
      procwatch.main(["1", "\x1b[31m"])
    self.assertEqual(caught.exception.code, 2)
    self.assertNotIn("\x1b", stderr.getvalue())
    self.assertIn("\\x1b", stderr.getvalue())

  def test_duration_keeps_interval_within_supported_range(self):
    for argv, expected in (
      (["--duration", "0.3", "--interval", "0.1"], (1, 0.1, 4)),
      (["--duration", "0.1"], (1, 0.1, 2)),
      (["--duration", "3600", "--interval", "60"], (1, 60.0, 61)),
      (["--duration", "3600", "--interval", "0.1"], (1, 36.363636, 100)),
    ):
      with self.subTest(argv=argv), \
           mock.patch.object(procwatch, "observe_extended", return_value=extended()) as observe:
        self.run_main(["--quiet", *argv, "1"])
        observe.assert_called_once_with(*expected)

  def test_invalid_pid_and_interval_exit_two(self):
    arguments = (
      [], ["0"], ["-1"], ["abc"], ["1", "extra"],
      ["1", "--interval", "0"], ["1", "--interval", "60.1"],
      ["1", "--interval", "nan"], ["1", "--interval", "inf"],
    )
    for argv in arguments:
      with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()), \
           self.assertRaises(SystemExit) as caught:
        procwatch.main(argv)
      self.assertEqual(caught.exception.code, 2)

  def test_interval_boundaries_and_default(self):
    parser = procwatch.build_argument_parser()
    self.assertEqual(parser.parse_args(["12"]).interval, 1.0)
    self.assertEqual(parser.parse_args(["12", "--interval", "0.1"]).interval, 0.1)
    self.assertEqual(parser.parse_args(["12", "--interval", "60"]).interval, 60.0)

  def test_success_partial_and_expected_errors(self):
    with mock.patch.object(procwatch, "observe_extended", return_value=extended()):
      code, stdout, stderr = self.run_main(["1"])
      self.assertEqual((code, stderr), (0, ""))
      self.assertIn("Conclusion: [OBSERVED]", stdout)
    with mock.patch.object(
      procwatch, "observe_extended", return_value=extended(incomplete="exited")
    ):
      code, stdout, stderr = self.run_main(["1"])
      self.assertEqual(code, 1)
      self.assertIn("Conclusion: [PARTIAL]", stdout)
      self.assertIn("incomplete observation", stderr)
    with mock.patch.object(
      procwatch, "observe_extended", side_effect=procwatch.InvalidTargetError("missing")
    ):
      self.assertEqual(self.run_main(["1"]), (2, "", "procwatch: missing\n"))
    with mock.patch.object(
      procwatch, "observe_extended", side_effect=procwatch.ObservationError("bad")
    ):
      self.assertEqual(self.run_main(["1"]), (3, "", "procwatch: bad\n"))

  def test_internal_error_and_interrupt_have_stable_output(self):
    with mock.patch.object(procwatch, "observe_extended", side_effect=RuntimeError("secret")):
      self.assertEqual(
        self.run_main(["1"]), (3, "", "procwatch: internal execution failure\n")
      )
    with mock.patch.object(procwatch, "observe_extended", side_effect=KeyboardInterrupt):
      self.assertEqual(self.run_main(["1"]), (130, "", "procwatch: interrupted\n"))

  def test_ascii_stdout_escapes_unencodable_unicode(self):
    stdout = StrictAsciiStream()
    stderr = io.StringIO()
    with mock.patch.object(procwatch.sys, "stdout", stdout), \
         mock.patch.object(procwatch.sys, "stderr", stderr), \
         mock.patch.object(procwatch, "observe_extended", return_value=extended(command="process é")):
      code = procwatch.main(["1"])
    self.assertEqual(code, 0)
    self.assertEqual(stderr.getvalue(), "")
    self.assertIn("process \\xe9", stdout.getvalue())

  def test_json_brief_quiet_and_sample_bounds(self):
    with mock.patch.object(procwatch, "observe_extended", return_value=extended()) as observe:
      code, stdout, stderr = self.run_main(["--json", "--samples", "4", "1"])
      self.assertEqual((code, stderr), (0, ""))
      self.assertEqual(json.loads(stdout)["tool"], "procwatch")
      observe.assert_called_with(1, 1.0, 4)
      self.assertIn("Samples:", self.run_main(["--brief", "1"])[1])
      self.assertEqual(self.run_main(["--quiet", "1"])[1], "")

  def test_late_failure_reports_partial_with_captured_samples(self):
    first = sample(observed_at=10.0)
    second = sample(user_ticks=150, rss_pages=110, observed_at=11.0)
    analysis = procwatch.AnalysisResult(
      123, 1.0, 100, 4096, first, second, 1.0,
      "sample 3 unavailable: gone; results cover samples 1-2 (1.000 s)", (first, second), 3,
    )
    result = procwatch.ExtendedResult(analysis, None, None, None, ())
    with mock.patch.object(procwatch, "observe_extended", return_value=result):
      code, stdout, stderr = self.run_main(["--json", "--samples", "3", "1"])
    document = json.loads(stdout)
    self.assertEqual((code, document["status"]), (1, "PARTIAL"))
    self.assertEqual(document["observations"]["sample_count"], 2)
    self.assertEqual(document["observations"]["rss_delta_bytes"], 10 * 4096)
    self.assertEqual(document["observations"]["cpu_utilization_percent"], 50.0)
    self.assertIn("2 of 3 bounded samples captured", document["conclusion"])
    self.assertIn("results cover samples 1-2", stderr)


class StatParsingTests(unittest.TestCase):
  def test_required_fields_are_parsed(self):
    result = procwatch.parse_stat(make_stat().encode(), 123, 10.5)
    self.assertEqual(result.pid, 123)
    self.assertEqual(result.command, "worker")
    self.assertEqual(result.state, "S")
    self.assertEqual(result.ppid, 1)
    self.assertEqual(result.cpu_ticks, 150)
    self.assertEqual(result.threads, 2)
    self.assertEqual(result.start_ticks, 9000)
    self.assertEqual(result.virtual_bytes, 1024 * 1024)
    self.assertEqual(result.rss_pages, 100)
    self.assertEqual(result.observed_at, 10.5)

  def test_command_can_contain_spaces_parentheses_and_controls(self):
    value = make_stat(command="name ) with\tspace")
    result = procwatch.parse_stat(value.encode(), 123, 1.0)
    self.assertEqual(result.command, "name ) with\tspace")
    self.assertIn("\\x09", procwatch.display_safe(result.command))

  def test_mismatched_pid_and_malformed_records_are_rejected(self):
    cases = (
      (make_stat(pid=124).encode(), 123),
      (b"123 worker S 1\n", 123),
      (b"123 (worker) S 1 2\n", 123),
      (make_stat(state="SS").encode(), 123),
      (make_stat(user_ticks=-1).encode(), 123),
    )
    for data, expected in cases:
      with self.subTest(data=data), self.assertRaises(procwatch.ProcReadError):
        procwatch.parse_stat(data, expected, 1.0)

  def test_non_integer_required_field_is_rejected(self):
    data = make_stat().replace(" 100 50 ", " nope 50 ").encode()
    with self.assertRaises(procwatch.ProcReadError):
      procwatch.parse_stat(data, 123, 1.0)


class ProcAccessTests(unittest.TestCase):
  def test_open_process_directory_uses_descriptor_metadata(self):
    directory = mock.Mock(st_mode=stat.S_IFDIR | 0o555, st_nlink=2)
    with mock.patch.object(procwatch.os, "open", return_value=9) as opened, \
         mock.patch.object(procwatch.os, "fstat", return_value=directory), \
         mock.patch.object(procwatch.os, "close") as closed:
      self.assertEqual(procwatch.open_process_directory(123), 9)
    self.assertIn("/proc/123", opened.call_args.args)
    closed.assert_not_called()

  def test_non_directory_target_is_rejected_and_closed(self):
    metadata = mock.Mock(st_mode=stat.S_IFREG | 0o444, st_nlink=1)
    with mock.patch.object(procwatch.os, "open", return_value=9), \
         mock.patch.object(procwatch.os, "fstat", return_value=metadata), \
         mock.patch.object(procwatch.os, "close") as closed:
      with self.assertRaises(procwatch.InvalidTargetError):
        procwatch.open_process_directory(123)
      closed.assert_called_once_with(9)

  def test_directory_link_count_does_not_decide_process_availability(self):
    metadata = mock.Mock(st_mode=stat.S_IFDIR | 0o555, st_nlink=0)
    with mock.patch.object(procwatch.os, "open", return_value=9), \
         mock.patch.object(procwatch.os, "fstat", return_value=metadata), \
         mock.patch.object(procwatch.os, "close") as closed:
      self.assertEqual(procwatch.open_process_directory(123), 9)
      closed.assert_not_called()

  def test_open_failure_is_terminal_safe(self):
    with mock.patch.object(procwatch.os, "open", side_effect=OSError("gone\nnow")):
      with self.assertRaises(procwatch.InvalidTargetError) as caught:
        procwatch.open_process_directory(123)
    self.assertNotIn("\n", str(caught.exception))
    self.assertIn("\\x0a", str(caught.exception))

  def test_bounded_read_accepts_limit_and_detects_overflow(self):
    with mock.patch.object(procwatch.os, "open", return_value=10), \
         mock.patch.object(procwatch.os, "read", side_effect=[b"abcd", b""]), \
         mock.patch.object(procwatch.os, "close") as closed:
      self.assertEqual(procwatch.read_bounded_proc_file(9, "stat", 4), b"abcd")
      closed.assert_called_once_with(10)
    with mock.patch.object(procwatch.os, "open", return_value=10), \
         mock.patch.object(procwatch.os, "read", side_effect=[b"abcde"]), \
         mock.patch.object(procwatch.os, "close"):
      with self.assertRaises(procwatch.ProcReadError):
        procwatch.read_bounded_proc_file(9, "stat", 4)

  def test_bounded_read_rejects_nul_and_sanitizes_read_error(self):
    with mock.patch.object(procwatch.os, "open", return_value=10), \
         mock.patch.object(procwatch.os, "read", side_effect=[b"a\x00b", b""]), \
         mock.patch.object(procwatch.os, "close"):
      with self.assertRaises(procwatch.ProcReadError):
        procwatch.read_bounded_proc_file(9, "stat", 10)
    with mock.patch.object(procwatch.os, "open", return_value=10), \
         mock.patch.object(procwatch.os, "read", side_effect=OSError("bad\nread")), \
         mock.patch.object(procwatch.os, "close"):
      with self.assertRaises(procwatch.ProcReadError) as caught:
        procwatch.read_bounded_proc_file(9, "stat", 10)
    self.assertIn("\\x0a", str(caught.exception))

  @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux /proc")
  def test_current_process_stat_can_be_captured(self):
    pid = os.getpid()
    directory_fd = procwatch.open_process_directory(pid)
    try:
      result = procwatch.capture_sample(directory_fd, pid)
    finally:
      os.close(directory_fd)
    self.assertEqual(result.pid, pid)
    self.assertGreater(result.start_ticks, 0)
    self.assertGreaterEqual(result.rss_pages, 0)


class ObservationTests(unittest.TestCase):
  def observe_with_samples(self, samples, sample_count=2):
    with mock.patch.object(procwatch, "system_parameter", side_effect=[100, 4096]), \
         mock.patch.object(procwatch, "open_process_directory", return_value=9), \
         mock.patch.object(procwatch, "capture_sample", side_effect=samples), \
         mock.patch.object(procwatch.os, "close") as closed:
      result = procwatch.observe_samples(
        123, 0.5, sample_count=sample_count, sleep_fn=lambda value: self.assertEqual(value, 0.5),
      )
    closed.assert_called_once_with(9)
    return result

  def test_late_failure_keeps_earlier_samples(self):
    first = sample(observed_at=10.0)
    second = sample(user_ticks=120, observed_at=10.5)
    result = self.observe_with_samples([first, second, procwatch.ProcReadError("gone")], sample_count=3)
    self.assertTrue(result.incomplete)
    self.assertEqual((result.final, result.elapsed_seconds, result.captured_samples), (second, 0.5, 2))
    self.assertIn("sample 3 unavailable", result.incomplete_warning)
    self.assertIn("results cover samples 1-2", result.incomplete_warning)

  def test_exited_process_is_incomplete(self):
    result = self.observe_with_samples([sample(state="Z")])
    self.assertIsNone(result.final)
    self.assertIn("already exited", result.incomplete_warning)
    result = self.observe_with_samples([sample(observed_at=10.0), sample(state="X", observed_at=10.5)])
    self.assertIsNone(result.final)
    self.assertIn("process exited (state X)", result.incomplete_warning)

  def test_complete_observation_keeps_same_identity(self):
    initial = sample(observed_at=10.0)
    final = sample(user_ticks=130, system_ticks=60, rss_pages=120, observed_at=10.5)
    result = self.observe_with_samples([initial, final])
    self.assertFalse(result.incomplete)
    self.assertEqual(result.elapsed_seconds, 0.5)
    self.assertEqual(result.final, final)

  def test_second_read_failure_produces_useful_incomplete_result(self):
    initial = sample(observed_at=10.0)
    result = self.observe_with_samples([initial, procwatch.ProcReadError("exited")])
    self.assertTrue(result.incomplete)
    self.assertIsNone(result.final)
    self.assertIn("second sample unavailable", result.incomplete_warning)

  def test_identity_change_and_individual_backward_cpu_are_incomplete(self):
    initial = sample(observed_at=10.0)
    for final, phrase in (
      (sample(start_ticks=9001, observed_at=11.0), "identity changed"),
      (sample(user_ticks=10, system_ticks=10, observed_at=11.0), "moved backwards"),
      (sample(user_ticks=90, system_ticks=70, observed_at=11.0), "moved backwards"),
      (sample(user_ticks=120, system_ticks=40, observed_at=11.0), "moved backwards"),
    ):
      with self.subTest(phrase=phrase):
        result = self.observe_with_samples([initial, final])
        self.assertTrue(result.incomplete)
        self.assertIn(phrase, result.incomplete_warning)

  def test_initial_read_failure_is_invalid_target(self):
    with mock.patch.object(procwatch, "system_parameter", side_effect=[100, 4096]), \
         mock.patch.object(procwatch, "open_process_directory", return_value=9), \
         mock.patch.object(procwatch, "capture_sample", side_effect=procwatch.ProcReadError("gone")), \
         mock.patch.object(procwatch.os, "close"):
      with self.assertRaises(procwatch.InvalidTargetError):
        procwatch.observe_samples(123, 1.0, sleep_fn=lambda _: None)

  def test_nonpositive_or_nonfinite_measured_interval_is_fatal(self):
    initial = sample(observed_at=10.0)
    for observed_at in (10.0, 9.0, math.inf):
      with self.subTest(observed_at=observed_at), self.assertRaises(procwatch.ObservationError):
        self.observe_with_samples([initial, sample(observed_at=observed_at)])

  def test_system_parameter_failure_is_fatal_before_open(self):
    with mock.patch.object(procwatch.os, "sysconf", side_effect=OSError("unsupported")), \
         mock.patch.object(procwatch, "open_process_directory") as opened:
      with self.assertRaises(procwatch.ObservationError):
        procwatch.observe_samples(123, 1.0, sleep_fn=lambda _: None)
    opened.assert_not_called()


class AuxiliaryTests(unittest.TestCase):
  def test_status_counters_survive_undecodable_name(self):
    values = procwatch._parse_proc_mapping(b"Name:\tw\xe9\nvoluntary_ctxt_switches:\t5\nbad:\t\xd9\xa1\n")
    self.assertEqual(values, {"voluntary_ctxt_switches": 5})

  @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux /proc")
  def test_thread_cap_is_reported_as_truncated(self):
    release = threading.Event()
    worker = threading.Thread(target=release.wait)
    worker.start()
    try:
      directory_fd = procwatch.open_process_directory(os.getpid())
      try:
        with mock.patch.object(procwatch, "MAX_THREAD_SAMPLES", 1):
          aux, _ = procwatch.capture_auxiliary(directory_fd)
      finally:
        os.close(directory_fd)
    finally:
      release.set()
      worker.join()
    self.assertGreaterEqual(aux.thread_count, 2)
    self.assertEqual(len(aux.thread_cpu_ticks), 1)
    self.assertTrue(aux.threads_truncated)
    self.assertEqual(len(aux.thread_cpu_ticks[0]), 3)


class CgroupTests(unittest.TestCase):
  def collect(self, cgroup_line, mount_root, files):
    with tempfile.TemporaryDirectory() as mount_point:
      for relative, value in files.items():
        path = Path(mount_point, relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)
      with mock.patch.object(procwatch, "read_bounded_proc_file", return_value=cgroup_line.encode()):
        return procwatch.collect_cgroup_context(9, (mount_point, mount_root))

  def test_tightest_ancestor_limits_are_reported(self):
    context, gaps = self.collect("0::/a/b\n", "/", {
      "a/cpu.max": "50000 100000\n",
      "a/memory.max": "1048576\n",
      "a/b/cpu.max": "max 100000\n",
      "a/b/memory.max": "2097152\n",
    })
    self.assertEqual(gaps, [])
    self.assertEqual(context.path, "/a/b")
    self.assertEqual((context.cpu_constraint, context.cpu_constraint_source), ("50000 100000", "/a"))
    self.assertEqual((context.memory_constraint, context.memory_constraint_source), ("1048576", "/a"))

  def test_unlimited_and_unsupported_values_are_distinguished(self):
    context, gaps = self.collect("0::/a\n", "/", {"a/cpu.max": "max 100000\n", "a/memory.max": "lots\n"})
    self.assertEqual((context.cpu_constraint, context.cpu_constraint_source), ("max 100000", None))
    self.assertIsNone(context.memory_constraint)
    self.assertTrue(any("memory.max at /a has an unsupported value" in gap for gap in gaps))
    self.assertIn("no limit at any readable level", procwatch._constraint_text("max 100000", None))

  def test_nested_mount_root_and_outside_paths(self):
    context, gaps = self.collect("0::/pod/app\n", "/pod", {"memory.max": "4096\n", "app/cpu.max": "max 100000\n"})
    self.assertEqual((context.memory_constraint, context.memory_constraint_source), ("4096", "/pod"))
    self.assertEqual(gaps, [])
    context, gaps = self.collect("0::/other\n", "/pod", {})
    self.assertIsNone(context.cpu_constraint)
    self.assertIn("not below cgroup2 mount root", gaps[0])
    context, gaps = self.collect("0::/../escaped\n", "/", {})
    self.assertIn("outside this cgroup namespace", gaps[0])

  def test_cgroup2_mount_is_found_with_escapes(self):
    mountinfo = (
      "24 1 8:1 / / rw - ext4 /dev/sda1 rw\n"
      "30 25 0:26 /pod /sys/fs/cgroup\\040x rw,nosuid shared:4 - cgroup2 cgroup2 rw\n"
    )
    self.assertEqual(procwatch.parse_cgroup2_mount(mountinfo), ("/sys/fs/cgroup x", "/pod"))
    self.assertIsNone(procwatch.parse_cgroup2_mount("24 1 8:1 / / rw - ext4 /dev/sda1 rw\n"))


class RenderingTests(unittest.TestCase):
  def test_complete_rendering_computes_cpu_and_memory_deltas(self):
    initial = sample(
      user_ticks=100,
      system_ticks=50,
      rss_pages=100,
      virtual_bytes=1024 * 1024,
      observed_at=10.0,
    )
    final = sample(
      command="worker",
      state="R",
      ppid=2,
      user_ticks=250,
      system_ticks=100,
      threads=4,
      rss_pages=102,
      virtual_bytes=1024 * 1024 + 4096,
      observed_at=12.0,
    )
    result = procwatch.AnalysisResult(123, 1.0, 100, 4096, initial, final, 2.0)
    output = procwatch.render_result(result)
    self.assertIn("Observation window: 2.000000 s", output)
    self.assertIn("User CPU delta: 1.500000 s", output)
    self.assertIn("System CPU delta: 0.500000 s", output)
    self.assertIn("Utilization relative to one logical CPU: 100.00%", output)
    self.assertIn("Resident set delta: +8.00 KiB", output)
    self.assertIn("Virtual memory delta: +4.00 KiB", output)
    self.assertIn("State: S -> R", output)
    self.assertIn("Threads: 2 -> 4", output)

  def test_utilization_can_exceed_one_hundred_percent(self):
    initial = sample(user_ticks=0, system_ticks=0, observed_at=1.0)
    final = sample(user_ticks=200, system_ticks=0, observed_at=2.0)
    result = procwatch.AnalysisResult(123, 1.0, 100, 4096, initial, final, 1.0)
    self.assertIn("200.00%", procwatch.render_result(result))

  def test_incomplete_rendering_has_initial_evidence_without_deltas(self):
    initial = sample(command="bad\nname")
    result = procwatch.AnalysisResult(
      123, 1.0, 100, 4096, initial, None, None, "second sample unavailable"
    )
    output = procwatch.render_result(result)
    self.assertIn("Status: incomplete", output)
    self.assertIn("Command name: bad\\x0aname", output)
    self.assertIn("Delta evidence", output)
    self.assertIn("Unavailable", output)
    self.assertNotIn("CPU evidence\n", output)

  def test_truncated_auxiliary_evidence_is_labelled(self):
    aux = procwatch.AuxiliarySample(
      1, 0, 0, 0, 0, 0, (7, 8), ((1, 10, 5),), children_truncated=True, thread_count=300, threads_truncated=True,
    )
    base = extended()
    output = procwatch.render_extended(procwatch.ExtendedResult(base.analysis, aux, None, None, ()))
    self.assertIn("Child PIDs: 7, 8 (truncated)", output)
    self.assertIn("Observed threads: 1 of 300 (truncated)", output)

  def test_reused_thread_id_is_not_compared(self):
    initial = procwatch.AuxiliarySample(1, 0, 0, 0, 0, 0, (), ((5, 10, 100), (6, 10, 100)))
    final = procwatch.AuxiliarySample(1, 0, 0, 0, 0, 0, (), ((5, 90, 200), (6, 30, 100)))
    base = extended()
    output = procwatch.render_extended(procwatch.ExtendedResult(base.analysis, initial, final, None, ()))
    self.assertIn("Top per-thread CPU tick deltas: 6:+20\n", output + "\n")


if __name__ == "__main__":
  unittest.main()
