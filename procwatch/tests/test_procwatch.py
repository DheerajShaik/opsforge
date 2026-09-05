import contextlib
import importlib.util
import io
import math
import os
from pathlib import Path
import stat
import sys
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


class CliTests(unittest.TestCase):
  def run_main(self, arguments):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
      code = procwatch.main(arguments)
    return code, stdout.getvalue(), stderr.getvalue()

  def test_help_is_stdout_and_does_not_inspect(self):
    for option in ("-h", "--help"):
      with self.subTest(option=option), mock.patch.object(procwatch, "inspect") as inspect:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), self.assertRaises(SystemExit) as caught:
          procwatch.main([option])
        self.assertEqual(caught.exception.code, 0)
        self.assertIn("bounded CPU and memory evidence", stdout.getvalue())
        inspect.assert_not_called()

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
    with mock.patch.object(procwatch, "inspect", return_value=("report", None, 0)):
      self.assertEqual(self.run_main(["1"]), (0, "report\n", ""))
    with mock.patch.object(
      procwatch, "inspect", return_value=("partial", "procwatch: warning: incomplete", 1)
    ):
      self.assertEqual(
        self.run_main(["1"]),
        (1, "partial\n", "procwatch: warning: incomplete\n"),
      )
    with mock.patch.object(
      procwatch, "inspect", side_effect=procwatch.InvalidTargetError("missing")
    ):
      self.assertEqual(self.run_main(["1"]), (2, "", "procwatch: missing\n"))
    with mock.patch.object(
      procwatch, "inspect", side_effect=procwatch.ObservationError("bad")
    ):
      self.assertEqual(self.run_main(["1"]), (3, "", "procwatch: bad\n"))

  def test_internal_error_and_interrupt_have_stable_output(self):
    with mock.patch.object(procwatch, "inspect", side_effect=RuntimeError("secret")):
      self.assertEqual(
        self.run_main(["1"]), (3, "", "procwatch: internal execution failure\n")
      )
    with mock.patch.object(procwatch, "inspect", side_effect=KeyboardInterrupt):
      self.assertEqual(self.run_main(["1"]), (130, "", "procwatch: interrupted\n"))

  def test_ascii_stdout_escapes_unencodable_unicode(self):
    stdout = StrictAsciiStream()
    stderr = io.StringIO()
    with mock.patch.object(procwatch.sys, "stdout", stdout), \
         mock.patch.object(procwatch.sys, "stderr", stderr), \
         mock.patch.object(procwatch, "inspect", return_value=("process é", None, 0)):
      code = procwatch.main(["1"])
    self.assertEqual(code, 0)
    self.assertEqual(stderr.getvalue(), "")
    self.assertIn("process \\xe9", stdout.getvalue())


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
  def observe_with_samples(self, samples):
    with mock.patch.object(procwatch, "system_parameter", side_effect=[100, 4096]), \
         mock.patch.object(procwatch, "open_process_directory", return_value=9), \
         mock.patch.object(procwatch, "capture_sample", side_effect=samples), \
         mock.patch.object(procwatch.os, "close") as closed:
      result = procwatch.observe(123, 0.5, sleep_fn=lambda value: self.assertEqual(value, 0.5))
    closed.assert_called_once_with(9)
    return result

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
        procwatch.observe(123, 1.0, sleep_fn=lambda _: None)

  def test_nonpositive_or_nonfinite_measured_interval_is_fatal(self):
    initial = sample(observed_at=10.0)
    for observed_at in (10.0, 9.0, math.inf):
      with self.subTest(observed_at=observed_at), self.assertRaises(procwatch.ObservationError):
        self.observe_with_samples([initial, sample(observed_at=observed_at)])

  def test_system_parameter_failure_is_fatal_before_open(self):
    with mock.patch.object(procwatch.os, "sysconf", side_effect=OSError("unsupported")), \
         mock.patch.object(procwatch, "open_process_directory") as opened:
      with self.assertRaises(procwatch.ObservationError):
        procwatch.observe(123, 1.0, sleep_fn=lambda _: None)
    opened.assert_not_called()


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
    self.assertIn("Observed sample interval: 2.000000 s", output)
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

  def test_inspect_maps_incomplete_to_exit_one_and_warning(self):
    initial = sample()
    result = procwatch.AnalysisResult(123, 1.0, 100, 4096, initial, None, None, "exited")
    with mock.patch.object(procwatch, "observe", return_value=result):
      output, warning, code = procwatch.inspect(123, 1.0)
    self.assertEqual(code, 1)
    self.assertIn("Status: incomplete", output)
    self.assertEqual(warning, "procwatch: warning: incomplete observation: exited")


if __name__ == "__main__":
  unittest.main()
