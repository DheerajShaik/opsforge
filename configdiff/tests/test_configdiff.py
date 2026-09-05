import contextlib
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).parents[1] / "configdiff.py"
SPEC = importlib.util.spec_from_file_location("configdiff", MODULE_PATH)
configdiff = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = configdiff
SPEC.loader.exec_module(configdiff)


class StrictAsciiStream(io.StringIO):
  @property
  def encoding(self):
    return "ascii"

  def write(self, value):
    value.encode("ascii", errors="strict")
    return super().write(value)


def metadata(
  *,
  mode=stat.S_IFREG | 0o644,
  size=4,
  device=1,
  inode=2,
  mtime_ns=10,
  ctime_ns=20,
):
  value = mock.Mock()
  value.st_mode = mode
  value.st_size = size
  value.st_dev = device
  value.st_ino = inode
  value.st_mtime_ns = mtime_ns
  value.st_ctime_ns = ctime_ns
  return value


class CliTests(unittest.TestCase):
  def run_main(self, arguments):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
      code = configdiff.main(arguments)
    return code, stdout.getvalue(), stderr.getvalue()

  def test_help_is_stdout_and_does_not_compare(self):
    for option in ("-h", "--help"):
      with self.subTest(option=option), mock.patch.object(configdiff, "inspect") as inspect:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), self.assertRaises(SystemExit) as caught:
          configdiff.main([option])
        self.assertEqual(caught.exception.code, 0)
        self.assertIn("exact byte-content drift", stdout.getvalue())
        inspect.assert_not_called()

  def test_invalid_invocation_exits_two(self):
    for argv in ([], ["one"], ["one", "two", "three"]):
      with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()), \
           self.assertRaises(SystemExit) as caught:
        configdiff.main(argv)
      self.assertEqual(caught.exception.code, 2)

  def test_success_and_drift_exit_codes(self):
    with mock.patch.object(configdiff, "inspect", return_value=("same", 0)):
      self.assertEqual(self.run_main(["a", "b"]), (0, "same\n", ""))
    with mock.patch.object(configdiff, "inspect", return_value=("different", 1)):
      self.assertEqual(self.run_main(["a", "b"]), (1, "different\n", ""))

  def test_expected_errors_have_stable_exit_codes(self):
    with mock.patch.object(
      configdiff, "inspect", side_effect=configdiff.InvalidTargetError("bad target")
    ):
      self.assertEqual(
        self.run_main(["a", "b"]), (2, "", "configdiff: bad target\n")
      )
    with mock.patch.object(
      configdiff, "inspect", side_effect=configdiff.ObservationError("unstable")
    ):
      self.assertEqual(
        self.run_main(["a", "b"]), (3, "", "configdiff: unstable\n")
      )

  def test_internal_error_and_interrupt_have_stable_output(self):
    with mock.patch.object(configdiff, "inspect", side_effect=RuntimeError("secret")):
      self.assertEqual(
        self.run_main(["a", "b"]),
        (3, "", "configdiff: internal execution failure\n"),
      )
    with mock.patch.object(configdiff, "inspect", side_effect=KeyboardInterrupt):
      self.assertEqual(
        self.run_main(["a", "b"]), (130, "", "configdiff: interrupted\n")
      )

  def test_ascii_stdout_escapes_unencodable_unicode(self):
    stdout = StrictAsciiStream()
    stderr = io.StringIO()
    with mock.patch.object(configdiff.sys, "stdout", stdout), \
         mock.patch.object(configdiff.sys, "stderr", stderr), \
         mock.patch.object(configdiff, "inspect", return_value=("path é", 0)):
      code = configdiff.main(["a", "b"])
    self.assertEqual(code, 0)
    self.assertEqual(stderr.getvalue(), "")
    self.assertIn("path \\xe9", stdout.getvalue())


class FileAccessTests(unittest.TestCase):
  def test_open_regular_file_uses_descriptor_metadata(self):
    info = metadata(size=4)
    with mock.patch.object(configdiff.os, "open", return_value=9) as opened, \
         mock.patch.object(configdiff.os, "fstat", return_value=info), \
         mock.patch.object(configdiff.os, "close") as closed:
      descriptor, returned = configdiff.open_regular_file("target", "baseline")
    self.assertEqual(descriptor, 9)
    self.assertIs(returned, info)
    self.assertEqual(opened.call_args.args[0], "target")
    closed.assert_not_called()

  def test_non_regular_file_is_rejected_and_closed(self):
    info = metadata(mode=stat.S_IFDIR | 0o755)
    with mock.patch.object(configdiff.os, "open", return_value=9), \
         mock.patch.object(configdiff.os, "fstat", return_value=info), \
         mock.patch.object(configdiff.os, "close") as closed:
      with self.assertRaises(configdiff.InvalidTargetError):
        configdiff.open_regular_file("target", "current")
    closed.assert_called_once_with(9)

  def test_oversized_file_is_rejected(self):
    info = metadata(size=configdiff.MAX_FILE_BYTES + 1)
    with mock.patch.object(configdiff.os, "open", return_value=9), \
         mock.patch.object(configdiff.os, "fstat", return_value=info), \
         mock.patch.object(configdiff.os, "close") as closed:
      with self.assertRaises(configdiff.InvalidTargetError) as caught:
        configdiff.open_regular_file("target", "baseline")
    self.assertIn(str(configdiff.MAX_FILE_BYTES), str(caught.exception))
    closed.assert_called_once_with(9)

  def test_open_failure_is_terminal_safe(self):
    with mock.patch.object(configdiff.os, "open", side_effect=OSError("bad\npath")):
      with self.assertRaises(configdiff.InvalidTargetError) as caught:
        configdiff.open_regular_file("target", "baseline")
    self.assertNotIn("\n", str(caught.exception))
    self.assertIn("\\x0a", str(caught.exception))

  def test_read_exact_snapshot_accepts_exact_size(self):
    info = metadata(size=4)
    with mock.patch.object(configdiff.os, "read", side_effect=[b"ab", b"cd", b""]):
      self.assertEqual(configdiff.read_exact_snapshot(9, info, "baseline"), b"abcd")

  def test_short_read_before_boundary_is_untrustworthy(self):
    info = metadata(size=4)
    with mock.patch.object(configdiff.os, "read", side_effect=[b"ab", b""]):
      with self.assertRaises(configdiff.ObservationError):
        configdiff.read_exact_snapshot(9, info, "baseline")

  def test_growth_past_initial_boundary_is_untrustworthy(self):
    info = metadata(size=4)
    with mock.patch.object(configdiff.os, "read", side_effect=[b"abcd", b"x"]):
      with self.assertRaises(configdiff.ObservationError):
        configdiff.read_exact_snapshot(9, info, "current")

  def test_read_error_is_terminal_safe(self):
    info = metadata(size=4)
    with mock.patch.object(configdiff.os, "read", side_effect=OSError("read\nfailed")):
      with self.assertRaises(configdiff.ObservationError) as caught:
        configdiff.read_exact_snapshot(9, info, "baseline")
    self.assertIn("\\x0a", str(caught.exception))

  def test_metadata_change_is_untrustworthy(self):
    initial = metadata(size=4, mtime_ns=10)
    final = metadata(size=4, mtime_ns=11)
    with mock.patch.object(configdiff.os, "fstat", return_value=final):
      with self.assertRaises(configdiff.ObservationError):
        configdiff.verify_unchanged(9, initial, "baseline")

  def test_final_component_symlink_is_rejected_on_linux(self):
    if not sys.platform.startswith("linux") or not hasattr(os, "O_NOFOLLOW"):
      self.skipTest("requires Linux O_NOFOLLOW")
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      target = root / "real.conf"
      link = root / "link.conf"
      target.write_bytes(b"value=1\n")
      link.symlink_to(target)
      with self.assertRaises(configdiff.InvalidTargetError):
        configdiff.open_regular_file(str(link), "baseline")


class ComparisonTests(unittest.TestCase):
  def compare_bytes(self, baseline, current):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      baseline_path = root / "baseline.conf"
      current_path = root / "current.conf"
      baseline_path.write_bytes(baseline)
      current_path.write_bytes(current)
      return configdiff.compare_files(str(baseline_path), str(current_path))

  def test_identical_files_have_no_drift(self):
    result = self.compare_bytes(b"key=value\n", b"key=value\n")
    self.assertFalse(result.drift_detected)
    self.assertEqual(result.baseline.sha256, result.current.sha256)
    self.assertEqual(result.baseline.size, 10)

  def test_same_size_different_bytes_are_drift(self):
    result = self.compare_bytes(b"key=one\n", b"key=two\n")
    self.assertTrue(result.drift_detected)
    self.assertNotEqual(result.baseline.sha256, result.current.sha256)

  def test_binary_and_nul_bytes_are_compared_exactly(self):
    result = self.compare_bytes(b"a\x00b\xff", b"a\x00b\xfe")
    self.assertTrue(result.drift_detected)
    self.assertEqual(result.baseline.size, 4)

  def test_empty_files_compare_successfully(self):
    result = self.compare_bytes(b"", b"")
    self.assertFalse(result.drift_detected)
    self.assertEqual(result.baseline.sha256, hashlib.sha256(b"").hexdigest())

  def test_report_does_not_print_file_contents(self):
    secret = b"password=do-not-print\n"
    result = self.compare_bytes(secret, b"password=changed\n")
    report = configdiff.render_report(result)
    self.assertIn("CONTENT DRIFT DETECTED", report)
    self.assertIn("SHA-256", report)
    self.assertNotIn("do-not-print", report)
    self.assertNotIn("password=changed", report)

  def test_report_paths_are_absolute_and_terminal_safe(self):
    result = self.compare_bytes(b"a", b"a")
    report = configdiff.render_report(result)
    self.assertIn("Baseline", report)
    self.assertTrue(os.path.isabs(result.baseline.path))
    self.assertTrue(os.path.isabs(result.current.path))

  def test_inspect_returns_zero_for_match_and_one_for_drift(self):
    with mock.patch.object(configdiff, "compare_files") as compare:
      observation = configdiff.FileObservation(
        path="/tmp/a",
        size=1,
        sha256="0" * 64,
      )
      compare.return_value = configdiff.ComparisonResult(observation, observation, False)
      report, code = configdiff.inspect("a", "b")
      self.assertEqual(code, 0)
      self.assertIn("NO CONTENT DRIFT", report)
      compare.return_value = configdiff.ComparisonResult(observation, observation, True)
      report, code = configdiff.inspect("a", "b")
      self.assertEqual(code, 1)
      self.assertIn("CONTENT DRIFT DETECTED", report)

  def test_compare_closes_both_descriptors_when_second_open_fails(self):
    baseline_info = metadata(size=0)
    with mock.patch.object(
      configdiff,
      "open_regular_file",
      side_effect=[(9, baseline_info), configdiff.InvalidTargetError("bad current")],
    ), mock.patch.object(configdiff.os, "close") as closed:
      with self.assertRaises(configdiff.InvalidTargetError):
        configdiff.compare_files("baseline", "current")
    closed.assert_called_once_with(9)


class DisplayTests(unittest.TestCase):
  def test_display_safe_escapes_controls_backslashes_and_surrogates(self):
    value = "a\\b\n\u202ec" + chr(0xDCFF)
    rendered = configdiff.display_safe(value)
    self.assertEqual(rendered, "a\\\\b\\x0a\\u202ec\\xff")


if __name__ == "__main__":
  unittest.main()
