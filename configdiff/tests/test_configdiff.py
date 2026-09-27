import contextlib
import hashlib
import importlib.util
import io
import json
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


def comparison(drift=False, path="/a"):
  baseline = configdiff.FileObservation(path, 1, "0" * 64)
  current = configdiff.FileObservation("/b", 1, ("1" if drift else "0") * 64)
  return configdiff.ComparisonResult(baseline, current, drift)


class CliTests(unittest.TestCase):
  def run_main(self, arguments):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
      code = configdiff.main(arguments)
    return code, stdout.getvalue(), stderr.getvalue()

  def test_help_is_stdout_and_does_not_compare(self):
    for option in ("-h", "--help"):
      with self.subTest(option=option), mock.patch.object(configdiff, "compare_files_mode") as compare:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), self.assertRaises(SystemExit) as caught:
          configdiff.main([option])
        self.assertEqual(caught.exception.code, 0)
        self.assertIn("bounded file or directory drift", stdout.getvalue())
        compare.assert_not_called()

  def test_invalid_invocation_exits_two(self):
    for argv in ([], ["one"], ["one", "two", "three"]):
      with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()), \
           self.assertRaises(SystemExit) as caught:
        configdiff.main(argv)
      self.assertEqual(caught.exception.code, 2)

  def test_success_and_drift_exit_codes(self):
    with mock.patch.object(configdiff, "compare_files_mode", return_value=comparison(False)):
      code, stdout, stderr = self.run_main(["a", "b"])
      self.assertEqual((code, stderr), (0, ""))
      self.assertIn("Conclusion: [UNCHANGED]", stdout)
    with mock.patch.object(configdiff, "compare_files_mode", return_value=comparison(True)):
      code, stdout, stderr = self.run_main(["a", "b"])
      self.assertEqual((code, stderr), (1, ""))
      self.assertIn("Conclusion: [DRIFT]", stdout)

  def test_expected_errors_have_stable_exit_codes(self):
    with mock.patch.object(
      configdiff, "compare_files_mode", side_effect=configdiff.InvalidTargetError("bad target")
    ):
      self.assertEqual(
        self.run_main(["a", "b"]), (2, "", "configdiff: bad target\n")
      )
    with mock.patch.object(
      configdiff, "compare_files_mode", side_effect=configdiff.ObservationError("unstable")
    ):
      self.assertEqual(
        self.run_main(["a", "b"]), (3, "", "configdiff: unstable\n")
      )

  def test_internal_error_and_interrupt_have_stable_output(self):
    with mock.patch.object(configdiff, "compare_files_mode", side_effect=RuntimeError("secret")):
      self.assertEqual(
        self.run_main(["a", "b"]),
        (3, "", "configdiff: internal execution failure\n"),
      )
    with mock.patch.object(configdiff, "compare_files_mode", side_effect=KeyboardInterrupt):
      self.assertEqual(
        self.run_main(["a", "b"]), (130, "", "configdiff: interrupted\n")
      )

  def test_ascii_stdout_escapes_unencodable_unicode(self):
    stdout = StrictAsciiStream()
    stderr = io.StringIO()
    with mock.patch.object(configdiff.sys, "stdout", stdout), \
         mock.patch.object(configdiff.sys, "stderr", stderr), \
         mock.patch.object(configdiff, "compare_files_mode", return_value=comparison(False, "/path é")):
      code = configdiff.main(["a", "b"])
    self.assertEqual(code, 0)
    self.assertEqual(stderr.getvalue(), "")
    self.assertIn("path \\xe9", stdout.getvalue())

  def test_json_brief_and_quiet(self):
    with mock.patch.object(configdiff, "compare_files_mode", return_value=comparison(False)):
      code, stdout, stderr = self.run_main(["--json", "a", "b"])
      self.assertEqual((code, stderr), (0, ""))
      self.assertEqual(json.loads(stdout)["tool"], "configdiff")
      self.assertIn("Drift: no", self.run_main(["--brief", "a", "b"])[1])
      self.assertEqual(self.run_main(["--quiet", "a", "b"])[1], "")


class FileAccessTests(unittest.TestCase):
  def patched(self, *, stat_info=None, **patches):
    stack = contextlib.ExitStack()
    stack.enter_context(mock.patch.object(configdiff.os, "stat", return_value=stat_info or metadata()))
    return stack, {name: stack.enter_context(mock.patch.object(configdiff.os, name, **value)) for name, value in patches.items()}

  def test_open_regular_file_uses_descriptor_metadata(self):
    info = metadata(size=4)
    stack, mocks = self.patched(stat_info=info, open={"return_value": 9}, fstat={"return_value": info}, close={})
    with stack:
      descriptor, returned = configdiff.open_regular_file("target", "baseline")
    self.assertEqual(descriptor, 9)
    self.assertIs(returned, info)
    self.assertEqual(mocks["open"].call_args.args[0], "target")
    self.assertTrue(mocks["open"].call_args.args[1] & os.O_NOCTTY)
    mocks["close"].assert_not_called()

  def test_non_regular_path_is_refused_before_opening(self):
    stack, mocks = self.patched(stat_info=metadata(mode=stat.S_IFCHR | 0o600), open={"return_value": 9})
    with stack, self.assertRaises(configdiff.InvalidTargetError):
      configdiff.open_regular_file("/dev/watchdog", "baseline")
    mocks["open"].assert_not_called()

  def test_descriptor_is_closed_if_validation_is_interrupted(self):
    stack, mocks = self.patched(open={"return_value": 9}, fstat={"side_effect": KeyboardInterrupt}, close={})
    with stack, self.assertRaises(KeyboardInterrupt):
      configdiff.open_regular_file("target", "baseline")
    mocks["close"].assert_called_once_with(9)

  def test_fstat_failure_is_observation_error_and_closes_descriptor(self):
    stack, mocks = self.patched(open={"return_value": 9}, fstat={"side_effect": OSError("stat failed")}, close={})
    with stack, self.assertRaises(configdiff.ObservationError):
      configdiff.open_regular_file("target", "baseline")
    mocks["close"].assert_called_once_with(9)

  def test_non_regular_file_is_rejected_and_closed(self):
    info = metadata(mode=stat.S_IFDIR | 0o755)
    stack, mocks = self.patched(open={"return_value": 9}, fstat={"return_value": info}, close={})
    with stack, self.assertRaises(configdiff.InvalidTargetError):
      configdiff.open_regular_file("target", "current")
    mocks["close"].assert_called_once_with(9)

  def test_oversized_file_is_rejected(self):
    info = metadata(size=configdiff.MAX_FILE_BYTES + 1)
    stack, mocks = self.patched(stat_info=info, open={"return_value": 9}, fstat={"return_value": info}, close={})
    with stack, self.assertRaises(configdiff.InvalidTargetError) as caught:
      configdiff.open_regular_file("target", "baseline")
    self.assertIn(str(configdiff.MAX_FILE_BYTES), str(caught.exception))
    mocks["close"].assert_called_once_with(9)

  def test_open_failure_is_terminal_safe(self):
    stack, _ = self.patched(open={"side_effect": OSError("bad\npath")})
    with stack, self.assertRaises(configdiff.InvalidTargetError) as caught:
      configdiff.open_regular_file("target", "baseline")
    self.assertNotIn("\n", str(caught.exception))
    self.assertIn("\\x0a", str(caught.exception))

  def test_real_fifo_is_refused_without_blocking(self):
    with tempfile.TemporaryDirectory() as directory:
      fifo = Path(directory, "pipe")
      os.mkfifo(fifo)
      with self.assertRaises(configdiff.InvalidTargetError):
        configdiff.open_regular_file(str(fifo), "baseline")

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
  def compare_bytes(self, baseline, current, mode="exact", **options):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      baseline_path = root / "baseline.conf"
      current_path = root / "current.conf"
      baseline_path.write_bytes(baseline)
      current_path.write_bytes(current)
      values = dict(permissions=False, ownership=False, selected_keys=(), unified=False, max_diff_lines=20)
      values.update(options)
      return configdiff.compare_files_mode(str(baseline_path), str(current_path), mode=mode, **values)

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

  def test_json_types_are_not_conflated(self):
    for left, right in ((b'{"verify": true}', b'{"verify": 1}'), (b'{"port": 1}', b'{"port": 1.0}'), (b'[false]', b'[0]')):
      with self.subTest(left=left, right=right):
        self.assertTrue(self.compare_bytes(left, right, "json").drift_detected)
    self.assertFalse(self.compare_bytes(b'{"a": 1.0, "b": [1]}', b'{"b": [1], "a": 1.00}', "json").drift_detected)

  def test_json_rejects_non_finite_and_deep_nesting_as_invalid_input(self):
    for payload in (b'{"t": NaN}', b'{"t": Infinity}', b'{"t": 1e999}', b"[" * 5000 + b"]" * 5000):
      with self.subTest(payload=payload[:20]), self.assertRaises(configdiff.InvalidTargetError):
        self.compare_bytes(payload, payload, "json")

  def test_missing_selected_key_is_drift_not_an_error(self):
    result = self.compare_bytes(b'{"feature": {"enabled": true}}', b'{"feature": {}}', "json", selected_keys=("feature.enabled",))
    self.assertTrue(result.drift_detected)
    self.assertIn("absent in current", result.details[0])

  def test_comment_mode_keeps_sudoers_directives(self):
    base = b"root ALL=(ALL) ALL\n#includedir /etc/sudoers.d\n# plain comment\n"
    self.assertTrue(self.compare_bytes(base, b"root ALL=(ALL) ALL\n# plain comment\n", "comments").drift_detected)
    self.assertTrue(self.compare_bytes(base, base + b"#1001 ALL=(ALL) NOPASSWD: ALL\n", "comments").drift_detected)
    self.assertFalse(self.compare_bytes(base, base.replace(b"plain", b"edited"), "comments").drift_detected)

  def test_metadata_only_drift_is_not_reported_as_byte_drift(self):
    with tempfile.TemporaryDirectory() as directory:
      baseline, current = Path(directory, "a"), Path(directory, "b")
      baseline.write_bytes(b"same\n")
      current.write_bytes(b"same\n")
      baseline.chmod(0o644)
      current.chmod(0o600)
      result = configdiff.compare_files_mode(
        str(baseline), str(current), mode="exact", permissions=True, ownership=False,
        selected_keys=(), unified=False, max_diff_lines=20,
      )
    report = configdiff.render_report(result)
    self.assertTrue(result.drift_detected)
    self.assertFalse(result.content_drift)
    self.assertIn("NO CONTENT DRIFT; METADATA DRIFT DETECTED", report)
    self.assertNotIn("bytes differ", report)

  def test_unified_diff_lines_are_bounded(self):
    result = self.compare_bytes(b"a" * 5000 + b"\n", b"b" * 5000 + b"\n", unified=True)
    self.assertTrue(all(len(line) <= configdiff.MAX_DIFF_LINE_CHARS + 32 for line in result.diff_lines))
    self.assertEqual(self.compare_bytes(b"same\n", b"same\n", unified=True).diff_lines, ())

  def test_compare_closes_both_descriptors_when_second_open_fails(self):
    baseline_info = metadata(size=0)
    with mock.patch.object(
      configdiff,
      "open_regular_file",
      side_effect=[(9, baseline_info), configdiff.InvalidTargetError("bad current")],
    ), mock.patch.object(configdiff.os, "close") as closed:
      with self.assertRaises(configdiff.InvalidTargetError):
        configdiff.read_file_pair("baseline", "current")
    closed.assert_called_once_with(9)

  def test_semantic_json_and_duplicate_keys(self):
    with tempfile.TemporaryDirectory() as directory:
      baseline = Path(directory, "a.json")
      current = Path(directory, "b.json")
      baseline.write_text('{"a":1,"nested":{"x":2}}', encoding="utf-8")
      current.write_text('{"nested":{"x":2},"a":1}', encoding="utf-8")
      result = configdiff.compare_files_mode(
        str(baseline), str(current), mode="json", permissions=False,
        ownership=False, selected_keys=(), unified=False, max_diff_lines=20,
      )
      self.assertFalse(result.drift_detected)
      current.write_text('{"a":1,"a":2}', encoding="utf-8")
      with self.assertRaises(configdiff.InvalidTargetError):
        configdiff.compare_files_mode(
          str(baseline), str(current), mode="json", permissions=False,
          ownership=False, selected_keys=(), unified=False, max_diff_lines=20,
        )

  def test_whitespace_comments_and_bounded_unified_diff(self):
    with tempfile.TemporaryDirectory() as directory:
      baseline = Path(directory, "a.conf")
      current = Path(directory, "b.conf")
      baseline.write_text("# old\na = 1\n", encoding="utf-8")
      current.write_text("; new\na=1\n", encoding="utf-8")
      whitespace = configdiff.compare_files_mode(
        str(baseline), str(current), mode="whitespace", permissions=False,
        ownership=False, selected_keys=(), unified=True, max_diff_lines=2,
      )
      self.assertTrue(whitespace.drift_detected)
      self.assertLessEqual(len(whitespace.diff_lines), 2)
      self.assertTrue(whitespace.diff_truncated)

  def test_bounded_directory_comparison_and_symlink_target(self):
    with tempfile.TemporaryDirectory() as directory:
      baseline = Path(directory, "a")
      current = Path(directory, "b")
      baseline.mkdir()
      current.mkdir()
      (baseline / "same").write_text("x")
      (current / "same").write_text("x")
      (current / "added").write_text("y")
      (baseline / "link").symlink_to("one")
      (current / "link").symlink_to("two")
      result = configdiff.compare_directories(
        str(baseline), str(current), max_files=20, max_depth=3,
        permissions=False, ownership=False,
      )
      self.assertEqual(result.added, ("added",))
      self.assertIn("link", result.changed)

  def test_directory_root_metadata_and_depth_are_not_silently_unchanged(self):
    with tempfile.TemporaryDirectory() as directory:
      baseline, current = Path(directory, "a"), Path(directory, "b")
      for root in (baseline, current):
        (root / "sub").mkdir(parents=True)
      (baseline / "sub" / "x").write_text("old")
      (current / "sub" / "x").write_text("new")
      baseline.chmod(0o700)
      current.chmod(0o777)
      result = configdiff.compare_directories(
        str(baseline), str(current), max_files=20, max_depth=3, permissions=True, ownership=False,
      )
      self.assertIn(".", result.changed)
      shallow = configdiff.compare_directories(
        str(baseline), str(current), max_files=20, max_depth=0, permissions=False, ownership=False,
      )
      self.assertFalse(shallow.drift_detected)
      self.assertEqual(shallow.unexamined, ("sub (below --max-depth)",))
      code = CliTests.run_main(self, [str(baseline), str(current), "--directory", "--max-depth", "0"])[0]
      self.assertEqual(code, 3)

  def test_symlink_retarget_is_drift_by_default(self):
    with tempfile.TemporaryDirectory() as directory:
      baseline, current = Path(directory, "a"), Path(directory, "b")
      baseline.mkdir()
      current.mkdir()
      (baseline / "app.conf").symlink_to("/etc/hostname")
      (current / "app.conf").symlink_to("/tmp/evil.conf")
      code = CliTests.run_main(self, [str(baseline), str(current), "--directory"])[0]
    self.assertEqual(code, 1)


class DisplayTests(unittest.TestCase):
  def test_display_safe_escapes_controls_backslashes_and_surrogates(self):
    value = "a\\b\n\u202ec" + chr(0xDCFF)
    rendered = configdiff.display_safe(value)
    self.assertEqual(rendered, "a\\\\b\\x0a\\u202ec\\xff")


if __name__ == "__main__":
  unittest.main()
