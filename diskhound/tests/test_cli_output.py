import contextlib
from decimal import Decimal
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import diskhound


def result(**overrides):
  values = dict(
    target="/target",
    target_allocated_bytes=512,
    unique_allocated_bytes=1536,
    capacity=diskhound.Capacity(10000, 7000, 3000, 2000, Decimal("77.777")),
    capacity_warning=None,
    branches=(diskhound.BranchResult("/target/a", 1024),),
    cross_device_immediate=0,
    failures=(),
  )
  values.update(overrides)
  return diskhound.ScanResult(**values)


class CliTests(unittest.TestCase):
  def run_main(self, arguments):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
      code = diskhound.main(arguments)
    return code, stdout.getvalue(), stderr.getvalue()

  def test_help(self):
    for option in ("-h", "--help"):
      with self.subTest(option=option):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), self.assertRaises(SystemExit) as caught:
          diskhound.main([option])
        self.assertEqual(caught.exception.code, 0)
        self.assertIn("allocated space", stdout.getvalue())

  def test_parser_rejects_missing_extra_and_options(self):
    parser = diskhound.build_argument_parser()
    for arguments in ([], ["a", "b"], ["--bytes", "a"], ["--limit", "2", "a"]):
      with self.subTest(arguments=arguments), self.assertRaises(SystemExit) as caught:
        parser.parse_args(arguments)
      self.assertEqual(caught.exception.code, 2)

  def test_nonexistent_and_regular_file_are_invalid(self):
    with tempfile.TemporaryDirectory() as directory:
      missing = Path(directory, "missing")
      file_path = Path(directory, "file")
      file_path.write_text("data")
      for path in (missing, file_path):
        with self.subTest(path=path):
          code, stdout, stderr = self.run_main([str(path)])
          self.assertEqual((code, stdout), (2, ""))
          self.assertIn("diskhound:", stderr)

  def test_empty_path_value_is_invalid(self):
    code, stdout, stderr = self.run_main([""])
    self.assertEqual((code, stdout), (2, ""))
    self.assertIn("must not be empty", stderr)

  def test_fifo_target_is_invalid(self):
    with tempfile.TemporaryDirectory() as directory:
      fifo = Path(directory, "fifo")
      os.mkfifo(fifo)
      code, stdout, stderr = self.run_main([str(fifo)])
    self.assertEqual((code, stdout), (2, ""))
    self.assertIn("not a directory", stderr)

  def test_final_target_symlink_is_rejected(self):
    with tempfile.TemporaryDirectory() as directory:
      target = Path(directory, "target")
      target.mkdir()
      link = Path(directory, "link")
      link.symlink_to(target, target_is_directory=True)
      code, stdout, stderr = self.run_main([str(link) + "/"])
    self.assertEqual((code, stdout), (2, ""))
    self.assertIn("symbolic link", stderr)

  def test_relative_absolute_dot_and_trailing_paths_normalize_lexically(self):
    with tempfile.TemporaryDirectory() as directory:
      previous = os.getcwd()
      os.chdir(directory)
      try:
        for path in (".", "./", os.path.abspath("."), "x/../"):
          with self.subTest(path=path):
            normalized, metadata = diskhound.validate_target(path)
            self.assertEqual(normalized, os.path.abspath(directory))
            self.assertTrue(stat.S_ISDIR(metadata.st_mode))
      finally:
        os.chdir(previous)

  def test_root_target_validation_without_scan(self):
    normalized, metadata = diskhound.validate_target("/")
    self.assertEqual(normalized, "/")
    self.assertTrue(stat.S_ISDIR(metadata.st_mode))

  @mock.patch.object(diskhound, "inspect", return_value=("normal", (), 0))
  def test_complete_result_stdout_and_empty_stderr(self, inspect):
    code, stdout, stderr = self.run_main(["/target"])
    self.assertEqual((code, stdout, stderr), (0, "normal\n", ""))

  @mock.patch.object(diskhound, "inspect", return_value=("partial", ("diskhound: warning: gap",), 1))
  def test_partial_result_and_warning_streams(self, inspect):
    code, stdout, stderr = self.run_main(["/target"])
    self.assertEqual((code, stdout), (1, "partial\n"))
    self.assertEqual(stderr, "diskhound: warning: gap\n")

  @mock.patch.object(diskhound, "inspect", side_effect=diskhound.DiagnosticError("fatal"))
  def test_fatal_has_no_normal_stdout(self, inspect):
    code, stdout, stderr = self.run_main(["/target"])
    self.assertEqual((code, stdout), (3, ""))
    self.assertIn("fatal", stderr)

  @mock.patch.object(diskhound, "inspect", side_effect=KeyboardInterrupt)
  def test_ctrl_c_has_no_normal_stdout(self, inspect):
    code, stdout, stderr = self.run_main(["/target"])
    self.assertEqual((code, stdout, stderr), (130, "", "diskhound: interrupted\n"))


class OutputTests(unittest.TestCase):
  def test_complete_output_contains_frozen_concepts(self):
    output = diskhound.render_result(result())
    self.assertIn("DiskHound: /target", output)
    self.assertIn("Observation: complete (not a filesystem snapshot)", output)
    self.assertIn("Filesystem free", output)
    self.assertIn("Available to caller", output)
    self.assertIn("Unique observed target allocation", output)
    self.assertIn("Eligible immediate entries: 1", output)
    self.assertIn("Showing 1 of 1", output)
    self.assertIn("not additive", output)
    self.assertIn("need not reconcile", output)

  def test_empty_and_top_ten_output(self):
    empty = diskhound.render_result(result(branches=()))
    self.assertIn("Showing 0 of 0", empty)
    self.assertIn("No eligible immediate entries", empty)
    branches = tuple(diskhound.BranchResult(f"/target/{index:02}", 1) for index in range(12))
    output = diskhound.render_result(result(branches=branches))
    self.assertIn("Showing 10 of 12", output)
    self.assertNotIn("/target/10", output)

  def test_ranking_uses_exact_bytes_then_byte_safe_path(self):
    branches = [
      diskhound.BranchResult("/target/z", 1025),
      diskhound.BranchResult("/target/b", 1024),
      diskhound.BranchResult("/target/a", 1024),
    ]
    branches.sort(key=lambda item: (-item.allocated_bytes, diskhound.path_sort_key(item.path)))
    self.assertEqual([Path(item.path).name for item in branches], ["z", "a", "b"])
    self.assertEqual(diskhound.format_bytes(1024).split(" (")[0], diskhound.format_bytes(1025).split(" (")[0])

  def test_terminal_safe_escaping(self):
    unsafe = "a\\b\n\t\r\x1b" + "\udcff"
    self.assertEqual(diskhound.display_safe(unsafe), "a\\\\b\\x0a\\x09\\x0d\\x1b\\xff")

  def test_warning_limit_order_and_suppression_are_deterministic(self):
    failures = tuple(
      diskhound.ObservationFailure(f"/target/{index:03}", "metadata", "gone")
      for index in reversed(range(25))
    )
    warnings = diskhound.render_warnings(result(failures=failures))
    self.assertEqual(len(warnings), 21)
    self.assertIn("/target/000", warnings[0])
    self.assertIn("/target/019", warnings[19])
    self.assertEqual(
      warnings[20], "diskhound: warning: 5 additional observation failures were suppressed",
    )

  def test_warning_boundaries_preserve_exact_counts(self):
    for count, expected_lines, suppressed in (
      (0, 0, None), (1, 1, None), (20, 20, None), (21, 21, 1), (163, 21, 143),
    ):
      failures = tuple(
        diskhound.ObservationFailure(f"/target/{index:03}", "metadata", "gone")
        for index in range(count)
      )
      with self.subTest(count=count):
        warnings = diskhound.render_warnings(result(failures=failures))
        self.assertEqual(len(warnings), expected_lines)
        if suppressed is not None:
          self.assertEqual(
            warnings[-1],
            f"diskhound: warning: {suppressed} additional observation failures were suppressed",
          )

  def test_capacity_warning_does_not_consume_path_warning_limit(self):
    failures = tuple(
      diskhound.ObservationFailure(f"/target/{index:02}", "metadata", "gone")
      for index in range(20)
    )
    warnings = diskhound.render_warnings(result(
      capacity=None, capacity_warning="filesystem capacity unavailable", failures=failures,
    ))
    self.assertEqual(len(warnings), 21)
    self.assertIn("capacity unavailable", warnings[-1])

  def test_warning_text_is_terminal_safe(self):
    warnings = diskhound.render_warnings(result(failures=(
      diskhound.ObservationFailure("/bad\nname", "metadata", "bad\x1bdetail"),
    )))
    self.assertNotIn("\n", warnings[0])
    self.assertNotIn("\x1b", warnings[0])
    self.assertIn("\\x0a", warnings[0])


if __name__ == "__main__":
  unittest.main()
