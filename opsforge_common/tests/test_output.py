import argparse
import contextlib
from dataclasses import dataclass
from decimal import Decimal
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from opsforge_common.output import (
  OutputError,
  OutputRecord,
  add_output_arguments,
  _bounded_output,
  emit_output,
  make_conclusion,
  to_jsonable,
  validate_output_arguments,
)


class OutputTests(unittest.TestCase):
  def record(self):
    return OutputRecord(
      tool="example",
      status="PASS",
      target="local",
      observations={"count": 2},
      conclusion=make_conclusion("PASS", "local", "check passed", "no action needed"),
      next_action="no action needed.",
      warnings=(),
      elapsed_seconds=0.125,
    )

  def test_json_envelope_is_stable_and_stdout_contains_json_only(self):
    stream = io.StringIO()
    emit_output(self.record(), detailed="details", brief="brief", json_mode=True, stdout=stream)
    payload = json.loads(stream.getvalue())
    self.assertEqual(payload["schema_version"], 1)
    self.assertEqual(payload["tool"], "example")
    self.assertEqual(payload["observations"], {"count": 2})

  def test_human_modes_end_with_conclusion(self):
    for brief_mode, expected in ((False, "details"), (True, "brief")):
      stream = io.StringIO()
      emit_output(self.record(), detailed="details", brief="brief", brief_mode=brief_mode, stdout=stream)
      self.assertTrue(stream.getvalue().startswith(expected + "\n"))
      self.assertTrue(stream.getvalue().rstrip().endswith("Next: no action needed."))

  def test_quiet_suppresses_stdout_but_output_file_is_written(self):
    with tempfile.TemporaryDirectory() as directory:
      destination = Path(directory, "result.json")
      stream = io.StringIO()
      emit_output(
        self.record(), detailed="details", brief="brief", json_mode=True,
        quiet=True, output_path=str(destination), stdout=stream,
      )
      self.assertEqual(stream.getvalue(), "")
      self.assertEqual(json.loads(destination.read_text())["status"], "PASS")

  def test_output_refuses_overwrite_without_force(self):
    with tempfile.TemporaryDirectory() as directory:
      destination = Path(directory, "result.txt")
      destination.write_text("original", encoding="utf-8")
      with self.assertRaisesRegex(OutputError, "already exists"):
        emit_output(self.record(), detailed="new", brief="brief", output_path=str(destination))
      self.assertEqual(destination.read_text(encoding="utf-8"), "original")
      emit_output(self.record(), detailed="new", brief="brief", output_path=str(destination), force=True)
      self.assertIn("new", destination.read_text(encoding="utf-8"))
      self.assertEqual(destination.stat().st_mode & 0o777, 0o600)

  @unittest.skipUnless(hasattr(os, "symlink"), "requires symlink support")
  def test_force_does_not_follow_symlink_or_replace_hardlink(self):
    with tempfile.TemporaryDirectory() as directory:
      original = Path(directory, "original")
      original.write_text("secret", encoding="utf-8")
      symlink = Path(directory, "symlink")
      symlink.symlink_to(original)
      with self.assertRaises(OutputError):
        emit_output(self.record(), detailed="new", brief="brief", output_path=str(symlink), force=True)
      hardlink = Path(directory, "hardlink")
      os.link(original, hardlink)
      with self.assertRaisesRegex(OutputError, "multiply-linked"):
        emit_output(self.record(), detailed="new", brief="brief", output_path=str(hardlink), force=True)
      self.assertEqual(original.read_text(encoding="utf-8"), "secret")

  def test_conclusion_sanitizes_controls(self):
    result = make_conclusion("pass\n", "x\x1b\u202e", "ok\r\u2028", "none\t\u2066")
    self.assertNotIn("\n", result)
    self.assertNotIn("\x1b", result)
    for character in ("\u202e", "\u2028", "\u2066"):
      self.assertNotIn(character, result)

  def test_output_limit_applies_to_stdout_and_files_before_writing(self):
    with mock.patch("opsforge_common.output.MAX_OUTPUT_BYTES", 64):
      stream = io.StringIO()
      with self.assertRaisesRegex(OutputError, "16 MiB"):
        emit_output(self.record(), detailed="x" * 64, brief="brief", stdout=stream)
      self.assertEqual(stream.getvalue(), "")
      with tempfile.TemporaryDirectory() as directory:
        destination = Path(directory, "result.txt")
        with self.assertRaisesRegex(OutputError, "16 MiB"):
          emit_output(
            self.record(), detailed="x" * 64, brief="brief",
            output_path=str(destination),
          )
        self.assertFalse(destination.exists())

  def test_output_limit_accepts_exact_boundary_and_rejects_plus_one(self):
    with mock.patch("opsforge_common.output.MAX_OUTPUT_BYTES", 4):
      self.assertEqual(_bounded_output("abc")[1], b"abc\n")
      with self.assertRaises(OutputError):
        _bounded_output("abcd")

  def test_jsonable_handles_dataclasses_and_decimal(self):
    @dataclass
    class Example:
      value: Decimal
    self.assertEqual(to_jsonable(Example(Decimal("1.25"))), {"value": "1.25"})

  def test_force_requires_output(self):
    parser = argparse.ArgumentParser()
    add_output_arguments(parser)
    arguments = parser.parse_args(["--force"])
    with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
      validate_output_arguments(parser, arguments)
    self.assertEqual(caught.exception.code, 2)


if __name__ == "__main__":
  unittest.main()
