import contextlib
import importlib.util
import io
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).parents[1] / "loghound.py"
SPEC = importlib.util.spec_from_file_location("loghound", MODULE_PATH)
loghound = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = loghound
SPEC.loader.exec_module(loghound)


class StrictAsciiStream(io.StringIO):
  @property
  def encoding(self):
    return "ascii"

  def write(self, value):
    value.encode("ascii", errors="strict")
    return super().write(value)


class CliTests(unittest.TestCase):
  def run_main(self, arguments):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
      code = loghound.main(arguments)
    return code, stdout.getvalue(), stderr.getvalue()

  def test_help_is_stdout_and_does_not_open_target(self):
    for option in ("-h", "--help"):
      with self.subTest(option=option), mock.patch.object(loghound.os, "open") as opened:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), self.assertRaises(SystemExit) as caught:
          loghound.main([option])
        self.assertEqual(caught.exception.code, 0)
        self.assertIn("one bounded local regular log file", stdout.getvalue())
        opened.assert_not_called()

  def test_invalid_invocations_exit_two(self):
    for arguments in ([], ["a", "b"], ["--limit", "a"]):
      with self.subTest(arguments=arguments):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
          loghound.main(arguments)
        self.assertEqual(caught.exception.code, 2)

  def test_success_and_dash_leading_filename(self):
    with tempfile.TemporaryDirectory() as directory:
      path = Path(directory, "-events")
      path.write_text("same\nsame\n", encoding="utf-8")
      with mock.patch.object(loghound.os.path, "abspath", return_value=str(path)):
        code, stdout, stderr = self.run_main(["--", "-events"])
    self.assertEqual((code, stderr), (0, ""))
    self.assertIn("Count: 2", stdout)

  def test_expected_and_internal_errors_use_stderr(self):
    with mock.patch.object(loghound, "inspect", side_effect=loghound.ObservationError("bad")):
      self.assertEqual(self.run_main(["x"]), (3, "", "loghound: bad\n"))
    with mock.patch.object(loghound, "inspect", side_effect=RuntimeError("secret")):
      self.assertEqual(
        self.run_main(["x"]), (3, "", "loghound: internal execution failure\n")
      )
    with mock.patch.object(loghound, "inspect", side_effect=KeyboardInterrupt):
      self.assertEqual(self.run_main(["x"]), (130, "", "loghound: interrupted\n"))

  def test_ascii_stdout_escapes_unencodable_unicode(self):
    stdout = StrictAsciiStream()
    stderr = io.StringIO()
    with mock.patch.object(loghound.sys, "stdout", stdout), \
         mock.patch.object(loghound.sys, "stderr", stderr), \
         mock.patch.object(loghound, "inspect", return_value=("recurring é", None, 0)):
      code = loghound.main(["x"])
    self.assertEqual(code, 0)
    self.assertEqual(stderr.getvalue(), "")
    self.assertIn("recurring \\xe9", stdout.getvalue())


class TargetTests(unittest.TestCase):
  def test_empty_missing_directory_and_symlinks_are_rejected(self):
    with self.assertRaises(loghound.InvalidTargetError):
      loghound.analyze("")
    with tempfile.TemporaryDirectory() as directory:
      target = Path(directory, "target")
      target.write_text("text")
      link = Path(directory, "link")
      link.symlink_to(target)
      dangling = Path(directory, "dangling")
      dangling.symlink_to(Path(directory, "missing"))
      for path in (Path(directory, "missing"), Path(directory), link, dangling):
        with self.subTest(path=path), self.assertRaises(loghound.InvalidTargetError):
          loghound.analyze(str(path))

  def test_fifo_socket_and_character_device_are_rejected_without_read(self):
    with tempfile.TemporaryDirectory() as directory:
      fifo = Path(directory, "fifo")
      os.mkfifo(fifo)
      sock_path = Path(directory, "socket")
      listener = socket.socket(socket.AF_UNIX)
      listener.bind(str(sock_path))
      try:
        for path in (fifo, sock_path, Path("/dev/null")):
          with self.subTest(path=path), mock.patch.object(loghound.os, "read") as read:
            with self.assertRaises(loghound.InvalidTargetError):
              loghound.analyze(str(path))
            read.assert_not_called()
      finally:
        listener.close()

  def test_descriptor_metadata_is_authoritative(self):
    metadata = mock.Mock(st_mode=stat.S_IFBLK, st_size=0)
    with mock.patch.object(loghound.os, "open", return_value=9), \
         mock.patch.object(loghound.os, "fstat", return_value=metadata), \
         mock.patch.object(loghound.os, "close"):
      with self.assertRaises(loghound.InvalidTargetError):
        loghound.open_target("anything")

  def test_permission_failure_is_target_error_and_terminal_safe(self):
    error = PermissionError("bad\npath")
    with mock.patch.object(loghound.os, "open", side_effect=error):
      with self.assertRaises(loghound.InvalidTargetError) as caught:
        loghound.open_target("x")
    self.assertNotIn("\n", str(caught.exception))
    self.assertIn("\\x0a", str(caught.exception))

  def test_size_boundaries(self):
    for size, accepted in ((loghound.MAX_FILE_BYTES, True), (loghound.MAX_FILE_BYTES + 1, False)):
      metadata = mock.Mock(st_mode=stat.S_IFREG, st_size=size)
      with self.subTest(size=size), mock.patch.object(loghound.os, "open", return_value=9), \
           mock.patch.object(loghound.os, "fstat", return_value=metadata), \
           mock.patch.object(loghound.os, "close"):
        if accepted:
          self.assertEqual(loghound.open_target("x"), (9, size))
        else:
          with self.assertRaises(loghound.InvalidTargetError):
            loghound.open_target("x")

  def test_plain_text_with_compressed_suffix_is_accepted(self):
    with tempfile.TemporaryDirectory() as directory:
      path = Path(directory, "application.log.gz")
      path.write_text("plain\nplain\n")
      self.assertEqual(loghound.inspect(str(path))[2], 0)

  def test_known_compressed_signatures_are_rejected(self):
    for signature, name in loghound.COMPRESSED_SIGNATURES:
      with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
        path = Path(directory, "log")
        path.write_bytes(signature + b"payload")
        with self.assertRaises(loghound.InvalidTargetError):
          loghound.analyze(str(path))

  def test_compressed_signature_detection_survives_short_reads(self):
    with mock.patch.object(loghound.os, "read", side_effect=[b"\x1f", b"\x8bpayload"]):
      with self.assertRaises(loghound.InvalidTargetError):
        loghound.observe_descriptor(9, "/log", 9)


class NormalizationTests(unittest.TestCase):
  def test_valid_timestamp_forms_are_removed(self):
    for prefix in (
      "2026-09-05T12:34:56Z ",
      "2024-02-29T00:00:00.123+05:30   ",
      "2026-09-05T12:34:56-04:00 ",
    ):
      with self.subTest(prefix=prefix):
        self.assertEqual(loghound.normalize_message(prefix + "message  "), "message  ")

  def test_unsupported_or_invalid_timestamps_remain(self):
    values = (
      "2026-09-05T12:34:56 message", "2026-09-05t12:34:56Z message",
      "2026-09-05T12:34:56z message", "2026-13-05T12:34:56Z message",
      "2026-02-30T12:34:56Z message", "2026-09-05T25:34:56Z message",
      "[2026-09-05T12:34:56Z] message", " 2026-09-05T12:34:56Z message",
      "prefix 2026-09-05T12:34:56Z message", "Sep  5 12:34:56 message",
      "2026-09-05T12:34:56Z\tmessage",
      "2026-09-05T12:34:56+05:60 message",
      "2026-09-05T12:34:56-00:99 message",
      "2026-09-05T12:34:56+24:00 message",
    )
    for value in values:
      with self.subTest(value=value):
        self.assertEqual(loghound.normalize_message(value), value)

  def test_all_other_textual_differences_are_preserved(self):
    values = (
      "pid=1", "pid=2", "number 1", "number 2", "uuid a-b", "uuid a-c",
      "10.0.0.1:80", "10.0.0.2:81", "/a", "/b", "ERROR", "error",
      "two spaces", "two  spaces", "trail", "trail ",
    )
    self.assertEqual([loghound.normalize_message(value) for value in values], list(values))


class ObservationTests(unittest.TestCase):
  def analyze_bytes(self, data):
    with tempfile.TemporaryDirectory() as directory:
      path = Path(directory, "log")
      path.write_bytes(data)
      return loghound.analyze(str(path))

  def test_line_shapes_and_physical_counts(self):
    for data, lines, analyzable in (
      (b"", 0, 0), (b"a", 1, 1), (b"a\n", 1, 1),
      (b"a\nb", 2, 2), (b"a\nb\n", 2, 2), (b"\n\n", 2, 0),
    ):
      with self.subTest(data=data):
        result = self.analyze_bytes(data)
        self.assertEqual((result.physical_lines, result.analyzable_lines), (lines, analyzable))

  def test_crlf_and_embedded_cr(self):
    result = self.analyze_bytes(b"same\r\nsame\r\ninside\rvalue\ninside\rvalue\n")
    recurring = {item.key: item.count for item in result.patterns}
    self.assertEqual(recurring, {"same": 2, "inside\rvalue": 2})

  def test_unterminated_trailing_cr_is_content(self):
    result = self.analyze_bytes(b"a\r\na\r")
    evidence = {item.key: item.count for item in result.patterns}
    self.assertEqual(evidence, {"a": 1, "a\r": 1})

  def test_blank_and_timestamp_only_lines_are_not_analyzable(self):
    result = self.analyze_bytes(b" \n\t\n2026-01-01T00:00:00Z   \nmessage\n")
    self.assertEqual((result.physical_lines, result.analyzable_lines), (4, 1))

  def test_timestamp_recurrence_and_line_evidence(self):
    result = self.analyze_bytes(
      b"\n2026-01-01T00:00:00Z repeated\nunique\n2026-01-02T00:00:00+01:00 repeated\n"
    )
    repeated = next(item for item in result.patterns if item.key == "repeated")
    self.assertEqual((repeated.count, repeated.first_line, repeated.last_line), (2, 2, 4))

  def test_invalid_utf8_is_lossless_and_distinct(self):
    result = self.analyze_bytes(b"bad\x80\nbad\x80\nbad\x81\nbad\x81\n")
    self.assertEqual(len(result.patterns), 2)
    output = loghound.render_result(result)
    self.assertIn("bad\\x80", output)
    self.assertIn("bad\\x81", output)

  def test_nul_anywhere_is_fatal_even_after_lines(self):
    for data in (b"\x00a", b"a\x00b", b"a\x00", b"valid\nvalid\n\x00"):
      with self.subTest(data=data), self.assertRaises(loghound.ObservationError):
        self.analyze_bytes(data)

  def test_line_length_boundary(self):
    self.assertEqual(self.analyze_bytes(b"a" * loghound.MAX_LINE_BYTES).analyzable_lines, 1)
    self.assertEqual(
      self.analyze_bytes(b"a" * loghound.MAX_LINE_BYTES + b"\r\n").analyzable_lines, 1
    )
    for data in (
      b"a" * (loghound.MAX_LINE_BYTES + 1),
      b"valid\n" + b"a" * (loghound.MAX_LINE_BYTES + 1),
      b"a" * loghound.MAX_LINE_BYTES + b"\r",
    ):
      with self.assertRaises(loghound.ObservationError):
        self.analyze_bytes(data)

  def test_chunk_boundaries_do_not_change_lines(self):
    data = b"a" * (loghound.READ_CHUNK_BYTES - 1) + b"\r\nnext\n"
    result = self.analyze_bytes(data)
    self.assertEqual((result.physical_lines, result.analyzable_lines), (2, 2))

  def test_many_short_lines_in_one_chunk(self):
    count = 20000
    result = self.analyze_bytes(b"x\n" * count)
    self.assertEqual((result.physical_lines, result.analyzable_lines), (count, count))
    self.assertEqual(result.patterns[0].count, count)

  def test_read_never_exceeds_boundary_and_append_is_excluded(self):
    reads = []
    chunks = [b"same\nsame\n", b"appended\n"]

    def fake_read(descriptor, size):
      reads.append(size)
      return chunks.pop(0)[:size]

    with mock.patch.object(loghound.os, "read", side_effect=fake_read):
      result = loghound.observe_descriptor(9, "/log", 10)
    self.assertEqual(result.consumed_bytes, 10)
    self.assertEqual(sum(reads), 10)
    self.assertEqual(result.physical_lines, 2)

  def test_early_eof_partial_requires_analyzable_line(self):
    for chunks, expected in (([b"line\n", b""], 1), ([b"\n", b""], 3)):
      with self.subTest(chunks=chunks):
        with mock.patch.object(loghound.os, "read", side_effect=chunks):
          if expected == 1:
            result = loghound.observe_descriptor(9, "/log", 100)
            self.assertTrue(result.incomplete)
          else:
            with self.assertRaises(loghound.ObservationError):
              loghound.observe_descriptor(9, "/log", 100)

  def test_read_failure_partial_discards_in_progress_line(self):
    failure = OSError("read\nfailed")
    with mock.patch.object(loghound.os, "read", side_effect=[b"kept\npartial", failure]):
      result = loghound.observe_descriptor(9, "/log", 100)
    self.assertTrue(result.incomplete)
    self.assertEqual((result.physical_lines, result.analyzable_lines), (1, 1))
    self.assertNotIn("partial", [item.key for item in result.patterns])
    self.assertIn("\\x0a", result.incomplete_warning)

  def test_read_failure_before_analyzable_line_is_fatal(self):
    with mock.patch.object(loghound.os, "read", side_effect=OSError("failed")):
      with self.assertRaises(loghound.ObservationError):
        loghound.observe_descriptor(9, "/log", 100)


class RankingAndRenderingTests(unittest.TestCase):
  def evidence(self, key, count, first, last):
    return loghound.PatternEvidence(key, count, first, last)

  def test_ranking_and_top_ten_are_deterministic(self):
    patterns = tuple(self.evidence(f"p{i}", 2, i, i + 20) for i in range(12))
    result = loghound.AnalysisResult("/log", 1, 1, 1, 24, patterns)
    ranked = loghound.rank_recurring(patterns)
    self.assertEqual([item.key for item in ranked[:2]], ["p0", "p1"])
    output = loghound.render_result(result)
    self.assertIn("Displayed recurring patterns: 10 of 12", output)
    self.assertNotIn("Excerpt: p10", output)

  def test_count_order_and_defensive_tie_breakers(self):
    patterns = (
      self.evidence("z", 3, 8, 9), self.evidence("b", 2, 2, 7),
      self.evidence("a", 2, 2, 7), self.evidence("later", 2, 4, 5),
    )
    self.assertEqual(
      [item.key for item in loghound.rank_recurring(patterns)], ["z", "a", "b", "later"]
    )

  def test_singletons_summary_no_recurrence_and_percentage(self):
    result = loghound.AnalysisResult(
      "/log", 4, 4, 4, 4,
      (self.evidence("repeat", 2, 1, 2), self.evidence("one", 1, 3, 3),
       self.evidence("two", 1, 4, 4)),
    )
    output = loghound.render_result(result)
    self.assertIn("Distinct normalized patterns: 3", output)
    self.assertIn("Percentage: 50.00%", output)
    empty = loghound.AnalysisResult("/empty", 0, 0, 0, 0, ())
    self.assertIn("No normalized pattern occurred at least twice", loghound.render_result(empty))

  def test_terminal_safe_display_and_excerpt_boundaries(self):
    bidi = chr(0x202E)
    line_separator = chr(0x2028)
    paragraph_separator = chr(0x2029)
    unsafe = "a\\b\n\t\r\b\x1b" + bidi + line_separator + paragraph_separator + "\udcff"
    rendered = loghound.display_safe(unsafe)
    for character in (
      "\n", "\t", "\r", "\b", "\x1b", bidi, line_separator, paragraph_separator, "\udcff"
    ):
      self.assertNotIn(character, rendered)
    self.assertIn("a\\\\b", rendered)
    self.assertIn("\\xff", rendered)
    self.assertEqual(loghound.display_excerpt("a" * 160), "a" * 160)
    self.assertEqual(loghound.display_excerpt("a" * 161), "a" * 160 + "... [truncated]")
    value = "a" * 159 + "\n" + "tail"
    self.assertTrue(loghound.display_excerpt(value).endswith("\\x0a... [truncated]"))

  def test_distinct_full_keys_with_identical_excerpts_remain_distinct(self):
    common = "x" * 160
    patterns = (self.evidence(common + "a", 2, 1, 3), self.evidence(common + "b", 2, 2, 4))
    self.assertEqual(len(loghound.rank_recurring(patterns)), 2)
    self.assertEqual(
      loghound.display_excerpt(patterns[0].key), loghound.display_excerpt(patterns[1].key)
    )

  def test_required_output_sections_and_interpretation(self):
    result = loghound.AnalysisResult("/log", 0, 0, 0, 0, ())
    output = loghound.render_result(result)
    positions = [output.index(name) for name in (
      "Target", "Observation", "Analysis summary", "Recurring patterns", "Interpretation limits"
    )]
    self.assertEqual(positions, sorted(positions))
    self.assertIn("Absence of recurrence does not establish health", output)
    self.assertIn("not an atomic snapshot", output)


if __name__ == "__main__":
  unittest.main()