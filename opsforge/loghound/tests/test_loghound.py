import contextlib
from datetime import datetime, timezone
import errno
import importlib.util
import io
import json
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


def normalize_message(message):
  """Normalize a whole line the way analysis does: drop the timestamp, then the operational identifiers."""
  return loghound.normalize_content(loghound.extract_timestamp(message)[1])


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
        self.assertIn("bounded local regular log files", stdout.getvalue())
        opened.assert_not_called()

  def test_invalid_invocations_exit_two(self):
    for arguments in ([], ["a", "b"], ["--limit", "a"]):
      with self.subTest(arguments=arguments):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
          loghound.main(arguments)
        self.assertEqual(caught.exception.code, 2)

  def test_success_and_dash_leading_filename(self):
    previous = os.getcwd()
    with tempfile.TemporaryDirectory() as directory:
      Path(directory, "-events").write_text("same\nsame\n", encoding="utf-8")
      os.chdir(directory)
      try:
        code, stdout, stderr = self.run_main(["--", "-events"])
      finally:
        os.chdir(previous)
    self.assertEqual((code, stderr), (0, ""))
    self.assertIn("Count: 2", stdout)

  def test_argument_errors_are_terminal_safe(self):
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit):
      loghound.main(["x", "\x1b[31m"])
    self.assertNotIn("\x1b", stderr.getvalue())
    self.assertIn("\\x1b", stderr.getvalue())

  def test_backslash_filter_is_printable_text(self):
    with tempfile.TemporaryDirectory() as directory:
      path = Path(directory, "log")
      path.write_text("C:\\temp failed\nC:\\temp failed\nother\n", encoding="utf-8")
      code, stdout, _ = self.run_main(["--include", "C:\\temp", str(path)])
    self.assertEqual(code, 0)
    self.assertIn("Count: 2", stdout)
    self.assertIn("Filtered physical lines: 1", stdout)

  def test_json_patterns_are_bounded_and_strictly_encodable(self):
    with tempfile.TemporaryDirectory() as directory:
      path = Path(directory, "log")
      path.write_bytes((b"x" * 400 + b"\n") * 2 + b"bad\x80\nbad\x80\n")
      code, stdout, _ = self.run_main(["--json", str(path)])
    self.assertEqual(code, 0)
    self.assertNotIn("\\udc", stdout)
    observations = json.loads(stdout)["observations"]
    self.assertEqual((observations["distinct_patterns"], observations["recurring_patterns"]), (2, 2))
    long_pattern, binary_pattern = observations["patterns"]
    self.assertEqual(long_pattern["key"], "x" * loghound.EXCERPT_CODEPOINTS)
    self.assertEqual((long_pattern["key_truncated"], long_pattern["key_length"]), (True, 400))
    self.assertEqual(len(long_pattern["key_digest"]), 32)
    self.assertEqual(binary_pattern["key"], "bad\\x80")

  def test_expected_and_internal_errors_use_stderr(self):
    with mock.patch.object(loghound, "analyze_sources", side_effect=loghound.ObservationError("bad")):
      self.assertEqual(self.run_main(["x"]), (3, "", "loghound: bad\n"))
    with mock.patch.object(loghound, "analyze_sources", side_effect=RuntimeError("secret")):
      self.assertEqual(
        self.run_main(["x"]), (3, "", "loghound: internal execution failure\n")
      )
    with mock.patch.object(loghound, "analyze_sources", side_effect=KeyboardInterrupt):
      self.assertEqual(self.run_main(["x"]), (130, "", "loghound: interrupted\n"))

  def test_ascii_stdout_escapes_unencodable_unicode(self):
    stdout = StrictAsciiStream()
    stderr = io.StringIO()
    with mock.patch.object(loghound.sys, "stdout", stdout), \
         mock.patch.object(loghound.sys, "stderr", stderr), \
         mock.patch.object(loghound, "analyze_sources", return_value=loghound.AnalysisResult(
           "/log", 1, 1, 2, 2, (loghound.PatternEvidence("recurring é", 2, 1, 2),),
         )):
      code = loghound.main(["x"])
    self.assertEqual(code, 0)
    self.assertEqual(stderr.getvalue(), "")
    self.assertIn("recurring \\xe9", stdout.getvalue())

  def test_json_brief_and_quiet(self):
    result = loghound.AnalysisResult(
      "/log", 1, 1, 2, 2, (loghound.PatternEvidence("error", 2, 1, 2),),
      severity_counts=(("critical", 0), ("error", 2), ("warning", 0), ("info", 0), ("debug", 0)),
    )
    with mock.patch.object(loghound, "analyze_sources", return_value=result):
      code, stdout, stderr = self.run_main(["--json", "x"])
      self.assertEqual((code, stderr), (0, ""))
      self.assertEqual(json.loads(stdout)["tool"], "loghound")
      self.assertIn("Recurring patterns:", self.run_main(["--brief", "x"])[1])
      self.assertEqual(self.run_main(["--quiet", "x"])[1], "")


class TargetTests(unittest.TestCase):
  run_main = CliTests.run_main
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

  def test_permission_failure_is_an_observation_error_and_terminal_safe(self):
    error = PermissionError(errno.EACCES, "bad\npath")
    with mock.patch.object(loghound.os, "open", side_effect=error):
      with self.assertRaises(loghound.ObservationError) as caught:
        loghound.open_target("x")
    self.assertNotIn("\n", str(caught.exception))
    self.assertIn("\\x0a", str(caught.exception))

  def test_open_errors_are_classified_by_errno(self):
    cases = (
      (errno.ENOENT, loghound.InvalidTargetError), (errno.ENOTDIR, loghound.InvalidTargetError),
      (errno.ENAMETOOLONG, loghound.InvalidTargetError), (errno.ELOOP, loghound.InvalidTargetError),
      (errno.EACCES, loghound.ObservationError), (errno.EPERM, loghound.ObservationError),
      (errno.EMFILE, loghound.ObservationError), (errno.EIO, loghound.ObservationError),
    )
    for number, expected in cases:
      with self.subTest(errno=errno.errorcode[number]), \
           mock.patch.object(loghound.os, "open", side_effect=OSError(number, "x")):
        with self.assertRaises(expected) as caught:
          loghound.open_target("x")
        self.assertIs(type(caught.exception), expected)

  def test_exit_codes_for_missing_unreadable_and_output_failures(self):
    with tempfile.TemporaryDirectory() as directory:
      missing = str(Path(directory, "missing.log"))
      self.assertEqual(self.run_main([missing])[0], 2)
      present = Path(directory, "app.log")
      present.write_text("a\na\n")
      with mock.patch.object(loghound.os, "open", side_effect=PermissionError(errno.EACCES, "denied")):
        code, stdout, stderr = self.run_main([str(present)])
      self.assertEqual((code, stdout), (3, ""))
      self.assertIn("cannot open target", stderr)
      code, stdout, stderr = self.run_main([str(present), "--output", str(Path(directory, "no", "report.txt"))])
      self.assertEqual((code, stdout), (3, ""))

  def test_an_unreadable_rotation_is_a_warning_not_a_failure(self):
    with tempfile.TemporaryDirectory() as directory:
      current, rotated = Path(directory, "app.log"), Path(directory, "app.log.1")
      current.write_text("boom\nboom\n")
      rotated.write_text("boom\n")
      real_open = os.open
      def selective(path, *args, **kwargs):
        if str(path) == str(rotated):
          raise PermissionError(errno.EACCES, "denied")
        return real_open(path, *args, **kwargs)
      with mock.patch.object(loghound.os, "open", side_effect=selective):
        code, stdout, stderr = self.run_main([str(current), "--rotated", "1", "--json"])
    payload = json.loads(stdout)
    self.assertEqual((code, payload["status"]), (1, "PARTIAL"))
    self.assertEqual(payload["observations"]["unavailable_sources"][0]["path"], str(rotated))
    self.assertIn("incomplete observation", stderr)

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
      self.assertFalse(loghound.analyze(str(path)).incomplete)

  def test_dotdot_after_symlinked_directory_follows_the_kernel(self):
    with tempfile.TemporaryDirectory() as directory:
      real = Path(directory, "real", "sub")
      real.mkdir(parents=True)
      Path(directory, "real", "app.log").write_text("kernel\nkernel\n")
      Path(directory, "app.log").write_text("lexical\nlexical\n")
      Path(directory, "link").symlink_to(real)
      result = loghound.analyze(str(Path(directory, "link")) + "/../app.log")
    self.assertEqual([item.key for item in result.patterns], ["kernel"])

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
      "2026-09-05 12:34:56,123 ",
      "2026-09-05t12:34:56z ",
      "2026-09-05T12:34:56+0530 ",
      "2026-09-05T12:34:56Z\t",
      "2026-09-05T12:34:56 ",
      "Sep  5 12:34:56 ",
      "Sep 27 01:02:03 ",
    ):
      with self.subTest(prefix=prefix):
        self.assertEqual(normalize_message(prefix + "message  "), "message  ")

  def test_unsupported_or_invalid_timestamps_remain(self):
    values = (
      "2026-13-05T12:34:56Z message", "2026-02-30T12:34:56Z message",
      "2026-09-05T25:34:56Z message", "[2026-09-05T12:34:56Z] message",
      " 2026-09-05T12:34:56Z message", "prefix 2026-09-05T12:34:56Z message",
      "2026-09-05T12:34:56+05:60 message",
      "2026-09-05T12:34:56-00:99 message",
      "2026-09-05T12:34:56+24:00 message",
      "2026-09-05T12:34:56Zmessage",
      "Sep 31 12:34:56 message", "Sept 5 12:34:56 message",
      "9999-12-31T23:59:59-01:00 message",
    )
    for value in values:
      with self.subTest(value=value):
        self.assertEqual(normalize_message(value), value)

  def test_rfc3164_year_comes_from_file_time_with_rollover(self):
    reference = datetime(2027, 1, 1, 12, 0, tzinfo=timezone.utc)
    for text, expected in (
      ("Dec 31 23:59:59 late", datetime(2026, 12, 31, 23, 59, 59)),
      ("Jan  1 00:00:01 early", datetime(2027, 1, 1, 0, 0, 1)),
      ("Feb 29 10:00:00 leap", datetime(2024, 2, 29, 10, 0, 0)),
    ):
      with self.subTest(text=text):
        timestamp, _, local = loghound.extract_timestamp(text, reference)
        self.assertEqual(timestamp.astimezone().replace(tzinfo=None), expected)
        self.assertTrue(local)

  def test_common_identifiers_normalize(self):
    first = "Sep 27 10:00:00 host sshd[4242]: Failed password for root from 10.0.0.5 port 22 ssh2"
    second = "Sep 27 10:00:01 host sshd[99]: Failed password for root from 10.0.0.7 port 40022 ssh2"
    self.assertEqual(
      normalize_message(first), "host sshd[<pid>]: Failed password for root from <ip> port <port> ssh2",
    )
    self.assertEqual(normalize_message(second), normalize_message(first))
    for value, expected in (
      ("id 0190b2e3-7c4a-7b3e-9f1d-2a3b4c5d6e7f", "id <uuid>"),
      ("connect to 2001:db8::1 failed", "connect to <ip> failed"),
      ("peer fe80::1%eth0 and ::ffff:10.0.0.1", "peer <ip> and <ip>"),
      ("dial [2001:db8::2]:443", "dial [<ip>]:443"),
      ("refused by 10.0.0.1.", "refused by <ip>."),
      ('{"pid": 4242, "request_id": "abc-1"}', '{"pid": <pid>, "request_id": "<id>"}'),
      ("at 10:00:00 mac 00:1a:2b:3c:4d:5e version 1.2.3.4.5", "at 10:00:00 mac 00:1a:2b:3c:4d:5e version 1.2.3.4.5"),
    ):
      with self.subTest(value=value):
        self.assertEqual(normalize_message(value), expected)

  def test_conservative_identifier_normalization(self):
    values = (
      "pid=1", "pid=2", "number 1", "number 2", "uuid a-b", "uuid a-c",
      "10.0.0.1:80", "10.0.0.2:81", "/a", "/b", "ERROR", "error",
      "two spaces", "two  spaces", "trail", "trail ",
    )
    normalized = [normalize_message(value) for value in values]
    self.assertEqual(normalized[:2], ["pid=<pid>", "pid=<pid>"])
    self.assertEqual(normalized[2:6], list(values[2:6]))
    self.assertEqual(normalized[6:8], ["<ip>:80", "<ip>:81"])
    self.assertEqual(normalized[8:], list(values[8:]))

  def test_uuid_and_labeled_ids_normalize(self):
    first = "request_id=abc-123 uuid 123e4567-e89b-12d3-a456-426614174000"
    second = "request_id=xyz-999 uuid 223e4567-e89b-12d3-a456-426614174999"
    self.assertEqual(normalize_message(first), normalize_message(second))


class SeverityTests(unittest.TestCase):
  def test_explicit_levels_win_and_absence_is_not_an_error(self):
    for message, expected in (
      ("INFO loaded 0 critical patches", "info"),
      ("DEBUG retrying after failure", "debug"),
      ("ok=5 changed=0 unreachable=0 failed=0", "info"),
      ("error=0 fatal=false", "info"),
      ("completed with no errors", "info"),
      ("GET /error 404", "info"),
      ('{"level":"error","msg":"disk"}', "error"),
      ("level=warn msg=slow", "warning"),
      ("<3>kernel: oops", "error"),
      ("E0905 12:34:56.789012 1 main.go:1] boom", "error"),
      ("[error] upstream timed out", "error"),
      ("ERR something", "error"),
      ("Connection failed.", "error"),
      ("Failing over to replica", "error"),
      ("3 errors found", "error"),
      ("panic: runtime error", "critical"),
      ("host sshd[1]: Failed password for root", "error"),
      ("request completed", "info"),
    ):
      with self.subTest(message=message):
        self.assertEqual(loghound.classify_severity(message), expected)


class WindowTests(unittest.TestCase):
  def analyze_text(self, text, now, mtime=None):
    with tempfile.TemporaryDirectory() as directory:
      path = Path(directory, "log")
      path.write_text(text, encoding="utf-8")
      if mtime is not None:
        os.utime(path, (mtime, mtime))
      options = loghound.AnalysisOptions(window_seconds=3600)
      return loghound.analyze_sources(str(path), options, 0, clock=lambda: now)

  def test_undated_lines_are_reported_and_continuations_inherit_time(self):
    result = self.analyze_text(
      "orphan line\n"
      "2026-01-01T00:00:00Z ERROR recent\n"
      "  continuation\n"
      "2025-01-01T00:00:00Z ERROR old\n"
      "  old continuation\n",
      datetime(2026, 1, 1, 0, 30, tzinfo=timezone.utc),
    )
    self.assertEqual((result.analyzable_lines, result.filtered_lines, result.undated_lines_excluded), (2, 3, 1))
    self.assertTrue(result.incomplete)
    self.assertIn("no recognized timestamp", result.incomplete_warning)

  def test_syslog_lines_are_placed_in_the_window(self):
    now = datetime(2026, 9, 27, 11, 0).astimezone(timezone.utc)
    text = "".join(f"Sep 27 10:{minute:02d}:00 host sshd[{minute}]: Failed password\n" for minute in range(0, 60, 10))
    result = self.analyze_text(text, now, mtime=now.timestamp())
    self.assertEqual((result.analyzable_lines, result.local_time_lines, len(result.patterns)), (6, 6, 1))
    self.assertFalse(result.incomplete)


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

  def test_bounded_stack_group_and_period_evidence(self):
    result = self.analyze_bytes(
      b"2026-01-01T00:00:00Z Traceback (most recent call last):\n"
      b"  File \"app.py\", line 7, in run\n"
      b"2026-01-01T00:10:00Z ERROR failed\n"
    )
    self.assertEqual((result.stack_trace_groups, result.stack_trace_lines), (1, 2))
    self.assertEqual((result.earlier_period_messages, result.later_period_messages), (1, 1))

  def test_python_traceback_with_source_caret_and_chain_is_one_group(self):
    result = self.analyze_bytes(
      b"Traceback (most recent call last):\n"
      b'  File "/app/server.py", line 10, in handle\n'
      b"    result = compute(x)\n"
      b"             ^^^^^^^^^^\n"
      b'  File "/app/logic.py", line 22, in compute\n'
      b"    return 1 / x\n"
      b"ZeroDivisionError: division by zero\n"
      b"\n"
      b"During handling of the above exception, another exception occurred:\n"
      b"\n"
      b"Traceback (most recent call last):\n"
      b'  File "/app/server.py", line 12, in handle\n'
      b'    raise RuntimeError("wrapped")\n'
      b"RuntimeError: wrapped\n"
      b"2026-09-27T10:00:01Z INFO next request\n"
    )
    self.assertEqual((result.stack_trace_groups, result.stack_trace_lines), (1, 12))

  def test_java_module_frames_and_cause_chain_are_grouped(self):
    result = self.analyze_bytes(
      b"2026-09-27T10:00:00Z ERROR request failed\n"
      b"java.lang.IllegalStateException: boom\n"
      b"\tat com.example.App.run(App.java:10)\n"
      b"\tat java.base/java.lang.Thread.run(Thread.java:833)\n"
      b"Caused by: java.io.IOException: disk\n"
      b"\tat com.example.Store.write(Store.java:5)\n"
      b"\t... 1 more\n"
      b"\tSuppressed: java.lang.Exception: close\n"
      b"\t\tat com.example.Store.close(Store.java:9)\n"
      b'Exception in thread "main" java.lang.Error: second\n'
      b"\tat com.example.Main.main(Main.java:3)\n"
    )
    self.assertEqual((result.stack_trace_groups, result.stack_trace_lines), (2, 10))

  def test_distinct_pattern_limit_is_partial(self):
    with mock.patch.object(loghound, "MAX_PATTERNS", 2):
      result = self.analyze_bytes(b"a\nb\nc\na\nd\n")
    self.assertEqual({item.key: item.count for item in result.patterns}, {"a": 2, "b": 1})
    self.assertEqual(result.untracked_lines, 2)
    self.assertIn("distinct pattern limit", result.incomplete_warning)

  def test_invalid_utf8_is_lossless_and_distinct(self):
    result = self.analyze_bytes(b"bad\x80\nbad\x80\nbad\x81\nbad\x81\n")
    self.assertEqual(len(result.patterns), 2)
    output = loghound.render_result(result)
    self.assertIn("bad\\x80", output)
    self.assertIn("bad\\x81", output)

  def test_nul_bytes_are_removed_and_reported(self):
    for data, keys in (
      (b"\x00a", {"a"}), (b"a\x00b", {"ab"}), (b"a\x00", {"a"}),
      (b"valid\nvalid\n" + b"\x00" * 8192, {"valid"}),
    ):
      with self.subTest(data=data[:16]):
        result = self.analyze_bytes(data)
        self.assertEqual({item.key for item in result.patterns}, keys)
        self.assertTrue(result.incomplete)
        self.assertIn("NUL bytes", result.incomplete_warning)

  def test_line_length_boundary(self):
    for data in (b"a" * loghound.MAX_LINE_BYTES, b"a" * loghound.MAX_LINE_BYTES + b"\r\n"):
      result = self.analyze_bytes(data)
      self.assertEqual((result.analyzable_lines, result.truncated_lines), (1, 0))
      self.assertFalse(result.incomplete)
    for data, lines in (
      (b"a" * (loghound.MAX_LINE_BYTES + 1), 1),
      (b"valid\n" + b"a" * (loghound.MAX_LINE_BYTES + 1), 2),
      (b"a" * loghound.MAX_LINE_BYTES + b"\r", 1),
      (b"a" * (3 * loghound.MAX_LINE_BYTES) + b"\nnext\n", 2),
    ):
      with self.subTest(size=len(data)):
        result = self.analyze_bytes(data)
        self.assertEqual((result.physical_lines, result.truncated_lines), (lines, 1))
        self.assertTrue(result.incomplete)
        self.assertIn("truncated", result.incomplete_warning)

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

  def test_message_rate_and_evidence_counters_are_rendered(self):
    result = loghound.AnalysisResult(
      "/log", 1, 1, 4, 4, (), timestamped_lines=4, duration_seconds=2.0, truncated_lines=1,
    )
    output = loghound.render_result(result)
    self.assertIn("Approximate message rate: 2.000 timestamped messages per second", output)
    self.assertIn(f"Lines truncated at {loghound.MAX_LINE_BYTES} bytes: 1", output)
    self.assertNotIn("NUL bytes removed", output)

  def test_truncated_pattern_excerpt_is_labelled(self):
    pattern = loghound.PatternEvidence("x" * loghound.EXCERPT_CODEPOINTS, 2, 1, 2, 500, "0" * 32)
    result = loghound.AnalysisResult("/log", 1, 1, 2, 2, (pattern,))
    self.assertIn("x" * loghound.EXCERPT_CODEPOINTS + "... [truncated]", loghound.render_result(result))


if __name__ == "__main__":
  unittest.main()
