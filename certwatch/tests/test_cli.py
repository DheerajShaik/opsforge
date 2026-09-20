import contextlib
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


PATH = pathlib.Path(__file__).parents[1] / "certwatch.py"
SPEC = importlib.util.spec_from_file_location("certwatch_cli", PATH)
c = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = c
SPEC.loader.exec_module(c)


class TestCli(unittest.TestCase):
  def invoke(self, arguments):
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
      try:
        code = c.main(arguments)
      except SystemExit as error:
        code = error.code
    return code, stdout.getvalue(), stderr.getvalue()

  def test_help(self):
    for flag in ("-h", "--help"):
      code, stdout, stderr = self.invoke([flag])
      self.assertEqual((code, bool(stdout), stderr), (0, True, ""))

  def test_invalid_invocations(self):
    invalid = (
      [], ["--no"], ["bad_name"], ["x", "--warn-days", "-1"],
      ["--warn-days", "+1", "x"], ["--warn-days", "1.5", "x"],
      ["--warn-days", "١", "x"],
      ["--critical-days", "31", "--warn-days", "30", "x"],
      ["--sni", "x", "one", "two"],
    )
    for arguments in invalid:
      with self.subTest(arguments=arguments):
        code, stdout, stderr = self.invoke(arguments)
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertNotIn("Traceback", stderr)

  def test_extremely_large_numeric_values_are_invocation_errors(self):
    huge = "9" * 5000
    for arguments in ((f"x:{huge}",), ("--warn-days", huge, "x")):
      code, stdout, stderr = self.invoke(list(arguments))
      self.assertEqual(code, 2)
      self.assertEqual(stdout, "")
      self.assertNotIn("internal execution failure", stderr)

  def test_decoder_before_network(self):
    with mock.patch.object(
      c, "find_decoder", side_effect=c.CertWatchError("required decoder 'openssl' is not available")
    ), mock.patch.object(c, "observe_leaf") as observe:
      code, stdout, stderr = self.invoke(["example.com"])
    self.assertEqual(code, 3)
    observe.assert_not_called()
    self.assertEqual(stdout, "")

  def successful(self, status, extra_arguments=(), verification=None):
    before = datetime(2026, 1, 1, tzinfo=timezone.utc)
    certificate = c.CertificateInfo(
      "CN=x", "CN=i", "01", (("DNS", "example.com"),),
      before, before + timedelta(days=40), "AA",
    )
    assessment = c.ValidityAssessment(
      status,
      timedelta(days=2) if status in (c.ValidityStatus.NORMAL, c.ValidityStatus.WARNING) else None,
      status is c.ValidityStatus.WARNING,
      0 if status is c.ValidityStatus.NORMAL else 1,
    )
    verification = verification or c.VerificationEvidence(True, True, None, 2, True)
    with mock.patch.object(c, "find_decoder", return_value="/openssl"), \
         mock.patch.object(c, "observe_leaf", return_value=c.LeafObservation("1.2.3.4", b"x")), \
         mock.patch.object(c, "decode_certificate", return_value=certificate), \
         mock.patch.object(c, "assess_validity", return_value=assessment), \
         mock.patch.object(c, "verify_endpoint", return_value=verification):
      return self.invoke([*extra_arguments, "--warn-days", "030", "example.com"])

  def test_status_outputs(self):
    cases = (
      (c.ValidityStatus.NORMAL, 0), (c.ValidityStatus.WARNING, 1),
      (c.ValidityStatus.CRITICAL, 1), (c.ValidityStatus.EXPIRED, 1),
      (c.ValidityStatus.NOT_YET, 1),
    )
    for status, expected in cases:
      code, stdout, stderr = self.successful(status)
      self.assertEqual(code, expected)
      self.assertIn("CertWatch:", stdout)
      self.assertIn("Conclusion:", stdout)
      self.assertEqual(stderr, "")

  def test_json_output(self):
    code, stdout, stderr = self.successful(c.ValidityStatus.NORMAL, ("--json",))
    self.assertEqual((code, stderr), (0, ""))
    payload = json.loads(stdout)
    self.assertEqual(payload["tool"], "certwatch")
    self.assertEqual(payload["status"], "VALID")

  def test_trust_or_identity_warning_exits_one(self):
    verification = c.VerificationEvidence(False, False, "untrusted", None, False)
    code, stdout, stderr = self.successful(c.ValidityStatus.NORMAL, verification=verification)
    self.assertEqual(code, 1)
    self.assertIn("Conclusion: [WARNING]", stdout)
    self.assertIn("untrusted", stderr)

  def test_operational_failure(self):
    with mock.patch.object(c, "find_decoder", return_value="/openssl"), mock.patch.object(
      c, "observe_leaf", side_effect=c.CertWatchError("TCP connection failed")
    ):
      code, stdout, stderr = self.invoke(["x"])
    self.assertEqual((code, stdout), (3, ""))
    self.assertEqual(stderr, "certwatch: TCP connection failed\n")

  def test_internal_and_interrupt(self):
    for error, code, text in (
      (RuntimeError(), 3, "internal execution failure"),
      (KeyboardInterrupt(), 130, "interrupted"),
    ):
      with mock.patch.object(c, "find_decoder", side_effect=error):
        got, stdout, stderr = self.invoke(["x"])
      self.assertEqual((got, stdout), (code, ""))
      self.assertIn(text, stderr)
      self.assertNotIn("Traceback", stderr)

  def test_decoder_interrupt_terminates_and_reaps_child(self):
    with tempfile.TemporaryDirectory() as directory:
      executable = pathlib.Path(directory, "fake-openssl")
      executable.write_text(
        f"#!{sys.executable}\nimport time\ntime.sleep(30)\n", encoding="utf-8",
      )
      executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
      children = []
      real_popen = subprocess.Popen
      def capture(*args, **kwargs):
        child = real_popen(*args, **kwargs)
        children.append(child)
        return child
      with mock.patch.object(c.selectors.DefaultSelector, "select", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
        c.run_decoder(str(executable), b"DER", popen=capture)
      self.assertEqual(len(children), 1)
      self.assertIsNotNone(children[0].poll())


def load_tests(loader, tests, pattern):
  return loader.loadTestsFromTestCase(TestCli)
