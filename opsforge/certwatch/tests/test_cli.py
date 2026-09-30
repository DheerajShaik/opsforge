import contextlib
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import json
import pathlib
import selectors
import stat
import subprocess
import sys
import tempfile
import threading
import time
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
    ), mock.patch.object(c, "observe_endpoint") as observe:
      code, stdout, stderr = self.invoke(["example.com"])
    self.assertEqual(code, 3)
    observe.assert_not_called()
    self.assertEqual(stdout, "")

  @staticmethod
  def leaf(trusted=True, error=None):
    return c.LeafObservation(
      "1.2.3.4", b"x", "TLSv1.3", "TLS_AES_256_GCM_SHA384", 0.01, 0.02, trusted, error, 2 if trusted else None,
    )

  @staticmethod
  def certificate(*names):
    before = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return c.CertificateInfo(
      "CN=x", "CN=i", "01", tuple(("DNS", name) for name in (names or ("example.com",))),
      before, before + timedelta(days=40), "AA",
    )

  def successful(self, status, extra_arguments=(), trusted=True):
    assessment = c.ValidityAssessment(
      status, timedelta(days=2) if status in (c.ValidityStatus.NORMAL, c.ValidityStatus.WARNING) else None,
    )
    error = None if trusted else "certificate verification failed: untrusted"
    with mock.patch.object(c, "find_decoder", return_value="/openssl"), \
         mock.patch.object(c, "observe_endpoint", return_value=self.leaf(trusted, error)), \
         mock.patch.object(c, "decode_certificate", return_value=self.certificate()), \
         mock.patch.object(c, "assess_validity", return_value=assessment):
      return self.invoke([*extra_arguments, "--warn-days", "030", "example.com"])

  def test_status_outputs(self):
    cases = (
      (c.ValidityStatus.NORMAL, 0, "VALID"), (c.ValidityStatus.WARNING, 1, "WARNING"),
      (c.ValidityStatus.CRITICAL, 1, "CRITICAL"), (c.ValidityStatus.EXPIRED, 1, "EXPIRED"),
      (c.ValidityStatus.NOT_YET, 1, "NOT_YET_VALID"),
    )
    for status, expected, name in cases:
      with self.subTest(name=name):
        code, stdout, stderr = self.successful(status)
        self.assertEqual(code, expected)
        self.assertIn("CertWatch:", stdout)
        self.assertIn(f"Conclusion: [{name}]", stdout)
        self.assertEqual(stderr, "")

  def test_json_output(self):
    code, stdout, stderr = self.successful(c.ValidityStatus.NORMAL, ("--json",))
    self.assertEqual((code, stderr), (0, ""))
    payload = json.loads(stdout)
    self.assertEqual(payload["tool"], "certwatch")
    self.assertEqual(payload["status"], "VALID")

  def test_trust_failure_exits_one(self):
    code, stdout, stderr = self.successful(c.ValidityStatus.NORMAL, trusted=False)
    self.assertEqual(code, 1)
    self.assertIn("Conclusion: [WARNING]", stdout)
    self.assertIn("untrusted", stderr)

  def test_identity_mismatch_exits_one(self):
    before = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with mock.patch.object(c, "find_decoder", return_value="/openssl"), \
         mock.patch.object(c, "observe_endpoint", return_value=self.leaf()), \
         mock.patch.object(c, "decode_certificate", return_value=self.certificate("other.example")), \
         mock.patch.object(c, "assess_validity", return_value=c.ValidityAssessment(c.ValidityStatus.NORMAL, timedelta(days=90))):
      code, stdout, _ = self.invoke(["example.com"])
    self.assertEqual(code, 1)
    self.assertIn("Host identity: mismatch", stdout)
    self.assertIn("Conclusion: [WARNING]", stdout)

  def test_critical_is_a_distinct_status(self):
    code, stdout, _ = self.successful(c.ValidityStatus.CRITICAL, ("--json",))
    self.assertEqual((code, json.loads(stdout)["status"]), (1, "CRITICAL"))

  def test_small_warn_days_without_critical_days_is_valid(self):
    with mock.patch.object(c, "find_decoder", return_value="/openssl"), \
         mock.patch.object(c, "observe_endpoint", return_value=self.leaf()), \
         mock.patch.object(c, "decode_certificate", return_value=self.certificate()):
      code, stdout, _ = self.invoke(["--warn-days", "3", "--json", "example.com"])
    self.assertNotEqual(code, 2)
    self.assertEqual(json.loads(stdout)["observations"]["critical_days"], 3)

  def test_invalid_sni_and_baseline_combinations(self):
    for arguments in (["--sni", "192.0.2.1", "x"], ["--baseline-sha256", "A" * 64, "a", "b"]):
      with self.subTest(arguments=arguments):
        self.assertEqual(self.invoke(arguments)[0], 2)

  def test_overall_time_limit_caps_budgets_and_skips_late_targets(self):
    names = ("a.example", "b.example", "c.example")
    options = c.RunOptions(tuple(c.parse_target(name) for name in names), 30, 7, None)
    ticks = iter([0.0, 0.0, 110.0, 130.0])
    normal = c.ValidityAssessment(c.ValidityStatus.NORMAL, timedelta(days=90))
    with mock.patch.object(c, "MAX_PARALLEL_TARGETS", 1), \
         mock.patch.object(c, "observe_endpoint", return_value=self.leaf()) as observe, \
         mock.patch.object(c, "decode_certificate", return_value=self.certificate(*names)), \
         mock.patch.object(c, "assess_validity", return_value=normal):
      outcomes = c.inspect_targets(options, "/openssl", clock=lambda: next(ticks))
    self.assertEqual([call.args[1] for call in observe.call_args_list], [c.CONNECT_BUDGET_SECONDS, 10.0])
    self.assertEqual([outcome.status for outcome in outcomes], ["VALID", "VALID", "SKIPPED"])
    self.assertIn("overall time limit", outcomes[2].observation["error"])
    self.assertEqual(c.aggregate_status([outcome.status for outcome in outcomes]), "INCOMPLETE")

  def test_exhausted_time_limit_reports_every_target_without_network(self):
    with mock.patch.object(c, "TOTAL_BUDGET_SECONDS", 0.0), \
         mock.patch.object(c, "find_decoder", return_value="/openssl"), \
         mock.patch.object(c, "observe_endpoint") as observe:
      code, stdout, stderr = self.invoke(["--json", "a.example", "b.example"])
    observe.assert_not_called()
    payload = json.loads(stdout)
    self.assertEqual((code, payload["status"]), (3, "ERROR"))
    self.assertEqual(len(payload["observations"]["targets"]), 2)
    self.assertEqual([item["status"] for item in payload["observations"]["targets"]], ["SKIPPED", "SKIPPED"])
    self.assertIn("not attempted", payload["observations"]["targets"][1]["error"])
    self.assertEqual(stderr.count("overall time limit"), 2)

  def test_a_target_still_running_at_the_overall_limit_is_abandoned_as_an_error(self):
    release = threading.Event()
    self.addCleanup(release.set)
    options = c.RunOptions((c.parse_target("slow.example"), c.parse_target("fast.example")), 30, 7, None)
    normal = c.ValidityAssessment(c.ValidityStatus.NORMAL, timedelta(days=90))

    def observe(target, budget, contexts):
      if target.host == "slow.example":
        release.wait(10)
      return self.leaf()

    started = time.monotonic()
    with mock.patch.object(c, "TOTAL_BUDGET_SECONDS", 0.3), mock.patch.object(c, "DEADLINE_GRACE_SECONDS", 0.05), \
         mock.patch.object(c, "observe_endpoint", side_effect=observe), \
         mock.patch.object(c, "decode_certificate", return_value=self.certificate("fast.example")), \
         mock.patch.object(c, "assess_validity", return_value=normal):
      outcomes = c.inspect_targets(options, "/openssl")
    self.assertLess(time.monotonic() - started, 3)
    self.assertEqual([outcome.status for outcome in outcomes], ["ERROR", "VALID"])
    self.assertIn("did not finish within the 0.3-second overall time limit", outcomes[0].observation["error"])
    self.assertEqual(c.aggregate_status([outcome.status for outcome in outcomes]), "INCOMPLETE")

  def test_a_queued_target_at_the_overall_limit_is_skipped_not_errored(self):
    release = threading.Event()
    self.addCleanup(release.set)
    options = c.RunOptions((c.parse_target("slow.example"), c.parse_target("queued.example")), 30, 7, None)

    def observe(target, budget, contexts):
      release.wait(10)
      return self.leaf()

    with mock.patch.object(c, "MAX_PARALLEL_TARGETS", 1), mock.patch.object(c, "TOTAL_BUDGET_SECONDS", 0.3), \
         mock.patch.object(c, "DEADLINE_GRACE_SECONDS", 0.05), mock.patch.object(c, "observe_endpoint", side_effect=observe):
      outcomes = c.inspect_targets(options, "/openssl")
    self.assertEqual([outcome.status for outcome in outcomes], ["ERROR", "SKIPPED"])
    self.assertIn("did not finish", outcomes[0].observation["error"])
    self.assertIn("not attempted", outcomes[1].observation["error"])

  def test_operational_failure_still_reports_and_emits_json(self):
    with mock.patch.object(c, "find_decoder", return_value="/openssl"), mock.patch.object(
      c, "observe_endpoint", side_effect=c.CertWatchError("TCP connection failed")
    ):
      code, stdout, stderr = self.invoke(["x"])
      json_code, json_stdout, _ = self.invoke(["--json", "x"])
    self.assertEqual(code, 3)
    self.assertIn("TCP connection failed", stdout)
    self.assertIn("Conclusion: [ERROR]", stdout)
    self.assertIn("certwatch: warning: x:443: TCP connection failed", stderr)
    payload = json.loads(json_stdout)
    self.assertEqual((json_code, payload["status"]), (3, "ERROR"))
    self.assertEqual(payload["observations"]["targets"][0]["error"], "TCP connection failed")

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
      with mock.patch.object(subprocess, "Popen", side_effect=capture), \
           mock.patch.object(selectors.DefaultSelector, "select", side_effect=KeyboardInterrupt), \
           self.assertRaises(KeyboardInterrupt):
        c.run_decoder(str(executable), b"DER")
      self.assertEqual(len(children), 1)
      self.assertIsNotNone(children[0].poll())


def load_tests(loader, tests, pattern):
  return loader.loadTestsFromTestCase(TestCli)
