import contextlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import svcdoctor


RUNNING = """Result=success
ExecMainCode=0
ExecMainStatus=0
Id=cron.service
LoadState=loaded
ActiveState=active
SubState=running
"""
INACTIVE = """Result=success
ExecMainCode=0
ExecMainStatus=0
Id=apparmor.service
LoadState=loaded
ActiveState=inactive
SubState=dead
"""
ACTIVE_EXITED = """Result=success
ExecMainCode=1
ExecMainStatus=0
Id=console-setup.service
LoadState=loaded
ActiveState=active
SubState=exited
"""
FAILED = """Result=exit-code
ExecMainCode=1
ExecMainStatus=7
Id=failing.service
LoadState=loaded
ActiveState=failed
SubState=failed
"""
MISSING = """Result=success
ExecMainCode=0
ExecMainStatus=0
Id=no-such.service
LoadState=not-found
ActiveState=inactive
SubState=dead
"""
INSTANCE = """Result=success
ExecMainCode=0
ExecMainStatus=0
Id=getty@tty1.service
LoadState=loaded
ActiveState=active
SubState=running
"""


def properties(text=RUNNING):
  return svcdoctor.parse_properties(text)


def evidence(text=RUNNING, **overrides):
  values = properties(text)
  values.update(overrides)
  return svcdoctor.ServiceEvidence(
    values["Id"], values, ("recent entry",), None, (),
  )


class TargetTests(unittest.TestCase):
  def test_normalization(self):
    cases = {
      "nginx": "nginx.service",
      "nginx.service": "nginx.service",
      "worker@3": "worker@3.service",
      "worker@3.service": "worker@3.service",
      "my.worker": "my.worker.service",
    }
    for target, expected in cases.items():
      with self.subTest(target=target):
        self.assertEqual(svcdoctor.normalize_target(target), expected)

  def test_invalid_targets(self):
    invalid = (
      "", "-bad", "/tmp/x.service", "bad name", "bad\tname", "bad\nname",
      "bad\rname", "bad\x1bname", "bad\u202ename", ".service", "worker@",
      "worker@.service",
    )
    for target in invalid:
      with self.subTest(target=target), self.assertRaises(svcdoctor.SvcDoctorError):
        svcdoctor.normalize_target(target)

  def test_non_service_suffixes_are_rejected(self):
    for suffix in svcdoctor.UNIT_SUFFIXES:
      if suffix == ".service":
        continue
      with self.subTest(suffix=suffix), self.assertRaises(svcdoctor.SvcDoctorError):
        svcdoctor.normalize_target(f"example{suffix}")

  def test_minimal_policy_does_not_reimplement_systemd_grammar(self):
    self.assertEqual(svcdoctor.normalize_target(r"odd\x2dname"), r"odd\x2dname.service")
    self.assertEqual(svcdoctor.normalize_target("name.unknown"), "name.unknown.service")


class ParserTests(unittest.TestCase):
  def test_property_order_is_irrelevant(self):
    parsed = properties(RUNNING)
    self.assertEqual(parsed["Id"], "cron.service")
    self.assertEqual(parsed["Result"], "success")

  def test_value_may_contain_equals(self):
    parsed = svcdoctor.parse_properties("Id=a=b.service\nLoadState=loaded\nActiveState=active\n")
    self.assertEqual(parsed["Id"], "a=b.service")

  def test_empty_output(self):
    for output in ("", "\n", "\n\n"):
      with self.subTest(output=output), self.assertRaisesRegex(
        svcdoctor.SvcDoctorError, "empty response"
      ):
        svcdoctor.parse_properties(output)

  def test_malformed_lines_and_names(self):
    malformed = (
      "not-a-property\n",
      "=value\n",
      "Unexpected=value\n",
      " Id=value\n",
      "Id=x.service\n\nLoadState=loaded\n",
      "Id=x.service\n   \nLoadState=loaded\n",
    )
    for output in malformed:
      with self.subTest(output=output), self.assertRaisesRegex(
        svcdoctor.SvcDoctorError, "malformed response"
      ):
        svcdoctor.parse_properties(output)

  def test_duplicate_core_and_optional_properties(self):
    for duplicate in ("Id", "Result"):
      with self.subTest(duplicate=duplicate), self.assertRaisesRegex(
        svcdoctor.SvcDoctorError, "malformed response"
      ):
        svcdoctor.parse_properties(RUNNING + f"{duplicate}=again\n")

  def test_single_trailing_blank_record_separator_is_harmless(self):
    self.assertEqual(properties(RUNNING + "\n")["Id"], "cron.service")

  def test_invalid_utf8_is_malformed(self):
    with self.assertRaisesRegex(svcdoctor.SvcDoctorError, "malformed response"):
      svcdoctor.decode_output(b"Id=bad\xff.service\n")


class CompletenessTests(unittest.TestCase):
  def test_missing_or_empty_core_property(self):
    base = properties()
    for name in svcdoctor.CORE_PROPERTIES:
      for mode in ("missing", "empty"):
        candidate = dict(base)
        if mode == "missing":
          candidate.pop(name, None)
        else:
          candidate[name] = ""
        with self.subTest(name=name, mode=mode), self.assertRaisesRegex(
          svcdoctor.SvcDoctorError, "missing or empty property"
        ):
          svcdoctor.validate_properties(candidate)

  def test_multiple_missing_core_properties_use_frozen_order(self):
    with self.assertRaises(svcdoctor.SvcDoctorError) as caught:
      svcdoctor.validate_properties({"Id": "", "LoadState": "", "ActiveState": ""})
    self.assertEqual(
      str(caught.exception),
      "incomplete systemd response: missing or empty property Id, LoadState, ActiveState",
    )

  def test_not_found_does_not_require_active_state(self):
    candidate = {"Id": "none.service", "LoadState": "not-found"}
    svcdoctor.validate_properties(candidate)

  def test_not_found_still_requires_identity_and_load_state(self):
    for candidate in ({"LoadState": "not-found"}, {"Id": "none.service"}):
      with self.assertRaises(svcdoctor.SvcDoctorError):
        svcdoctor.validate_properties(candidate)

  def test_supporting_properties_may_be_missing_or_empty(self):
    base = properties()
    for name in svcdoctor.OPTIONAL_PROPERTIES:
      for mode in ("missing", "empty"):
        candidate = dict(base)
        if mode == "missing":
          candidate.pop(name, None)
        else:
          candidate[name] = ""
        with self.subTest(name=name, mode=mode):
          svcdoctor.validate_properties(candidate)

  def test_returned_id_must_be_a_service(self):
    candidate = properties()
    candidate["Id"] = "example.socket"
    with self.assertRaisesRegex(svcdoctor.SvcDoctorError, "malformed response"):
      svcdoctor.validate_properties(candidate)


class FormattingAndClassificationTests(unittest.TestCase):
  def test_running_output_contains_legacy_and_v2_evidence(self):
    output = svcdoctor.render_diagnostic("cron.service", properties())
    self.assertIn("Requested: cron.service", output)
    self.assertIn("Active: active", output)
    self.assertIn("Main status: 0", output)
    self.assertIn("Restart policy:", output)
    self.assertIn("Resource evidence", output)
    self.assertTrue(output.endswith('ActiveState equals "failed": no'))

  def test_all_optional_values_render_as_dash(self):
    candidate = {"Id": "example.service", "LoadState": "loaded", "ActiveState": "active"}
    output = svcdoctor.render_diagnostic("example.service", candidate)
    self.assertGreaterEqual(output.count(": -"), 4)
    self.assertIn('ActiveState equals "failed": no', output)

  def test_empty_optional_values_render_as_dash(self):
    candidate = properties()
    for name in svcdoctor.OPTIONAL_PROPERTIES:
      candidate[name] = ""
    self.assertGreaterEqual(svcdoctor.render_diagnostic("cron.service", candidate).count(": -"), 4)

  def test_only_exact_lowercase_failed_classifies_failed(self):
    for state, expected in (
      ("failed", "yes"), ("Failed", "no"), ("active", "no"),
      ("inactive", "no"), ("activating", "no"), ("deactivating", "no"),
      ("reloading", "no"), ("future-state", "no"),
    ):
      candidate = properties()
      candidate["ActiveState"] = state
      with self.subTest(state=state):
        self.assertTrue(svcdoctor.render_diagnostic("cron.service", candidate).endswith(expected))

  def test_supporting_failure_evidence_does_not_classify_failure(self):
    variants = (
      {"ActiveState": "active", "Result": "exit-code"},
      {"ActiveState": "inactive", "ExecMainStatus": "9"},
      {"ActiveState": "active", "SubState": "failed"},
      {"ActiveState": "active", "ExecMainCode": "1"},
    )
    for overrides in variants:
      candidate = properties()
      candidate.update(overrides)
      with self.subTest(overrides=overrides):
        self.assertTrue(svcdoctor.render_diagnostic("cron.service", candidate).endswith("no"))

  def test_active_exited_keeps_raw_code_separate(self):
    output = svcdoctor.render_diagnostic("console-setup.service", properties(ACTIVE_EXITED))
    self.assertIn("  Main code: 1\n  Main status: 0\n", output)
    self.assertTrue(output.endswith("no"))

  def test_untrusted_values_are_single_line_and_deterministically_escaped(self):
    unsafe = "bad\\name\n\r\t\x1b\u202e\u2028"
    self.assertEqual(
      svcdoctor.display_safe(unsafe),
      r"bad\\name\x0a\x0d\x09\x1b\u202e\u2028",
    )
    candidate = properties()
    candidate["SubState"] = "running\nAssessment"
    output = svcdoctor.render_diagnostic("cron.service", candidate)
    self.assertNotIn("running\nAssessment", output)
    self.assertIn(r"running\x0aAssessment", output)

  def test_normal_printable_unicode_is_preserved(self):
    self.assertEqual(svcdoctor.display_safe("café-日本語-🙂"), "café-日本語-🙂")

  def test_format_is_independent_of_input_property_order(self):
    first = properties(RUNNING)
    second = dict(reversed(tuple(first.items())))
    self.assertEqual(
      svcdoctor.render_diagnostic("cron.service", first),
      svcdoctor.render_diagnostic("cron.service", second),
    )


class InspectTests(unittest.TestCase):
  @staticmethod
  def command(output, returncode=0, stderr=b""):
    return svcdoctor.CommandResult(returncode, output.encode(), stderr)

  @mock.patch.object(svcdoctor, "run_systemctl")
  def test_empirical_regression_fixtures(self, run):
    cases = (
      ("cron.service", RUNNING, 0),
      ("apparmor.service", INACTIVE, 0),
      ("console-setup.service", ACTIVE_EXITED, 0),
      ("failing.service", FAILED, 1),
      ("getty@tty1.service", INSTANCE, 0),
    )
    for target, fixture, expected_code in cases:
      with self.subTest(target=target):
        run.return_value = self.command(fixture)
        output, code = svcdoctor.inspect_service(target)
        self.assertEqual(code, expected_code)
        self.assertIn(f"Requested: {target}", output)

  @mock.patch.object(svcdoctor, "run_systemctl")
  def test_missing_precedes_result_active_and_substate(self, run):
    run.return_value = self.command(MISSING)
    with self.assertRaisesRegex(svcdoctor.SvcDoctorError, "service not found: no-such.service"):
      svcdoctor.inspect_service("no-such.service")

  @mock.patch.object(svcdoctor, "run_systemctl")
  def test_missing_needs_no_active_or_supporting_values(self, run):
    run.return_value = self.command("Id=no-such.service\nLoadState=not-found\n")
    with self.assertRaisesRegex(svcdoctor.SvcDoctorError, "service not found"):
      svcdoctor.inspect_service("no-such.service")

  @mock.patch.object(svcdoctor, "run_systemctl")
  def test_nonzero_command_discards_valid_partial_output(self, run):
    run.return_value = self.command(RUNNING, returncode=1)
    with self.assertRaisesRegex(svcdoctor.SvcDoctorError, "systemd query failed"):
      svcdoctor.inspect_service("cron.service")

  @mock.patch.object(svcdoctor, "run_systemctl")
  def test_empty_and_malformed_responses(self, run):
    for output, message in (("", "empty response"), ("broken\n", "malformed response")):
      with self.subTest(output=output):
        run.return_value = self.command(output)
        with self.assertRaisesRegex(svcdoctor.SvcDoctorError, message):
          svcdoctor.inspect_service("cron.service")


class CliTests(unittest.TestCase):
  def run_main(self, arguments):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
      code = svcdoctor.main(arguments)
    return code, stdout.getvalue(), stderr.getvalue()

  def test_help_is_stdout_exit_zero_and_does_not_query(self):
    for option in ("-h", "--help"):
      with self.subTest(option=option), mock.patch.object(svcdoctor, "collect_service") as inspect:
        code, stdout, stderr = self.run_main([option])
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("one local system service", stdout)
        self.assertIn("bare names receive .service", stdout)
        self.assertIn("Exit codes", stdout)
        inspect.assert_not_called()

  def test_missing_multiple_and_unknown_options(self):
    for arguments in ([], ["one", "two"], ["--json"], ["-x"]):
      with self.subTest(arguments=arguments), mock.patch.object(svcdoctor, "collect_service") as inspect:
        code, stdout, stderr = self.run_main(arguments)
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("svcdoctor:", stderr)
        self.assertTrue(stderr.endswith("\n"))
        inspect.assert_not_called()

  @mock.patch.object(svcdoctor, "collect_service", return_value=evidence())
  def test_success_stdout_and_normalization(self, inspect):
    code, stdout, stderr = self.run_main(["nginx"])
    self.assertEqual((code, stderr), (0, ""))
    self.assertIn("Conclusion: [ACTIVE]", stdout)
    inspect.assert_called_once_with("nginx.service", 20)

  @mock.patch.object(svcdoctor, "collect_service", return_value=evidence(FAILED))
  def test_failed_diagnostic_stdout_and_exit_one(self, inspect):
    code, stdout, stderr = self.run_main(["failing.service"])
    self.assertEqual((code, stderr), (1, ""))
    self.assertIn("Conclusion: [FAILED]", stdout)

  @mock.patch.object(svcdoctor, "collect_service", side_effect=svcdoctor.SvcDoctorError("systemd query failed"))
  def test_fatal_observation_has_empty_stdout(self, inspect):
    self.assertEqual(
      self.run_main(["nginx"]),
      (2, "", "svcdoctor: systemd query failed\n"),
    )

  def test_required_stable_error_categories(self):
    messages = (
      "systemctl is not available",
      "could not execute systemctl",
      "systemd system manager is unavailable",
      "permission denied while querying the systemd system manager",
      "systemd query timed out after 5 seconds",
      "systemd query failed",
      "systemd returned an empty response",
      "systemd returned a malformed response",
    )
    for message in messages:
      with self.subTest(message=message), mock.patch.object(
        svcdoctor, "collect_service", side_effect=svcdoctor.SvcDoctorError(message)
      ):
        self.assertEqual(self.run_main(["x"]), (2, "", f"svcdoctor: {message}\n"))

  @mock.patch.object(svcdoctor, "collect_service", return_value=evidence())
  def test_json_brief_and_quiet(self, collect):
    code, stdout, stderr = self.run_main(["--json", "cron"])
    self.assertEqual((code, stderr), (0, ""))
    self.assertEqual(json.loads(stdout)["tool"], "svcdoctor")
    code, stdout, _ = self.run_main(["--brief", "cron"])
    self.assertIn("State: active/running", stdout)
    code, stdout, _ = self.run_main(["--quiet", "cron"])
    self.assertEqual((code, stdout), (0, ""))


class SubprocessTests(unittest.TestCase):
  def make_systemctl(self, directory, body):
    path = Path(directory, "systemctl")
    path.write_text(f"#!{sys.executable}\n" + textwrap.dedent(body), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path

  def test_exact_arguments_and_allowlist(self):
    expected = ["systemctl", "show", "--system", "--no-pager"]
    expected.extend(f"--property={name}" for name in svcdoctor.PROPERTIES)
    expected.extend(("--", "nginx.service"))
    self.assertEqual(svcdoctor.systemctl_arguments("nginx.service"), expected)
    self.assertEqual(svcdoctor.systemctl_arguments("nginx.service").count("--"), 1)

  def test_one_real_boundary_query_has_stable_environment_and_no_shell(self):
    with tempfile.TemporaryDirectory() as directory:
      self.make_systemctl(directory, """
        import os
        import sys
        arguments = sys.argv[1:]
        if (arguments[:3] != ['show', '--system', '--no-pager']
            or arguments[-2:] != ['--', 'x.service']
            or not all(value.startswith('--property=') for value in arguments[3:-2])
            or os.environ.get('LC_ALL') != 'C'):
          raise SystemExit(9)
        print('Id=x.service')
        print('LoadState=loaded')
        print('ActiveState=active')
      """)
      with mock.patch.dict(os.environ, {"PATH": directory}, clear=False):
        result = svcdoctor.run_systemctl("x.service")
    self.assertEqual(result.returncode, 0)
    self.assertIn(b"Id=x.service", result.stdout)

  def test_missing_executable(self):
    with mock.patch.dict(os.environ, {"PATH": ""}, clear=False), self.assertRaisesRegex(
      svcdoctor.SvcDoctorError, "systemctl is not available"
    ):
      svcdoctor.run_systemctl("x.service")

  @mock.patch.object(svcdoctor.subprocess, "Popen", side_effect=PermissionError)
  def test_execution_failure(self, popen):
    with self.assertRaisesRegex(svcdoctor.SvcDoctorError, "could not execute systemctl"):
      svcdoctor.run_systemctl("x.service")

  def test_nonzero_and_abnormal_completion_are_returned_to_classifier(self):
    with tempfile.TemporaryDirectory() as directory:
      self.make_systemctl(directory, "raise SystemExit(3)\n")
      with mock.patch.dict(os.environ, {"PATH": directory}, clear=False):
        result = svcdoctor.run_systemctl("x.service")
    self.assertEqual(result.returncode, 3)

  def test_stdout_limit_is_enforced(self):
    with tempfile.TemporaryDirectory() as directory:
      self.make_systemctl(directory, f"import sys\nsys.stdout.write('x' * {svcdoctor.MAX_STREAM_BYTES + 1})\n")
      with mock.patch.dict(os.environ, {"PATH": directory}, clear=False), self.assertRaisesRegex(
        svcdoctor.ResponseTooLargeError, "malformed response"
      ):
        svcdoctor.run_systemctl("x.service")

  def test_stderr_limit_is_enforced(self):
    with tempfile.TemporaryDirectory() as directory:
      self.make_systemctl(directory, f"import sys\nsys.stderr.write('x' * {svcdoctor.MAX_STREAM_BYTES + 1})\n")
      with mock.patch.dict(os.environ, {"PATH": directory}, clear=False), self.assertRaisesRegex(
        svcdoctor.ResponseTooLargeError, "malformed response"
      ):
        svcdoctor.run_systemctl("x.service")

  def test_timeout_kills_and_reaps_child(self):
    with tempfile.TemporaryDirectory() as directory:
      self.make_systemctl(directory, "import time\ntime.sleep(30)\n")
      with mock.patch.dict(os.environ, {"PATH": directory}, clear=False), mock.patch.object(
        svcdoctor, "TIMEOUT_SECONDS", 0.05
      ):
        started = time.monotonic()
        with self.assertRaisesRegex(svcdoctor.SvcDoctorError, "timed out after 5 seconds"):
          svcdoctor.run_systemctl("x.service")
        self.assertLess(time.monotonic() - started, 2)

  def test_auxiliary_command_output_and_timeout_are_bounded(self):
    with self.assertRaisesRegex(svcdoctor.ResponseTooLargeError, "oversized"):
      svcdoctor.run_simple_command(
        (sys.executable, "-c", f"import sys; sys.stdout.write('x' * {svcdoctor.MAX_STREAM_BYTES + 1})"),
        "helper",
      )
    started = time.monotonic()
    with self.assertRaisesRegex(svcdoctor.SvcDoctorError, "timed out"):
      svcdoctor.run_simple_command(
        (sys.executable, "-c", "import time; time.sleep(30)"), "helper", timeout=0.05,
      )
    self.assertLess(time.monotonic() - started, 2)


if __name__ == "__main__":
  unittest.main()
