import contextlib
import io
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import svcdoctor
from opsforge_common.process import ProcessResult
from opsforge_common.systemd import UNIT_SUFFIXES


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
CORE_PROPERTIES = ("Id", "LoadState", "ActiveState")
OPTIONAL_PROPERTIES = tuple(name for name in svcdoctor.PROPERTIES if name not in CORE_PROPERTIES)


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
    for suffix in UNIT_SUFFIXES:
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

  def test_only_newline_separates_properties(self):
    value = "/etc/a\x0bb\x0cc\x1cd\x1de\x1ef\x85g\u2028h\u2029i.conf"
    parsed = svcdoctor.parse_properties(
      f"Id=x.service\nLoadState=loaded\nActiveState=active\nDropInPaths={value}\n"
    )
    self.assertEqual(parsed["DropInPaths"], value)


class CompletenessTests(unittest.TestCase):
  def test_missing_or_empty_core_property(self):
    base = properties()
    for name in CORE_PROPERTIES:
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
    for name in OPTIONAL_PROPERTIES:
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
    report = svcdoctor.render_service_evidence(evidence())
    self.assertIn("Assessment\n  Status: ACTIVE\n  Service failure established: no\n", report)

  def test_activation_timestamp_is_labelled_as_the_last_entry_into_active(self):
    candidate = properties(FAILED)
    candidate["ActiveEnterTimestamp"] = "Sun 2026-09-27 10:00:00 UTC"
    output = svcdoctor.render_diagnostic("failing.service", candidate)
    self.assertIn("  Last entered active: Sun 2026-09-27 10:00:00 UTC\n", output)
    self.assertNotIn("Active since", output)

  def test_all_optional_values_render_as_dash(self):
    candidate = {"Id": "example.service", "LoadState": "loaded", "ActiveState": "active"}
    output = svcdoctor.render_diagnostic("example.service", candidate)
    self.assertGreaterEqual(output.count(": -"), 4)

  def test_empty_optional_values_render_as_dash(self):
    candidate = properties()
    for name in OPTIONAL_PROPERTIES:
      candidate[name] = ""
    self.assertGreaterEqual(svcdoctor.render_diagnostic("cron.service", candidate).count(": -"), 4)

  def test_only_exact_lowercase_failed_classifies_failed(self):
    for state, expected in (
      ("failed", True), ("Failed", False), ("active", False),
      ("inactive", False), ("activating", False), ("deactivating", False),
      ("reloading", False), ("future-state", False),
    ):
      candidate = properties()
      candidate["ActiveState"] = state
      with self.subTest(state=state):
        self.assertIs(svcdoctor.assess_service(candidate, ())[1], expected)

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
        self.assertFalse(svcdoctor.assess_service(candidate, ())[1])

  def test_active_exited_keeps_raw_code_separate(self):
    output = svcdoctor.render_diagnostic("console-setup.service", properties(ACTIVE_EXITED))
    self.assertIn("  Main code: 1\n  Main status: 0\n", output)
    self.assertEqual(svcdoctor.assess_service(properties(ACTIVE_EXITED), ())[:2], ("ACTIVE", False))

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


class AssessmentTests(unittest.TestCase):
  CASES = (
    ("failed", {"ActiveState": "failed", "SubState": "failed", "Result": "exit-code"}, (), "FAILED", 1),
    ("failed before load error", {"LoadState": "bad-setting", "ActiveState": "failed"}, (), "FAILED", 1),
    ("bad setting", {"LoadState": "bad-setting", "ActiveState": "inactive", "SubState": "dead"}, (), "LOAD-ERROR", 1),
    ("load error", {"LoadState": "error", "ActiveState": "inactive", "SubState": "dead"}, (), "LOAD-ERROR", 1),
    (
      "crash loop",
      {"ActiveState": "activating", "SubState": "auto-restart", "Result": "exit-code", "NRestarts": "37"},
      (), "RESTARTING", 1,
    ),
    ("inactive after failure", {"ActiveState": "inactive", "SubState": "dead", "Result": "exit-code"}, (), "DEGRADED", 1),
    ("stopping after timeout", {"ActiveState": "deactivating", "SubState": "stop-sigterm", "Result": "timeout"}, None, "DEGRADED", 1),
    ("dependency failed", {"ActiveState": "inactive", "SubState": "dead"}, ("home.mount",), "DEPENDENCY-FAILED", 1),
    ("active despite failed dependency", {}, ("home.mount",), "ACTIVE", 0),
    ("active after an earlier failure", {"Result": "exit-code"}, (), "ACTIVE", 0),
    ("inactive", {"ActiveState": "inactive", "SubState": "dead"}, (), "INACTIVE", 0),
    ("inactive, dependencies unavailable", {"ActiveState": "inactive", "SubState": "dead"}, None, "INACTIVE", 0),
    ("activating", {"ActiveState": "activating", "SubState": "start"}, (), "ACTIVATING", 0),
    ("reloading", {"ActiveState": "reloading", "SubState": "reload"}, (), "RELOADING", 0),
    ("deactivating", {"ActiveState": "deactivating", "SubState": "stop-sigterm"}, (), "DEACTIVATING", 0),
    ("maintenance", {"ActiveState": "maintenance", "SubState": "cleaning"}, (), "MAINTENANCE", 0),
    ("refreshing", {"ActiveState": "refreshing", "SubState": "refreshing"}, (), "REFRESHING", 0),
  )

  @staticmethod
  def run_main(arguments, collected):
    stdout = io.StringIO()
    with mock.patch.object(svcdoctor, "collect_service", return_value=collected), \
         contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
      code = svcdoctor.main(arguments)
    return code, stdout.getvalue()

  def test_status_mapping_and_exit_codes(self):
    for label, overrides, failed_dependencies, status, expected_code in self.CASES:
      values = properties()
      values.update(overrides)
      collected = svcdoctor.ServiceEvidence("cron.service", values, (), None, failed_dependencies)
      with self.subTest(label):
        code, stdout = self.run_main(["cron"], collected)
        self.assertEqual(code, expected_code)
        self.assertIn(f"Conclusion: [{status}] cron.service", stdout)
        self.assertIn(
          f"  Status: {status}\n  Service failure established: {'yes' if expected_code else 'no'}\n", stdout,
        )
        self.assertEqual("no service failure was established" in stdout, expected_code == 0)
        code, stdout = self.run_main(["cron", "--json"], collected)
        self.assertEqual((code, json.loads(stdout)["status"]), (expected_code, status))

  def test_findings_explain_the_matching_rule_and_restart_count(self):
    crash = properties()
    crash.update({"ActiveState": "activating", "SubState": "auto-restart", "Result": "exit-code", "NRestarts": "37"})
    finding = svcdoctor.assess_service(crash, ())[2]
    self.assertIn("crash-looping", finding)
    self.assertIn("NRestarts is 37", finding)
    self.assertIn("home.mount", svcdoctor.assess_service(properties(INACTIVE), ("home.mount",))[2])
    restarted = properties()
    restarted["NRestarts"] = "3"
    self.assertEqual(
      svcdoctor.assess_service(restarted, ()),
      ("ACTIVE", False, "ActiveState is active and SubState is running; NRestarts is 3"),
    )
    for count in ("0", "", "x", "\u0663"):
      restarted["NRestarts"] = count
      with self.subTest(count=count):
        self.assertNotIn("NRestarts", svcdoctor.assess_service(restarted, ())[2])


class CollectServiceTests(unittest.TestCase):
  @staticmethod
  def command(output, returncode=0, stderr=b""):
    return ProcessResult(returncode, output.encode(), stderr)

  def collect(self, output, target="cron.service", returncode=0):
    with mock.patch.object(svcdoctor, "run_systemctl", return_value=self.command(output, returncode)), \
         mock.patch.object(svcdoctor, "collect_journal", return_value=((), None)):
      return svcdoctor.collect_service(target, 20)

  def test_empirical_regression_fixtures(self):
    cases = (
      ("cron.service", RUNNING, 0),
      ("apparmor.service", INACTIVE, 0),
      ("console-setup.service", ACTIVE_EXITED, 0),
      ("failing.service", FAILED, 1),
      ("getty@tty1.service", INSTANCE, 0),
    )
    for target, fixture, expected_code in cases:
      with self.subTest(target=target):
        stdout = io.StringIO()
        with mock.patch.object(svcdoctor, "run_systemctl", return_value=self.command(fixture)), \
             mock.patch.object(svcdoctor, "collect_journal", return_value=((), None)), \
             contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
          code = svcdoctor.main([target])
        self.assertEqual(code, expected_code)
        self.assertIn(f"Requested: {target}", stdout.getvalue())

  def test_missing_precedes_result_active_and_substate(self):
    with self.assertRaisesRegex(svcdoctor.SvcDoctorError, "service not found: no-such.service"):
      self.collect(MISSING, "no-such.service")

  def test_missing_needs_no_active_or_supporting_values(self):
    with self.assertRaisesRegex(svcdoctor.SvcDoctorError, "service not found"):
      self.collect("Id=no-such.service\nLoadState=not-found\n", "no-such.service")

  def test_not_found_unit_with_runtime_state_is_inspected(self):
    for active, sub in (("active", "running"), ("failed", "failed"), ("deactivating", "stop-sigterm")):
      with self.subTest(active=active):
        collected = self.collect(
          f"Id=gone.service\nLoadState=not-found\nActiveState={active}\nSubState={sub}\n", "gone.service",
        )
        self.assertEqual(collected.properties["ActiveState"], active)

  def test_nonzero_command_discards_valid_partial_output(self):
    with self.assertRaisesRegex(svcdoctor.SvcDoctorError, "systemd query failed"):
      self.collect(RUNNING, returncode=1)

  def test_empty_and_malformed_responses(self):
    for output, message in (("", "empty response"), ("broken\n", "malformed response")):
      with self.subTest(output=output), self.assertRaisesRegex(svcdoctor.SvcDoctorError, message):
        self.collect(output)

  def test_journal_is_collected_for_the_resolved_unit(self):
    alias = RUNNING.replace("Id=cron.service", "Id=systemd-logind.service")
    with mock.patch.object(svcdoctor, "run_systemctl", return_value=self.command(alias)), \
         mock.patch.object(svcdoctor, "collect_journal", return_value=((), None)) as journal:
      svcdoctor.collect_service("dbus-org.freedesktop.login1.service", 7)
    journal.assert_called_once_with("systemd-logind.service", 7)


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

  def test_interrupt_and_internal_failure_are_sanitized(self):
    with mock.patch.object(svcdoctor, "collect_service", side_effect=KeyboardInterrupt):
      self.assertEqual(self.run_main(["x"]), (130, "", "svcdoctor: interrupted\n"))
    with mock.patch.object(svcdoctor, "collect_service", side_effect=RuntimeError("secret")):
      self.assertEqual(self.run_main(["x"]), (2, "", "svcdoctor: internal execution failure\n"))

  @mock.patch.object(svcdoctor, "collect_service", return_value=evidence())
  def test_json_brief_and_quiet(self, collect):
    code, stdout, stderr = self.run_main(["--json", "cron"])
    self.assertEqual((code, stderr), (0, ""))
    self.assertEqual(json.loads(stdout)["tool"], "svcdoctor")
    code, stdout, _ = self.run_main(["--brief", "cron"])
    self.assertIn("State: active/running", stdout)
    code, stdout, _ = self.run_main(["--quiet", "cron"])
    self.assertEqual((code, stdout), (0, ""))

  def test_parser_errors_escape_terminal_controls(self):
    code, stdout, stderr = self.run_main(["x", "--bogus\x1b]0;title\x07"])
    self.assertEqual((code, stdout), (2, ""))
    self.assertNotIn("\x1b", stderr)
    self.assertNotIn("\x07", stderr)
    self.assertIn("--bogus\\x1b]0;title\\x07", stderr)

  def test_output_argument_errors_return_instead_of_raising(self):
    for arguments in (["x", "--force"], ["x", "--output", ""]):
      with self.subTest(arguments=arguments), mock.patch.object(svcdoctor, "collect_service") as collect:
        code, stdout, stderr = self.run_main(arguments)
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("svcdoctor: error: --", stderr)
        collect.assert_not_called()


class SubprocessTests(unittest.TestCase):
  def make_systemctl(self, directory, body):
    path = Path(directory, "systemctl")
    path.write_text(f"#!{sys.executable}\n" + textwrap.dedent(body), encoding="utf-8")
    path.chmod(0o700)
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

  def test_child_environment_is_minimal_and_utc(self):
    with tempfile.TemporaryDirectory() as directory:
      self.make_systemctl(directory, """
        import os
        expected = {'LC_ALL': 'C', 'TZ': 'UTC', 'SYSTEMD_PAGER': '', 'SYSTEMD_COLORS': '0'}
        leaked = {'DBUS_SYSTEM_BUS_ADDRESS', 'SYSTEMD_LOG_LEVEL'} & set(os.environ)
        if leaked or any(os.environ.get(name) != value for name, value in expected.items()):
          raise SystemExit(9)
      """)
      ambient = {
        "PATH": directory, "DBUS_SYSTEM_BUS_ADDRESS": "unix:path=/tmp/fake-bus",
        "SYSTEMD_LOG_LEVEL": "debug", "SYSTEMD_COLORS": "1", "TZ": "America/New_York",
      }
      with mock.patch.dict(os.environ, ambient, clear=False):
        self.assertEqual(svcdoctor.run_systemctl("x.service").returncode, 0)

  def test_missing_executable(self):
    with mock.patch.dict(os.environ, {"PATH": ""}, clear=False), self.assertRaisesRegex(
      svcdoctor.SvcDoctorError, "systemctl is not available"
    ):
      svcdoctor.run_systemctl("x.service")

  def test_execution_failure(self):
    with tempfile.TemporaryDirectory() as directory:
      self.make_systemctl(directory, "raise SystemExit(0)\n")
      with mock.patch.dict(os.environ, {"PATH": directory}, clear=False), \
           mock.patch.object(subprocess, "Popen", side_effect=PermissionError), \
           self.assertRaisesRegex(svcdoctor.SvcDoctorError, "could not execute systemctl"):
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
        svcdoctor.ResponseTooLargeError, "systemd returned oversized output"
      ):
        svcdoctor.run_systemctl("x.service")

  def test_stderr_limit_is_enforced(self):
    with tempfile.TemporaryDirectory() as directory:
      self.make_systemctl(directory, f"import sys\nsys.stderr.write('x' * {svcdoctor.MAX_STREAM_BYTES + 1})\n")
      with mock.patch.dict(os.environ, {"PATH": directory}, clear=False), self.assertRaisesRegex(
        svcdoctor.ResponseTooLargeError, "systemd returned oversized output"
      ):
        svcdoctor.run_systemctl("x.service")

  def test_timeout_kills_and_reaps_child(self):
    with tempfile.TemporaryDirectory() as directory:
      self.make_systemctl(directory, "import time\ntime.sleep(30)\n")
      with mock.patch.dict(os.environ, {"PATH": directory}, clear=False), mock.patch.object(
        svcdoctor, "TIMEOUT_SECONDS", 0.05
      ):
        started = time.monotonic()
        with self.assertRaisesRegex(svcdoctor.SvcDoctorError, "^systemd query timed out after 0.05 seconds$"):
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

  def test_keyboard_interrupt_terminates_and_reaps_child(self):
    children = []
    real_popen = subprocess.Popen
    def capture(*args, **kwargs):
      child = real_popen(*args, **kwargs)
      children.append(child)
      return child
    with mock.patch.object(subprocess, "Popen", side_effect=capture), mock.patch.object(
      selectors.DefaultSelector, "select", side_effect=KeyboardInterrupt,
    ), self.assertRaises(KeyboardInterrupt):
      svcdoctor.run_simple_command((sys.executable, "-c", "import time; time.sleep(30)"), "helper")
    self.assertEqual(len(children), 1)
    self.assertIsNotNone(children[0].poll())


class FakeSystemdTests(unittest.TestCase):
  """Run SvcDoctor against fake systemctl and journalctl executables on PATH."""

  def setUp(self):
    temporary = tempfile.TemporaryDirectory()
    self.addCleanup(temporary.cleanup)
    self.directory = Path(temporary.name)
    environment = mock.patch.dict(os.environ, {"PATH": temporary.name})
    environment.start()
    self.addCleanup(environment.stop)
    self.install_journalctl()

  def install(self, name, body):
    path = self.directory / name
    path.write_text(f"#!{sys.executable}\n" + textwrap.dedent(body), encoding="utf-8")
    path.chmod(0o700)

  def install_systemctl(self, states=None, **values):
    shown = {
      "Id": "demo.service", "LoadState": "loaded", "ActiveState": "active", "SubState": "running",
      "Result": "success", "Requires": "", "Requisite": "", "BindsTo": "", "Wants": "",
    }
    shown.update(values)
    record = "".join(f"{name}={value}\n" for name, value in shown.items())
    self.install("systemctl", f"""
      import json, sys
      arguments = sys.argv[1:]
      if arguments[0] == "show":
        sys.stdout.write({record!r})
        raise SystemExit(0)
      names = arguments[arguments.index("--") + 1:]
      with open({str(self.directory / "is-failed.json")!r}, "w") as handle:
        json.dump(names, handle)
      states = [{dict(states or {})!r}.get(name, "active") for name in names]
      sys.stdout.write("".join(state + "\\n" for state in states))
      raise SystemExit(0 if "failed" in states else 1)
    """)

  def install_journalctl(self, output=b"", code=0):
    data = self.directory / "journal.bin"
    data.write_bytes(output)
    self.install("journalctl", f"""
      import json, shutil, sys
      with open({str(self.directory / "journalctl.json")!r}, "w") as handle:
        json.dump(sys.argv[1:], handle)
      with open({str(data)!r}, "rb") as handle:
        shutil.copyfileobj(handle, sys.stdout.buffer)
      raise SystemExit({code})
    """)

  def recorded(self, name):
    path = self.directory / f"{name}.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

  def run_main(self, arguments):
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
      code = svcdoctor.main(arguments)
    return code, stdout.getvalue(), stderr.getvalue()

  def test_journal_uses_the_resolved_unit_newest_first_and_quietly(self):
    self.install_systemctl(Id="systemd-logind.service")
    self.install_journalctl(b"2026-09-27T10:00:00+00:00 host systemd-logind[1]: New session 1.\n")
    code, stdout, stderr = self.run_main(["dbus-org.freedesktop.login1.service"])
    self.assertEqual((code, stderr), (0, ""))
    self.assertEqual(self.recorded("journalctl"), [
      "--system", "--no-pager", "--quiet", "--reverse", "--output=short-iso",
      "--lines", "20", "--unit", "systemd-logind.service",
    ])
    self.assertIn("  2026-09-27T10:00:00+00:00 host systemd-logind[1]: New session 1.\n", stdout)
    self.assertIn("  journalctl --system --unit systemd-logind.service --lines 50 --no-pager\n", stdout)

  def test_newest_lines_are_kept_in_chronological_order(self):
    self.install_journalctl(
      b"T6 host demo[1]: sixth\n"
      b"T5 host demo[1]: fifth, first line\n"
      b"                 fifth, continuation\n"
      b"\n"
      b"T4 host demo[1]: fourth\n"
      b"T3 host demo[1]: third\n"
    )
    self.assertEqual(svcdoctor.collect_journal("demo.service", 4), ((
      "T4 host demo[1]: fourth",
      "T5 host demo[1]: fifth, first line",
      "                 fifth, continuation",
      "T6 host demo[1]: sixth",
    ), None))

  def test_oversized_journal_output_keeps_the_newest_lines(self):
    self.install_journalctl(b"T3 newest\nT2 middle\n" + b"T1 older entry\n" * 40_000)
    self.assertEqual(svcdoctor.collect_journal("demo.service", 2), (("T2 middle", "T3 newest"), None))
    self.install_journalctl(b"T2 newest\n" + b"x" * svcdoctor.MAX_JOURNAL_BYTES)
    journal, warning = svcdoctor.collect_journal("demo.service", 5)
    self.assertEqual(journal, ("T2 newest",))
    self.assertIn("256 KiB", warning)

  def test_zero_journal_lines_skips_journalctl_without_warning(self):
    self.install_systemctl()
    code, stdout, stderr = self.run_main(["demo", "--journal-lines", "0", "--json"])
    self.assertEqual((code, stderr), (0, ""))
    self.assertIsNone(self.recorded("journalctl"))
    result = json.loads(stdout)
    self.assertEqual((result["observations"]["recent_journal"], result["warnings"]), ([], []))

  def test_json_keeps_raw_bounded_journal_lines_and_human_output_escapes_them(self):
    self.install_systemctl()
    exact = "e" * svcdoctor.MAX_JOURNAL_LINE_CHARACTERS
    self.install_journalctl(
      b"T4 bad \xff byte\n" + ("T3 " + "\x01" * 600 + "\n" + exact + "\n").encode() + b"T1 \x1b[31mred\n"
    )
    code, stdout, stderr = self.run_main(["demo", "--json"])
    self.assertEqual((code, stderr), (0, ""))
    self.assertEqual(json.loads(stdout)["observations"]["recent_journal"], [
      "T1 \x1b[31mred", exact, "T3 " + "\x01" * 509 + "... [truncated]", "T4 bad \udcff byte",
    ])
    code, stdout, _ = self.run_main(["demo"])
    self.assertIn("  T1 \\x1b[31mred\n", stdout)
    self.assertIn(f"  {exact}\n", stdout)
    self.assertIn("  T3 " + "\\x01" * 509 + "... [truncated]\n", stdout)
    self.assertIn("  T4 bad \\xff byte\n", stdout)
    self.assertNotIn("\x1b", stdout)

  def test_failed_journalctl_is_only_a_warning(self):
    self.install_systemctl()
    self.install_journalctl(b"T1 partial\n", code=1)
    code, stdout, stderr = self.run_main(["demo"])
    self.assertEqual((code, stderr), (0, "svcdoctor: warning: recent journal evidence unavailable\n"))
    self.assertIn("Recent journal evidence\n  unavailable or empty\n", stdout)

  def test_dependencies_of_every_unit_type_are_checked_and_a_failed_mount_is_reported(self):
    self.install_systemctl(
      states={"home.mount": "failed"}, ActiveState="inactive", SubState="dead",
      Requires="local-fs.target home.mount", Requisite="dbus.socket",
      BindsTo="dev-sda1.device", Wants="helper.service home.mount",
    )
    code, stdout, stderr = self.run_main(["demo"])
    self.assertEqual((code, stderr), (1, ""))
    checked = ["local-fs.target", "home.mount", "dbus.socket", "dev-sda1.device", "helper.service"]
    self.assertEqual(self.recorded("is-failed"), checked)
    self.assertIn("  Failed dependencies: home.mount\n", stdout)
    self.assertIn("Conclusion: [DEPENDENCY-FAILED] demo.service", stdout)
    code, stdout, _ = self.run_main(["demo", "--json"])
    observations = json.loads(stdout)["observations"]
    self.assertEqual(
      (observations["failed_dependencies"], observations["dependencies_checked"], observations["dependencies_truncated"]),
      (["home.mount"], checked, False),
    )

  def test_dependency_summary_distinguishes_healthy_from_absent_dependencies(self):
    self.install_systemctl(Requires="home.mount", Wants="dbus.socket")
    code, stdout, _ = self.run_main(["demo"])
    self.assertEqual(code, 0)
    self.assertIn("  Failed dependencies: none of 2 checked\n", stdout)
    self.install_systemctl()
    code, stdout, _ = self.run_main(["demo", "--brief"])
    self.assertIn("Failed dependencies: none checked (no dependencies)\n", stdout)

  def test_malformed_dependency_response_warns_with_one_prefix(self):
    self.install_systemctl(states={"home.mount": "bogus"}, Requires="home.mount")
    code, stdout, stderr = self.run_main(["demo"])
    self.assertEqual(code, 0)
    self.assertEqual(
      stderr, "svcdoctor: warning: dependency evidence unavailable: malformed or incomplete systemd response\n",
    )
    self.assertIn("  Failed dependencies: unavailable\n", stdout)

  def test_not_found_unit_that_is_still_running_is_inspected(self):
    self.install_systemctl(Id="gone.service", LoadState="not-found")
    code, stdout, stderr = self.run_main(["gone"])
    self.assertEqual((code, stderr), (0, ""))
    self.assertIn("  Load: not-found\n", stdout)
    self.assertIn("Conclusion: [ACTIVE] gone.service", stdout)
    self.install_systemctl(Id="gone.service", LoadState="not-found", ActiveState="failed", SubState="failed")
    self.assertEqual(self.run_main(["gone"])[0], 1)
    self.install_systemctl(Id="gone.service", LoadState="not-found", ActiveState="inactive", SubState="dead")
    self.assertEqual(self.run_main(["gone"]), (2, "", "svcdoctor: service not found: gone.service\n"))

  def test_next_command_quotes_the_resolved_unit_without_doubling_backslashes(self):
    unit = "systemd-fsck@dev-disk-by\\x2duuid-1234.service"
    self.install_systemctl(Id=unit)
    code, stdout, _ = self.run_main([unit])
    self.assertEqual(code, 0)
    self.assertIn(f"  journalctl --system --unit '{unit}' --lines 50 --no-pager\n", stdout)
    self.assertEqual(self.recorded("journalctl")[-1], unit)


if __name__ == "__main__":
  unittest.main()
