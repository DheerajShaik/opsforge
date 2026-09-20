import contextlib
import io
import json
import unittest
from unittest import mock

from test_svcdoctor import svcdoctor


class DependencyEvidenceTests(unittest.TestCase):
  def test_exited_helper_still_terminates_descendants_and_reaps(self):
    process = mock.Mock(pid=12345)
    process.poll.return_value = 0
    with mock.patch.object(svcdoctor.os, 'killpg') as killpg:
      svcdoctor._stop_process(process)
    killpg.assert_called_once_with(12345, svcdoctor.signal.SIGKILL)
    process.wait.assert_called_once_with(timeout=1.0)

  def states(self, names, output, code):
    with mock.patch.object(svcdoctor, 'run_simple_command', return_value=svcdoctor.CommandResult(code, output, b'')):
      return svcdoctor.find_failed_dependencies(names)

  def test_no_dependencies_is_observed_empty(self):
    with mock.patch.object(svcdoctor, 'run_simple_command') as command:
      self.assertEqual(svcdoctor.find_failed_dependencies(()), ())
    command.assert_not_called()

  def test_healthy_dependencies(self):
    self.assertEqual(self.states(('a.service', 'b.service'), b'active\ninactive\n', 1), ())

  def test_one_failed_dependency(self):
    self.assertEqual(self.states(('a.service', 'b.service'), b'active\nfailed\n', 0), ('b.service',))

  def test_several_failed_dependencies(self):
    self.assertEqual(self.states(('a.service', 'b.service'), b'failed\nfailed\n', 0), ('a.service', 'b.service'))

  def test_malformed_and_non_ascii_are_unavailable(self):
    for output in (b'garbage\n', b'\xff\n', b'', b'failed\nactive\n', b'unknown\n'):
      with self.subTest(output=output), self.assertRaises(svcdoctor.SvcDoctorError):
        self.states(('a.service',), output, 0)

  def test_inconsistent_exit_status_is_unavailable(self):
    for code, output in ((2, b'active\n'), (0, b'active\n'), (1, b'failed\n')):
      with self.subTest(code=code), self.assertRaises(svcdoctor.SvcDoctorError):
        self.states(('a.service',), output, code)

  def collect(self, error=None):
    properties = b'Id=test.service\nLoadState=loaded\nActiveState=active\nRequires=a.service\nWants=\n'
    with mock.patch.object(svcdoctor, 'run_systemctl', return_value=svcdoctor.CommandResult(0, properties, b'')), \
         mock.patch.object(svcdoctor, 'run_simple_command', side_effect=error, return_value=svcdoctor.CommandResult(1, b'active\n', b'')), \
         mock.patch.object(svcdoctor, 'collect_journal', return_value=((), None)):
      return svcdoctor.collect_service('test.service', 0)

  def test_command_failures_keep_main_state_and_mark_dependencies_unavailable(self):
    for reason in ('command timed out', 'systemctl was not found', 'command execution failed'):
      with self.subTest(reason=reason):
        evidence = self.collect(svcdoctor.SvcDoctorError(reason))
        self.assertEqual(evidence.properties['ActiveState'], 'active')
        self.assertIsNone(evidence.failed_dependencies)
        self.assertIn(reason, evidence.dependency_warning)
        self.assertIn('Failed dependencies: unavailable', svcdoctor.render_service_evidence(evidence))

  def test_interruption_propagates(self):
    with self.assertRaises(KeyboardInterrupt):
      self.collect(KeyboardInterrupt())

  def test_missing_dependency_properties_are_unavailable(self):
    properties = b'Id=test.service\nLoadState=loaded\nActiveState=active\n'
    with mock.patch.object(svcdoctor, 'run_systemctl', return_value=svcdoctor.CommandResult(0, properties, b'')), \
         mock.patch.object(svcdoctor, 'collect_journal', return_value=((), None)):
      evidence = svcdoctor.collect_service('test.service', 0)
    self.assertIsNone(evidence.failed_dependencies)
    self.assertIn('omitted dependency properties', evidence.dependency_warning)

  def test_json_null_is_distinct_from_observed_empty(self):
    for error in (None, svcdoctor.SvcDoctorError('timeout')):
      evidence = self.collect(error)
      stdout = io.StringIO()
      with mock.patch.object(svcdoctor, 'collect_service', return_value=evidence), \
           contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
        self.assertEqual(svcdoctor.main(['test', '--json']), 0)
      result = json.loads(stdout.getvalue())
      self.assertEqual(result['observations']['failed_dependencies'], [] if error is None else None)
      self.assertEqual(result['observations']['dependencies_observed'], error is None)
      self.assertEqual(bool(result['warnings']), error is not None)
