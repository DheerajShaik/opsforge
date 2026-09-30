import contextlib
import io
import json
import unittest
from unittest import mock

from test_svcdoctor import svcdoctor
from opsforge.common.process import ProcessResult


SYSTEMCTL = '/usr/bin/systemctl'


class DependencyEvidenceTests(unittest.TestCase):
  def states(self, names, output, code):
    with mock.patch.object(svcdoctor, 'resolve_executable', return_value=SYSTEMCTL), \
         mock.patch.object(svcdoctor, 'run_simple_command', return_value=ProcessResult(code, output, b'')):
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

  def test_every_unit_type_is_queried_after_an_option_terminator(self):
    names = ('home.mount', 'dbus.socket', 'dev-sda1.device', 'local-fs.target')
    output = ProcessResult(0, b'active\nfailed\ninactive\nactive\n', b'')
    with mock.patch.object(svcdoctor, 'resolve_executable', return_value=SYSTEMCTL), \
         mock.patch.object(svcdoctor, 'run_simple_command', return_value=output) as command:
      self.assertEqual(svcdoctor.find_failed_dependencies(names), ('dbus.socket',))
    self.assertEqual(command.call_args.args[0], (SYSTEMCTL, 'is-failed', '--system', '--no-pager', '--', *names))

  def test_dependency_names_cover_every_unit_type_in_order_without_duplicates(self):
    names, truncated = svcdoctor.dependency_names({
      'Requires': 'local-fs.target home.mount', 'Requisite': 'dbus.socket',
      'BindsTo': 'dev-sda1.device home.mount', 'Wants': 'helper.service dbus.socket',
    })
    self.assertEqual(names, ('local-fs.target', 'home.mount', 'dbus.socket', 'dev-sda1.device', 'helper.service'))
    self.assertFalse(truncated)

  def test_dependency_names_are_capped_and_flag_truncation(self):
    limit = svcdoctor.MAX_DEPENDENCIES
    names, truncated = svcdoctor.dependency_names({'Wants': ' '.join(f'u{index}.mount' for index in range(limit + 5))})
    self.assertEqual((len(names), truncated), (limit, True))
    exact = ' '.join(f'u{index}.mount' for index in range(limit))
    self.assertEqual(svcdoctor.dependency_names({'Requires': exact, 'Wants': 'u0.mount'})[1], False)

  def test_dependency_descriptions(self):
    many = tuple(f'u{index}.mount' for index in range(svcdoctor.MAX_DEPENDENCIES))
    cases = (
      (None, ('a.mount',), False, 'unavailable'),
      ((), (), False, 'none checked (no dependencies)'),
      ((), ('a.mount', 'b.socket'), False, 'none of 2 checked'),
      (('b.socket',), ('a.mount', 'b.socket'), False, 'b.socket'),
      ((), many, True, f'none of {len(many)} checked (only the first {len(many)} dependencies were checked)'),
    )
    for failed, checked, truncated, expected in cases:
      evidence = svcdoctor.ServiceEvidence(
        't.service', {'Id': 't.service'}, (), None, failed,
        dependencies_checked=checked, dependencies_truncated=truncated,
      )
      with self.subTest(expected=expected):
        self.assertEqual(svcdoctor.describe_failed_dependencies(evidence), expected)

  def collect(self, error=None, output=b'active\n'):
    properties = b'Id=test.service\nLoadState=loaded\nActiveState=active\nRequires=a.service\nRequisite=\nBindsTo=\nWants=\n'
    with mock.patch.object(svcdoctor, 'run_systemctl', return_value=ProcessResult(0, properties, b'')), \
         mock.patch.object(svcdoctor, 'resolve_executable', return_value=SYSTEMCTL), \
         mock.patch.object(svcdoctor, 'run_simple_command', side_effect=error, return_value=ProcessResult(1, output, b'')), \
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

  def test_dependency_warning_is_prefixed_once(self):
    evidence = self.collect(output=b'garbage\n')
    self.assertEqual(
      evidence.dependency_warning, 'dependency evidence unavailable: malformed or incomplete systemd response',
    )

  def test_interruption_propagates(self):
    with self.assertRaises(KeyboardInterrupt):
      self.collect(KeyboardInterrupt())

  def test_missing_dependency_properties_are_unavailable(self):
    for properties in (
      b'Id=test.service\nLoadState=loaded\nActiveState=active\n',
      b'Id=test.service\nLoadState=loaded\nActiveState=active\nRequires=\nWants=\n',
    ):
      with self.subTest(properties=properties), \
           mock.patch.object(svcdoctor, 'run_systemctl', return_value=ProcessResult(0, properties, b'')), \
           mock.patch.object(svcdoctor, 'collect_journal', return_value=((), None)):
        evidence = svcdoctor.collect_service('test.service', 0)
        self.assertIsNone(evidence.failed_dependencies)
        self.assertEqual(
          evidence.dependency_warning, 'dependency evidence unavailable: systemd response omitted dependency properties',
        )

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
      self.assertEqual(result['observations']['dependencies_checked'], ['a.service'])
      self.assertFalse(result['observations']['dependencies_truncated'])
      self.assertEqual(any('dependency evidence' in warning for warning in result['warnings']), error is not None)
