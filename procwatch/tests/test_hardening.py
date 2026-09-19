import contextlib
import io
import json
import unittest
from unittest import mock

from test_procwatch import procwatch, sample, extended


class AuxiliaryIdentityTests(unittest.TestCase):
  def observe(self, identities):
    aux = procwatch.AuxiliarySample(8, 2, 100, 200, 3, 4, (456,), ((123, 150),))
    with mock.patch.object(procwatch, 'open_process_directory', return_value=9), \
         mock.patch.object(procwatch.os, 'close'), \
         mock.patch.object(procwatch, 'capture_sample', side_effect=[sample(start_ticks=value) for value in identities]), \
         mock.patch.object(procwatch, 'capture_auxiliary', return_value=aux), \
         mock.patch.object(procwatch, 'collect_cgroup_context', return_value=('/example', 'max', 'max')), \
         mock.patch.object(procwatch, 'observe_samples', return_value=extended().analysis):
      return procwatch.observe_extended(123, 0.1, 2)

  def test_stable_identity_preserves_auxiliary_evidence(self):
    result = self.observe([9000] * 4)
    self.assertIsNotNone(result.auxiliary_initial)
    self.assertIsNotNone(result.auxiliary_final)
    self.assertEqual(result.warnings, ())
    self.assertIn('delta +0', procwatch.render_extended(result))

  def test_reused_before_main_discards_initial_and_cgroup(self):
    result = self.observe([8000, 8000, 9000, 9000])
    self.assertIsNone(result.auxiliary_initial)
    self.assertIsNone(result.cgroup)
    self.assertIsNone(result.cpu_constraint)
    self.assertIsNone(result.memory_constraint)
    self.assertIn('identity mismatch', ' '.join(result.warnings))
    self.assertNotIn('delta +0', procwatch.render_extended(result))

  def test_reused_after_main_discards_final(self):
    result = self.observe([9000, 9000, 10000])
    self.assertIsNone(result.auxiliary_final)
    self.assertIn('identity mismatch', ' '.join(result.warnings))
    self.assertIn('File descriptors: unavailable', procwatch.render_extended(result))

  def test_identity_changes_during_initial_auxiliary_collection(self):
    result = self.observe([8000, 9000, 9000, 9000])
    self.assertIsNone(result.auxiliary_initial)
    self.assertIsNone(result.cgroup)
    self.assertIn('identity mismatch', ' '.join(result.warnings))

  def test_identity_changes_during_final_auxiliary_collection(self):
    result = self.observe([9000, 9000, 9000, 10000])
    self.assertIsNone(result.auxiliary_final)
    self.assertIn('identity mismatch', ' '.join(result.warnings))

  def test_json_and_conclusion_never_compute_cross_identity_delta(self):
    result = self.observe([8000, 8000, 10000])
    stdout = io.StringIO()
    with mock.patch.object(procwatch, 'observe_extended', return_value=result), \
         contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
      self.assertEqual(procwatch.main(['123', '--json']), 0)
    document = json.loads(stdout.getvalue())
    self.assertIsNone(document['observations']['auxiliary_initial'])
    self.assertIsNone(document['observations']['auxiliary_final'])
    self.assertNotIn('file descriptors changed', document['conclusion'])
