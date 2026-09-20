from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_loghound import loghound


class RotatedTimingTests(unittest.TestCase):
  def analyze(self, *sources):
    with tempfile.TemporaryDirectory() as temp:
      path = Path(temp) / 'app.log'
      for index, text in enumerate(sources):
        Path(str(path) + (f'.{index}' if index else '')).write_text(text, encoding='utf-8')
      return loghound.analyze_sources(str(path), loghound.AnalysisOptions(), len(sources) - 1)

  def lines(self, *times):
    return ''.join(f'2026-09-19T{time}Z INFO request completed\n' for time in times)

  def test_one_file(self):
    result = self.analyze(self.lines('10:00:00', '10:00:01'))
    self.assertEqual(result.duration_seconds, 1)
    self.assertEqual(result.peak_messages_per_minute, 2)

  def test_adjacent_rotations(self):
    result = self.analyze(self.lines('10:01:00', '10:01:01'), self.lines('10:00:00', '10:00:01'))
    self.assertEqual(result.duration_seconds, 61)
    self.assertEqual((result.earlier_period_messages, result.later_period_messages), (2, 2))

  def test_rotations_separated_by_hours(self):
    result = self.analyze(self.lines('18:00:00', '18:00:01'), self.lines('10:00:00', '10:00:01'))
    self.assertEqual(result.duration_seconds, 28801)
    self.assertEqual(result.timestamped_lines, 4)
    self.assertEqual((result.earlier_period_messages, result.later_period_messages), (2, 2))

  def test_overlapping_minutes_sum_counts(self):
    result = self.analyze(self.lines('10:00:40', '10:00:50'), self.lines('10:00:00', '10:00:01'))
    self.assertEqual(result.peak_messages_per_minute, 4)
    self.assertEqual(result.duration_seconds, 50)

  def test_out_of_order_physical_sources_keep_physical_evidence(self):
    result = self.analyze(self.lines('10:00:01', '10:00:00'), self.lines('18:00:01', '18:00:00'))
    self.assertEqual(result.duration_seconds, 28801)
    self.assertEqual(result.patterns[0].first_line, 1)
    self.assertEqual(result.patterns[0].last_line, 4)
    self.assertTrue(result.sources[1].endswith('.1'))
    self.assertEqual(dict(result.severity_counts)['info'], 4)

  def test_untimestamped_sources_have_no_timing(self):
    result = self.analyze('message\nmessage\n', 'message\n')
    self.assertIsNone(result.duration_seconds)
    self.assertIsNone(result.peak_messages_per_minute)
    self.assertIsNone(result.earlier_period_messages)
    self.assertEqual(result.analyzable_lines, 3)

  def test_mixed_timestamped_and_untimestamped(self):
    result = self.analyze('untimed\n', self.lines('10:00:00', '10:00:30'))
    self.assertEqual(result.duration_seconds, 30)
    self.assertEqual(result.timestamped_lines, 2)
    self.assertEqual(result.analyzable_lines, 3)
    self.assertEqual(result.peak_messages_per_minute, 2)

  def test_global_minute_histogram_overflow_is_explicitly_unavailable(self):
    with mock.patch.object(loghound, 'MAX_MINUTE_BUCKETS', 2):
      result = self.analyze(self.lines('10:00:00', '10:01:00'), self.lines('10:02:00', '10:03:00'))
    self.assertEqual(len(result.minute_counts), 2)
    self.assertFalse(result.minute_counts_complete)
    self.assertTrue(result.incomplete)
    self.assertIsNone(result.peak_messages_per_minute)
    self.assertIsNone(result.earlier_period_messages)
    self.assertIsNone(result.later_period_messages)
    self.assertEqual(result.duration_seconds, 180)

  def test_single_source_histogram_overflow_stays_bounded(self):
    with mock.patch.object(loghound, 'MAX_MINUTE_BUCKETS', 1):
      result = self.analyze(self.lines('10:00:00', '10:01:00'))
    self.assertEqual(len(result.minute_counts), 1)
    self.assertIsNone(result.peak_messages_per_minute)
    self.assertIn('histogram limit', result.incomplete_warning)

  def test_stack_and_severity_evidence_preserved(self):
    result = self.analyze('Traceback (most recent call last):\n  File "a.py", line 1\n', self.lines('10:00:00'))
    self.assertEqual(result.stack_trace_groups, 1)
    self.assertEqual(result.stack_trace_lines, 2)
    self.assertEqual(dict(result.severity_counts)['info'], 3)
