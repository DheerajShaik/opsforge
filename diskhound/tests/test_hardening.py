import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_scanning import diskhound
from opsforge_common.output import OutputRecord


class GlobalBudgetTests(unittest.TestCase):
  def fixture(self, root, count=2000):
    for index in range(count):
      (root / f'{index:04d}').touch()

  def assert_budget(self, limit):
    with tempfile.TemporaryDirectory() as temp:
      self.fixture(Path(temp))
      with mock.patch.object(diskhound, '_scan_branch', wraps=diskhound._scan_branch) as scan_branch, \
           mock.patch.object(diskhound.os, 'stat', wraps=os.stat) as inspected:
        result = diskhound.scan(temp, diskhound.ScanOptions(max_entries=limit))
      self.assertEqual(result.visited_entries, limit)
      self.assertEqual(scan_branch.call_count, limit)
      self.assertLessEqual(inspected.call_count, limit)
      self.assertEqual(len(result.failures), 1)
      self.assertEqual(result.failures[0].category, 'entry-limit')
      self.assertEqual(diskhound.inspect_result_code(result), 1)
      self.assertLess(len(diskhound.render_result(result)), 16000)
      self.assertEqual(len(diskhound.render_warnings(result)), 1)
      record = OutputRecord('diskhound', 'PARTIAL', temp, diskhound.result_observations(result), 'partial', 'review', (), 0.0)
      self.assertLess(len(json.dumps(record.as_json_object())), 65536)

  def test_one_entry_global_limit(self):
    self.assert_budget(1)

  def test_ten_entry_global_limit(self):
    self.assert_budget(10)

  def test_nested_tree_global_enumeration_and_visits(self):
    with tempfile.TemporaryDirectory() as temp:
      root = Path(temp)
      for name in ('a', 'b', 'c'):
        (root / name).mkdir()
        self.fixture(root / name, 50)
      with mock.patch.object(diskhound.os, 'stat', wraps=os.stat) as inspected:
        result = diskhound.scan(temp, diskhound.ScanOptions(max_entries=10))
      self.assertLessEqual(inspected.call_count, 10)
      self.assertEqual(result.visited_entries, 10)
      self.assertEqual(len(result.failures), 1)
      self.assertEqual(len(result.largest_files), 7)

  def test_exact_file_budget_is_complete(self):
    with tempfile.TemporaryDirectory() as temp:
      self.fixture(Path(temp), 10)
      result = diskhound.scan(temp, diskhound.ScanOptions(max_entries=10))
      self.assertFalse(result.incomplete)
      self.assertEqual(result.visited_entries, 10)

  def test_exclusions_and_depth_still_bound_work(self):
    with tempfile.TemporaryDirectory() as temp:
      root = Path(temp)
      (root / 'nested').mkdir()
      (root / 'excluded').mkdir()
      self.fixture(root / 'nested', 20)
      result = diskhound.scan(temp, diskhound.ScanOptions(max_entries=10, max_depth=1, excludes=('excluded',)))
      self.assertEqual(result.excluded_entries, 1)
      self.assertEqual(result.depth_limited_directories, 1)
      self.assertFalse(result.incomplete)
