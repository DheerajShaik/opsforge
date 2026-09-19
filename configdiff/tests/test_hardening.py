import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_configdiff import configdiff


class DirectoryAnchoringTests(unittest.TestCase):
  def collect(self, root, **options):
    return configdiff.collect_directory(str(root), max_files=options.get('max_files', 20),
      max_depth=options.get('max_depth', 4), symlinks=options.get('symlinks', False))[1]

  def test_symlink_root_refused(self):
    with tempfile.TemporaryDirectory() as temp:
      root = Path(temp)
      (root / 'link').symlink_to(root, target_is_directory=True)
      with self.assertRaises(configdiff.InvalidTargetError):
        self.collect(root / 'link')

  def test_nested_directories_and_symlink_not_descended(self):
    with tempfile.TemporaryDirectory() as temp:
      root = Path(temp)
      (root / 'nested').mkdir()
      (root / 'nested' / 'file').write_bytes(b'config')
      (root / 'link').symlink_to(root / 'nested', target_is_directory=True)
      entries = self.collect(root)
      self.assertEqual([item.relative_path for item in entries], ['link', 'nested', 'nested/file'])
      self.assertIsNone(entries[0].symlink_target)
      self.assertEqual(self.collect(root, symlinks=True)[0].symlink_target, str(root / 'nested'))

  def swap_child(self, symlink=False, regular=False):
    with tempfile.TemporaryDirectory() as temp:
      parent = Path(temp)
      root = parent / 'root'
      root.mkdir()
      outside = parent / 'outside'
      outside.mkdir()
      (outside / 'secret').write_bytes(b'outside')
      child = root / 'child'
      if regular:
        child.write_bytes(b'inside')
      else:
        child.mkdir()
      original = os.open
      def open_swapped(path, flags, *args, **kwargs):
        if path == 'child':
          child.rename(parent / 'original')
          if symlink:
            child.symlink_to(outside, target_is_directory=True)
          elif regular:
            child.write_bytes(b'replaced')
          else:
            child.mkdir()
          self.assertEqual(os.lstat(child).st_dev, os.lstat(root).st_dev)
        return original(path, flags, *args, **kwargs)
      with mock.patch.object(configdiff.os, 'open', side_effect=open_swapped), \
           mock.patch.object(configdiff, 'read_exact_snapshot', wraps=configdiff.read_exact_snapshot) as read:
        with self.assertRaises(configdiff.ObservationError):
          self.collect(root)
        read.assert_not_called()

  def test_same_filesystem_child_identity_replacement_refused(self):
    self.swap_child()

  def test_child_symlink_swap_never_reads_outside(self):
    self.swap_child(symlink=True)

  def test_regular_file_identity_replacement_refused(self):
    self.swap_child(regular=True)

  def test_max_files_and_depth(self):
    with tempfile.TemporaryDirectory() as temp:
      root = Path(temp)
      (root / 'nested').mkdir()
      (root / 'nested' / 'file').write_bytes(b'x')
      self.assertEqual(len(self.collect(root, max_depth=0, max_files=1)), 1)
      self.assertEqual(len(self.collect(root, max_depth=1, max_files=2)), 2)
      with self.assertRaisesRegex(configdiff.ObservationError, 'entry limit'):
        self.collect(root, max_files=1)

  def test_descriptors_closed_on_interruption(self):
    with tempfile.TemporaryDirectory() as temp:
      (Path(temp) / 'nested').mkdir()
      before = len(os.listdir('/proc/self/fd'))
      with mock.patch.object(configdiff.os, 'scandir', side_effect=KeyboardInterrupt):
        with self.assertRaises(KeyboardInterrupt):
          self.collect(temp)
      self.assertEqual(len(os.listdir('/proc/self/fd')), before)
