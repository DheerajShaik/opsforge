import os
from pathlib import Path
import socket
import stat
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import diskhound


def metadata(*, device=1, inode=1, blocks=1, mode=stat.S_IFREG | 0o644):
  return SimpleNamespace(st_dev=device, st_ino=inode, st_blocks=blocks, st_mode=mode)


def capacity():
  return SimpleNamespace(f_frsize=1, f_blocks=100, f_bfree=40, f_bavail=30)


class RealFilesystemScanningTests(unittest.TestCase):
  def test_empty_directory_is_complete(self):
    with tempfile.TemporaryDirectory() as directory:
      result = diskhound.scan(directory)
    self.assertEqual(result.branches, ())
    self.assertFalse(result.incomplete)
    self.assertGreaterEqual(result.unique_allocated_bytes, 0)

  def test_nested_files_hard_links_and_symlinks(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      (root / "a").mkdir()
      (root / "b").mkdir()
      data = root / "a" / "data"
      data.write_bytes(b"x" * 8192)
      os.link(data, root / "a" / "again")
      os.link(data, root / "b" / "shared")
      os.symlink(data, root / "file-link")
      os.symlink(root / "a", root / "directory-link")
      os.symlink(root / "missing", root / "broken-link")
      result = diskhound.scan(directory)
      branches = {Path(item.path).name: item.allocated_bytes for item in result.branches}
      file_allocation = os.lstat(data).st_blocks * 512
      a_directory = os.lstat(root / "a").st_blocks * 512
      b_directory = os.lstat(root / "b").st_blocks * 512
      self.assertEqual(branches["a"], a_directory + file_allocation)
      self.assertEqual(branches["b"], b_directory + file_allocation)
      self.assertIn("file-link", branches)
      self.assertIn("directory-link", branches)
      self.assertIn("broken-link", branches)
      unique_inode_total = sum(
        os.lstat(path).st_blocks * 512
        for path in (root, root / "a", root / "b", data, root / "file-link", root / "directory-link", root / "broken-link")
      )
      self.assertEqual(result.unique_allocated_bytes, unique_inode_total)
      self.assertGreater(
        sum(branches.values()), result.unique_allocated_bytes - os.lstat(root).st_blocks * 512,
      )

  def test_fifo_and_unix_socket_are_metadata_only_entries(self):
    with tempfile.TemporaryDirectory() as directory:
      fifo = Path(directory, "fifo")
      os.mkfifo(fifo)
      socket_path = Path(directory, "socket")
      endpoint = socket.socket(socket.AF_UNIX)
      try:
        endpoint.bind(str(socket_path))
        result = diskhound.scan(directory)
      finally:
        endpoint.close()
    names = {Path(item.path).name for item in result.branches}
    self.assertEqual(names, {"fifo", "socket"})

  def test_tree_deeper_than_python_recursion_limit(self):
    directory = tempfile.mkdtemp()
    created = []
    try:
      current = Path(directory)
      # Component length keeps the total path under Linux PATH_MAX while
      # exceeding Python's usual recursion limit.
      for _ in range(1050):
        current /= "d"
        current.mkdir()
        created.append(current)
      result = diskhound.scan(directory)
      self.assertEqual(len(result.branches), 1)
      self.assertFalse(result.incomplete)
    finally:
      for path in reversed(created):
        path.rmdir()
      Path(directory).rmdir()


class MockedTraversalSemanticsTests(unittest.TestCase):
  def run_scan(self, directory_map):
    target = metadata(inode=1, blocks=1, mode=stat.S_IFDIR | 0o755)

    def listing(path, expected=None):
      value = directory_map[path]
      if isinstance(value, BaseException):
        raise value
      return value

    with mock.patch.object(diskhound, "validate_target", return_value=("/target", target)), \
         mock.patch.object(diskhound, "list_directory", side_effect=listing), \
         mock.patch.object(diskhound, "_open_directory", return_value=9), \
         mock.patch.object(diskhound.os, "fstat", return_value=target), \
         mock.patch.object(diskhound.os, "fstatvfs", return_value=capacity()), \
         mock.patch.object(diskhound.os, "close"):
      return diskhound.scan("ignored")

  def test_cross_device_immediate_is_excluded_from_every_total(self):
    same = diskhound.ObservedEntry("/target/same", metadata(inode=2, blocks=2))
    foreign = diskhound.ObservedEntry("/target/foreign", metadata(device=2, inode=3, blocks=99))
    result = self.run_scan({"/target": ([foreign, same], [])})
    self.assertEqual(result.cross_device_immediate, 1)
    self.assertEqual([Path(item.path).name for item in result.branches], ["same"])
    self.assertEqual(result.unique_allocated_bytes, 3 * 512)

  def test_nested_cross_device_entry_is_excluded(self):
    branch = diskhound.ObservedEntry(
      "/target/a", metadata(inode=2, blocks=2, mode=stat.S_IFDIR | 0o755),
    )
    foreign = diskhound.ObservedEntry("/target/a/mount", metadata(device=2, inode=3, blocks=99))
    result = self.run_scan({"/target": ([branch], []), "/target/a": ([foreign], [])})
    self.assertEqual(result.branches[0].allocated_bytes, 2 * 512)
    self.assertEqual(result.unique_allocated_bytes, 3 * 512)

  def test_cross_sibling_hard_link_is_per_branch_but_globally_unique(self):
    first = diskhound.ObservedEntry("/target/a", metadata(inode=2, blocks=4))
    second = diskhound.ObservedEntry("/target/b", metadata(inode=2, blocks=4))
    forward = self.run_scan({"/target": ([first, second], [])})
    reverse = self.run_scan({"/target": ([second, first], [])})
    self.assertEqual([item.allocated_bytes for item in forward.branches], [2048, 2048])
    self.assertEqual(forward.unique_allocated_bytes, 512 + 2048)
    self.assertGreater(sum(item.allocated_bytes for item in forward.branches), 2048)
    self.assertEqual(forward.branches, reverse.branches)
    self.assertEqual(forward.unique_allocated_bytes, reverse.unique_allocated_bytes)

  def test_metadata_failure_is_incomplete_not_cross_device(self):
    failure = diskhound.ObservationFailure("/target/unknown", "metadata", "gone")
    result = self.run_scan({"/target": ([], [failure])})
    self.assertEqual(result.cross_device_immediate, 0)
    self.assertEqual(len(result.failures), 1)
    self.assertTrue(result.incomplete)

  def test_unusable_directory_allocation_does_not_prevent_descent(self):
    branch = diskhound.ObservedEntry(
      "/target/a", metadata(inode=2, blocks=-1, mode=stat.S_IFDIR | 0o755),
    )
    child = diskhound.ObservedEntry("/target/a/file", metadata(inode=3, blocks=4))
    result = self.run_scan({"/target": ([branch], []), "/target/a": ([child], [])})
    self.assertEqual(result.branches[0].allocated_bytes, 4 * 512)
    self.assertEqual(len(result.failures), 1)

  def test_enumeration_failure_preserves_directory_allocation(self):
    branch = diskhound.ObservedEntry(
      "/target/a", metadata(inode=2, blocks=2, mode=stat.S_IFDIR | 0o755),
    )
    result = self.run_scan({"/target": ([branch], []), "/target/a": PermissionError("denied")})
    self.assertEqual(result.branches[0].allocated_bytes, 2 * 512)
    self.assertEqual(result.failures[0].category, "enumeration")

  def test_capacity_failure_preserves_useful_tree(self):
    target = metadata(inode=1, blocks=1, mode=stat.S_IFDIR | 0o755)
    with mock.patch.object(diskhound, "validate_target", return_value=("/target", target)), \
         mock.patch.object(diskhound, "list_directory", return_value=([], [])), \
         mock.patch.object(diskhound, "_open_directory", side_effect=OSError("capacity failed")):
      result = diskhound.scan("ignored")
    self.assertIsNone(result.capacity)
    self.assertTrue(result.incomplete)
    self.assertEqual(diskhound.inspect_result_code(result), 1)


if __name__ == "__main__":
  unittest.main()
