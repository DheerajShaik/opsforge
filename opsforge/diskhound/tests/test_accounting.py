from decimal import Decimal
import os
from pathlib import Path
import tempfile
import unittest

from opsforge.diskhound import diskhound


def metadata(*, blocks=1):
  return diskhound.EntryMetadata(1, 1, 0o100644, blocks, 512, 0.0)


def statvfs(frsize, blocks, bfree, bavail, files=0, ffree=0):
  return os.statvfs_result((frsize, frsize, blocks, bfree, bavail, files, ffree, ffree, 0, 255))


class AllocationTests(unittest.TestCase):
  def test_allocated_bytes_uses_512_byte_blocks(self):
    self.assertEqual(diskhound.allocated_bytes(metadata(blocks=7)), 3584)

  def test_wrapped_negative_allocation_is_rejected(self):
    with self.assertRaises(ValueError):
      diskhound.allocated_bytes(metadata(blocks=-1))

  def test_real_sparse_file_uses_blocks_not_apparent_size(self):
    with tempfile.TemporaryDirectory() as directory:
      path = Path(directory, "sparse")
      with path.open("wb") as handle:
        handle.truncate(16 * 1024 * 1024)
      observed = os.lstat(path)
      self.assertEqual(diskhound.allocated_bytes(observed), observed.st_blocks * 512)
      self.assertLess(diskhound.allocated_bytes(observed), observed.st_size)


class CapacityTests(unittest.TestCase):
  def test_frozen_capacity_formulas(self):
    result = diskhound.calculate_capacity(statvfs(4096, 100, 25, 20, files=1000, ffree=250))
    self.assertEqual(result.total_bytes, 409600)
    self.assertEqual(result.free_bytes, 102400)
    self.assertEqual(result.available_bytes, 81920)
    self.assertEqual(result.used_bytes, 307200)
    self.assertEqual(result.use_percent, Decimal(75) * 100 / Decimal(95))
    self.assertEqual((result.inode_total, result.inode_used, result.inode_free), (1000, 750, 250))
    self.assertEqual(result.inode_use_percent, Decimal(75))

  def test_filesystem_without_inode_limit_has_no_inode_percentage(self):
    result = diskhound.calculate_capacity(statvfs(4096, 100, 25, 20))
    self.assertEqual((result.inode_total, result.inode_used, result.inode_free), (0, 0, 0))
    self.assertIsNone(result.inode_use_percent)

  def test_wrapped_inode_counts_are_unavailable(self):
    result = diskhound.calculate_capacity(statvfs(4096, 100, 25, 20, files=-1, ffree=-1))
    self.assertEqual((result.inode_total, result.inode_used, result.inode_free), (None, None, None))
    self.assertIsNone(result.inode_use_percent)
    self.assertNotIn("Inodes total", diskhound.render_result(diskhound.ScanResult(
      "/target", 512, 512, result, None, (), 0, (),
    )))

  def test_non_positive_percentage_denominator_is_unavailable(self):
    result = diskhound.calculate_capacity(statvfs(1, 10, 20, 10))
    self.assertIsNone(result.use_percent)
    self.assertEqual(result.used_bytes, -10)

  def test_unusual_percentage_above_one_hundred_is_not_clamped(self):
    result = diskhound.calculate_capacity(statvfs(1, 100, 0, -20))
    self.assertEqual(result.use_percent, Decimal(125))
    self.assertEqual(diskhound.format_percent(result.use_percent), "125.0%")

  def test_structurally_unusable_capacity_is_rejected(self):
    for fragment in (0, -1):
      with self.subTest(fragment=fragment), self.assertRaises(ValueError):
        diskhound.calculate_capacity(statvfs(fragment, 1, 1, 1))


class IecFormattingTests(unittest.TestCase):
  def test_units_and_exact_bytes(self):
    cases = (
      (1023, "1023 B (1023 bytes)"),
      (1024, "1.0 KiB (1024 bytes)"),
      (1 << 20, "1.0 MiB (1048576 bytes)"),
      (1 << 30, "1.0 GiB (1073741824 bytes)"),
      (1 << 40, "1.0 TiB (1099511627776 bytes)"),
      (1 << 50, "1.0 PiB (1125899906842624 bytes)"),
      (1 << 60, "1024.0 PiB (1152921504606846976 bytes)"),
    )
    for value, expected in cases:
      with self.subTest(value=value):
        self.assertEqual(diskhound.format_bytes(value), expected)

  def test_half_even_rounding_is_deterministic(self):
    self.assertEqual(diskhound.format_bytes(1280), "1.2 KiB (1280 bytes)")
    self.assertEqual(diskhound.format_bytes(1281), "1.3 KiB (1281 bytes)")

  def test_equal_display_values_do_not_hide_exact_bytes(self):
    self.assertNotEqual(diskhound.format_bytes(1024), diskhound.format_bytes(1025))
    self.assertIn("1025 bytes", diskhound.format_bytes(1025))


if __name__ == "__main__":
  unittest.main()
