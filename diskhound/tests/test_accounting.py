from decimal import Decimal
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import diskhound


def metadata(*, device=1, inode=1, blocks=1, mode=0o100644):
  return SimpleNamespace(st_dev=device, st_ino=inode, st_blocks=blocks, st_mode=mode)


class AllocationTests(unittest.TestCase):
  def test_allocated_bytes_uses_512_byte_blocks(self):
    self.assertEqual(diskhound.allocated_bytes(metadata(blocks=7)), 3584)

  def test_unusable_allocation_is_rejected(self):
    for blocks in (-1, None, True, "2"):
      with self.subTest(blocks=blocks), self.assertRaises(ValueError):
        diskhound.allocated_bytes(metadata(blocks=blocks))

  def test_real_sparse_file_uses_blocks_not_apparent_size(self):
    import tempfile
    with tempfile.TemporaryDirectory() as directory:
      path = Path(directory, "sparse")
      with path.open("wb") as handle:
        handle.truncate(16 * 1024 * 1024)
      observed = os.lstat(path)
      self.assertEqual(diskhound.allocated_bytes(observed), observed.st_blocks * 512)
      self.assertLess(diskhound.allocated_bytes(observed), observed.st_size)


class CapacityTests(unittest.TestCase):
  def test_frozen_capacity_formulas(self):
    values = SimpleNamespace(f_frsize=4096, f_blocks=100, f_bfree=25, f_bavail=20)
    result = diskhound.calculate_capacity(values)
    self.assertEqual(result.total_bytes, 409600)
    self.assertEqual(result.free_bytes, 102400)
    self.assertEqual(result.available_bytes, 81920)
    self.assertEqual(result.used_bytes, 307200)
    self.assertEqual(result.use_percent, Decimal(75) * 100 / Decimal(95))

  def test_non_positive_percentage_denominator_is_unavailable(self):
    values = SimpleNamespace(f_frsize=1, f_blocks=10, f_bfree=20, f_bavail=10)
    result = diskhound.calculate_capacity(values)
    self.assertIsNone(result.use_percent)
    self.assertEqual(result.used_bytes, -10)

  def test_unusual_percentage_above_one_hundred_is_not_clamped(self):
    values = SimpleNamespace(f_frsize=1, f_blocks=100, f_bfree=0, f_bavail=-20)
    result = diskhound.calculate_capacity(values)
    self.assertEqual(result.use_percent, Decimal(125))
    self.assertEqual(diskhound.format_percent(result.use_percent), "125.0%")

  def test_structurally_unusable_capacity_is_rejected(self):
    for fragment in (0, -1, None, True):
      values = SimpleNamespace(f_frsize=fragment, f_blocks=1, f_bfree=1, f_bavail=1)
      with self.subTest(fragment=fragment), self.assertRaises(ValueError):
        diskhound.calculate_capacity(values)


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
