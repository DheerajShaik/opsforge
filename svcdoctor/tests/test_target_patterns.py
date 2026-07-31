from pathlib import Path
import sys
import unittest
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import svcdoctor


class ConcreteTargetTests(unittest.TestCase):
  def test_systemd_glob_patterns_are_rejected(self):
    patterns = (
      "*",
      "*.service",
      "foo*",
      "foo?",
      "foo[12]",
      "foo[abc].service",
    )
    for target in patterns:
      with self.subTest(target=target), self.assertRaisesRegex(
        svcdoctor.SvcDoctorError, "concrete unit, not a pattern"
      ):
        svcdoctor.normalize_target(target)

  def test_pattern_rejection_happens_before_systemctl(self):
    with mock.patch.object(svcdoctor, "inspect_service") as inspect:
      code = svcdoctor.main(["*.service"])
    self.assertEqual(code, 2)
    inspect.assert_not_called()

  def test_concrete_targets_remain_supported(self):
    cases = {
      "cron": "cron.service",
      "cron.service": "cron.service",
      "getty@tty1": "getty@tty1.service",
      "getty@tty1.service": "getty@tty1.service",
      "my.worker": "my.worker.service",
    }
    for target, expected in cases.items():
      with self.subTest(target=target):
        self.assertEqual(svcdoctor.normalize_target(target), expected)


if __name__ == "__main__":
  unittest.main()
