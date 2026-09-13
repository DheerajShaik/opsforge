from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import socket
import sys
import unittest


PATH = Path(__file__).parents[1] / "certwatch.py"
SPEC = importlib.util.spec_from_file_location("certwatch_verification", PATH)
c = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = c
SPEC.loader.exec_module(c)


def certificate(sans):
  now = datetime(2026, 1, 1, tzinfo=timezone.utc)
  return c.CertificateInfo("", "CN=issuer", "01", sans, now, now, "AA")


class VerificationTests(unittest.TestCase):
  def test_hostname_and_wildcard_identity(self):
    self.assertTrue(c.verify_hostname(c.parse_target("api.example.com"), certificate((("DNS", "*.example.com"),))))
    self.assertFalse(c.verify_hostname(c.parse_target("example.net"), certificate((("DNS", "*.example.com"),))))

  def test_ip_identity_and_missing_san(self):
    self.assertTrue(c.verify_hostname(c.parse_target("192.0.2.1"), certificate((("IP", "192.0.2.1"),))))
    self.assertIsNone(c.verify_hostname(c.parse_target("example.com"), certificate(())))

  def test_resolver_candidates_are_deduplicated_and_bounded(self):
    record = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 443))
    result = c.resolve_candidates(c.parse_target("example.com"), lambda *args: [record] * 100)
    self.assertEqual(len(result), 1)

  def test_explicit_critical_threshold(self):
    from datetime import timedelta
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    end = start + timedelta(days=10)
    result = c.assess_validity(
      start, end, 30, lambda: end - timedelta(days=2), critical_days=7,
    )
    self.assertIs(result.status, c.ValidityStatus.CRITICAL)


if __name__ == "__main__":
  unittest.main()
