from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import socket
import ssl
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
    self.assertFalse(c.verify_hostname(c.parse_target("example.com"), certificate((("IP", "192.0.2.1"),))))

  def test_identity_follows_the_sni_name(self):
    cert = certificate((("DNS", "api.example.com"),))
    by_ip = c.replace(c.parse_target("192.0.2.10:443"), sni_name="api.example.com")
    by_host = c.replace(c.parse_target("node5.internal"), sni_name="api.example.com")
    misrouted = c.replace(c.parse_target("node5.internal"), sni_name="api.example.com")
    self.assertTrue(c.verify_hostname(by_ip, cert))
    self.assertTrue(c.verify_hostname(by_host, cert))
    self.assertFalse(c.verify_hostname(misrouted, certificate((("DNS", "node5.internal"),))))
    self.assertEqual(c.parse_target("example.com.").sni_name, "example.com")

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

  def test_wildcard_and_name_edge_cases(self):
    cases = (
      ("a.b.example.com", "*.example.com", False),
      ("example.com", "*.example.com", False),
      ("foo.example.com", "f*.example.com", False),
      ("f*.example.com", "f*.example.com", False),
      ("example.com", "*.com", False),
      ("api.example.com", "*.EXAMPLE.COM", True),
      ("API.Example.com.", "api.example.com.", True),
      ("api.example.com", "*.*.com", False),
    )
    for host, san, expected in cases:
      with self.subTest(host=host, san=san):
        # A literal "*" is not a valid target, so the odd name is built directly.
        target = c.Target(host, 443, host, f"{host}:443") if "*" in host else c.parse_target(host)
        self.assertIs(c.verify_hostname(target, certificate((("DNS", san),))), expected)

  def test_ip_targets_use_ip_sans_only(self):
    self.assertFalse(c.verify_hostname(c.parse_target("192.0.2.1"), certificate((("DNS", "192.0.2.1"),))))
    self.assertTrue(c.verify_hostname(c.parse_target("[2001:db8::10]:443"), certificate((("IP", "2001:db8::10"),))))
    self.assertFalse(c.verify_hostname(c.parse_target("192.0.2.1"), certificate((("IP", "192.0.2.2"),))))

  def test_shared_tls_contexts_use_version_independent_verification(self):
    verified, unverified = c.tls_contexts()
    self.assertEqual((verified.verify_mode, verified.check_hostname), (ssl.CERT_REQUIRED, False))
    self.assertEqual(verified.verify_flags & (ssl.VERIFY_X509_PARTIAL_CHAIN | ssl.VERIFY_X509_STRICT),
                     ssl.VERIFY_X509_PARTIAL_CHAIN | ssl.VERIFY_X509_STRICT)
    self.assertEqual((unverified.verify_mode, unverified.check_hostname), (ssl.CERT_NONE, False))

  def test_target_classification_ranks_the_most_severe_condition(self):
    def validity(status):
      return c.ValidityAssessment(status, None)
    normal, warning = validity(c.ValidityStatus.NORMAL), validity(c.ValidityStatus.WARNING)
    cases = (
      (normal, True, True, None, "VALID"),
      (normal, True, True, False, "VALID"),
      (normal, False, True, None, "WARNING"),
      (normal, True, None, None, "WARNING"),
      (normal, True, False, None, "WARNING"),
      (warning, True, True, None, "WARNING"),
      (normal, True, True, True, "DRIFT"),
      (validity(c.ValidityStatus.CRITICAL), False, False, True, "CRITICAL"),
      (validity(c.ValidityStatus.NOT_YET), False, True, True, "NOT_YET_VALID"),
      (validity(c.ValidityStatus.EXPIRED), False, False, True, "EXPIRED"),
    )
    for assessment, trusted, identity, drift, expected in cases:
      with self.subTest(expected=expected, trusted=trusted, identity=identity, drift=drift):
        self.assertEqual(c.classify_target(assessment, trusted, identity, drift), expected)

  def test_aggregate_status_policy(self):
    cases = (
      (["VALID", "VALID"], "VALID"),
      (["VALID", "EXPIRED", "WARNING"], "EXPIRED"),
      (["WARNING", "ERROR", "SKIPPED"], "WARNING"),
      (["DRIFT", "NOT_YET_VALID", "CRITICAL"], "NOT_YET_VALID"),
      (["ERROR", "VALID"], "INCOMPLETE"),
      (["VALID", "SKIPPED"], "INCOMPLETE"),
      (["ERROR", "ERROR"], "ERROR"),
      (["ERROR", "SKIPPED"], "ERROR"),
      (["SKIPPED"], "ERROR"),
    )
    for statuses, expected in cases:
      with self.subTest(statuses=statuses):
        self.assertEqual(c.aggregate_status(statuses), expected)


if __name__ == "__main__":
  unittest.main()
