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

  def test_trusted_handshake_leaf_is_correlated_to_observed_leaf(self):
    class Tcp:
      def settimeout(self, value): pass
      def connect(self, address): pass
      def close(self): pass
    class Tls:
      def __init__(self, der): self.der = der
      def getpeercert(self, binary_form=False): return self.der
      def close(self): pass
    class Context:
      def __init__(self, der): self.der = der
      def wrap_socket(self, tcp, server_hostname=None): return Tls(self.der)

    record = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 443))
    target = c.parse_target("example.com")
    observed_der = b"observed"
    cert = certificate((("DNS", "example.com"),))
    cert = c.replace(cert, sha256_fingerprint=c.fingerprint(observed_der))
    matched = c.verify_endpoint(
      target, cert, resolver=lambda *args: [record], socket_factory=lambda *args: Tcp(),
      context_factory=lambda: Context(observed_der),
    )
    self.assertTrue(matched.trust_verified)
    self.assertTrue(matched.leaf_matches_observation)
    changed = c.verify_endpoint(
      target, cert, resolver=lambda *args: [record], socket_factory=lambda *args: Tcp(),
      context_factory=lambda: Context(b"different"),
    )
    self.assertIsNone(changed.trust_verified)
    self.assertFalse(changed.leaf_matches_observation)
    self.assertIn("different leaf", changed.verification_error)

  def test_trust_is_verified_on_the_observed_candidate_only(self):
    class Tcp:
      connected = []
      def settimeout(self, value): pass
      def connect(self, address): Tcp.connected.append(address)
      def close(self): pass
    class Context:
      def wrap_socket(self, tcp, server_hostname=None): raise OSError("refused")
    observed = c.ConnectionCandidate(socket.AF_INET, socket.SOCK_STREAM, 6, ("192.0.2.7", 443))
    resolver_calls = []
    evidence = c.verify_endpoint(
      c.parse_target("example.com"), certificate((("DNS", "example.com"),)),
      resolver=lambda *args: resolver_calls.append(args) or [], socket_factory=lambda *args: Tcp(),
      context_factory=Context, candidate=observed,
    )
    self.assertEqual((Tcp.connected, resolver_calls), ([("192.0.2.7", 443)], []))
    self.assertIsNone(evidence.trust_verified)

  def test_status_ranking_and_aggregation(self):
    verified = c.VerificationEvidence(True, True, None, 2, True)
    expired = c.ValidityAssessment(c.ValidityStatus.EXPIRED, None, False, 1)
    critical = c.ValidityAssessment(c.ValidityStatus.CRITICAL, None, True, 1)
    self.assertEqual(c.classify_target(expired, verified, True), "EXPIRED")
    self.assertEqual(c.classify_target(critical, verified, None), "CRITICAL")
    self.assertEqual(c.aggregate_status(["VALID", "EXPIRED", "WARNING"]), "EXPIRED")
    self.assertEqual(c.aggregate_status(["ERROR", "ERROR"]), "ERROR")
    self.assertEqual(c.aggregate_status(["ERROR", "VALID"]), "PARTIAL")


if __name__ == "__main__":
  unittest.main()
