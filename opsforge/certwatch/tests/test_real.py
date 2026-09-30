import contextlib
import json
import io
import socket
import ssl
import tempfile
import threading
import time
import unittest
from unittest import mock

from test_observation import c
from opsforge.common.tests import tls_fixtures
from opsforge.common.tests.loopback import LoopbackServer, server_tls_context, unused_port


REAL_CREATE_DEFAULT_CONTEXT = ssl.create_default_context


@contextlib.contextmanager
def trusting_the_fixture_ca():
  """Make CertWatch's own tls_contexts() trust only the throwaway CA."""
  with mock.patch.object(
    c.ssl, "create_default_context", side_effect=lambda *args, **kwargs: REAL_CREATE_DEFAULT_CONTEXT(cadata=tls_fixtures.CA_CERTIFICATE),
  ):
    yield


class RealTlsTests(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    try:
      cls.decoder = c.find_decoder()
    except c.CertWatchError:
      raise unittest.SkipTest("openssl is not available")
    cls.directory = tempfile.TemporaryDirectory()
    cls.addClassCleanup(cls.directory.cleanup)

  def serve(self, name, **options):
    return LoopbackServer(context=server_tls_context(self.directory.name, name), **options)

  def observe(self, server):
    target = c.parse_target(f"127.0.0.1:{server.port}")
    with trusting_the_fixture_ca():
      return target, c.observe_endpoint(target)

  def classify(self, target, observation):
    certificate = c.decode_certificate(self.decoder, observation.der_certificate)
    assessment = c.assess_validity(certificate.not_before, certificate.not_after, 30, critical_days=7)
    identity = c.verify_hostname(target, certificate)
    return c.classify_target(assessment, observation.trust_verified, identity, None), certificate, identity

  def test_a_valid_certificate_needs_one_connection_and_one_handshake(self):
    with self.serve("VALID") as server:
      target, observation = self.observe(server)
      accepts = server.accepts
    status, certificate, identity = self.classify(target, observation)
    self.assertEqual((status, accepts), ("VALID", 1))
    self.assertEqual((observation.trust_verified, observation.verification_error, identity), (True, None, True))
    self.assertEqual(observation.connected_address, "127.0.0.1")
    self.assertTrue(observation.tls_version.startswith("TLSv1."))
    self.assertTrue(observation.cipher)
    self.assertIn(observation.chain_certificates, (None, 1, 2))
    self.assertEqual(certificate.sans, (("DNS", "localhost"), ("IP", "127.0.0.1")))
    self.assertEqual((certificate.not_before.year, certificate.not_after.year), (2020, 2099))

  def test_an_expired_certificate_reconnects_once_unverified_and_is_found_expired(self):
    with self.serve("EXPIRED") as server:
      target, observation = self.observe(server)
      accepts = server.accepts
    status, _, _ = self.classify(target, observation)
    self.assertEqual((status, accepts), ("EXPIRED", 2))
    self.assertFalse(observation.trust_verified)
    self.assertIn("certificate has expired", observation.verification_error)
    self.assertIsNone(observation.chain_certificates)

  def test_a_not_yet_valid_certificate_is_found_not_yet_valid(self):
    with self.serve("NOT_YET_VALID") as server:
      target, observation = self.observe(server)
    self.assertEqual(self.classify(target, observation)[0], "NOT_YET_VALID")
    self.assertIn("not yet valid", observation.verification_error)

  def test_a_name_mismatch_is_trusted_but_a_warning(self):
    with self.serve("MISMATCH") as server:
      target, observation = self.observe(server)
      accepts = server.accepts
    status, _, identity = self.classify(target, observation)
    self.assertEqual((status, identity, observation.trust_verified, accepts), ("WARNING", False, True, 1))

  def test_a_server_that_never_answers_the_handshake_times_out(self):
    with LoopbackServer(lambda connection: time.sleep(5)) as server, mock.patch.object(c, "TLS_TIMEOUT", 0.3):
      started = time.monotonic()
      with self.assertRaisesRegex(c.CertWatchError, "^TLS handshake timed out after 0.3 seconds$"):
        c.observe_endpoint(c.parse_target(f"127.0.0.1:{server.port}"))
      accepts = server.accepts
    self.assertLess(time.monotonic() - started, 3)
    self.assertEqual(accepts, 1)

  def test_a_plaintext_server_is_a_handshake_failure(self):
    with LoopbackServer(lambda connection: connection.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")) as server:
      with self.assertRaisesRegex(c.CertWatchError, "^TLS handshake failed: "):
        c.observe_endpoint(c.parse_target(f"127.0.0.1:{server.port}"))

  def test_a_closed_port_is_a_connection_failure(self):
    with self.assertRaisesRegex(c.CertWatchError, "^TCP connection failed$"):
      c.observe_endpoint(c.parse_target(f"127.0.0.1:{unused_port()}"))

  def test_a_resolver_that_never_answers_is_a_bounded_failure(self):
    release = threading.Event()
    self.addCleanup(release.set)
    started = time.monotonic()
    with mock.patch.object(c, "RESOLVE_TIMEOUT", 0.2):
      with self.assertRaisesRegex(c.CertWatchError, "^name resolution failed: OS resolver did not answer within 0.2 s$"):
        c.observe_endpoint(c.parse_target("example.com"), resolver=lambda *a: release.wait(10))
    self.assertLess(time.monotonic() - started, 3)

  def test_a_resolver_answer_beyond_the_candidate_limit_is_reported(self):
    with self.serve("VALID") as server:
      records = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", server.port))]
      records += [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (f"192.0.2.{index}", server.port)) for index in range(1, 20)]
      target = c.parse_target(f"localhost:{server.port}")
      with trusting_the_fixture_ca():
        observation = c.observe_endpoint(target, resolver=lambda *a: records)
    self.assertTrue(observation.resolution_truncated)

  def run_main(self, arguments):
    stdout, stderr = io.StringIO(), io.StringIO()
    with trusting_the_fixture_ca(), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
      code = c.main(arguments)
    return code, stdout.getvalue(), stderr.getvalue()

  def test_one_run_ranks_real_targets_in_input_order_and_exits_one(self):
    names = ("VALID", "EXPIRED", "NOT_YET_VALID", "MISMATCH")
    with contextlib.ExitStack() as stack:
      servers = [stack.enter_context(self.serve(name)) for name in names]
      code, stdout, stderr = self.run_main(["--json", *[f"127.0.0.1:{server.port}" for server in servers]])
      accepts = [server.accepts for server in servers]
    payload = json.loads(stdout)
    statuses = [target["status"] for target in payload["observations"]["targets"]]
    self.assertEqual(statuses, ["VALID", "EXPIRED", "NOT_YET_VALID", "WARNING"])
    self.assertEqual((code, payload["status"]), (1, "EXPIRED"))
    self.assertEqual(accepts, [1, 2, 2, 1])
    self.assertEqual(stderr.count("certificate has expired"), 1)

  def test_a_run_with_one_unreachable_target_keeps_the_finding_and_exits_one(self):
    with self.serve("EXPIRED") as server:
      code, stdout, _ = self.run_main(["--json", f"127.0.0.1:{unused_port()}", f"127.0.0.1:{server.port}"])
    payload = json.loads(stdout)
    self.assertEqual([target["status"] for target in payload["observations"]["targets"]], ["ERROR", "EXPIRED"])
    self.assertEqual((code, payload["status"]), (1, "EXPIRED"))

  def test_healthy_and_unreachable_targets_leave_the_run_incomplete(self):
    with self.serve("VALID") as server:
      code, stdout, _ = self.run_main(["--json", f"127.0.0.1:{server.port}", f"127.0.0.1:{unused_port()}"])
    payload = json.loads(stdout)
    self.assertEqual((code, payload["status"]), (3, "INCOMPLETE"))

  def test_targets_are_inspected_in_parallel(self):
    with contextlib.ExitStack() as stack:
      servers = [stack.enter_context(self.serve("VALID", delay=0.4)) for _ in range(8)]
      started = time.monotonic()
      code, stdout, _ = self.run_main(["--json", *[f"127.0.0.1:{server.port}" for server in servers]])
      elapsed = time.monotonic() - started
    payload = json.loads(stdout)
    self.assertEqual((code, payload["status"]), (0, "VALID"))
    # One after another these eight would need at least 3.2 seconds of server delay alone.
    self.assertLess(elapsed, 2.5)
    self.assertEqual([server.accepts for server in servers], [1] * 8)
    self.assertEqual(
      [target["target"] for target in payload["observations"]["targets"]], [f"127.0.0.1:{server.port}" for server in servers],
    )


if __name__ == "__main__":
  unittest.main()
