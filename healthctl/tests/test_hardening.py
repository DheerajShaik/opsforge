import socket
import ssl
import unittest
from unittest import mock

from test_healthctl import healthctl, FakeSocket


class ManagedSocket(FakeSocket):
  def __enter__(self):
    return self

  def __exit__(self, *args):
    self.close()

  def getpeercert(self):
    return {'notAfter': 'Jan  1 00:00:00 2099 GMT'}


class CertificateBoundsTests(unittest.TestCase):
  def test_exited_helper_still_terminates_descendants_and_reaps(self):
    process = mock.Mock(pid=12345)
    process.poll.return_value = 0
    with mock.patch.object(healthctl.os, 'killpg') as killpg:
      healthctl._stop_process_group(process)
    killpg.assert_called_once_with(12345, healthctl.signal.SIGKILL)
    process.wait.assert_called_once_with(timeout=1.0)

  def check(self, host='example.test'):
    return healthctl.GenericCheck('cert', 'certificate_expiry', f'{host}:443', 1.0,
      options=(('host', host), ('port', 443), ('warn_days', 30), ('critical_days', 7)))

  def records(self, count=2):
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', (f'192.0.2.{i + 1}', 443)) for i in range(count)]

  def run_check(self, *, days=60, clients=None, records=None, tls_error=None, clock=None, host='example.test'):
    clients = clients or [ManagedSocket()]
    tls = ManagedSocket()
    context = mock.Mock()
    context.wrap_socket.side_effect = tls_error
    context.wrap_socket.return_value = tls
    with mock.patch.object(healthctl.socket, 'getaddrinfo', return_value=records or self.records()) as resolver, \
         mock.patch.object(healthctl.socket, 'socket', side_effect=clients) as factory, \
         mock.patch.object(healthctl.socket, 'create_connection', side_effect=AssertionError('unbounded helper forbidden')), \
         mock.patch.object(healthctl.ssl, 'create_default_context', return_value=context) as trust, \
         mock.patch.object(healthctl.ssl, 'cert_time_to_seconds', return_value=days * 86400), \
         mock.patch.object(healthctl.time, 'time', return_value=0), \
         mock.patch.object(healthctl.time, 'monotonic', side_effect=clock, return_value=0):
      result = healthctl.run_generic_check(self.check(host))
    self.assertIn('revocation not checked', result.evidence)
    trust.assert_called_once_with()
    return result, factory, context, resolver, tls

  def test_valid_certificate_uses_bounded_candidates_and_sni(self):
    client = ManagedSocket()
    result, factory, context, _, tls = self.run_check(clients=[client])
    self.assertEqual(result.status, 'PASS')
    context.wrap_socket.assert_called_once_with(client, server_hostname='example.test')
    self.assertTrue(client.closed)
    self.assertTrue(tls.closed)

  def test_first_candidate_fails_second_succeeds(self):
    clients = [ManagedSocket(OSError('refused')), ManagedSocket()]
    result, factory, _, _, _ = self.run_check(clients=clients)
    self.assertEqual(result.status, 'PASS')
    self.assertEqual(factory.call_count, 2)
    self.assertTrue(all(client.closed for client in clients))

  def test_candidate_cap_refuses_before_any_connect(self):
    result, factory, _, _, _ = self.run_check(records=self.records(healthctl.MAX_RESOLVER_CANDIDATES + 1))
    self.assertEqual(result.status, 'ERROR')
    factory.assert_not_called()

  def test_tls_trust_failure(self):
    client = ManagedSocket()
    result, _, _, _, _ = self.run_check(clients=[client], tls_error=ssl.SSLCertVerificationError('untrusted'))
    self.assertEqual(result.status, 'ERROR')
    self.assertTrue(client.closed)

  def test_hostname_mismatch(self):
    result, _, _, _, _ = self.run_check(tls_error=ssl.CertificateError('hostname mismatch'))
    self.assertEqual(result.status, 'ERROR')

  def test_total_deadline_stops_before_next_candidate(self):
    client = ManagedSocket(OSError('timeout'))
    result, factory, context, _, _ = self.run_check(clients=[client], clock=[0, 0.1, 1.1])
    self.assertEqual(result.status, 'ERROR')
    self.assertEqual(factory.call_count, 1)
    self.assertAlmostEqual(client.timeout, 0.9)
    context.wrap_socket.assert_not_called()

  def test_tls_uses_remaining_total_deadline(self):
    client = ManagedSocket()
    result, _, _, _, _ = self.run_check(clients=[client], clock=[0, 0.1, 0.7, 0.9])
    self.assertEqual(result.status, 'PASS')
    self.assertAlmostEqual(client.timeout, 0.3)

  def test_expiry_warning(self):
    result, *_ = self.run_check(days=20)
    self.assertEqual((result.status, result.severity), ('FAIL', 'WARN'))

  def test_expiry_critical(self):
    result, *_ = self.run_check(days=3)
    self.assertEqual((result.status, result.severity), ('FAIL', 'CRITICAL'))

  def test_numeric_host_sets_resolver_flag(self):
    result, _, _, resolver, _ = self.run_check(host='192.0.2.1')
    self.assertEqual(result.status, 'PASS')
    self.assertEqual(resolver.call_args.args[-1], socket.AI_NUMERICHOST)

  def test_interruption_closes_connect_socket(self):
    client = ManagedSocket(KeyboardInterrupt())
    with self.assertRaises(KeyboardInterrupt):
      self.run_check(clients=[client])
    self.assertTrue(client.closed)
