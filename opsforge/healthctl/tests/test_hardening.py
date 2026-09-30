import contextlib
import io
import json
import socket
import ssl
import unittest
from unittest import mock

from test_healthctl import healthctl, FakeSocket


class ManagedSocket(FakeSocket):
  def __init__(self, *args, on_connect=None, **kwargs):
    super().__init__(*args, **kwargs)
    self.on_connect = on_connect

  def connect(self, sockaddr):
    if self.on_connect:
      self.on_connect()
    super().connect(sockaddr)

  def __enter__(self):
    return self

  def __exit__(self, *args):
    self.close()

  def getpeercert(self):
    return {'notAfter': 'Jan  1 00:00:00 2099 GMT'}


class CertificateBoundsTests(unittest.TestCase):
  def test_invalid_http_targets_and_severity_are_config_errors(self):
    for url, severity in (('http://example.test:0/', 'CRITICAL'), ('http://@example.test/', 'CRITICAL'), ('http://example.test/', [])):
      with self.subTest(url=url, severity=severity), self.assertRaises(healthctl.ConfigError):
        healthctl.parse_config_document({'version': 1, 'checks': [
          {'name': 'web', 'type': 'http', 'url': url, 'severity': severity}]}, path='health.json')
    with self.assertRaises(healthctl.RedirectPolicyError):
      healthctl.validate_redirect_url('http://example.test/', 'http://example.test:0/')

  def test_error_is_counted_once_in_summary(self):
    check = self.check()
    result = healthctl.CheckResult(check.name, check.type, 'ERROR', check.target, 'unavailable')
    stdout = io.StringIO()
    with mock.patch.object(healthctl, 'load_config', return_value=healthctl.HealthConfig('/health.json', (check,))), \
         mock.patch.object(healthctl, 'evaluate_config', return_value=(result,)), \
         contextlib.redirect_stdout(stdout):
      self.assertEqual(healthctl.main(['health.json', '--json']), 3)
    document = json.loads(stdout.getvalue())
    self.assertEqual(document['status'], 'ERROR')
    self.assertIn('1 error(s)', document['conclusion'])
    self.assertEqual(
      document['observations']['summary'],
      {'pass': 0, 'fail_warning': 0, 'fail_critical': 0, 'error': 1, 'skipped': 0},
    )

  def check(self, host='example.test', severity='CRITICAL'):
    return healthctl.GenericCheck('cert', 'certificate_expiry', f'{host}:443', 1.0, severity=severity,
      options=(('host', host), ('port', 443), ('warn_days', 30), ('critical_days', 7)))

  def records(self, count=2):
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', (f'192.0.2.{i + 1}', 443)) for i in range(count)]

  def run_check(self, *, days=60, clients=None, records=None, tls_error=None, clock=None, host='example.test', severity='CRITICAL'):
    clients = clients or [ManagedSocket()]
    tls = ManagedSocket()
    context = mock.Mock()
    context.wrap_socket.side_effect = tls_error
    context.wrap_socket.return_value = tls
    with mock.patch.object(healthctl.socket, 'getaddrinfo', return_value=records or self.records()) as resolver, \
         mock.patch.object(healthctl.socket, 'socket', side_effect=clients) as factory, \
         mock.patch.object(healthctl.socket, 'create_connection', side_effect=AssertionError('unbounded helper forbidden')), \
         mock.patch.object(healthctl, 'default_tls_context', return_value=context) as trust, \
         mock.patch.object(healthctl.ssl, 'cert_time_to_seconds', return_value=days * 86400), \
         mock.patch.object(healthctl.time, 'time', return_value=0), \
         mock.patch.object(healthctl.time, 'monotonic', side_effect=clock, return_value=0):
      result = healthctl.run_generic_check(self.check(host, severity))
    self.assertIn('revocation not checked', result.evidence)
    trust.assert_called_once_with()
    return result, factory, context, resolver, tls

  def verification_error(self, code, message):
    error = ssl.SSLCertVerificationError(1, f'[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: {message}')
    error.verify_code = code
    error.verify_message = message
    return error

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

  def test_candidate_cap_keeps_first_16_candidates(self):
    result, factory, _, _, _ = self.run_check(records=self.records(healthctl.MAX_CANDIDATES + 1))
    self.assertEqual(result.status, 'PASS')
    self.assertEqual(factory.call_count, 1)
    self.assertIn('only the first 16', result.evidence)
    clients = [ManagedSocket(OSError('refused')) for _ in range(healthctl.MAX_CANDIDATES + 1)]
    result, factory, _, _, _ = self.run_check(clients=clients, records=self.records(healthctl.MAX_CANDIDATES + 1))
    self.assertEqual(result.status, 'ERROR')
    self.assertEqual(factory.call_count, healthctl.MAX_CANDIDATES)

  def test_tls_trust_failure(self):
    client = ManagedSocket()
    result, _, _, _, _ = self.run_check(clients=[client], tls_error=ssl.SSLCertVerificationError('untrusted'))
    self.assertEqual((result.status, result.severity), ('FAIL', 'CRITICAL'))
    self.assertTrue(client.closed)

  def test_hostname_mismatch(self):
    error = self.verification_error(62, "Hostname mismatch, certificate is not valid for 'example.test'.")
    result, _, _, _, _ = self.run_check(tls_error=error, severity='WARNING')
    self.assertEqual((result.status, result.severity), ('FAIL', 'WARNING'))
    self.assertIn("certificate verification failed (Hostname mismatch", result.evidence)

  def test_expired_or_not_yet_valid_certificate_is_critical_failure(self):
    for code, message in ((10, 'certificate has expired'), (9, 'certificate is not yet valid')):
      with self.subTest(code=code):
        result, _, _, _, _ = self.run_check(tls_error=self.verification_error(code, message), severity='WARNING')
        self.assertEqual((result.status, result.severity), ('FAIL', 'CRITICAL'))
        self.assertIn(f'{message} ({message})', result.evidence)

  def test_tls_protocol_failure_is_error_without_severity(self):
    result, _, _, _, _ = self.run_check(tls_error=ssl.SSLError(1, 'wrong version number'), severity='WARNING')
    self.assertEqual((result.status, result.severity), ('ERROR', None))
    self.assertIn('TLS protocol error (SSLError)', result.evidence)

  def test_total_deadline_stops_before_next_candidate(self):
    now = [0.0]
    client = ManagedSocket(OSError('timeout'), on_connect=lambda: now.__setitem__(0, 1.1))
    result, factory, context, _, _ = self.run_check(clients=[client], clock=lambda: now[0])
    self.assertEqual(result.status, 'ERROR')
    self.assertIn('the check deadline passed', result.evidence)
    self.assertEqual(factory.call_count, 1)
    self.assertAlmostEqual(client.timeout, 0.5)
    context.wrap_socket.assert_not_called()

  def test_tls_uses_remaining_total_deadline(self):
    now = [0.0]
    client = ManagedSocket(on_connect=lambda: now.__setitem__(0, 0.7))
    result, _, _, _, _ = self.run_check(clients=[client], clock=lambda: now[0])
    self.assertEqual(result.status, 'PASS')
    self.assertAlmostEqual(client.timeout, 0.3)

  def test_expiry_warning(self):
    result, *_ = self.run_check(days=20)
    self.assertEqual((result.status, result.severity), ('FAIL', 'WARNING'))

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
