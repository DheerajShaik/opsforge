import contextlib
import io
import json
import socket
import unittest
from unittest import mock

from test_netdoctor import netdoctor, candidate


class RouteContextTests(unittest.TestCase):
  def report(self, address, local, route):
    family = socket.AF_INET6 if ':' in address else socket.AF_INET
    host, kind = netdoctor.parse_host(address)
    target = netdoctor.Target(address, host, 443, kind)
    selected = candidate(address, family=family)
    result = netdoctor.DiagnosticResult(target, 'resolved', None, (selected,),
      (netdoctor.ConnectionAttempt(selected, 'connected', local_endpoint=local),))
    stdout = io.StringIO()
    with mock.patch.object(netdoctor, 'diagnose', return_value=result), \
         mock.patch.object(netdoctor, 'default_route_context', return_value=route), \
         mock.patch.object(netdoctor, 'resolver_context', return_value=()), \
         mock.patch.object(netdoctor, 'proxy_context', return_value=()), \
         contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
      self.assertEqual(netdoctor.main([address, '443', '--json']), 0)
    return json.loads(stdout.getvalue())['observations']

  def test_loopback_does_not_infer_interface(self):
    self.assertIsNone(self.report('127.0.0.1', '127.0.0.1:4000', ('eth0', '192.0.2.1'))['selected_interface'])

  def test_ipv4_default_route_remains_context_only(self):
    result = self.report('192.0.2.2', '192.0.2.3:4000', ('eth0', '192.0.2.1'))
    self.assertIsNone(result['selected_interface'])
    self.assertEqual(result['ipv4_default_route_context'], '192.0.2.1 via eth0')
    self.assertNotIn('default_route', result)

  def test_ipv6_cannot_inherit_ipv4_interface(self):
    result = self.report('2001:db8::1', '[2001:db8::2]:4000', ('eth0', '192.0.2.1'))
    self.assertIsNone(result['selected_interface'])

  def test_missing_default_route_is_unavailable(self):
    result = self.report('127.0.0.1', '127.0.0.1:4000', (None, None))
    self.assertIsNone(result['ipv4_default_route_context'])
    self.assertIsNone(result['selected_interface'])
