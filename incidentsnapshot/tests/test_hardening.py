import unittest
from unittest import mock

from test_incidentsnapshot import incident


class EvidenceAndCleanupTests(unittest.TestCase):
  def test_failed_service_query_is_unavailable_not_empty(self):
    with mock.patch.object(incident, 'run_bounded_command', return_value=(1, b'')):
      result = incident._optional_section('Failed systemd services', incident.collect_failed_services)
    self.assertEqual(result.status, 'unavailable')
    self.assertIsNone(result.value)

  def test_successful_empty_service_query_is_observed(self):
    with mock.patch.object(incident, 'run_bounded_command', return_value=(0, b'')):
      self.assertEqual(incident.collect_failed_services().value, ())

  def test_malformed_service_query_is_unavailable(self):
    for output in (b'bad response\n', b'\xff', b'x.service loaded active running x\n'):
      with self.subTest(output=output), mock.patch.object(incident, 'run_bounded_command', return_value=(0, output)):
        with self.assertRaises(incident.SectionUnavailable):
          incident.collect_failed_services()

  def test_valid_failed_service_query(self):
    with mock.patch.object(incident, 'run_bounded_command', return_value=(0, b'x.service loaded failed failed Example\n')):
      self.assertEqual(incident.collect_failed_services().value, ('x.service',))

  def test_unavailable_ipv6_routes_do_not_become_observed_empty(self):
    def read(path, limit):
      if path == incident.IPV6_ROUTE_PATH:
        raise incident.SectionUnavailable('unavailable')
      return b'Iface Destination Gateway Flags RefCnt Use Metric Mask\n'
    with self.assertRaises(incident.SectionUnavailable):
      incident.collect_routes(read)
