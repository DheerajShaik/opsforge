from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portlens


class EndpointParsingTests(unittest.TestCase):
  def test_ipv4_and_wildcard_endpoints(self):
    self.assertEqual(portlens.parse_endpoint("127.0.0.1:8080"), ("127.0.0.1", 8080))
    self.assertEqual(portlens.parse_endpoint("0.0.0.0:8080"), ("0.0.0.0", 8080))
    self.assertEqual(portlens.parse_endpoint("*:8080"), ("*", 8080))

  def test_ipv6_and_wildcard_endpoints(self):
    self.assertEqual(portlens.parse_endpoint("[::1]:8080"), ("::1", 8080))
    self.assertEqual(portlens.parse_endpoint("[::]:8080"), ("::", 8080))
    self.assertEqual(portlens.parse_endpoint(":::8080"), ("::", 8080))

  def test_malformed_endpoints_fail(self):
    for endpoint in ("127.0.0.1", "[::1:8080", "127.0.0.1:http", ":8080"):
      with self.subTest(endpoint=endpoint):
        with self.assertRaises(portlens.PortLensError):
          portlens.parse_endpoint(endpoint)


class SsParsingTests(unittest.TestCase):
  IPV4 = 'LISTEN 0 128 127.0.0.1:8080 0.0.0.0:* users:(("python3",pid=1234,fd=3))'
  IPV6 = 'LISTEN  0  128  [::]:8080  [::]:*  users:(("python3",pid=1234,fd=4))'

  def test_process_metadata_present(self):
    observation = portlens.parse_ss_row(self.IPV4, "ipv4")
    self.assertEqual((observation.protocol, observation.state, observation.family), ("tcp", "LISTEN", "ipv4"))
    self.assertEqual((observation.local_address, observation.local_port), ("127.0.0.1", 8080))
    self.assertEqual(observation.processes, (portlens.ProcessReference(1234, "python3"),))

  def test_process_metadata_absent(self):
    observation = portlens.parse_ss_row("LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*", "ipv4")
    self.assertEqual(observation.processes, ())

  def test_ipv6_and_unexpected_whitespace(self):
    observation = portlens.parse_ss_row(self.IPV6, "ipv6")
    self.assertEqual((observation.local_address, observation.local_port), ("::", 8080))

  def test_multiple_rows_and_matches_are_preserved(self):
    observations = portlens.parse_ss_output(f"{self.IPV4}\n{self.IPV4}\n{self.IPV6}\n", "ipv4")
    self.assertEqual(len(observations), 3)
    self.assertEqual(sum(item.local_port == 8080 for item in observations), 3)

  def test_malformed_core_rows_fail(self):
    for row in ("garbage", "ESTAB 0 0 127.0.0.1:8080 0.0.0.0:*", "LISTEN x 1 127.0.0.1:8080 0.0.0.0:*"):
      with self.subTest(row=row):
        with self.assertRaises(portlens.PortLensError):
          portlens.parse_ss_row(row, "ipv4")

  def test_optional_process_metadata_failure_preserves_socket(self):
    row = 'LISTEN 0 128 127.0.0.1:8080 0.0.0.0:* users:(("broken",pid=nope,fd=3))'
    self.assertEqual(portlens.parse_ss_row(row, "ipv4").processes, ())

  def test_unavailable_enrichment(self):
    observation = portlens.SocketObservation("tcp", "LISTEN", "ipv4", "0.0.0.0", 8080)
    self.assertEqual(portlens.to_display(observation).pid, "-")

  def test_process_exit_preserves_pid_and_falls_back_to_ss_name(self):
    reference = portlens.ProcessReference(999999999, "listener")
    user, process = portlens.enrich_process(reference)
    self.assertEqual(user, "-")
    self.assertEqual(process, "listener")

  @mock.patch.object(portlens.pwd, "getpwuid")
  @mock.patch.object(portlens.os, "stat")
  def test_user_and_process_are_enriched_from_procfs(self, stat, getpwuid):
    stat.return_value.st_uid = 1000
    getpwuid.return_value.pw_name = "appuser"
    reference = portlens.ProcessReference(1234, "ss-name")
    with mock.patch("builtins.open", mock.mock_open(read_data="listener\n")):
      self.assertEqual(portlens.enrich_process(reference), ("appuser", "listener"))

  @mock.patch.object(portlens.pwd, "getpwuid", side_effect=KeyError)
  @mock.patch.object(portlens.os, "stat")
  def test_numeric_uid_is_preserved_when_username_lookup_fails(self, stat, getpwuid):
    stat.return_value.st_uid = 4242
    reference = portlens.ProcessReference(1234, "ss-name")
    with mock.patch("builtins.open", mock.mock_open(read_data="listener\n")):
      self.assertEqual(portlens.enrich_process(reference)[0], "4242")

  def test_deterministic_sorting_and_no_deduplication(self):
    values = [
      portlens.DisplayObservation("tcp", "LISTEN", "ipv6", "::", 8080, "-", "-", "-"),
      portlens.DisplayObservation("tcp", "LISTEN", "ipv4", "127.0.0.1", 8080, "2", "u", "z"),
      portlens.DisplayObservation("tcp", "LISTEN", "ipv4", "0.0.0.0", 8080, "1", "u", "a"),
      portlens.DisplayObservation("tcp", "LISTEN", "ipv4", "0.0.0.0", 8080, "1", "u", "a"),
    ]
    result = portlens.sort_observations(values)
    self.assertEqual([item.family for item in result], ["ipv4", "ipv4", "ipv4", "ipv6"])
    self.assertEqual(len(result), 4)

  def test_terminal_controls_are_sanitized(self):
    self.assertEqual(portlens.sanitize_display("a\n\t\x1b[31m"), "a???[31m")


class RealSsOutputRegressionTests(unittest.TestCase):
  """Sanitized rows observed from iproute2 ss 6.1.0 on Ubuntu WSL."""

  def assert_observation(self, row, family, address, pid):
    observation = portlens.parse_ss_row(row, family)
    self.assertEqual(observation.protocol, "tcp")
    self.assertEqual(observation.state, "LISTEN")
    self.assertEqual(observation.family, family)
    self.assertEqual(observation.local_address, address)
    self.assertEqual(observation.local_port, 18080)
    self.assertEqual(
      observation.processes,
      (portlens.ProcessReference(pid, "python3"),),
    )

  def test_observed_ipv4_loopback_row(self):
    row = 'LISTEN 0 5 127.0.0.1:18080 0.0.0.0:* users:(("python3",pid=4101,fd=3))'
    self.assert_observation(row, "ipv4", "127.0.0.1", 4101)

  def test_observed_ipv4_wildcard_row(self):
    row = 'LISTEN 0 5 0.0.0.0:18080 0.0.0.0:* users:(("python3",pid=4102,fd=3))'
    self.assert_observation(row, "ipv4", "0.0.0.0", 4102)

  def test_observed_ipv6_loopback_row(self):
    row = 'LISTEN 0 5 [::1]:18080 [::]:* users:(("python3",pid=4103,fd=3))'
    self.assert_observation(row, "ipv6", "::1", 4103)

  def test_observed_ipv6_wildcard_row_uses_query_family(self):
    row = 'LISTEN 0 5 *:18080 *:* users:(("python3",pid=4104,fd=3))'
    self.assert_observation(row, "ipv6", "*", 4104)


if __name__ == "__main__":
  unittest.main()
