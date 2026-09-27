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
    for endpoint in ("127.0.0.1", "[::1:8080", "127.0.0.1:http", ":8080", "[::1]x:53", "1.2.3.4%:53", "not-an-ip:53"):
      with self.subTest(endpoint=endpoint):
        with self.assertRaises(portlens.PortLensError):
          portlens.parse_endpoint(endpoint)

  def test_interface_scoped_endpoints(self):
    self.assertEqual(portlens.split_endpoint("[fe80::215:5dff:fecc:968f]%eth0:546"), ("fe80::215:5dff:fecc:968f", "eth0", 546))
    self.assertEqual(portlens.split_endpoint("127.0.0.53%lo:53"), ("127.0.0.53", "lo", 53))
    self.assertEqual(portlens.split_endpoint("0.0.0.0%enp0s3:68"), ("0.0.0.0", "enp0s3", 68))
    self.assertEqual(portlens.split_endpoint("*%eth0:68"), ("*", "eth0", 68))


class SsParsingTests(unittest.TestCase):
  IPV4 = "LISTEN 0 128 127.0.0.1:8080 0.0.0.0:* uid:1000 ino:4242 sk:1 cgroup:/user.slice <->"
  IPV6 = "LISTEN  0  128  [::]:8080  [::]:*  ino:4343 sk:2 v6only:1 <->"

  def test_inode_is_taken_from_the_kernel_field(self):
    observation = portlens.parse_ss_row(self.IPV4, "ipv4")
    self.assertEqual((observation.protocol, observation.state, observation.family), ("tcp", "LISTEN", "ipv4"))
    self.assertEqual((observation.local_address, observation.local_port, observation.inode), ("127.0.0.1", 8080, 4242))
    self.assertEqual(observation.processes, ())
    spoof = "LISTEN 0 128 127.0.0.1:8080 0.0.0.0:* ino:4242 sk:1 cgroup:/x ino:1 <->"
    self.assertEqual(portlens.parse_ss_row(spoof, "ipv4").inode, 4242)

  def test_udp_and_scoped_rows(self):
    observation = portlens.parse_ss_row("UNCONN 0 0 0.0.0.0:53 0.0.0.0:* ino:9 sk:3 <->", "ipv4", "udp")
    self.assertEqual((observation.protocol, observation.state, observation.local_port), ("udp", "UNCONN", 53))
    scoped = portlens.parse_ss_row("UNCONN 0 0 [fe80::1]%eth0:546 [::]:* ino:10 sk:4 v6only:1 <->", "ipv6", "udp")
    self.assertEqual((scoped.local_address, scoped.interface, scoped.inode), ("fe80::1", "eth0", 10))

  def test_process_metadata_absent(self):
    observation = portlens.parse_ss_row("LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*", "ipv4")
    self.assertEqual((observation.processes, observation.inode), ((), None))

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

  def test_malformed_rows_become_warnings_when_collected(self):
    malformed = []
    observations = portlens.parse_ss_output(f"{self.IPV4}\ngarbage\x0bline\n", "ipv4", malformed=malformed)
    self.assertEqual(len(observations), 1)
    self.assertEqual(len(malformed), 1)

  def test_bind_classification(self):
    self.assertEqual(portlens.classify_bind("::ffff:127.0.0.1"), "loopback only")
    self.assertEqual(portlens.classify_bind("fe80::1", "eth0"), "link-local address; bound to interface eth0")
    self.assertTrue(portlens.classify_bind("0.0.0.0", "eth0").startswith("wildcard"))
    self.assertIn("IPv4 and IPv6", portlens.classify_bind("*"))

  def test_unavailable_enrichment(self):
    observation = portlens.SocketObservation("tcp", "LISTEN", "ipv4", "0.0.0.0", 8080)
    self.assertEqual(portlens.to_display(observation).pid, "-")

  def test_process_exit_leaves_owner_details_unavailable(self):
    user, process = portlens.enrich_process(portlens.ProcessReference(999999999))
    self.assertEqual((user, process), ("-", "-"))

  @mock.patch.object(portlens.pwd, "getpwuid")
  @mock.patch.object(portlens.os, "stat")
  def test_user_and_process_are_enriched_from_procfs(self, stat, getpwuid):
    stat.return_value.st_uid = 1000
    getpwuid.return_value.pw_name = "appuser"
    reference = portlens.ProcessReference(1234)
    with mock.patch("builtins.open", mock.mock_open(read_data=b"listener\n")):
      self.assertEqual(portlens.enrich_process(reference), ("appuser", "listener"))

  @mock.patch.object(portlens.pwd, "getpwuid", side_effect=KeyError)
  @mock.patch.object(portlens.os, "stat")
  def test_numeric_uid_is_preserved_when_username_lookup_fails(self, stat, getpwuid):
    stat.return_value.st_uid = 4242
    reference = portlens.ProcessReference(1234)
    with mock.patch("builtins.open", mock.mock_open(read_data=b"listener\n")):
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
    self.assertEqual(portlens.sanitize_text("a\n\t\x1b[31m"), r"a\x0a\x09\x1b[31m")

  def test_unicode_presentation_controls_are_sanitized(self):
    rendered = portlens.sanitize_text("left\u202eright\u2028next\u2066")
    self.assertNotIn("\u202e", rendered)
    self.assertNotIn("\u2028", rendered)
    self.assertNotIn("\u2066", rendered)



if __name__ == "__main__":
  unittest.main()
