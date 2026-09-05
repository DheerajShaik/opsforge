import contextlib
import errno
import importlib.util
import io
from pathlib import Path
import socket
import sys
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).parents[1] / "netdoctor.py"
SPEC = importlib.util.spec_from_file_location("netdoctor", MODULE_PATH)
netdoctor = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = netdoctor
SPEC.loader.exec_module(netdoctor)


class StrictAsciiStream(io.StringIO):
  @property
  def encoding(self):
    return "ascii"

  def write(self, value):
    value.encode("ascii", errors="strict")
    return super().write(value)


class FakeSocket:
  def __init__(
    self,
    *,
    connect_error=None,
    local=("192.0.2.10", 40000),
    peer=("198.51.100.8", 443),
  ):
    self.connect_error = connect_error
    self.local = local
    self.peer = peer
    self.timeout = None
    self.connected_to = None
    self.closed = False

  def settimeout(self, value):
    self.timeout = value

  def connect(self, sockaddr):
    self.connected_to = sockaddr
    if self.connect_error is not None:
      raise self.connect_error

  def getsockname(self):
    return self.local

  def getpeername(self):
    return self.peer

  def close(self):
    self.closed = True


def candidate(address="198.51.100.8", port=443, family=socket.AF_INET):
  if family == socket.AF_INET:
    sockaddr = (address, port)
  else:
    sockaddr = (address, port, 0, 0)
  return netdoctor.ConnectionCandidate(
    family=family,
    socket_type=socket.SOCK_STREAM,
    protocol=socket.IPPROTO_TCP,
    sockaddr=sockaddr,
    endpoint=netdoctor.format_sockaddr(family, sockaddr),
  )


class CliTests(unittest.TestCase):
  def run_main(self, arguments):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
      code = netdoctor.main(arguments)
    return code, stdout.getvalue(), stderr.getvalue()

  def test_help_is_stdout_and_does_not_diagnose(self):
    for option in ("-h", "--help"):
      with self.subTest(option=option), mock.patch.object(netdoctor, "diagnose") as diagnose:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), self.assertRaises(SystemExit) as caught:
          netdoctor.main([option])
        self.assertEqual(caught.exception.code, 0)
        self.assertIn("name resolution and TCP connection establishment", stdout.getvalue())
        diagnose.assert_not_called()

  def test_invalid_invocation_and_port_exit_two(self):
    cases = (
      [], ["example.com"], ["example.com", "443", "extra"],
      ["example.com", "0"], ["example.com", "65536"],
      ["example.com", "-1"], ["example.com", "+1"],
      ["example.com", "1.5"], ["example.com", "١"],
    )
    for arguments in cases:
      with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()), \
           self.assertRaises(SystemExit) as caught:
        netdoctor.main(arguments)
      self.assertEqual(caught.exception.code, 2)

  def test_invalid_host_is_stable_exit_two(self):
    for host in ("", "bad name", "[::1]", "fe80::1%eth0", "a_b", "é.example"):
      with self.subTest(host=host):
        code, stdout, stderr = self.run_main([host, "443"])
        self.assertEqual((code, stdout), (2, ""))
        self.assertTrue(stderr.startswith("netdoctor:"))
        self.assertNotIn("Traceback", stderr)

  def test_success_and_negative_result_exit_codes(self):
    resolved = candidate()
    target_result = netdoctor.DiagnosticResult(
      netdoctor.Target("example.com", "example.com", 443, "hostname"),
      "resolved",
      None,
      (resolved,),
      (netdoctor.ConnectionAttempt(resolved, "connected"),),
    )
    with mock.patch.object(netdoctor, "diagnose", return_value=target_result):
      code, stdout, stderr = self.run_main(["example.com", "443"])
    self.assertEqual((code, stderr), (0, ""))
    self.assertIn("Status: connected", stdout)

    negative = netdoctor.DiagnosticResult(
      target_result.target,
      "failed",
      "name or address was not known",
      (),
      (),
    )
    with mock.patch.object(netdoctor, "diagnose", return_value=negative):
      code, stdout, stderr = self.run_main(["example.com", "443"])
    self.assertEqual((code, stderr), (1, ""))
    self.assertIn("Status: not connected", stdout)

  def test_expected_internal_and_interrupt_paths(self):
    with mock.patch.object(
      netdoctor, "diagnose", side_effect=netdoctor.ObservationError("resolver shape")
    ):
      self.assertEqual(
        self.run_main(["example.com", "443"]),
        (3, "", "netdoctor: resolver shape\n"),
      )
    with mock.patch.object(netdoctor, "diagnose", side_effect=RuntimeError("secret")):
      self.assertEqual(
        self.run_main(["example.com", "443"]),
        (3, "", "netdoctor: internal execution failure\n"),
      )
    with mock.patch.object(netdoctor, "diagnose", side_effect=KeyboardInterrupt):
      self.assertEqual(
        self.run_main(["example.com", "443"]),
        (130, "", "netdoctor: interrupted\n"),
      )

  def test_ascii_stdout_escapes_unencodable_unicode(self):
    stdout = StrictAsciiStream()
    stderr = io.StringIO()
    result = netdoctor.DiagnosticResult(
      netdoctor.Target("example.com", "example.com", 443, "hostname"),
      "failed",
      "résolution failed",
      (),
      (),
    )
    with mock.patch.object(netdoctor.sys, "stdout", stdout), \
         mock.patch.object(netdoctor.sys, "stderr", stderr), \
         mock.patch.object(netdoctor, "diagnose", return_value=result):
      code = netdoctor.main(["example.com", "443"])
    self.assertEqual(code, 1)
    self.assertEqual(stderr.getvalue(), "")
    self.assertIn("r\\xe9solution", stdout.getvalue())


class TargetTests(unittest.TestCase):
  def test_hostname_ipv4_ipv6_parsing(self):
    self.assertEqual(netdoctor.parse_host("example.com"), ("example.com", "hostname"))
    self.assertEqual(netdoctor.parse_host("localhost"), ("localhost", "hostname"))
    self.assertEqual(netdoctor.parse_host("EXAMPLE.COM."), ("EXAMPLE.COM.", "hostname"))
    self.assertEqual(netdoctor.parse_host("192.0.2.1"), ("192.0.2.1", "ipv4"))
    self.assertEqual(netdoctor.parse_host("2001:0db8::1"), ("2001:db8::1", "ipv6"))

  def test_bad_host_forms_are_rejected(self):
    values = (
      "", " ", "bad name", "bad\nname", "bad\u202ename", "[::1]", "::1]",
      "fe80::1%3", "a_b", "-bad", "bad-", "a..b", "é.example",
    )
    for value in values:
      with self.subTest(value=value), self.assertRaises(netdoctor.argparse.ArgumentTypeError):
        netdoctor.parse_host(value)

  def test_port_boundaries(self):
    for value, expected in (("1", 1), ("443", 443), ("065535", 65535)):
      with self.subTest(value=value):
        self.assertEqual(netdoctor.parse_port(value), expected)

  def test_display_endpoint_uses_brackets_for_ipv6(self):
    self.assertEqual(netdoctor.format_endpoint("192.0.2.1", 443), "192.0.2.1:443")
    self.assertEqual(netdoctor.format_endpoint("2001:db8::1", 443), "[2001:db8::1]:443")
    self.assertEqual(netdoctor.format_endpoint("fe80::1", 443, 3), "[fe80::1%3]:443")


class ResolverTests(unittest.TestCase):
  def test_hostname_resolution_signature_order_and_ipv6_scope(self):
    calls = []
    records = [
      (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("2001:db8::1", 443, 0, 0)),
      (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.0.2.1", 443)),
      (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("fe80::1", 443, 0, 4)),
    ]

    def resolver(*arguments):
      calls.append(arguments)
      return records

    target = netdoctor.Target("example.com", "example.com", 443, "hostname")
    candidates, failure = netdoctor.resolve_candidates(target, resolver=resolver)
    self.assertIsNone(failure)
    self.assertEqual(
      calls[0],
      ("example.com", 443, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, 0),
    )
    self.assertEqual(
      [item.endpoint for item in candidates],
      ["[2001:db8::1]:443", "192.0.2.1:443", "[fe80::1%4]:443"],
    )

  def test_numeric_target_requests_numeric_host_resolution(self):
    calls = []

    def resolver(*arguments):
      calls.append(arguments)
      return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 80))]

    target = netdoctor.Target("192.0.2.1", "192.0.2.1", 80, "ipv4")
    candidates, failure = netdoctor.resolve_candidates(target, resolver=resolver)
    self.assertEqual(len(candidates), 1)
    self.assertIsNone(failure)
    self.assertEqual(calls[0][-1], getattr(socket, "AI_NUMERICHOST", 0))

  def test_resolution_failures_are_useful_negative_evidence(self):
    error = socket.gaierror(getattr(socket, "EAI_NONAME", -2), "no name")
    target = netdoctor.Target("missing.invalid", "missing.invalid", 443, "hostname")
    result = netdoctor.diagnose(target, resolver=mock.Mock(side_effect=error))
    self.assertEqual(result.resolution_status, "failed")
    self.assertIn("not known", result.resolution_detail)
    self.assertFalse(result.connected)
    self.assertEqual(result.candidates, ())

  def test_duplicate_resolver_candidates_are_suppressed_in_first_seen_order(self):
    target = netdoctor.Target("example.com", "example.com", 443, "hostname")
    first = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 443))
    second = (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 443, 0, 0))
    candidates, failure = netdoctor.resolve_candidates(
      target,
      resolver=lambda *args: [first, first, second, first, second],
    )
    self.assertIsNone(failure)
    self.assertEqual(
      [item.endpoint for item in candidates],
      ["192.0.2.1:443", "[2001:db8::1]:443"],
    )

  def test_no_candidates_is_useful_negative_evidence(self):
    target = netdoctor.Target("example.com", "example.com", 443, "hostname")
    candidates, failure = netdoctor.resolve_candidates(target, resolver=lambda *args: [])
    self.assertEqual(candidates, ())
    self.assertEqual(failure, "resolver returned no TCP candidates")

  def test_over_limit_and_malformed_records_are_fatal(self):
    target = netdoctor.Target("example.com", "example.com", 443, "hostname")
    records = [
      (socket.AF_INET, socket.SOCK_STREAM, 6, "", (f"192.0.2.{index}", 443))
      for index in range(1, netdoctor.MAX_RESOLVER_CANDIDATES + 2)
    ]
    with self.assertRaises(netdoctor.ObservationError):
      netdoctor.resolve_candidates(target, resolver=lambda *args: records)
    for bad in (
      (socket.AF_UNIX, socket.SOCK_STREAM, 0, "", ("x", 443)),
      (socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("192.0.2.1", 443)),
      (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 80)),
      (socket.AF_INET, socket.SOCK_STREAM, 6, ""),
    ):
      with self.subTest(bad=bad), self.assertRaises(netdoctor.ObservationError):
        netdoctor.resolve_candidates(target, resolver=lambda *args, bad=bad: [bad])

  def test_unexpected_resolver_os_error_is_fatal(self):
    target = netdoctor.Target("example.com", "example.com", 443, "hostname")
    with self.assertRaises(netdoctor.ObservationError):
      netdoctor.resolve_candidates(target, resolver=mock.Mock(side_effect=OSError("boom")))


class ConnectionTests(unittest.TestCase):
  def test_timeout_then_success_preserves_order_and_stops(self):
    first = FakeSocket(connect_error=socket.timeout())
    second = FakeSocket()
    third = FakeSocket()
    sockets = [first, second, third]
    candidates = (
      candidate("192.0.2.1"), candidate("198.51.100.8"), candidate("203.0.113.9")
    )

    def factory(*args):
      return sockets.pop(0)

    attempts = netdoctor.attempt_connections(candidates, socket_factory=factory)
    self.assertEqual([item.outcome for item in attempts], ["timed out", "connected"])
    self.assertEqual(first.timeout, netdoctor.CONNECT_TIMEOUT_SECONDS)
    self.assertTrue(first.closed)
    self.assertTrue(second.closed)
    self.assertFalse(third.closed)
    self.assertEqual(attempts[1].local_endpoint, "192.0.2.10:40000")
    self.assertEqual(attempts[1].peer_endpoint, "198.51.100.8:443")

  def test_known_connect_errors_are_classified(self):
    cases = (
      (ConnectionRefusedError(errno.ECONNREFUSED, "refused"), "connection refused"),
      (OSError(errno.EHOSTUNREACH, "host"), "host unreachable"),
      (OSError(errno.ENETUNREACH, "network"), "network unreachable"),
      (PermissionError(errno.EACCES, "denied"), "permission denied"),
      (OSError(errno.EIO, "other"), "connection error"),
    )
    for error, expected in cases:
      with self.subTest(expected=expected):
        fake = FakeSocket(connect_error=error)
        attempts = netdoctor.attempt_connections((candidate(),), socket_factory=lambda *args: fake)
        self.assertEqual(attempts[0].outcome, expected)
        self.assertTrue(fake.closed)

  def test_socket_creation_and_timeout_setup_failures_are_fatal(self):
    with self.assertRaises(netdoctor.ObservationError):
      netdoctor.attempt_connections(
        (candidate(),), socket_factory=mock.Mock(side_effect=OSError("no fds"))
      )
    fake = FakeSocket()
    fake.settimeout = mock.Mock(side_effect=OSError("failed"))
    with self.assertRaises(netdoctor.ObservationError):
      netdoctor.attempt_connections((candidate(),), socket_factory=lambda *args: fake)
    self.assertTrue(fake.closed)

  def test_keyboard_interrupt_closes_socket_and_propagates(self):
    fake = FakeSocket(connect_error=KeyboardInterrupt())
    with self.assertRaises(KeyboardInterrupt):
      netdoctor.attempt_connections((candidate(),), socket_factory=lambda *args: fake)
    self.assertTrue(fake.closed)

  def test_peer_metadata_failure_does_not_erase_success(self):
    fake = FakeSocket()
    fake.getsockname = mock.Mock(side_effect=OSError("gone"))
    fake.getpeername = mock.Mock(side_effect=OSError("gone"))
    attempts = netdoctor.attempt_connections((candidate(),), socket_factory=lambda *args: fake)
    self.assertTrue(attempts[0].connected)
    self.assertIsNone(attempts[0].local_endpoint)
    self.assertEqual(attempts[0].peer_endpoint, "198.51.100.8:443")

  def test_all_failures_produce_no_connected_attempt(self):
    candidates = (candidate("192.0.2.1"), candidate("192.0.2.2"))
    sockets = [
      FakeSocket(connect_error=ConnectionRefusedError(errno.ECONNREFUSED, "refused")),
      FakeSocket(connect_error=OSError(errno.ENETUNREACH, "network")),
    ]
    attempts = netdoctor.attempt_connections(candidates, socket_factory=lambda *args: sockets.pop(0))
    self.assertEqual(len(attempts), 2)
    self.assertFalse(any(item.connected for item in attempts))


class RenderingTests(unittest.TestCase):
  def test_success_output_contains_required_scope_and_limits(self):
    target = netdoctor.Target("example.com", "example.com", 443, "hostname")
    resolved = candidate()
    result = netdoctor.DiagnosticResult(
      target,
      "resolved",
      None,
      (resolved,),
      (
        netdoctor.ConnectionAttempt(
          resolved,
          "connected",
          local_endpoint="192.0.2.10:40000",
          peer_endpoint="198.51.100.8:443",
        ),
      ),
    )
    output = netdoctor.render_result(result)
    for heading in (
      "Target", "Observation", "Resolution candidates", "Connection attempts", "Interpretation limits"
    ):
      self.assertIn(heading, output)
    self.assertIn("Status: connected", output)
    self.assertIn("Local endpoint: 192.0.2.10:40000", output)
    self.assertIn("sends no application data", output)
    self.assertIn("does not establish application, TLS, HTTP, service, readiness", output)

  def test_resolution_failure_and_connect_failure_are_explicit(self):
    target = netdoctor.Target("missing.invalid", "missing.invalid", 443, "hostname")
    resolution = netdoctor.DiagnosticResult(
      target, "failed", "name or address was not known", (), ()
    )
    output = netdoctor.render_result(resolution)
    self.assertIn("Name resolution: failed", output)
    self.assertIn("No TCP connection attempt was made", output)

    resolved = candidate()
    failure = netdoctor.DiagnosticResult(
      target,
      "resolved",
      None,
      (resolved,),
      (netdoctor.ConnectionAttempt(resolved, "connection refused", errno.ECONNREFUSED),),
    )
    output = netdoctor.render_result(failure)
    self.assertIn("Outcome: connection refused", output)
    self.assertIn(f"OS error number: {errno.ECONNREFUSED}", output)

  def test_numeric_target_states_no_hostname_lookup(self):
    target = netdoctor.Target("192.0.2.1", "192.0.2.1", 443, "ipv4")
    output = netdoctor.render_result(
      netdoctor.DiagnosticResult(target, "resolved", None, (candidate("192.0.2.1"),), ())
    )
    self.assertIn("Address expansion: resolved", output)
    self.assertIn("AI_NUMERICHOST requested no hostname lookup", output)

  def test_terminal_safe_rendering(self):
    value = "a\\b\n\u202ec" + chr(0xDCFF)
    self.assertEqual(netdoctor.display_safe(value), "a\\\\b\\x0a\\u202ec\\xff")


@unittest.skipUnless(hasattr(socket, "AF_INET"), "requires IPv4 sockets")
class LoopbackIntegrationTests(unittest.TestCase):
  def test_real_loopback_tcp_handshake_without_application_data(self):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.addCleanup(listener.close)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    target = netdoctor.Target("127.0.0.1", "127.0.0.1", port, "ipv4")
    result = netdoctor.diagnose(target)
    self.assertTrue(result.connected)
    self.assertEqual(result.resolution_status, "resolved")
    self.assertGreaterEqual(len(result.candidates), 1)
    self.assertEqual(result.attempts[-1].outcome, "connected")


if __name__ == "__main__":
  unittest.main()
