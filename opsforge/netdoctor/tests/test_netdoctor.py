import contextlib
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import threading
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).parents[1] / "netdoctor.py"
SPEC = importlib.util.spec_from_file_location("netdoctor", MODULE_PATH)
netdoctor = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = netdoctor
SPEC.loader.exec_module(netdoctor)
net = netdoctor.net


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
  sockaddr = (address, port) if family == socket.AF_INET else (address, port, 0, 0)
  normalized, endpoint = net.normalize_sockaddr(family, sockaddr)
  return net.Candidate(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, normalized, endpoint)


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

  def test_no_testable_candidate_is_incomplete_exit_three(self):
    resolved = candidate()
    result = netdoctor.DiagnosticResult(
      netdoctor.Target("example.com", "example.com", 443, "hostname"), "resolved", None, (resolved,),
      (netdoctor.ConnectionAttempt(resolved, "socket unavailable (EAFNOSUPPORT)"),),
    )
    with mock.patch.object(netdoctor, "diagnose", return_value=result):
      code, stdout, stderr = self.run_main(["--json", "example.com", "443"])
    self.assertEqual((code, stderr), (3, ""))
    payload = json.loads(stdout)
    self.assertEqual(payload["status"], "INCOMPLETE")
    self.assertTrue(any("could not create a socket" in item for item in payload["warnings"]))

  def test_output_failure_exits_three(self):
    resolved = candidate()
    result = netdoctor.DiagnosticResult(
      netdoctor.Target("example.com", "example.com", 443, "hostname"), "resolved", None, (resolved,),
      (netdoctor.ConnectionAttempt(resolved, "connected"),),
    )
    with tempfile.TemporaryDirectory() as directory, mock.patch.object(netdoctor, "diagnose", return_value=result):
      code, stdout, stderr = self.run_main(["--output", os.path.join(directory, "missing", "out.txt"), "example.com", "443"])
    self.assertEqual(code, 3)
    self.assertTrue(stderr.startswith("netdoctor:"))

  def test_sni_requires_tls(self):
    with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
      netdoctor.main(["example.com", "443", "--sni", "example.com"])
    self.assertEqual(caught.exception.code, 2)

  def test_expected_internal_and_interrupt_paths(self):
    with mock.patch.object(
      netdoctor, "diagnose", side_effect=netdoctor.ObservationError("resolver shape")
    ):
      self.assertEqual(
        self.run_main(["example.com", "443"]),
        (3, "", "netdoctor: resolver shape\n"),
      )
    with mock.patch.object(netdoctor, "diagnose", side_effect=net.NetworkAPIError("resolver shape")):
      self.assertEqual(self.run_main(["example.com", "443"]), (3, "", "netdoctor: resolver shape\n"))
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

  def test_a_resolver_that_never_answers_is_abandoned(self):
    release = threading.Event()
    self.addCleanup(release.set)
    target = netdoctor.Target("example.com", "example.com", 443, "hostname")
    with mock.patch.object(netdoctor, "RESOLVE_TIMEOUT_SECONDS", 0.2):
      with self.assertRaisesRegex(net.NetworkAPIError, "did not answer within 0.2 s"):
        netdoctor.diagnose(target, resolver=lambda *a: release.wait(10))

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

  def test_json_brief_and_quiet(self):
    resolved = candidate()
    result = netdoctor.DiagnosticResult(
      netdoctor.Target("example.com", "example.com", 443, "hostname"),
      "resolved", None, (resolved,),
      (netdoctor.ConnectionAttempt(resolved, "connected", duration_seconds=0.01),),
      resolution_seconds=0.02,
    )
    with mock.patch.object(netdoctor, "diagnose", return_value=result), \
         mock.patch.object(netdoctor, "resolver_context", return_value=("192.0.2.53",)), \
         mock.patch.object(netdoctor, "default_route_context", return_value="192.0.2.1 via eth0"), \
         mock.patch.object(netdoctor, "proxy_context", return_value=()):
      code, stdout, stderr = self.run_main(["--json", "example.com", "443"])
      self.assertEqual((code, stderr), (0, ""))
      payload = json.loads(stdout)
      self.assertEqual(payload["tool"], "netdoctor")
      self.assertEqual(payload["observations"]["stage"], "tcp")
      self.assertIn("Stage: TCP", self.run_main(["--brief", "example.com", "443"])[1])
      self.assertEqual(self.run_main(["--quiet", "example.com", "443"])[1], "")


class TargetTests(unittest.TestCase):
  def test_port_boundaries(self):
    for value, expected in (("1", 1), ("443", 443), ("065535", 65535)):
      with self.subTest(value=value):
        self.assertEqual(netdoctor.parse_port(value), expected)

  def test_timeout_and_retries_are_plain_decimals(self):
    self.assertEqual(netdoctor.parse_timeout(".5"), 0.5)
    for value in ("0.05", "31", "1e0", "+1", "nan", ""):
      with self.subTest(value=value), self.assertRaises(netdoctor.argparse.ArgumentTypeError):
        netdoctor.parse_timeout(value)
    for value in ("-1", "4", "x", "\u0661"):
      with self.subTest(retries=value), self.assertRaises(netdoctor.argparse.ArgumentTypeError):
        netdoctor.parse_retries(value)


class DiagnoseTests(unittest.TestCase):
  TARGET = netdoctor.Target("example.com", "example.com", 443, "hostname")

  def test_resolution_failures_are_useful_negative_evidence(self):
    error = socket.gaierror(socket.EAI_NONAME, "no name")
    result = netdoctor.diagnose(self.TARGET, resolver=mock.Mock(side_effect=error))
    self.assertEqual(result.resolution_status, "failed")
    self.assertIn("not known", result.resolution_detail)
    self.assertFalse(result.connected)
    self.assertEqual(result.candidates, ())

  def test_resolver_api_failure_is_not_a_negative_answer(self):
    with self.assertRaises(net.NetworkAPIError):
      netdoctor.diagnose(self.TARGET, resolver=mock.Mock(side_effect=OSError("boom")))

  def test_temporary_resolver_failures_are_not_an_unreachable_answer(self):
    for code in (socket.EAI_AGAIN, socket.EAI_FAIL):
      with self.subTest(code=code), self.assertRaises(net.NetworkAPIError):
        netdoctor.diagnose(self.TARGET, resolver=mock.Mock(side_effect=socket.gaierror(code, "temporary")))

  def test_over_limit_candidates_add_a_note(self):
    records = [
      (socket.AF_INET, socket.SOCK_STREAM, 6, "", (f"192.0.2.{index}", 443))
      for index in range(1, net.MAX_CANDIDATES + 2)
    ]
    refused = lambda *args: FakeSocket(connect_error=ConnectionRefusedError(errno.ECONNREFUSED, "refused"))
    result = netdoctor.diagnose(self.TARGET, resolver=lambda *args: records, socket_factory=refused)
    self.assertEqual((len(result.candidates), len(result.attempts)), (net.MAX_CANDIDATES, net.MAX_CANDIDATES))
    self.assertEqual(len(result.notes), 1)
    self.assertIn(f"only the first {net.MAX_CANDIDATES}", result.notes[0])

  def test_retries_repeat_rounds_until_a_connection_succeeds(self):
    sockets = [
      FakeSocket(connect_error=ConnectionRefusedError(errno.ECONNREFUSED, "refused")),
      FakeSocket(),
    ]
    records = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 443))]
    result = netdoctor.diagnose(
      self.TARGET, resolver=lambda *args: records, socket_factory=lambda *args: sockets.pop(0), retries=3,
    )
    self.assertEqual((result.retries, [item.outcome for item in result.attempts]), (1, ["connection refused", "connected"]))


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

  def test_socket_creation_failure_is_an_attempt_and_timeout_setup_is_fatal(self):
    fallback = FakeSocket()
    sockets = [OSError(errno.EAFNOSUPPORT, "no ipv6"), fallback]
    def factory(*args):
      item = sockets.pop(0)
      if isinstance(item, Exception):
        raise item
      return item
    attempts = netdoctor.attempt_connections(
      (candidate("2001:db8::1", family=socket.AF_INET6), candidate()), socket_factory=factory,
    )
    self.assertEqual([item.outcome for item in attempts], ["socket unavailable (EAFNOSUPPORT)", "connected"])
    fake = FakeSocket()
    fake.settimeout = mock.Mock(side_effect=OSError("failed"))
    with self.assertRaises(net.NetworkAPIError):
      netdoctor.attempt_connections((candidate(),), socket_factory=lambda *args: fake)
    self.assertTrue(fake.closed)

  def test_ssl_errors_are_not_permission_denied(self):
    outcome, number = net.classify_connect_error(ssl.SSLError(1, "[SSL: WRONG_VERSION_NUMBER] wrong version number"))
    self.assertTrue(outcome.startswith("TLS protocol error"))
    self.assertIsNone(number)

    class Context:
      check_hostname = True
      verify_mode = None
      def wrap_socket(self, sock, server_hostname=None):
        raise ssl.SSLError(1, "[SSL: WRONG_VERSION_NUMBER] wrong version number")
    status, *_ = netdoctor.tls_handshake(
      candidate(), timeout=1.0, sni_name="example.com",
      socket_factory=lambda *args: FakeSocket(), context_factory=Context,
    )
    self.assertTrue(status.startswith("failed: TLS protocol error"), status)

  def test_tls_reconnect_failure_is_reported_and_missing_socket_is_fatal(self):
    refused = FakeSocket(connect_error=ConnectionRefusedError(errno.ECONNREFUSED, "refused"))
    status, version, cipher, seconds = netdoctor.tls_handshake(
      candidate(), timeout=1.0, sni_name=None, socket_factory=lambda *args: refused,
    )
    self.assertEqual((status, version, cipher, seconds), ("failed: TCP reconnect for TLS failed (connection refused)", None, None, 0.0))

    def no_socket(*args):
      raise OSError(errno.EAFNOSUPPORT, "no ipv6")
    with self.assertRaises(netdoctor.ObservationError):
      netdoctor.tls_handshake(candidate(), timeout=1.0, sni_name=None, socket_factory=no_socket)

  def test_context_files_follow_symlinks_but_refuse_fifos(self):
    with tempfile.TemporaryDirectory() as directory:
      real = Path(directory, "stub-resolv.conf")
      real.write_text("nameserver 127.0.0.53\n")
      link = Path(directory, "resolv.conf")
      link.symlink_to(real)
      fifo = Path(directory, "fifo")
      os.mkfifo(fifo)
      self.assertIn("127.0.0.53", netdoctor.read_bounded_text(str(link)))
      self.assertIsNone(netdoctor.read_bounded_text(str(fifo)))

  def test_default_route_ignores_split_routes_and_prefers_lowest_metric(self):
    table = (
      "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
      "tun0\t00000000\t0100080A\t0003\t0\t0\t0\t00000080\t0\t0\t0\n"
      "eth1\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"
      "eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
    )
    with tempfile.TemporaryDirectory() as directory:
      path = Path(directory, "route")
      path.write_text(table)
      context = netdoctor.default_route_context(str(path), netdoctor.parse_ipv4_default_routes)
      self.assertEqual(context, "192.168.2.1 via eth0")
      self.assertIsNone(netdoctor.default_route_context(str(Path(directory, "missing")), netdoctor.parse_ipv4_default_routes))

  def test_device_only_default_route_has_no_gateway(self):
    table = (
      "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
      "wg0\t00000000\t00000000\t0001\t0\t0\t50\t00000000\t0\t0\t0\n"
    )
    with tempfile.TemporaryDirectory() as directory:
      path = Path(directory, "route")
      path.write_text(table)
      context = netdoctor.default_route_context(str(path), netdoctor.parse_ipv4_default_routes)
    self.assertEqual(context, "direct via wg0 (no gateway)")

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

  def test_attempt_duration_and_all_family_mode(self):
    sockets = [FakeSocket(), FakeSocket()]
    times = iter((1.0, 1.1, 2.0, 2.2))
    attempts = netdoctor.attempt_connections(
      (candidate("192.0.2.1"), candidate("2001:db8::1", family=socket.AF_INET6)),
      socket_factory=lambda *args: sockets.pop(0), stop_on_success=False,
      monotonic_fn=lambda: next(times),
    )
    self.assertEqual(len(attempts), 2)
    self.assertAlmostEqual(attempts[0].duration_seconds, 0.1)


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
