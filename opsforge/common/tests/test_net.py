import errno
import socket
import ssl
import threading
import time
import unittest
from unittest import mock

from opsforge.common import net


def record(family, address, port=443, *extra):
  sockaddr = (address, port) if family == socket.AF_INET else (address, port, *(extra or (0, 0)))
  return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)


def candidate(address="192.0.2.1", port=443, family=socket.AF_INET):
  sockaddr = (address, port) if family == socket.AF_INET else (address, port, 0, 0)
  normalized, endpoint = net.normalize_sockaddr(family, sockaddr)
  return net.Candidate(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, normalized, endpoint)


class FakeSocket:
  def __init__(self, error=None):
    self.error = error
    self.timeout = None
    self.closed = False

  def settimeout(self, value):
    self.timeout = value

  def connect(self, sockaddr):
    if self.error is not None:
      raise self.error

  def close(self):
    self.closed = True


class ParseHostTests(unittest.TestCase):
  def test_hostnames_and_canonical_literals(self):
    self.assertEqual(net.parse_host("example.com"), ("example.com", "hostname"))
    self.assertEqual(net.parse_host("EXAMPLE.COM."), ("EXAMPLE.COM.", "hostname"))
    self.assertEqual(net.parse_host("localhost"), ("localhost", "hostname"))
    self.assertEqual(net.parse_host("192.0.2.1"), ("192.0.2.1", "ipv4"))
    self.assertEqual(net.parse_host("2001:0db8::1"), ("2001:db8::1", "ipv6"))

  def test_bad_forms_are_rejected(self):
    values = (
      "", " ", "bad name", "bad\nname", "bad\u202ename", "[::1]", "::1]", "fe80::1%3", "a_b", "-bad", "bad-",
      "a..b", ".", "\u00e9.example", "fa\u00df.de", "a" * 64 + ".example", ("a." * 130) + "com",
    )
    for value in values:
      with self.subTest(value=value), self.assertRaises(net.HostError):
        net.parse_host(value)

  def test_lenient_ipv4_spellings_are_not_hostnames(self):
    for value in ("127.1", "010.0.0.1", "0x7f.1", "1.2.3", "2130706433", "example.0x1f"):
      with self.subTest(value=value), self.assertRaises(net.HostError):
        net.parse_host(value)
    self.assertEqual(net.parse_host("1example.com"), ("1example.com", "hostname"))

  def test_label_is_used_in_messages(self):
    with self.assertRaisesRegex(net.HostError, "^certificate host must not be empty$"):
      net.parse_host("", "certificate host")

  def test_sni_names(self):
    self.assertEqual(net.sni_name("example.com.", "hostname"), "example.com")
    self.assertIsNone(net.sni_name("192.0.2.1", "ipv4"))
    self.assertEqual(net.parse_sni("Api.Example.com."), "Api.Example.com")
    for value in ("192.0.2.1", "::1", "bad name", ""):
      with self.subTest(value=value), self.assertRaises(net.HostError):
        net.parse_sni(value)

  def test_endpoint_formatting(self):
    self.assertEqual(net.format_endpoint("192.0.2.1", 443), "192.0.2.1:443")
    self.assertEqual(net.format_endpoint("2001:db8::1", 443), "[2001:db8::1]:443")
    self.assertEqual(net.format_endpoint("fe80::1", 443, 3), "[fe80::1%3]:443")


class NormalizeSockaddrTests(unittest.TestCase):
  def test_valid_addresses(self):
    self.assertEqual(net.normalize_sockaddr(socket.AF_INET, ("192.0.2.1", 80)), (("192.0.2.1", 80), "192.0.2.1:80"))
    sockaddr, endpoint = net.normalize_sockaddr(socket.AF_INET6, ("2001:0DB8::1", 80, 0, 4))
    self.assertEqual((sockaddr, endpoint), (("2001:db8::1", 80, 0, 4), "[2001:db8::1%4]:80"))

  def test_malformed_addresses_are_api_errors(self):
    cases = (
      (socket.AF_UNIX, ("x", 80)), (socket.AF_INET, ("192.0.2.1",)), (socket.AF_INET, ("192.0.2.1", 0)),
      (socket.AF_INET, ("192.0.2.1", 70000)), (socket.AF_INET, ("192.0.2.1", True)), (socket.AF_INET, (b"192.0.2.1", 80)),
      (socket.AF_INET, ("not-an-ip", 80)), (socket.AF_INET, ("::1", 80)), (socket.AF_INET6, ("192.0.2.1", 80, 0, 0)),
      (socket.AF_INET6, ("::1", 80)), (socket.AF_INET6, ("::1", 80, -1, 0)), (socket.AF_INET, "192.0.2.1:80"),
    )
    for family, sockaddr in cases:
      with self.subTest(family=family, sockaddr=sockaddr), self.assertRaises(net.NetworkAPIError):
        net.normalize_sockaddr(family, sockaddr)


class ResolveTcpTests(unittest.TestCase):
  def test_request_shape_order_and_scope(self):
    calls = []
    records = [
      record(socket.AF_INET6, "2001:db8::1"), record(socket.AF_INET, "192.0.2.1"), record(socket.AF_INET6, "fe80::1", 443, 0, 4),
    ]

    def resolver(*arguments):
      calls.append(arguments)
      return records

    result = net.resolve_tcp("example.com", 443, "hostname", resolver=resolver)
    self.assertEqual(calls, [("example.com", 443, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, 0)])
    self.assertEqual([item.endpoint for item in result.candidates], ["[2001:db8::1]:443", "192.0.2.1:443", "[fe80::1%4]:443"])
    self.assertEqual((result.failure, result.truncated), (None, False))
    self.assertEqual([item.family_name for item in result.candidates], ["ipv6", "ipv4", "ipv6"])

  def test_ip_literals_never_query_dns(self):
    calls = []
    net.resolve_tcp("192.0.2.1", 80, "ipv4", resolver=lambda *a: calls.append(a) or [record(socket.AF_INET, "192.0.2.1", 80)])
    self.assertEqual(calls[0][-1], socket.AI_NUMERICHOST)

  def test_duplicates_are_suppressed_in_first_seen_order(self):
    first, second = record(socket.AF_INET, "192.0.2.1"), record(socket.AF_INET6, "2001:db8::1")
    result = net.resolve_tcp("example.com", 443, "hostname", resolver=lambda *a: [first, first, second, first, second])
    self.assertEqual([item.endpoint for item in result.candidates], ["192.0.2.1:443", "[2001:db8::1]:443"])

  def test_more_than_the_limit_is_truncated(self):
    records = [record(socket.AF_INET, f"192.0.2.{index}") for index in range(1, net.MAX_CANDIDATES + 3)]
    result = net.resolve_tcp("example.com", 443, "hostname", resolver=lambda *a: records)
    self.assertEqual((len(result.candidates), result.truncated), (net.MAX_CANDIDATES, True))
    exact = net.resolve_tcp("example.com", 443, "hostname", resolver=lambda *a: records[:net.MAX_CANDIDATES])
    self.assertEqual((len(exact.candidates), exact.truncated), (net.MAX_CANDIDATES, False))

  def test_negative_answers_are_failures_not_errors(self):
    for code in (socket.EAI_NONAME, socket.EAI_NODATA):
      with self.subTest(code=code):
        result = net.resolve_tcp("x.invalid", 443, "hostname", resolver=mock.Mock(side_effect=socket.gaierror(code, "text")))
        self.assertEqual(result.candidates, ())
        self.assertEqual(result.failure, net.NEGATIVE_RESOLVER_ANSWERS[code])

  def test_temporary_and_nonrecoverable_resolver_failures_are_not_negative_answers(self):
    for code in (socket.EAI_AGAIN, socket.EAI_FAIL):
      with self.subTest(code=code), self.assertRaisesRegex(net.NetworkAPIError, "OS resolver failed"):
        net.resolve_tcp("x.invalid", 443, "hostname", resolver=mock.Mock(side_effect=socket.gaierror(code, "text")))

  def test_api_failures_and_malformed_results_are_errors(self):
    with self.assertRaises(net.NetworkAPIError):
      net.resolve_tcp("x", 443, "hostname", resolver=mock.Mock(side_effect=socket.gaierror(socket.EAI_MEMORY, "memory")))
    with self.assertRaises(net.NetworkAPIError):
      net.resolve_tcp("x", 443, "hostname", resolver=mock.Mock(side_effect=OSError("boom")))
    bad_results = (
      [], None, "text",
      [(socket.AF_UNIX, socket.SOCK_STREAM, 0, "", ("x", 443))],
      [(socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("192.0.2.1", 443))],
      [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 80))],
      [(socket.AF_INET, socket.SOCK_STREAM, 6, "")],
      [(socket.AF_INET, socket.SOCK_STREAM, True, "", ("192.0.2.1", 443))],
    )
    for result in bad_results:
      with self.subTest(result=result), self.assertRaises(net.NetworkAPIError):
        net.resolve_tcp("x", 443, "hostname", resolver=lambda *a, result=result: result)

  def test_a_resolver_that_never_answers_is_abandoned_after_the_timeout(self):
    release = threading.Event()
    self.addCleanup(release.set)
    started = time.monotonic()
    with self.assertRaisesRegex(net.NetworkAPIError, "did not answer within 0.2 s"):
      net.resolve_tcp("x", 443, "hostname", resolver=lambda *a: release.wait(10), timeout=0.2)
    self.assertLess(time.monotonic() - started, 5)

  def test_a_bounded_resolver_still_reports_answers_and_failures(self):
    result = net.resolve_tcp("example.com", 443, "hostname", resolver=lambda *a: [record(socket.AF_INET, "192.0.2.1")], timeout=5)
    self.assertEqual([item.endpoint for item in result.candidates], ["192.0.2.1:443"])
    gone = mock.Mock(side_effect=socket.gaierror(socket.EAI_NONAME, "text"))
    self.assertEqual(net.resolve_tcp("x.invalid", 443, "hostname", resolver=gone, timeout=5).failure, net.NEGATIVE_RESOLVER_ANSWERS[socket.EAI_NONAME])
    with self.assertRaises(net.NetworkAPIError):
      net.resolve_tcp("x", 443, "hostname", resolver=mock.Mock(side_effect=OSError("boom")), timeout=5)

  def test_real_os_resolver_for_loopback_literals(self):
    result = net.resolve_tcp("127.0.0.1", 9, "ipv4")
    self.assertEqual([item.endpoint for item in result.candidates], ["127.0.0.1:9"])


class ClassifyConnectErrorTests(unittest.TestCase):
  def test_errno_classes(self):
    cases = (
      (ConnectionRefusedError(errno.ECONNREFUSED, "x"), "connection refused"),
      (ConnectionResetError(errno.ECONNRESET, "x"), "connection reset"),
      (OSError(errno.EHOSTUNREACH, "x"), "host unreachable"),
      (OSError(errno.ENETUNREACH, "x"), "network unreachable"),
      (PermissionError(errno.EACCES, "x"), "permission denied"),
      (OSError(errno.EPERM, "x"), "permission denied"),
      (socket.timeout("x"), "timed out"),
      (OSError(errno.ETIMEDOUT, "x"), "timed out"),
      (OSError(errno.EIO, "x"), "connection error"),
    )
    for error, outcome in cases:
      with self.subTest(outcome=outcome, error=error):
        self.assertEqual(net.classify_connect_error(error)[0], outcome)

  def test_tls_errors_are_never_os_errors(self):
    # A plaintext server makes a real handshake fail; SSL_ERROR_SSL is 1, the same number as EPERM.
    with socket.socket() as listener:
      listener.bind(("127.0.0.1", 0))
      listener.listen()

      def serve():
        connection, _ = listener.accept()
        with connection:
          connection.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
          connection.recv(1)

      worker = threading.Thread(target=serve)
      worker.start()
      client = socket.create_connection(listener.getsockname(), timeout=5)
      context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
      context.check_hostname = False
      context.verify_mode = ssl.CERT_NONE
      with client, self.assertRaises(ssl.SSLError) as caught:
        context.wrap_socket(client)
      worker.join(5)
    outcome, number = net.classify_connect_error(caught.exception)
    self.assertTrue(outcome.startswith("TLS protocol error ("), outcome)
    self.assertNotIn("permission", outcome)
    self.assertNotIn("SSLError", outcome)
    self.assertIsNone(number)


class ConnectFirstTests(unittest.TestCase):
  def test_requires_a_timeout_or_deadline(self):
    with self.assertRaises(ValueError):
      net.connect_first((candidate(),))

  def test_first_reachable_candidate_wins_and_stays_open(self):
    sockets = [FakeSocket(socket.timeout()), FakeSocket(), FakeSocket()]
    pool = list(sockets)
    client, attempts = net.connect_first(
      (candidate("192.0.2.1"), candidate("192.0.2.2"), candidate("192.0.2.3")), timeout=2.0,
      socket_factory=lambda *a: pool.pop(0),
    )
    self.assertIs(client, sockets[1])
    self.assertEqual([item.outcome for item in attempts], ["timed out", net.CONNECTED])
    self.assertEqual((sockets[0].closed, sockets[1].closed, sockets[2].closed), (True, False, False))
    self.assertEqual(sockets[0].timeout, 2.0)

  def test_socket_creation_failure_is_recorded_and_skipped(self):
    def factory(family, *args):
      if family == socket.AF_INET6:
        raise OSError(errno.EAFNOSUPPORT, "no ipv6")
      return FakeSocket()
    client, attempts = net.connect_first(
      (candidate("2001:db8::1", family=socket.AF_INET6), candidate()), timeout=1.0, socket_factory=factory,
    )
    self.assertIsNotNone(client)
    self.assertEqual([item.outcome for item in attempts], ["socket unavailable (EAFNOSUPPORT)", net.CONNECTED])
    self.assertTrue(attempts[0].socket_unavailable)

  def test_all_candidates_failing_returns_no_socket(self):
    pool = [FakeSocket(ConnectionRefusedError(errno.ECONNREFUSED, "x")), FakeSocket(OSError(errno.ENETUNREACH, "x"))]
    client, attempts = net.connect_first((candidate(), candidate("192.0.2.2")), timeout=1.0, socket_factory=lambda *a: pool.pop(0))
    self.assertIsNone(client)
    self.assertEqual([item.outcome for item in attempts], ["connection refused", "network unreachable"])

  def test_deadline_caps_each_timeout_and_expires(self):
    now = [0.0]
    sockets = [FakeSocket(socket.timeout()), FakeSocket(socket.timeout())]
    pool = list(sockets)

    def factory(*args):
      return pool.pop(0)

    def clock():
      now[0] += 1.0
      return now[0]

    with self.assertRaisesRegex(TimeoutError, "deadline"):
      net.connect_first(
        (candidate(), candidate("192.0.2.2"), candidate("192.0.2.3")), timeout=5.0, deadline=3.0,
        socket_factory=factory, clock=clock,
      )
    self.assertEqual(sockets[0].timeout, 2.0)
    self.assertEqual(sockets[1].timeout, 1.0)
    self.assertTrue(sockets[0].closed and sockets[1].closed)

  def test_keyboard_interrupt_closes_the_socket(self):
    fake = FakeSocket(KeyboardInterrupt())
    with self.assertRaises(KeyboardInterrupt):
      net.connect_first((candidate(),), timeout=1.0, socket_factory=lambda *a: fake)
    self.assertTrue(fake.closed)

  def test_timeout_that_cannot_be_applied_is_an_api_error(self):
    fake = FakeSocket()
    fake.settimeout = mock.Mock(side_effect=OSError("failed"))
    with self.assertRaises(net.NetworkAPIError):
      net.connect_first((candidate(),), timeout=1.0, socket_factory=lambda *a: fake)
    self.assertTrue(fake.closed)


class LoopbackTests(unittest.TestCase):
  def test_real_connection_and_real_refusal(self):
    with socket.socket() as listener:
      listener.bind(("127.0.0.1", 0))
      listener.listen()
      port = listener.getsockname()[1]
      client, attempts = net.connect_first((candidate("127.0.0.1", port),), timeout=2.0)
      self.assertIsNotNone(client)
      with client:
        self.assertEqual(client.getpeername(), ("127.0.0.1", port))
      self.assertEqual([item.outcome for item in attempts], [net.CONNECTED])
    # The listener is closed now, so the same port refuses.
    client, attempts = net.connect_first((candidate("127.0.0.1", port),), timeout=2.0)
    self.assertIsNone(client)
    self.assertEqual((attempts[0].outcome, attempts[0].error_number), ("connection refused", errno.ECONNREFUSED))


if __name__ == "__main__":
  unittest.main()
