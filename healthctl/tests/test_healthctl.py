import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "healthctl.py"
SPEC = importlib.util.spec_from_file_location("healthctl_module", MODULE_PATH)
healthctl = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = healthctl
SPEC.loader.exec_module(healthctl)


class FakeUsage:
  def __init__(self, total, free):
    self.total = total
    self.used = total - free
    self.free = free


class FakeSocket:
  def __init__(self, connect_error=None, timeout_error=None):
    self.connect_error = connect_error
    self.timeout_error = timeout_error
    self.timeout = None
    self.connected_to = None
    self.closed = False

  def settimeout(self, timeout):
    if self.timeout_error:
      raise self.timeout_error
    self.timeout = timeout

  def connect(self, sockaddr):
    self.connected_to = sockaddr
    if self.connect_error:
      raise self.connect_error

  def close(self):
    self.closed = True


class HealthCtlTests(unittest.TestCase):
  def valid_document(self):
    return {
      "version": 1,
      "checks": [
        {
          "name": "root-space",
          "type": "disk_free_percent",
          "path": "/",
          "minimum_free_percent": 10,
        },
        {
          "name": "api-tcp",
          "type": "tcp_connect",
          "host": "127.0.0.1",
          "port": 8080,
          "timeout_seconds": 0.5,
        },
      ],
    }

  def test_parse_valid_config(self):
    config = healthctl.parse_config_document(self.valid_document(), path="health.json")
    self.assertEqual(len(config.checks), 2)
    self.assertIsInstance(config.checks[0], healthctl.DiskFreeCheck)
    self.assertIsInstance(config.checks[1], healthctl.TcpConnectCheck)
    self.assertEqual(config.checks[1].timeout_seconds, 0.5)

  def test_tcp_timeout_defaults(self):
    document = self.valid_document()
    del document["checks"][1]["timeout_seconds"]
    config = healthctl.parse_config_document(document, path="health.json")
    self.assertEqual(config.checks[1].timeout_seconds, 1.0)

  def test_rejects_unknown_root_field(self):
    document = self.valid_document()
    document["extra"] = True
    with self.assertRaisesRegex(healthctl.ConfigError, "unsupported field"):
      healthctl.parse_config_document(document, path="health.json")

  def test_rejects_wrong_version(self):
    document = self.valid_document()
    document["version"] = 2
    with self.assertRaisesRegex(healthctl.ConfigError, "integer 1"):
      healthctl.parse_config_document(document, path="health.json")

  def test_rejects_empty_checks(self):
    with self.assertRaisesRegex(healthctl.ConfigError, "at least one"):
      healthctl.parse_config_document({"version": 1, "checks": []}, path="x")

  def test_rejects_too_many_checks(self):
    checks = [
      {"name": f"c{i}", "type": "disk_free_percent", "path": "/", "minimum_free_percent": 1}
      for i in range(33)
    ]
    with self.assertRaisesRegex(healthctl.ConfigError, "32-check"):
      healthctl.parse_config_document({"version": 1, "checks": checks}, path="x")

  def test_rejects_duplicate_names(self):
    document = self.valid_document()
    document["checks"][1]["name"] = "root-space"
    with self.assertRaisesRegex(healthctl.ConfigError, "duplicate check name"):
      healthctl.parse_config_document(document, path="x")

  def test_rejects_invalid_check_name(self):
    document = self.valid_document()
    document["checks"][0]["name"] = "bad name"
    with self.assertRaisesRegex(healthctl.ConfigError, "1-64 ASCII"):
      healthctl.parse_config_document(document, path="x")

  def test_rejects_unknown_check_type(self):
    document = self.valid_document()
    document["checks"][0] = {"name": "shell", "type": "command", "command": "true"}
    with self.assertRaisesRegex(healthctl.ConfigError, "unsupported in V1"):
      healthctl.parse_config_document(document, path="x")

  def test_parses_extended_checks_and_common_fields(self):
    document = {
      "version": 1,
      "max_workers": 2,
      "checks": [
        {"name": "web", "type": "https", "url": "https://example.com/health", "severity": "WARN", "retries": 2},
        {"name": "hash", "type": "config_hash", "path": "/etc/hosts", "sha256": "0" * 64, "depends_on": ["web"]},
      ],
    }
    config = healthctl.parse_config_document(document, path="health.json")
    self.assertEqual(config.max_workers, 2)
    self.assertEqual(config.checks[0].severity, "WARN")
    self.assertEqual(config.checks[0].retries, 2)
    self.assertEqual(config.checks[1].depends_on, ("web",))

  def test_http_url_rejects_credentials_queries_and_downgrade_redirects(self):
    for url in ("https://user@example.com/", "https://example.com/?token=secret"):
      document = {"version": 1, "checks": [{"name": "web", "type": "https", "url": url}]}
      with self.subTest(url=url), self.assertRaises(healthctl.ConfigError):
        healthctl.parse_config_document(document, path="x")
    handler = healthctl.LimitedRedirectHandler()
    request = healthctl.urllib.request.Request("https://example.com/start")
    with self.assertRaises(healthctl.RedirectPolicyError):
      handler.redirect_request(request, None, 302, "", {}, "http://example.com/next")
    with self.assertRaises(healthctl.RedirectPolicyError):
      healthctl.validate_redirect_url("https://example.com/start", "/next?token=secret")

  def test_http_head_is_proxy_free_redirect_bounded_and_uses_total_deadline(self):
    record = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 80))
    responses = [
      b"HTTP/1.1 302 Found\r\nLocation: /ready\r\nContent-Length: 0\r\n\r\n",
      b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
    ]
    sockets = []
    class FakeSocket:
      def __init__(self, response): self.response = response; self.sent = b""; self.closed = False
      def settimeout(self, value): self.timeout = value
      def connect(self, address): self.address = address
      def sendall(self, data): self.sent += data
      def recv(self, size):
        value, self.response = self.response[:size], self.response[size:]
        return value
      def close(self): self.closed = True
    def factory(*args):
      value = FakeSocket(responses[len(sockets)])
      sockets.append(value)
      return value
    check = healthctl.GenericCheck("web", "http", "http://example.com/start", 1.0)
    with mock.patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:9"}), mock.patch.object(
      healthctl.urllib.request, "build_opener", side_effect=AssertionError("proxy opener used"),
    ):
      status = healthctl.run_http_head(
        check, resolver=lambda *args: [record], socket_factory=factory, clock=lambda: 0.0,
      )
    self.assertEqual(status, 204)
    self.assertEqual(len(sockets), 2)
    self.assertIn(b"HEAD /ready HTTP/1.1", sockets[1].sent)
    self.assertTrue(all(item.closed for item in sockets))

    now = [0.0]
    class SlowSocket(FakeSocket):
      def recv(self, size):
        now[0] += 0.6
        return b"H"
    with self.assertRaisesRegex(TimeoutError, "total deadline"):
      healthctl.run_http_head(
        check, resolver=lambda *args: [record], socket_factory=lambda *args: SlowSocket(b""),
        clock=lambda: now[0],
      )

    oversized = b"HTTP/1.1 200 OK\r\nX-Fill: " + (b"a" * healthctl.MAX_HTTP_HEADER_BYTES)
    with self.assertRaisesRegex(healthctl.ObservationError, "64 KiB"):
      healthctl.run_http_head(
        check, resolver=lambda *args: [record],
        socket_factory=lambda *args: FakeSocket(oversized), clock=lambda: 0.0,
      )

  def test_rejects_dependency_cycle(self):
    document = {
      "version": 1,
      "checks": [
        {"name": "a", "type": "file_exists", "path": "/a", "depends_on": ["b"]},
        {"name": "b", "type": "file_exists", "path": "/b", "depends_on": ["a"]},
      ],
    }
    with self.assertRaisesRegex(healthctl.ConfigError, "cycle"):
      healthctl.parse_config_document(document, path="x")

  def test_rejects_unknown_check_field(self):
    document = self.valid_document()
    document["checks"][0]["surprise"] = 1
    with self.assertRaisesRegex(healthctl.ConfigError, "unsupported field"):
      healthctl.parse_config_document(document, path="x")

  def test_rejects_invalid_percent(self):
    document = self.valid_document()
    document["checks"][0]["minimum_free_percent"] = 101
    with self.assertRaisesRegex(healthctl.ConfigError, "0 through 100"):
      healthctl.parse_config_document(document, path="x")

  def test_rejects_boolean_percent(self):
    document = self.valid_document()
    document["checks"][0]["minimum_free_percent"] = True
    with self.assertRaisesRegex(healthctl.ConfigError, "JSON number"):
      healthctl.parse_config_document(document, path="x")

  def test_rejects_invalid_port(self):
    document = self.valid_document()
    document["checks"][1]["port"] = 70000
    with self.assertRaisesRegex(healthctl.ConfigError, "1 through 65535"):
      healthctl.parse_config_document(document, path="x")

  def test_rejects_timeout_outside_bounds(self):
    document = self.valid_document()
    document["checks"][1]["timeout_seconds"] = 10
    with self.assertRaisesRegex(healthctl.ConfigError, "0.1 through 5.0"):
      healthctl.parse_config_document(document, path="x")

  def test_parse_hostname_and_ip_literals(self):
    self.assertEqual(healthctl.parse_host("example.com", "host"), ("example.com", "hostname"))
    self.assertEqual(healthctl.parse_host("127.0.0.1", "host"), ("127.0.0.1", "ipv4"))
    host, kind = healthctl.parse_host("2001:db8::1", "host")
    self.assertEqual(kind, "ipv6")
    self.assertEqual(host, "2001:db8::1")

  def test_rejects_bracketed_or_unicode_host(self):
    with self.assertRaises(healthctl.ConfigError):
      healthctl.parse_host("[::1]", "host")
    with self.assertRaises(healthctl.ConfigError):
      healthctl.parse_host("exämple.com", "host")

  def test_load_config_from_regular_file(self):
    with tempfile.TemporaryDirectory() as tempdir:
      path = Path(tempdir) / "health.json"
      path.write_text(json.dumps(self.valid_document()), encoding="utf-8")
      config = healthctl.load_config(str(path))
      self.assertEqual(len(config.checks), 2)
      self.assertEqual(config.path, str(path.resolve()))

  @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "requires O_NOFOLLOW")
  def test_rejects_final_symlink_config(self):
    with tempfile.TemporaryDirectory() as tempdir:
      real = Path(tempdir) / "real.json"
      link = Path(tempdir) / "link.json"
      real.write_text(json.dumps(self.valid_document()), encoding="utf-8")
      link.symlink_to(real)
      with self.assertRaisesRegex(healthctl.ConfigError, "symlink"):
        healthctl.load_config(str(link))

  def test_rejects_non_regular_config(self):
    with tempfile.TemporaryDirectory() as tempdir:
      with self.assertRaisesRegex(healthctl.ConfigError, "regular file"):
        healthctl.load_config(tempdir)

  def test_rejects_oversized_config(self):
    with tempfile.TemporaryDirectory() as tempdir:
      path = Path(tempdir) / "big.json"
      path.write_bytes(b"x" * (healthctl.CONFIG_MAX_BYTES + 1))
      with self.assertRaisesRegex(healthctl.ConfigError, "65536-byte"):
        healthctl.load_config(str(path))

  def test_rejects_invalid_utf8(self):
    with tempfile.TemporaryDirectory() as tempdir:
      path = Path(tempdir) / "bad.json"
      path.write_bytes(b"\xff")
      with self.assertRaisesRegex(healthctl.ConfigError, "UTF-8"):
        healthctl.load_config(str(path))

  def test_rejects_duplicate_json_object_fields(self):
    with tempfile.TemporaryDirectory() as tempdir:
      path = Path(tempdir) / "duplicate.json"
      path.write_text('{"version":1,"version":1,"checks":[]}', encoding="utf-8")
      with self.assertRaisesRegex(healthctl.ConfigError, "duplicate object field"):
        healthctl.load_config(str(path))

  def test_rejects_invalid_json_with_location(self):
    with tempfile.TemporaryDirectory() as tempdir:
      path = Path(tempdir) / "bad.json"
      path.write_text("{", encoding="utf-8")
      with self.assertRaisesRegex(healthctl.ConfigError, "line 1, column 2"):
        healthctl.load_config(str(path))

  def test_disk_check_passes_and_fails_at_threshold(self):
    check = healthctl.DiskFreeCheck("disk", "/", 25.0)
    passed = healthctl.run_disk_check(check, disk_usage=lambda _: FakeUsage(1000, 250))
    failed = healthctl.run_disk_check(check, disk_usage=lambda _: FakeUsage(1000, 249))
    self.assertEqual(passed.status, "PASS")
    self.assertEqual(failed.status, "FAIL")
    self.assertIn("25.00%", passed.evidence)

  def test_disk_check_returns_error_when_path_unobservable(self):
    check = healthctl.DiskFreeCheck("disk", "/missing", 10)
    result = healthctl.run_disk_check(check, disk_usage=lambda _: (_ for _ in ()).throw(FileNotFoundError()))
    self.assertEqual(result.status, "ERROR")

  def test_disk_check_rejects_invalid_api_values(self):
    check = healthctl.DiskFreeCheck("disk", "/", 10)
    with self.assertRaises(healthctl.ObservationError):
      healthctl.run_disk_check(check, disk_usage=lambda _: FakeUsage(0, 0))

  def ipv4_record(self, address="127.0.0.1", port=8080):
    return (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port))

  def test_resolver_deduplicates_candidates(self):
    check = healthctl.TcpConnectCheck("tcp", "localhost", "hostname", 8080, 1)
    records = [self.ipv4_record(), self.ipv4_record()]
    candidates = healthctl.resolve_tcp_candidates(check, resolver=lambda *args: records)
    self.assertEqual(len(candidates), 1)

  def test_resolver_normal_failure_is_useful_fail(self):
    check = healthctl.TcpConnectCheck("tcp", "example.invalid", "hostname", 8080, 1)
    def resolver(*args):
      raise socket.gaierror(getattr(socket, "EAI_NONAME", -2), "no")
    result = healthctl.run_tcp_check(check, resolver=resolver)
    self.assertEqual(result.status, "FAIL")
    self.assertIn("no usable TCP candidate", result.evidence)

  def test_resolver_rejects_family_address_mismatch(self):
    check = healthctl.TcpConnectCheck("tcp", "localhost", "hostname", 8080, 1)
    record = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("::1", 8080))
    with self.assertRaisesRegex(healthctl.ObservationError, "declared address family"):
      healthctl.resolve_tcp_candidates(check, resolver=lambda *args: [record])

  def test_resolver_rejects_extra_unhashable_sockaddr_fields_as_observation_error(self):
    check = healthctl.TcpConnectCheck("tcp", "localhost", "hostname", 8080, 1)
    record = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 8080, []))
    with self.assertRaisesRegex(healthctl.ObservationError, "IPv4 socket address shape"):
      healthctl.resolve_tcp_candidates(check, resolver=lambda *args: [record])

  def test_resolver_candidate_bound_is_conservative(self):
    check = healthctl.TcpConnectCheck("tcp", "localhost", "hostname", 8080, 1)
    records = [self.ipv4_record(f"127.0.0.{i}") for i in range(1, 18)]
    with self.assertRaisesRegex(healthctl.ObservationError, "16-candidate"):
      healthctl.resolve_tcp_candidates(check, resolver=lambda *args: records)

  def test_tcp_check_passes_on_first_success_and_closes_socket(self):
    check = healthctl.TcpConnectCheck("tcp", "127.0.0.1", "ipv4", 8080, 0.5)
    fake = FakeSocket()
    result = healthctl.run_tcp_check(
      check,
      resolver=lambda *args: [self.ipv4_record()],
      socket_factory=lambda *args: fake,
    )
    self.assertEqual(result.status, "PASS")
    self.assertEqual(fake.timeout, 0.5)
    self.assertTrue(fake.closed)

  def test_tcp_check_retries_after_refusal_then_passes(self):
    check = healthctl.TcpConnectCheck("tcp", "localhost", "hostname", 8080, 1)
    sockets = [
      FakeSocket(OSError(111, "refused")),
      FakeSocket(),
    ]
    def factory(*args):
      return sockets.pop(0)
    records = [self.ipv4_record("127.0.0.1"), self.ipv4_record("127.0.0.2")]
    result = healthctl.run_tcp_check(check, resolver=lambda *args: records, socket_factory=factory)
    self.assertEqual(result.status, "PASS")
    self.assertIn("2 attempt(s)", result.evidence)

  def test_tcp_check_fails_after_all_candidates(self):
    check = healthctl.TcpConnectCheck("tcp", "127.0.0.1", "ipv4", 8080, 1)
    fake = FakeSocket(OSError(111, "refused"))
    result = healthctl.run_tcp_check(
      check,
      resolver=lambda *args: [self.ipv4_record()],
      socket_factory=lambda *args: fake,
    )
    self.assertEqual(result.status, "FAIL")
    self.assertIn("connection refused", result.evidence)

  def test_socket_creation_failure_becomes_error_in_evaluation(self):
    check = healthctl.TcpConnectCheck("tcp", "127.0.0.1", "ipv4", 8080, 1)
    config = healthctl.HealthConfig("/tmp/x", (check,))
    def executor(item):
      return healthctl.run_tcp_check(
        item,
        resolver=lambda *args: [self.ipv4_record()],
        socket_factory=lambda *args: (_ for _ in ()).throw(OSError("no socket")),
      )
    results = healthctl.evaluate_config(config, executor=executor)
    self.assertEqual(results[0].status, "ERROR")

  def test_evaluate_preserves_config_order(self):
    checks = (
      healthctl.DiskFreeCheck("a", "/", 1),
      healthctl.DiskFreeCheck("b", "/", 1),
    )
    config = healthctl.HealthConfig("/tmp/x", checks)
    results = healthctl.evaluate_config(
      config,
      executor=lambda check: healthctl.CheckResult(check.name, check.type, "PASS", "/", "ok"),
    )
    self.assertEqual([result.name for result in results], ["a", "b"])

  def test_failed_dependency_skips_dependent_check(self):
    checks = (
      healthctl.GenericCheck("a", "file_exists", "/a"),
      healthctl.GenericCheck("b", "file_exists", "/b", depends_on=("a",)),
    )
    calls = []
    def executor(check):
      calls.append(check.name)
      return healthctl.CheckResult(check.name, check.type, "FAIL", check.target, "no", check.severity)
    results = healthctl.evaluate_config(healthctl.HealthConfig("/tmp/x", checks), executor=executor)
    self.assertEqual(calls, ["a"])
    self.assertIn("dependency did not pass", results[1].evidence)

  def test_config_hash_check_matches_regular_file(self):
    import hashlib
    with tempfile.TemporaryDirectory() as tempdir:
      path = Path(tempdir) / "config"
      path.write_bytes(b"safe\n")
      digest = hashlib.sha256(b"safe\n").hexdigest()
      check = healthctl.GenericCheck("hash", "config_hash", str(path), options=(("sha256", digest),))
      self.assertEqual(healthctl.run_generic_check(check).status, "PASS")

  def test_generic_file_process_systemd_and_certificate_checks(self):
    with tempfile.TemporaryDirectory() as tempdir:
      path = Path(tempdir) / "file"
      path.write_bytes(b"abc")
      exists = healthctl.GenericCheck("exists", "file_exists", str(path))
      metadata = healthctl.GenericCheck(
        "metadata", "file_metadata", str(path),
        options=(("minimum_bytes", 3), ("maximum_bytes", 3)),
      )
      self.assertEqual(healthctl.run_generic_check(exists).status, "PASS")
      self.assertEqual(healthctl.run_generic_check(metadata).status, "PASS")
    process = healthctl.GenericCheck("process", "process", str(os.getpid()), options=(("pid", os.getpid()),))
    with mock.patch.object(healthctl.os, "stat", return_value=mock.Mock(st_mode=healthctl.stat.S_IFDIR)):
      self.assertEqual(healthctl.run_generic_check(process).status, "PASS")
    service = healthctl.GenericCheck("service", "systemd_service", "dbus.service", 1.0)
    with mock.patch.object(healthctl, "run_silent_command", return_value=0) as run:
      self.assertEqual(healthctl.run_generic_check(service).status, "PASS")
    self.assertEqual(
      run.call_args.args,
      (["systemctl", "is-active", "--system", "--quiet", "--", "dbus.service"], 1.0),
    )

    class CertificateSocket:
      def settimeout(self, timeout): pass
      def __enter__(self): return self
      def __exit__(self, *args): pass
    class Tls(CertificateSocket):
      def getpeercert(self): return {"notAfter": "Jan  1 00:00:00 2099 GMT"}
    class Context:
      def wrap_socket(self, tcp, server_hostname=None): return Tls()
    certificate = healthctl.GenericCheck(
      "certificate", "certificate_expiry", "example.com:443", 1.0,
      options=(("host", "example.com"), ("port", 443), ("warn_days", 30), ("critical_days", 7)),
    )
    with mock.patch.object(healthctl, "_connect_tcp_target", return_value=CertificateSocket()), mock.patch.object(
      healthctl.ssl, "create_default_context", return_value=Context(),
    ):
      self.assertEqual(healthctl.run_generic_check(certificate).status, "PASS")

  def test_silent_command_timeout_terminates_and_reaps_child(self):
    real_popen = healthctl.subprocess.Popen
    children = []
    def capture(*args, **kwargs):
      process = real_popen(*args, **kwargs)
      children.append(process)
      return process
    with mock.patch.object(healthctl.subprocess, "Popen", side_effect=capture):
      with self.assertRaisesRegex(healthctl.ObservationError, "deadline"):
        healthctl.run_silent_command(
          [sys.executable, "-c", "import time; time.sleep(30)"], 0.05,
        )
    self.assertEqual(len(children), 1)
    self.assertIsNotNone(children[0].poll())

  def test_dns_check_rejects_excess_resolver_addresses(self):
    check = healthctl.GenericCheck("dns", "dns", "example.test")
    records = [
      (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (f"10.0.0.{index}", 0))
      for index in range(1, 18)
    ]
    with mock.patch.object(healthctl.socket, "getaddrinfo", return_value=records):
      result = healthctl.run_generic_check(check)
    self.assertEqual(result.status, "ERROR")
    self.assertIn("16-address", result.evidence)

  def test_render_report_escapes_external_text(self):
    config = healthctl.HealthConfig("/tmp/x", (healthctl.DiskFreeCheck("disk", "/", 1),))
    results = (healthctl.CheckResult("disk", "disk_free_percent", "ERROR", "/tmp/a\nb", "bad\x1b[31m"),)
    report = healthctl.render_report(config, results)
    self.assertIn("/tmp/a\\x0ab", report)
    self.assertIn("bad\\x1b[31m", report)

  def test_exit_code_precedence(self):
    pass_result = healthctl.CheckResult("a", "x", "PASS", "x", "x")
    fail_result = healthctl.CheckResult("b", "x", "FAIL", "x", "x")
    error_result = healthctl.CheckResult("c", "x", "ERROR", "x", "x")
    self.assertEqual(healthctl.result_exit_code([pass_result]), 0)
    self.assertEqual(healthctl.result_exit_code([pass_result, fail_result]), 1)
    self.assertEqual(healthctl.result_exit_code([fail_result, error_result]), 3)

  def test_main_invalid_config_returns_2_without_traceback(self):
    with tempfile.TemporaryDirectory() as tempdir:
      path = Path(tempdir) / "bad.json"
      path.write_text("{}", encoding="utf-8")
      stdout = io.StringIO()
      stderr = io.StringIO()
      with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = healthctl.main([str(path)])
      self.assertEqual(code, 2)
      self.assertEqual(stdout.getvalue(), "")
      self.assertIn("configuration error", stderr.getvalue())
      self.assertNotIn("Traceback", stderr.getvalue())

  def test_main_unexpected_load_failure_returns_3_without_traceback(self):
    stdout = io.StringIO()
    stderr = io.StringIO()
    original = healthctl.load_config
    try:
      healthctl.load_config = lambda path: (_ for _ in ()).throw(RuntimeError("boom"))
      with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = healthctl.main(["ignored.json"])
    finally:
      healthctl.load_config = original
    self.assertEqual(code, 3)
    self.assertEqual(stdout.getvalue(), "")
    self.assertIn("internal error", stderr.getvalue())
    self.assertNotIn("Traceback", stderr.getvalue())

  def test_main_help_returns_0(self):
    stdout = io.StringIO()
    with self.assertRaises(SystemExit) as caught:
      with contextlib.redirect_stdout(stdout):
        healthctl.main(["--help"])
    self.assertEqual(caught.exception.code, 0)
    self.assertIn("healthctl", stdout.getvalue())


if __name__ == "__main__":
  unittest.main()
