import hashlib
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from test_healthctl import healthctl
from opsforge.common.tests import tls_fixtures
from opsforge.common.tests.loopback import (
  LoopbackServer,
  server_tls_context,
  trusting_client_context,
  unused_port,
)


ROUTES = {
  "/ok": ("204 No Content", None),
  "/redirect": ("302 Found", "/ok"),
  "/away": ("302 Found", "http://127.0.0.1:1/"),
  "/down": ("503 Service Unavailable", None),
}


def answer_http(connection):
  data = read_request(connection)
  if data is None:
    return
  status, location = ROUTES.get(data.split(b" ", 2)[1].decode(), ("404 Not Found", None))
  head = f"HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n"
  if location:
    head += f"Location: {location}\r\n"
  connection.sendall((head + "\r\n").encode())


def read_request(connection):
  data = b""
  while b"\r\n\r\n" not in data:
    chunk = connection.recv(4096)
    if not chunk:
      return None
    data += chunk
  return data


class TlsFixtureCase(unittest.TestCase):
  """Loopback TLS servers presenting the throwaway certificates in opsforge.common.tests.tls_fixtures."""

  @classmethod
  def setUpClass(cls):
    cls.directory = tempfile.TemporaryDirectory()
    cls.addClassCleanup(cls.directory.cleanup)
    cls.client_context = trusting_client_context()

  @classmethod
  def server_context(cls, name):
    return server_tls_context(cls.directory.name, name)

  def certificate_check(self, port, host="127.0.0.1", warn_days=30, critical_days=7, severity="CRITICAL", timeout=2.0):
    check = healthctl.GenericCheck(
      "cert", "certificate_expiry", f"{host}:{port}", timeout, severity=severity,
      options=(("host", host), ("port", port), ("warn_days", warn_days), ("critical_days", critical_days)),
    )
    with mock.patch.object(healthctl, "default_tls_context", return_value=self.client_context):
      return healthctl.run_generic_check(check)


class RealCertificateTests(TlsFixtureCase):
  def serve(self, name):
    return LoopbackServer(lambda connection: None, self.server_context(name))

  def test_valid_certificate_passes_and_reports_days_remaining(self):
    with self.serve("VALID") as server:
      result = self.certificate_check(server.port)
    self.assertEqual((result.status, result.severity), ("PASS", "OK"))
    self.assertRegex(result.evidence, r"trusted certificate expires in \d+\.\d\d days; revocation not checked")

  def test_valid_certificate_is_found_by_name_through_the_resolver(self):
    with self.serve("VALID") as server:
      result = self.certificate_check(server.port, host="localhost")
    self.assertEqual(result.status, "PASS")

  def test_expiry_windows_use_the_real_not_after(self):
    with self.serve("VALID") as server:
      warning = self.certificate_check(server.port, warn_days=36500, critical_days=7)
      critical = self.certificate_check(server.port, warn_days=36500, critical_days=36500, severity="WARNING")
    self.assertEqual((warning.status, warning.severity), ("FAIL", "WARNING"))
    self.assertEqual((critical.status, critical.severity), ("FAIL", "CRITICAL"))

  def test_expired_certificate_is_a_critical_failure(self):
    with self.serve("EXPIRED") as server:
      result = self.certificate_check(server.port, severity="WARNING")
    self.assertEqual((result.status, result.severity), ("FAIL", "CRITICAL"))
    self.assertIn("certificate has expired (certificate has expired)", result.evidence)

  def test_not_yet_valid_certificate_is_a_critical_failure(self):
    with self.serve("NOT_YET_VALID") as server:
      result = self.certificate_check(server.port, severity="WARNING")
    self.assertEqual((result.status, result.severity), ("FAIL", "CRITICAL"))
    self.assertIn("certificate is not yet valid", result.evidence)

  def test_name_mismatch_keeps_the_configured_severity(self):
    with self.serve("MISMATCH") as server:
      result = self.certificate_check(server.port, severity="WARNING")
    self.assertEqual((result.status, result.severity), ("FAIL", "WARNING"))
    self.assertIn("certificate verification failed (", result.evidence)
    self.assertIn("mismatch", result.evidence)

  def test_an_untrusted_issuer_is_a_verification_failure(self):
    with self.serve("VALID") as server:
      check = healthctl.GenericCheck(
        "cert", "certificate_expiry", f"127.0.0.1:{server.port}", 2.0,
        options=(("host", "127.0.0.1"), ("port", server.port), ("warn_days", 30), ("critical_days", 7)),
      )
      with mock.patch.object(healthctl, "default_tls_context", return_value=ssl.create_default_context(cadata=tls_fixtures.EXPIRED_CERTIFICATE)):
        result = healthctl.run_generic_check(check)
    self.assertEqual((result.status, result.severity), ("FAIL", "CRITICAL"))
    self.assertIn("certificate verification failed", result.evidence)

  def test_a_plaintext_server_is_a_tls_error_not_a_finding(self):
    with LoopbackServer(lambda connection: connection.sendall(b"HTTP/1.1 200 OK\r\n\r\n")) as server:
      result = self.certificate_check(server.port)
    self.assertEqual((result.status, result.severity), ("ERROR", None))
    self.assertIn("TLS protocol error", result.evidence)

  def test_a_closed_port_is_an_error_that_names_the_outcome(self):
    result = self.certificate_check(unused_port())
    self.assertEqual((result.status, result.severity), ("ERROR", None))
    self.assertIn("connection refused", result.evidence)

  def https_result(self, port, path, expected):
    check = healthctl.GenericCheck(
      "web", "https", f"https://127.0.0.1:{port}{path}", 2.0, options=(("expected_status", expected),),
    )
    real = healthctl.run_http_head
    trusting = lambda target, **options: real(target, context_factory=lambda: self.client_context, **options)
    with mock.patch.object(healthctl, "run_http_head", side_effect=trusting):
      return healthctl._http_check(check, dict(check.options))

  def test_https_head_over_real_tls(self):
    with LoopbackServer(answer_http, self.server_context("VALID")) as server:
      for path, expected, status in (("/ok", 204, "PASS"), ("/redirect", 204, "PASS"), ("/down", 200, "FAIL")):
        with self.subTest(path=path):
          self.assertEqual(self.https_result(server.port, path, expected).status, status)

  def test_https_head_to_an_expired_certificate_fails_with_the_reason(self):
    with LoopbackServer(answer_http, self.server_context("EXPIRED")) as server:
      result = self.https_result(server.port, "/ok", 204)
    self.assertEqual(result.status, "FAIL")
    self.assertIn("certificate verification failed (certificate has expired)", result.evidence)


class RealHttpTests(unittest.TestCase):
  def head(self, server, path, expected):
    check = healthctl.GenericCheck(
      "web", "http", f"http://127.0.0.1:{server.port}{path}", 2.0, options=(("expected_status", expected),),
    )
    return healthctl.run_check(check)

  def test_status_redirects_and_origin_policy_over_a_real_socket(self):
    with LoopbackServer(answer_http) as server:
      ok = self.head(server, "/ok", 204)
      followed = self.head(server, "/redirect", 204)
      not_followed = self.head(server, "/redirect", 302)
      wrong = self.head(server, "/down", 200)
      away = self.head(server, "/away", 200)
    self.assertEqual((ok.status, ok.evidence), ("PASS", "HTTP status 204; required 204"))
    self.assertEqual(followed.status, "PASS")
    self.assertIn("followed 1 same-origin redirect(s) to /ok", followed.evidence)
    self.assertEqual((not_followed.status, not_followed.evidence), ("PASS", "HTTP status 302; required 302"))
    self.assertEqual((wrong.status, wrong.severity, wrong.evidence), ("FAIL", "CRITICAL", "HTTP status 503; required 200"))
    self.assertEqual((away.status, away.severity), ("ERROR", None))
    self.assertIn("redirect left the configured origin", away.evidence)

  def test_a_server_that_never_answers_fails_at_the_deadline(self):
    release = threading.Event()
    self.addCleanup(release.set)
    with LoopbackServer(lambda connection: release.wait(10)) as server:
      check = healthctl.GenericCheck(
        "web", "http", f"http://127.0.0.1:{server.port}/", 0.3, options=(("expected_status", 200),),
      )
      started = time.monotonic()
      result = healthctl.run_check(check)
    self.assertLess(time.monotonic() - started, 3)
    self.assertEqual((result.status, result.severity), ("FAIL", "CRITICAL"))
    self.assertIn("timed out", result.evidence)

  def test_a_dropped_connection_is_reported_not_raised(self):
    with LoopbackServer(read_request) as server:
      result = self.head(server, "/", 200)
    self.assertEqual(result.status, "ERROR")
    self.assertIn("HTTP response ended before complete headers", result.evidence)


class RealTcpTests(unittest.TestCase):
  def test_listening_and_closed_ports(self):
    with LoopbackServer(lambda connection: None) as server:
      up = healthctl.run_check(healthctl.TcpConnectCheck("up", "127.0.0.1", "ipv4", server.port, 1.0))
    down = healthctl.run_check(healthctl.TcpConnectCheck("down", "127.0.0.1", "ipv4", unused_port(), 1.0))
    self.assertEqual((up.status, up.severity), ("PASS", "OK"))
    self.assertIn("TCP handshake completed to 127.0.0.1:", up.evidence)
    self.assertEqual((down.status, down.severity), ("FAIL", "CRITICAL"))
    self.assertIn("last outcome: connection refused", down.evidence)

  def test_a_name_with_no_address_is_a_finding(self):
    result = healthctl.run_check(healthctl.TcpConnectCheck("gone", "nonexistent.invalid", "hostname", 80, 1.0))
    self.assertEqual((result.status, result.severity), ("FAIL", "CRITICAL"))
    self.assertIn("name did not resolve", result.evidence)

  def test_dns_check_resolves_localhost(self):
    result = healthctl.run_check(healthctl.GenericCheck("dns", "dns", "localhost"))
    self.assertEqual(result.status, "PASS")
    self.assertIn("127.0.0.1", result.evidence)


class RealSystemTests(unittest.TestCase):
  def process_check(self, pid):
    return healthctl.run_check(healthctl.GenericCheck(str(pid), "process", str(pid), options=(("pid", pid),)))

  def test_this_process_is_alive(self):
    result = self.process_check(os.getpid())
    self.assertEqual((result.status, result.severity), ("PASS", "OK"))
    self.assertRegex(result.evidence, r"process is alive \(state [A-Za-z]\)")

  def test_a_thread_id_is_not_a_process(self):
    ready, done = threading.Event(), threading.Event()
    ids = []
    def worker():
      ids.append(threading.get_native_id())
      ready.set()
      done.wait(10)
    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    self.addCleanup(done.set)
    self.assertTrue(ready.wait(5))
    result = self.process_check(ids[0])
    self.assertEqual((result.status, result.severity), ("FAIL", "CRITICAL"))
    self.assertEqual(result.evidence, f"PID is a thread of process {os.getpid()}, not a process")

  def test_a_zombie_fails_and_a_reaped_child_is_gone(self):
    child = subprocess.Popen([sys.executable, "-c", "pass"])
    self.addCleanup(child.wait)
    deadline = time.monotonic() + 10
    while healthctl.read_process_status(child.pid).get(b"State", b"")[:1] != b"Z":
      self.assertLess(time.monotonic(), deadline, "the child never became a zombie")
      time.sleep(0.02)
    zombie = self.process_check(child.pid)
    self.assertEqual((zombie.status, zombie.severity), ("FAIL", "CRITICAL"))
    self.assertIn("(zombie)", zombie.evidence)
    child.wait()
    gone = self.process_check(child.pid)
    self.assertEqual((gone.status, gone.evidence), ("FAIL", "no process with this PID was observed"))

  def test_disk_check_reads_real_capacity(self):
    with tempfile.TemporaryDirectory() as directory:
      result = healthctl.run_check(healthctl.DiskFreeCheck("disk", directory, 0.0))
      missing = healthctl.run_check(healthctl.DiskFreeCheck("gone", os.path.join(directory, "missing"), 0.0))
    self.assertEqual((result.status, result.severity), ("PASS", "OK"))
    self.assertRegex(result.evidence, r"free \d+\.\d+% \(\d+ of \d+ bytes\); required >= 0%")
    self.assertEqual((missing.status, missing.severity), ("ERROR", None))
    self.assertIn("ENOENT", missing.evidence)

  def test_a_blocked_filesystem_probe_is_an_error_not_a_hang(self):
    release = threading.Event()
    self.addCleanup(release.set)
    check = healthctl.DiskFreeCheck("disk", "/", 10)
    started = time.monotonic()
    with mock.patch.object(healthctl, "FILESYSTEM_TIMEOUT_SECONDS", 0.05), \
         self.assertRaisesRegex(healthctl.ProbeTimeoutError, "filesystem capacity probe timed out after 0.05 s"):
      healthctl.run_disk_check(check, disk_usage=lambda path: release.wait(30))
    self.assertLess(time.monotonic() - started, 2)
    real_lstat = os.lstat
    def blocking_lstat(path, *args, **kwargs):
      if path == "/some/path":
        release.wait(30)
      return real_lstat(path, *args, **kwargs)
    with mock.patch.object(healthctl, "FILESYSTEM_TIMEOUT_SECONDS", 0.05), \
         mock.patch.object(healthctl.os, "lstat", side_effect=blocking_lstat):
      blocked = healthctl.run_check(healthctl.GenericCheck("file", "file_exists", "/some/path"))
    self.assertEqual((blocked.status, blocked.severity), ("ERROR", None))
    self.assertIn("file metadata probe timed out", blocked.evidence)

  def test_systemctl_runs_as_a_real_process_and_its_exit_status_decides(self):
    service = healthctl.GenericCheck("svc", "systemd_service", "demo.service", 5.0, severity="WARNING")
    expected = {
      0: ("PASS", "OK"), 3: ("FAIL", "WARNING"), 4: ("FAIL", "WARNING"), 1: ("ERROR", None), 99: ("ERROR", None),
    }
    with tempfile.TemporaryDirectory() as directory:
      script = Path(directory, "systemctl")
      for code, outcome in expected.items():
        script.write_text(
          '#!/bin/sh\n[ "$*" = "is-active --system --quiet -- demo.service" ] || exit 99\n'
          f"[ {code} -eq 99 ] && exit 99\nexit {code}\n",
          encoding="utf-8",
        )
        script.chmod(0o700)
        with self.subTest(code=code), mock.patch.dict(os.environ, {"PATH": directory}):
          result = healthctl.run_check(service)
          self.assertEqual((result.status, result.severity), outcome)
          self.assertIn(f"status {code}" if code else "active", result.evidence)
      script.unlink()
      with mock.patch.dict(os.environ, {"PATH": directory}):
        self.assertEqual(healthctl.run_check(service).status, "ERROR")

  def test_config_hash_over_a_real_file(self):
    with tempfile.TemporaryDirectory() as directory:
      path = Path(directory, "config")
      path.write_bytes(b"one\n")
      good, bad = hashlib.sha256(b"one\n").hexdigest(), hashlib.sha256(b"two\n").hexdigest()
      results = [
        healthctl.run_check(healthctl.GenericCheck("hash", "config_hash", str(path), options=(("sha256", digest),)))
        for digest in (good, bad)
      ]
      link = Path(directory, "link")
      link.symlink_to(path)
      symlink = healthctl.run_check(healthctl.GenericCheck("link", "file_exists", str(link)))
    self.assertEqual([item.status for item in results], ["PASS", "FAIL"])
    self.assertEqual(results[1].evidence, "SHA-256 did not match")
    self.assertEqual((symlink.status, symlink.evidence), ("ERROR", "final-component symlinks are not followed"))


class SchedulerTests(unittest.TestCase):
  @staticmethod
  def passed(check):
    return healthctl.CheckResult(check.name, check.type, "PASS", check.target, "ok", "OK")

  def test_a_dependent_starts_when_its_own_dependency_finishes(self):
    dependent_started = threading.Event()
    slow_finished_first = []
    def executor(check):
      if check.name == "slow":
        # Only a scheduler that starts dependents as soon as their dependency passes lets this event be set.
        slow_finished_first.append(not dependent_started.wait(5))
      elif check.name == "dependent":
        dependent_started.set()
      return self.passed(check)
    checks = (
      healthctl.GenericCheck("slow", "file_exists", "/slow"),
      healthctl.GenericCheck("fast", "file_exists", "/fast"),
      healthctl.GenericCheck("dependent", "file_exists", "/dependent", depends_on=("fast",)),
    )
    results = healthctl.evaluate_config(healthctl.HealthConfig("/x", checks, 3), executor=executor)
    self.assertEqual(slow_finished_first, [False])
    self.assertEqual([item.name for item in results], ["slow", "fast", "dependent"])

  def test_parallelism_never_exceeds_max_workers(self):
    lock = threading.Lock()
    state = {"running": 0, "peak": 0}
    def executor(check):
      with lock:
        state["running"] += 1
        state["peak"] = max(state["peak"], state["running"])
      time.sleep(0.05)
      with lock:
        state["running"] -= 1
      return self.passed(check)
    checks = tuple(healthctl.GenericCheck(f"c{index}", "file_exists", f"/{index}") for index in range(8))
    for workers in (1, 3):
      state.update(running=0, peak=0)
      with self.subTest(workers=workers):
        results = healthctl.evaluate_config(healthctl.HealthConfig("/x", checks, workers), executor=executor)
        self.assertEqual(len(results), 8)
        self.assertEqual(state["peak"], workers)

  def test_an_interrupt_stops_scheduling_and_abandons_running_checks(self):
    release = threading.Event()
    self.addCleanup(release.set)
    started = []
    def executor(check):
      started.append(check.name)
      release.wait(30)
      return self.passed(check)
    class InterruptedQueue(healthctl.queue.Queue):
      def get(self, *args, **kwargs):
        raise KeyboardInterrupt
    checks = tuple(healthctl.GenericCheck(f"c{index}", "file_exists", f"/{index}") for index in range(3))
    began = time.monotonic()
    with mock.patch.object(healthctl.queue, "Queue", InterruptedQueue), self.assertRaises(KeyboardInterrupt):
      healthctl.evaluate_config(healthctl.HealthConfig("/x", checks, 1), executor=executor)
    self.assertLess(time.monotonic() - began, 2)
    self.assertLessEqual(len(started), 1)

  def test_blocked_checks_do_not_keep_the_interpreter_alive(self):
    program = (
      "import threading; from opsforge.healthctl import healthctl\n"
      "healthctl.call_with_timeout(lambda: threading.Event().wait(60), 0.05, 'probe')\n"
    )
    root = str(Path(healthctl.__file__).resolve().parents[2])
    started = time.monotonic()
    result = subprocess.run(
      [sys.executable, "-c", program],
      capture_output=True, text=True, timeout=30, env={**os.environ, "PYTHONPATH": root},
    )
    self.assertLess(time.monotonic() - started, 10)
    self.assertIn("ProbeTimeoutError", result.stderr)


class CallWithTimeoutTests(unittest.TestCase):
  def test_returns_value_and_propagates_exceptions(self):
    self.assertEqual(healthctl.call_with_timeout(lambda: 7, 1, "probe"), 7)
    with self.assertRaises(ZeroDivisionError):
      healthctl.call_with_timeout(lambda: 1 / 0, 1, "probe")

  def test_a_blocked_call_times_out_and_is_abandoned(self):
    release = threading.Event()
    self.addCleanup(release.set)
    with self.assertRaisesRegex(healthctl.ProbeTimeoutError, "^probe timed out after 0.05 s$"):
      healthctl.call_with_timeout(lambda: release.wait(30), 0.05, "probe")


if __name__ == "__main__":
  unittest.main()
