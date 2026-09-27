import contextlib
import io
import json
import math
import os
from pathlib import Path
import signal
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

from opsforge_common import fs, procfs, process, systemd
from opsforge_common.output import OutputError, OutputRecord, emit_output, make_conclusion, to_jsonable
from opsforge_common.text import has_unsafe_characters, sanitize_text


def record(**overrides):
  values = dict(
    tool="example", status="PASS", target="local", observations={"count": 2},
    conclusion=make_conclusion("PASS", "local", "check passed", "no action needed"),
    next_action="no action needed.", warnings=(), elapsed_seconds=0.1,
  )
  values.update(overrides)
  return OutputRecord(**values)


class SanitizeTextTests(unittest.TestCase):
  def test_escapes_are_unambiguous(self):
    self.assertEqual(sanitize_text("plain text"), "plain text")
    self.assertEqual(sanitize_text("a\\b\n\t\x1b\x7f"), "a\\\\b\\x0a\\x09\\x1b\\x7f")
    self.assertEqual(sanitize_text("\u0085\u009b\u00ad"), "\\u0085\\u009b\\u00ad")
    self.assertEqual(sanitize_text("\udc85\udcff"), "\\x85\\xff")
    self.assertEqual(sanitize_text("\u202e\u2028\U000e0001"), "\\u202e\\u2028\\U000e0001")
    self.assertEqual(sanitize_text("caf\u00e9 \u6f22"), "caf\u00e9 \u6f22")

  def test_unsafe_character_detection(self):
    self.assertTrue(has_unsafe_characters("x\u202ey"))
    self.assertFalse(has_unsafe_characters("C:\\temp"))


class OutputHardeningTests(unittest.TestCase):
  def test_force_replaces_with_a_new_private_inode(self):
    with tempfile.TemporaryDirectory() as directory:
      destination = Path(directory, "report.txt")
      destination.write_text("old", encoding="utf-8")
      destination.chmod(0o644)
      with open(destination, "rb") as reader:
        emit_output(record(), detailed="new", brief="b", output_path=str(destination), force=True)
        self.assertEqual(reader.read(), b"old")
      self.assertIn("new", destination.read_text(encoding="utf-8"))
      self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
      self.assertEqual(sorted(os.listdir(directory)), ["report.txt"])

  def test_failed_force_write_keeps_previous_report(self):
    with tempfile.TemporaryDirectory() as directory:
      destination = Path(directory, "report.txt")
      destination.write_text("previous good report", encoding="utf-8")
      with mock.patch("opsforge_common.output.os.write", side_effect=OSError(28, "No space left on device")):
        with self.assertRaisesRegex(OutputError, "could not write"):
          emit_output(record(), detailed="new", brief="b", output_path=str(destination), force=True)
      self.assertEqual(destination.read_text(encoding="utf-8"), "previous good report")
      self.assertEqual(os.listdir(directory), ["report.txt"])

  def test_failed_new_write_leaves_no_partial_file(self):
    with tempfile.TemporaryDirectory() as directory:
      destination = Path(directory, "report.txt")
      with mock.patch("opsforge_common.output.os.write", side_effect=OSError(28, "No space left on device")):
        with self.assertRaises(OutputError):
          emit_output(record(), detailed="new", brief="b", output_path=str(destination))
      self.assertFalse(destination.exists())

  def test_force_refuses_fifo_without_opening_it(self):
    with tempfile.TemporaryDirectory() as directory:
      fifo = Path(directory, "pipe")
      os.mkfifo(fifo)
      started = time.monotonic()
      with self.assertRaisesRegex(OutputError, "not a regular file"):
        emit_output(record(), detailed="new", brief="b", output_path=str(fifo), force=True)
      self.assertLess(time.monotonic() - started, 5)
      self.assertTrue(stat.S_ISFIFO(os.lstat(fifo).st_mode))

  def test_json_is_strict(self):
    stream = io.StringIO()
    emit_output(record(observations={"x": math.nan, "y": math.inf}, warnings="one warning"), detailed="d", brief="b", json_mode=True, stdout=stream)
    payload = json.loads(stream.getvalue())
    self.assertEqual(payload["observations"], {"x": None, "y": None})
    self.assertEqual(payload["warnings"], ["one warning"])
    self.assertIsNone(to_jsonable(-math.inf))

  def test_conclusion_status_is_uppercased_before_escaping(self):
    self.assertIn("[PASS\\x1b]", make_conclusion("pass\x1b", "t", "f", "n"))

  def test_broken_stdout_pipe_is_silent(self):
    read_end, write_end = os.pipe()
    os.close(read_end)
    stream = io.TextIOWrapper(os.fdopen(write_end, "wb"), encoding="utf-8")
    try:
      emit_output(record(), detailed="x" * 200_000, brief="b", stdout=stream)
      stream.write("more")
      stream.flush()
    finally:
      stream.close()


class ProcessTests(unittest.TestCase):
  def script(self, directory, body):
    path = Path(directory, "tool")
    path.write_text(f"#!{sys.executable}\n{body}\n", encoding="utf-8")
    path.chmod(0o700)
    return str(path)

  def test_stdout_stdin_and_exit_status(self):
    with tempfile.TemporaryDirectory() as directory:
      tool = self.script(directory, "import sys\ndata = sys.stdin.buffer.read()\nsys.stdout.buffer.write(data[::-1])\nsys.exit(3)")
      result = process.run_bounded([tool], timeout=10, max_output_bytes=1024, stdin_data=b"abc")
    self.assertEqual((result.returncode, result.stdout, result.stdout_truncated), (3, b"cba", False))

  def test_child_environment_is_minimal(self):
    with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {"OPENSSL_CONF": "/evil"}):
      tool = self.script(directory, "import os, sys\nsys.stdout.write(repr(sorted(os.environ)))")
      result = process.run_bounded([tool], timeout=10, max_output_bytes=4096)
    self.assertNotIn(b"OPENSSL_CONF", result.stdout)
    self.assertIn(b"LC_ALL", result.stdout)

  def test_timeout_kills_the_whole_group(self):
    with tempfile.TemporaryDirectory() as directory:
      marker = Path(directory, "grandchild.pid")
      tool = self.script(directory, (
        "import os, subprocess, sys, time\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        f"open({str(marker)!r}, 'w').write(str(child.pid))\n"
        "time.sleep(60)"
      ))
      with self.assertRaises(process.ProcessTimeoutError):
        process.run_bounded([tool], timeout=2.0, max_output_bytes=1024)
      grandchild = int(marker.read_text())
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
      try:
        with open(f"/proc/{grandchild}/stat", "rb") as handle:
          if procfs.split_stat(handle.read())[2][0] == b"Z":
            break
      except FileNotFoundError:
        break
      time.sleep(0.05)
    else:
      self.fail("grandchild survived the timeout")

  def test_output_limit_and_truncation(self):
    with tempfile.TemporaryDirectory() as directory:
      tool = self.script(directory, "import sys\nsys.stdout.write('x' * 100000)")
      with self.assertRaises(process.ProcessOutputLimitError):
        process.run_bounded([tool], timeout=10, max_output_bytes=1000)
      result = process.run_bounded([tool], timeout=10, max_output_bytes=1000, truncate_stdout=True)
    self.assertEqual((len(result.stdout), result.stdout_truncated), (1000, True))

  def test_missing_executable(self):
    with self.assertRaises(process.ProcessNotFoundError):
      process.run_bounded(["/nonexistent/opsforge-tool"], timeout=1, max_output_bytes=10)

  def test_interrupt_kills_and_reaps(self):
    with tempfile.TemporaryDirectory() as directory:
      tool = self.script(directory, "import time\ntime.sleep(30)")
      children = []
      real_popen = process.subprocess.Popen

      def capture(*args, **kwargs):
        children.append(real_popen(*args, **kwargs))
        return children[-1]

      with mock.patch.object(process.subprocess, "Popen", side_effect=capture), mock.patch.object(
        process.selectors.DefaultSelector, "select", side_effect=KeyboardInterrupt,
      ), self.assertRaises(KeyboardInterrupt):
        process.run_bounded([tool], timeout=10, max_output_bytes=10)
    self.assertIsNotNone(children[0].returncode)

  def test_group_is_killed_before_reaping_and_never_after(self):
    events = []
    child = mock.Mock(pid=12345, returncode=None)
    child.wait.side_effect = lambda timeout: events.append("wait")
    with mock.patch.object(process.os, "killpg", side_effect=lambda pid, sig: events.append(("killpg", pid, sig))):
      process.stop_process_group(child)
    self.assertEqual(events, [("killpg", 12345, signal.SIGKILL), "wait"])
    reaped = mock.Mock(pid=12345, returncode=0)
    with mock.patch.object(process.os, "killpg") as killpg:
      process.stop_process_group(reaped)
    killpg.assert_not_called()

  def test_resolve_executable_trusts_only_absolute_private_locations(self):
    with tempfile.TemporaryDirectory() as directory:
      tool = self.script(directory, "pass")
      self.assertEqual(process.resolve_executable("tool", directory), tool)
      self.assertIsNone(process.resolve_executable("tool", "relative:" + ""))
      os.chmod(directory, 0o777)
      try:
        self.assertIsNone(process.resolve_executable("tool", directory))
      finally:
        os.chmod(directory, 0o700)
      os.chmod(tool, 0o722)
      self.assertIsNone(process.resolve_executable("tool", directory))
    self.assertIsNone(process.resolve_executable("tool", ""))


class ProcfsTests(unittest.TestCase):
  def test_stat_accepts_any_name_bytes(self):
    pid, name, fields = procfs.split_stat(b"42 (a) (b\xff\n) S 1 2 3\n")
    self.assertEqual((pid, name, fields[:2]), (42, b"a) (b\xff\n", [b"S", b"1"]))
    with self.assertRaises(ValueError):
      procfs.split_stat(b"garbage")

  def test_unified_cgroup_path_keeps_colons(self):
    text = "12:cpu,cpuacct:/v1\n0::/user.slice/x:/system.slice/sshd.service\n"
    self.assertEqual(procfs.unified_cgroup_path(text), "/user.slice/x:/system.slice/sshd.service")
    self.assertIsNone(procfs.unified_cgroup_path("3:memory:/only-v1\n"))

  def test_ipv4_default_routes(self):
    text = (
      "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
      "tun0\t00000000\t0100080A\t0003\t0\t0\t0\t00000080\t0\t0\t0\n"
      "eth1\t00000000\t0101A8C0\t0003\t0\t0\t200\t00000000\t0\t0\t0\n"
      "eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
      "ppp0\t00000000\t00000000\t0001\t0\t0\t300\t00000000\t0\t0\t0\n"
      "blk\t00000000\t00000000\t0201\t0\t0\t0\t00000000\t0\t0\t0\n"
    )
    routes = procfs.parse_ipv4_default_routes(text)
    self.assertEqual([(route.interface, route.metric) for route in routes], [("eth0", 100), ("eth1", 200), ("ppp0", 300)])
    self.assertEqual(routes[0].gateway, "192.168.2.1" if sys.byteorder == "little" else routes[0].gateway)
    self.assertIsNone(routes[2].gateway)

  def test_ipv6_reject_placeholder_is_not_a_default_route(self):
    zero = "0" * 32
    text = (
      f"{zero} 00 {zero} 00 {zero} ffffffff 00000001 00000000 00200200       lo\n"
      f"{zero} 00 {zero} 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003     eth0\n"
    )
    routes = procfs.parse_ipv6_default_routes(text)
    self.assertEqual([(route.interface, route.gateway) for route in routes], [("eth0", "fe80::1")])


class SystemdNameTests(unittest.TestCase):
  def test_rejects_non_concrete_units(self):
    for value in ("", "-x", "*", "nginx*", "a b", "a/b", "foo@", "foo@.service", ".service", "x.socket", "a\x00b"):
      with self.subTest(value=value), self.assertRaises(systemd.UnitNameError):
        systemd.normalize_service_name(value)
    self.assertEqual(systemd.normalize_service_name("nginx"), "nginx.service")
    self.assertEqual(systemd.normalize_service_name("getty@tty1.service"), "getty@tty1.service")


class RegularFileTests(unittest.TestCase):
  def test_refuses_fifo_and_symlink_without_blocking(self):
    with tempfile.TemporaryDirectory() as directory:
      regular = Path(directory, "file")
      regular.write_bytes(b"data")
      fifo = Path(directory, "fifo")
      os.mkfifo(fifo)
      link = Path(directory, "link")
      link.symlink_to(regular)
      descriptor, metadata = fs.open_regular_file(str(regular))
      os.close(descriptor)
      self.assertEqual(metadata.st_size, 4)
      with self.assertRaises(fs.NotRegularFileError):
        fs.open_regular_file(str(fifo))
      with self.assertRaises(fs.NotRegularFileError):
        fs.open_regular_file(str(link))
      descriptor, _ = fs.open_regular_file(str(link), follow_symlinks=True)
      os.close(descriptor)


if __name__ == "__main__":
  unittest.main()
