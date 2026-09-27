import contextlib
import io
import json
import os
from pathlib import Path
import selectors
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portlens


def inspection(report, observations, code, warnings=(), shared=0):
  return portlens.Inspection(report, observations, code, warnings, shared)


class CliTests(unittest.TestCase):
  def test_enrichment_caveat_in_human_and_json_output(self):
    self.assertIn('non-atomic', portlens.render_result(8080, []))
    with mock.patch.object(portlens, 'inspect_selection', return_value=inspection('report', [], 1)):
      code, stdout, stderr = self.run_main(['8080', '--json'])
    self.assertEqual(code, 1)
    result = json.loads(stdout)
    self.assertIn('socket inode', result['observations']['process_enrichment'])
    self.assertIn('PID reuse', result['warnings'][0])

  def run_main(self, arguments):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
      code = portlens.main(arguments)
    return code, stdout.getvalue(), stderr.getvalue()

  def test_help_options_exit_zero(self):
    for option in ("-h", "--help"):
      with self.subTest(option=option):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), self.assertRaises(SystemExit) as context:
          portlens.main([option])
        self.assertEqual(context.exception.code, 0)
        self.assertIn("TCP listeners or UDP sockets", stdout.getvalue())

  @mock.patch.object(portlens, "inspect_selection", return_value=inspection("matched output", [
    portlens.DisplayObservation("tcp", "LISTEN", "ipv4", "127.0.0.1", 8080, "1", "u", "p")
  ], 0))
  def test_match_path(self, inspect):
    code, stdout, stderr = self.run_main(["8080"])
    self.assertEqual((code, stderr), (0, ""))
    self.assertIn("matched output\nConclusion: [FOUND]", stdout)

  @mock.patch.object(portlens, "inspect_selection", return_value=inspection("no match output", [], 1))
  def test_no_match_path(self, inspect):
    code, stdout, stderr = self.run_main(["8080"])
    self.assertEqual((code, stderr), (1, ""))
    self.assertIn("no match output\nConclusion: [NOT_FOUND]", stdout)

  @mock.patch.object(portlens, "inspect_selection", return_value=inspection("detail", [], 1))
  def test_json_is_json_only(self, inspect):
    code, stdout, stderr = self.run_main(["--json", "8080"])
    self.assertEqual((code, stderr), (1, ""))
    payload = json.loads(stdout)
    self.assertEqual(payload["tool"], "portlens")
    self.assertEqual(payload["status"], "NOT_FOUND")

  @mock.patch.object(portlens, "inspect_selection", return_value=inspection("detail", [], 1))
  def test_brief_and_quiet(self, inspect):
    code, stdout, _ = self.run_main(["--brief", "8080"])
    self.assertEqual(code, 1)
    self.assertNotIn("detail", stdout)
    self.assertIn("Conclusion:", stdout)
    code, stdout, _ = self.run_main(["--quiet", "8080"])
    self.assertEqual((code, stdout), (1, ""))

  def test_invalid_input_uses_stderr_and_exit_two(self):
    with self.assertRaises(SystemExit) as context:
      portlens.main(["invalid"])
    self.assertEqual(context.exception.code, 2)

  @mock.patch.object(portlens, "find_ss", side_effect=portlens.PortLensError("required command 'ss' was not found"))
  def test_missing_ss(self, find_ss):
    code, stdout, stderr = self.run_main(["8080"])
    self.assertEqual((code, stdout), (2, ""))
    self.assertIn("required command 'ss' was not found", stderr)

  @mock.patch.object(portlens, "inspect_selection", side_effect=KeyboardInterrupt)
  def test_interrupt_is_clean(self, inspect):
    self.assertEqual(
      self.run_main(["8080"]),
      (130, "", "portlens: interrupted\n"),
    )

  @mock.patch.object(portlens, "find_ss", return_value="/usr/bin/ss")
  @mock.patch.object(portlens, "discover_sockets", side_effect=portlens.PortLensError("'ss' exited with status 1"))
  def test_ss_failure(self, discover, find_ss):
    code, stdout, stderr = self.run_main(["8080"])
    self.assertEqual((code, stdout), (2, ""))
    self.assertIn("exited with status 1", stderr)

  @mock.patch.object(portlens, "find_ss", return_value="/usr/bin/ss")
  @mock.patch.object(portlens, "discover_sockets", side_effect=portlens.PortLensError("ss returned a malformed socket row"))
  def test_fatal_parser_failure(self, discover, find_ss):
    code, stdout, stderr = self.run_main(["8080"])
    self.assertEqual((code, stdout), (2, ""))
    self.assertIn("malformed socket row", stderr)

  def test_fixed_family_queries_filter_ports_in_the_kernel(self):
    calls = []
    def runner(executable, arguments):
      calls.append((executable, tuple(arguments)))
      return ""
    self.assertEqual(portlens.discover_sockets("/usr/bin/ss", runner), [])
    portlens.discover_sockets("/usr/bin/ss", runner, families=("ipv4",), selection=portlens.PortSelection(53, 53))
    portlens.discover_sockets("/usr/bin/ss", runner, families=("ipv4",), selection=portlens.PortSelection(8000, 8100))
    self.assertEqual(calls, [
      ("/usr/bin/ss", ("-H", "-4", "-ltne")),
      ("/usr/bin/ss", ("-H", "-6", "-ltne")),
      ("/usr/bin/ss", ("-H", "-4", "-ltne", "sport", "=", ":53")),
      ("/usr/bin/ss", ("-H", "-4", "-ltne", "(", "sport", ">=", ":8000", "and", "sport", "<=", ":8100", ")")),
    ])

  def test_udp_query_is_protocol_specific(self):
    calls = []
    portlens.discover_sockets(
      "/usr/bin/ss",
      lambda executable, arguments: calls.append(tuple(arguments)) or "",
      protocol="udp",
      families=("ipv4",),
    )
    self.assertEqual(calls, [("-H", "-4", "-lune")])

  def selected(self, rows, owners=None, **options):
    values = dict(all_ports=False, protocol="tcp", families=("ipv4", "ipv6"), pid=None, process=None)
    values.update(options)
    details = portlens.ProcessDetails("u", "python3", "1000", "python3", "/")
    with mock.patch.object(portlens, "find_ss", return_value="/usr/bin/ss"), \
         mock.patch.object(portlens, "discover_sockets", return_value=rows), \
         mock.patch.object(portlens, "find_socket_owners", return_value=(owners or {}, {})), \
         mock.patch.object(portlens, "process_details", return_value=details):
      return portlens.inspect_selection(values.pop("selection", portlens.PortSelection(8080, 8080)), **values)

  def test_inspect_filters_exact_port_and_preserves_duplicate_rows(self):
    matching = portlens.SocketObservation("tcp", "LISTEN", "ipv4", "127.0.0.1", 8080)
    result = self.selected([matching, matching, portlens.SocketObservation("tcp", "LISTEN", "ipv4", "127.0.0.1", 18080)])
    self.assertEqual(result.exit_code, 0)
    self.assertIn("Found 2 matching sockets.", result.report)
    self.assertIn("Likely shared/reused bind groups: 1", result.report)
    self.assertNotIn("18080", result.report)

  def test_owners_come_only_from_inode_matches(self):
    row = portlens.SocketObservation("tcp", "LISTEN", "ipv4", "127.0.0.1", 8080, inode=77)
    other = portlens.SocketObservation("tcp", "LISTEN", "ipv4", "127.0.0.1", 8080, inode=78)
    result = self.selected([row, other], owners={77: (portlens.ProcessReference(354, 3),)})
    self.assertEqual([item.pid for item in result.observations], ["354", "-"])
    self.assertEqual(self.selected([row], owners={77: (portlens.ProcessReference(354, 3),)}, pid=1).exit_code, 1)

  def test_shared_bind_count_ignores_owner_filters(self):
    rows = [
      portlens.SocketObservation("udp", "UNCONN", "ipv4", "0.0.0.0", 8080, inode=1),
      portlens.SocketObservation("udp", "UNCONN", "ipv4", "0.0.0.0", 8080, inode=2),
    ]
    result = self.selected(rows, owners={1: (portlens.ProcessReference(10, 3),), 2: (portlens.ProcessReference(20, 4),)}, pid=10, protocol="udp")
    self.assertEqual((len(result.observations), result.shared_groups), (1, 1))

  def test_ipv4_selection_includes_dual_stack_wildcards(self):
    rows = [
      portlens.SocketObservation("tcp", "LISTEN", "ipv6", "*", 8080),
      portlens.SocketObservation("tcp", "LISTEN", "ipv6", "::", 8080),
      portlens.SocketObservation("tcp", "LISTEN", "ipv6", "::ffff:127.0.0.1", 8080),
    ]
    result = self.selected(rows, families=("ipv4",))
    self.assertEqual(sorted(item.local_address for item in result.observations), ["*", "::ffff:127.0.0.1"])

  def test_long_process_names_match_truncated_comm(self):
    row = portlens.SocketObservation("tcp", "LISTEN", "ipv4", "127.0.0.53", 8080, inode=5)
    owners = {5: (portlens.ProcessReference(7, 3),)}
    details = portlens.ProcessDetails("systemd-resolve", "systemd-resolve", "991", "-", "/")
    with mock.patch.object(portlens, "find_ss", return_value="/usr/bin/ss"), \
         mock.patch.object(portlens, "discover_sockets", return_value=[row]), \
         mock.patch.object(portlens, "find_socket_owners", return_value=(owners, {})), \
         mock.patch.object(portlens, "process_details", return_value=details):
      result = portlens.inspect_selection(
        portlens.PortSelection(8080, 8080), all_ports=False, protocol="tcp",
        families=("ipv4",), pid=None, process="systemd-resolved",
      )
    self.assertEqual(result.exit_code, 0)
    self.assertTrue(portlens.process_name_matches("a,b", "a,b", "-"))
    self.assertFalse(portlens.process_name_matches("a", "a,b", "-"))

  def test_watch_reports_every_snapshot_and_any_match(self):
    found = portlens.DisplayObservation("tcp", "LISTEN", "ipv4", "127.0.0.1", 8080, "1", "u", "p")
    results = [inspection("first", [found], 0), inspection("second", [], 1)]
    with mock.patch.object(portlens, "inspect_selection", side_effect=results), mock.patch.object(portlens.time, "sleep"):
      code, stdout, _ = self.run_main(["8080", "--watch", "2"])
    self.assertEqual(code, 0)
    self.assertIn("Snapshot 1 of 2\nfirst", stdout)
    self.assertIn("Snapshot 2 of 2\nsecond", stdout)
    self.assertIn("[FOUND]", stdout)
    self.assertIn("1 of 2 snapshots matched", stdout)

  def test_real_socket_owner_is_found_by_inode(self):
    with socket.socket() as listener:
      listener.bind(("127.0.0.1", 0))
      listener.listen()
      inode = os.fstat(listener.fileno()).st_ino
      owners, counts = portlens.find_socket_owners({inode})
      self.assertIn(portlens.ProcessReference(os.getpid(), listener.fileno()), owners[inode])
      self.assertGreaterEqual(counts[os.getpid()], 1)

  @mock.patch("subprocess.Popen")
  def test_subprocess_uses_argument_array_without_shell(self, popen):
    stdout_read, stdout_write = os.pipe()
    stderr_read, stderr_write = os.pipe()
    os.close(stdout_write)
    os.close(stderr_write)
    process = popen.return_value
    process.stdout = os.fdopen(stdout_read, "rb")
    process.stderr = os.fdopen(stderr_read, "rb")
    process.poll.return_value = 0
    process.wait.return_value = 0
    portlens.run_ss_query("/usr/bin/ss", ("-H", "-4", "-ltnp"))
    positional, keyword = popen.call_args
    self.assertEqual(positional[0], ["/usr/bin/ss", "-H", "-4", "-ltnp"])
    self.assertNotIn("shell", keyword)

  def test_ss_output_limit_is_enforced(self):
    with tempfile.TemporaryDirectory() as directory:
      executable = Path(directory, "fake-ss")
      executable.write_text(
        f"#!{sys.executable}\nimport sys\nsys.stdout.buffer.write(b'x' * {portlens.MAX_SS_STREAM_BYTES + 1})\n",
        encoding="utf-8",
      )
      executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
      with self.assertRaisesRegex(portlens.PortLensError, "8 MiB"):
        portlens.run_ss_query(str(executable), ())

  def test_keyboard_interrupt_terminates_and_reaps_ss(self):
    with tempfile.TemporaryDirectory() as directory:
      executable = Path(directory, "fake-ss")
      executable.write_text(
        f"#!{sys.executable}\nimport time\ntime.sleep(30)\n", encoding="utf-8",
      )
      executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
      children = []
      real_popen = subprocess.Popen
      def capture(*args, **kwargs):
        child = real_popen(*args, **kwargs)
        children.append(child)
        return child
      with mock.patch.object(subprocess, "Popen", side_effect=capture), mock.patch.object(
        selectors.DefaultSelector, "select", side_effect=KeyboardInterrupt,
      ), self.assertRaises(KeyboardInterrupt):
        portlens.run_ss_query(str(executable), ())
      self.assertEqual(len(children), 1)
      self.assertIsNotNone(children[0].poll())


if __name__ == "__main__":
  unittest.main()
