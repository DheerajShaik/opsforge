import contextlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portlens


class CliTests(unittest.TestCase):
  def test_exited_helper_still_terminates_descendants_and_reaps(self):
    process = mock.Mock(pid=12345)
    process.poll.return_value = 0
    with mock.patch.object(portlens.os, 'killpg') as killpg:
      portlens._stop_process(process)
    killpg.assert_called_once_with(12345, portlens.signal.SIGKILL)
    process.wait.assert_called_once_with(timeout=1.0)

  def test_enrichment_caveat_in_human_and_json_output(self):
    self.assertIn('non-atomic', portlens.render_result(8080, []))
    with mock.patch.object(portlens, 'inspect_selection', return_value=('report', [], 1)):
      code, stdout, stderr = self.run_main(['8080', '--json'])
    self.assertEqual(code, 1)
    result = json.loads(stdout)
    self.assertIn('socket/PID association from ss', result['observations']['process_enrichment'])
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

  @mock.patch.object(portlens, "inspect_selection", return_value=("matched output", [
    portlens.DisplayObservation("tcp", "LISTEN", "ipv4", "127.0.0.1", 8080, "1", "u", "p")
  ], 0))
  def test_match_path(self, inspect):
    code, stdout, stderr = self.run_main(["8080"])
    self.assertEqual((code, stderr), (0, ""))
    self.assertIn("matched output\nConclusion: [FOUND]", stdout)

  @mock.patch.object(portlens, "inspect_selection", return_value=("no match output", [], 1))
  def test_no_match_path(self, inspect):
    code, stdout, stderr = self.run_main(["8080"])
    self.assertEqual((code, stderr), (1, ""))
    self.assertIn("no match output\nConclusion: [NOT_FOUND]", stdout)

  @mock.patch.object(portlens, "inspect_selection", return_value=("detail", [], 1))
  def test_json_is_json_only(self, inspect):
    code, stdout, stderr = self.run_main(["--json", "8080"])
    self.assertEqual((code, stderr), (1, ""))
    payload = json.loads(stdout)
    self.assertEqual(payload["tool"], "portlens")
    self.assertEqual(payload["status"], "NOT_FOUND")

  @mock.patch.object(portlens, "inspect_selection", return_value=("detail", [], 1))
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

  def test_fixed_family_queries_do_not_include_port(self):
    calls = []
    def runner(executable, arguments):
      calls.append((executable, tuple(arguments)))
      return ""
    self.assertEqual(portlens.discover_sockets("/usr/bin/ss", runner), [])
    self.assertEqual(calls, [
      ("/usr/bin/ss", ("-H", "-4", "-ltnp")),
      ("/usr/bin/ss", ("-H", "-6", "-ltnp")),
    ])

  def test_udp_query_is_protocol_specific(self):
    calls = []
    portlens.discover_sockets(
      "/usr/bin/ss",
      lambda executable, arguments: calls.append(tuple(arguments)) or "",
      protocol="udp",
      families=("ipv4",),
    )
    self.assertEqual(calls, [("-H", "-4", "-lunp")])

  @mock.patch.object(portlens, "find_ss", return_value="/usr/bin/ss")
  @mock.patch.object(portlens, "discover_sockets")
  def test_inspect_filters_exact_port_and_preserves_duplicate_rows(self, discover, find_ss):
    matching = portlens.SocketObservation("tcp", "LISTEN", "ipv4", "127.0.0.1", 8080)
    discover.return_value = [matching, matching, portlens.SocketObservation(
      "tcp", "LISTEN", "ipv4", "127.0.0.1", 18080,
    )]
    output, code = portlens.inspect(8080)
    self.assertEqual(code, 0)
    self.assertIn("Found 2 matching sockets.", output)
    self.assertIn("Likely shared/reused bind groups: 1", output)
    self.assertNotIn("18080", output)

  @mock.patch.object(portlens.subprocess, "Popen")
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
      with mock.patch.object(portlens.subprocess, "Popen", side_effect=capture), mock.patch.object(
        portlens.selectors.DefaultSelector, "select", side_effect=KeyboardInterrupt,
      ), self.assertRaises(KeyboardInterrupt):
        portlens.run_ss_query(str(executable), ())
      self.assertEqual(len(children), 1)
      self.assertIsNotNone(children[0].poll())


if __name__ == "__main__":
  unittest.main()
