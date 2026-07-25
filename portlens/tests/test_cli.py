import contextlib
import io
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portlens


class CliTests(unittest.TestCase):
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
        self.assertIn("TCP LISTEN", stdout.getvalue())

  @mock.patch.object(portlens, "inspect", return_value=("matched output", 0))
  def test_match_path(self, inspect):
    code, stdout, stderr = self.run_main(["8080"])
    self.assertEqual((code, stderr), (0, ""))
    self.assertEqual(stdout, "matched output\n")
    inspect.assert_called_once_with(8080)

  @mock.patch.object(portlens, "inspect", return_value=("no match output", 1))
  def test_no_match_path(self, inspect):
    code, stdout, stderr = self.run_main(["8080"])
    self.assertEqual((code, stderr), (1, ""))
    self.assertEqual(stdout, "no match output\n")

  def test_invalid_input_uses_stderr_and_exit_two(self):
    with self.assertRaises(SystemExit) as context:
      portlens.main(["invalid"])
    self.assertEqual(context.exception.code, 2)

  @mock.patch.object(portlens, "find_ss", side_effect=portlens.PortLensError("required command 'ss' was not found"))
  def test_missing_ss(self, find_ss):
    code, stdout, stderr = self.run_main(["8080"])
    self.assertEqual((code, stdout), (2, ""))
    self.assertIn("required command 'ss' was not found", stderr)

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
    self.assertNotIn("18080", output)

  @mock.patch.object(portlens.subprocess, "run")
  def test_subprocess_uses_argument_array_without_shell(self, run):
    run.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")
    portlens.run_ss_query("/usr/bin/ss", ("-H", "-4", "-ltnp"))
    positional, keyword = run.call_args
    self.assertEqual(positional[0], ["/usr/bin/ss", "-H", "-4", "-ltnp"])
    self.assertNotIn("shell", keyword)


if __name__ == "__main__":
  unittest.main()
