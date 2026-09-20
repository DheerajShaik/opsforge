import signal
import socket
import unittest
from unittest import mock

from test_observation import c, Sock


class ExceptionalCleanupTests(unittest.TestCase):
  def test_connect_interrupt_closes_socket(self):
    client = Sock(KeyboardInterrupt())
    candidate = c.ConnectionCandidate(socket.AF_INET, socket.SOCK_STREAM, 6, ('127.0.0.1', 443))
    with self.assertRaises(KeyboardInterrupt):
      c._connect([candidate], lambda *args: client)
    self.assertTrue(client.closed)

  def test_exited_decoder_still_terminates_descendants_and_reaps(self):
    process = mock.Mock(pid=12345)
    process.poll.return_value = 0
    with mock.patch.object(c.os, 'killpg') as killpg:
      c._stop_decoder(process)
    killpg.assert_called_once_with(12345, signal.SIGKILL)
    process.wait.assert_called_once_with(timeout=1.0)
