import socket
import unittest

from test_observation import c, Sock


class ExceptionalCleanupTests(unittest.TestCase):
  def test_connect_interrupt_closes_socket(self):
    client = Sock(KeyboardInterrupt())
    candidate = c.Candidate(socket.AF_INET, socket.SOCK_STREAM, 6, ('127.0.0.1', 443), '127.0.0.1:443')
    with self.assertRaises(KeyboardInterrupt):
      c._connect([candidate], lambda *args: client)
    self.assertTrue(client.closed)

  def test_socket_creation_failure_tries_next_candidate(self):
    candidates = [
      c.Candidate(socket.AF_INET6, socket.SOCK_STREAM, 6, ('::1', 443, 0, 0), '[::1]:443'),
      c.Candidate(socket.AF_INET, socket.SOCK_STREAM, 6, ('127.0.0.1', 443), '127.0.0.1:443'),
    ]
    good = Sock()
    def factory(family, *args):
      if family == socket.AF_INET6:
        raise OSError(97, 'Address family not supported by protocol')
      return good
    sock, candidate = c._connect(candidates, factory)
    self.assertIs(sock, good)
    self.assertEqual(candidate.family, socket.AF_INET)
