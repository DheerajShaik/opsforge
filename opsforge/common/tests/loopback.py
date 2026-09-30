"""Real loopback servers for tests: plain TCP or TLS, presenting the throwaway certificates in tls_fixtures."""

import socket
import ssl
import threading
import time
from pathlib import Path

from . import tls_fixtures


class LoopbackServer:
  """Serve each connection on 127.0.0.1 with `handle`, wrapped in TLS when a server context is given.

  `accepts` counts accepted connections; `delay` seconds pass between accepting and handling a connection.
  """

  def __init__(self, handle=lambda connection: None, context=None, delay=0.0):
    self.handle = handle
    self.context = context
    self.delay = delay
    self.accepts = 0
    self.stopped = False
    self.listener = socket.socket()
    self.listener.bind(("127.0.0.1", 0))
    self.listener.listen(32)
    self.listener.settimeout(0.05)
    self.port = self.listener.getsockname()[1]
    self.thread = threading.Thread(target=self.serve, daemon=True)

  def __enter__(self):
    self.thread.start()
    return self

  def __exit__(self, *args):
    self.stopped = True
    self.thread.join(5)
    self.listener.close()

  def serve(self):
    while not self.stopped:
      try:
        connection, _ = self.listener.accept()
      except socket.timeout:
        continue
      except OSError:
        return
      self.accepts += 1
      threading.Thread(target=self.serve_one, args=(connection,), daemon=True).start()

  def serve_one(self, connection):
    try:
      connection.settimeout(5)
      if self.delay:
        time.sleep(self.delay)
      if self.context is not None:
        connection = self.context.wrap_socket(connection, server_side=True)
      self.handle(connection)
    except (OSError, ssl.SSLError):
      pass
    finally:
      connection.close()


def unused_port():
  with socket.socket() as probe:
    probe.bind(("127.0.0.1", 0))
    return probe.getsockname()[1]


def server_tls_context(directory, name):
  """Return a server context presenting the fixture certificate NAME (VALID, EXPIRED, NOT_YET_VALID, MISMATCH)."""
  certificate, key = Path(directory, f"{name}.pem"), Path(directory, f"{name}.key")
  certificate.write_text(getattr(tls_fixtures, f"{name}_CERTIFICATE"), encoding="ascii")
  key.write_text(getattr(tls_fixtures, f"{name}_KEY"), encoding="ascii")
  context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
  context.load_cert_chain(str(certificate), str(key))
  return context


def trusting_client_context():
  """Return a client context that trusts only the fixture CA."""
  return ssl.create_default_context(cadata=tls_fixtures.CA_CERTIFICATE)
