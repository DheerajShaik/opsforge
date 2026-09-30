import errno
import importlib.util
from pathlib import Path
import stat
import sys
import types
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "incidentsnapshot.py"
SPEC = importlib.util.spec_from_file_location("incidentsnapshot_regressions", MODULE_PATH)
incident = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = incident
SPEC.loader.exec_module(incident)


class FailingStream:
  encoding = "utf-8"

  def write(self, value):
    del value
    raise OSError(errno.EIO, "hidden stream failure")


class CleanupRegressionTests(unittest.TestCase):
  def test_close_failure_does_not_override_successful_read(self):
    metadata = types.SimpleNamespace(st_mode=stat.S_IFREG, st_size=0)
    with mock.patch.object(incident.os, "open", return_value=55), \
         mock.patch.object(incident.os, "fstat", return_value=metadata), \
         mock.patch.object(incident.os, "read", side_effect=[b"12.5 4\n", b""]), \
         mock.patch.object(incident.os, "close", side_effect=OSError(errno.EIO, "hidden")):
      self.assertEqual(incident.read_bounded_ascii("/proc/uptime", 4096), b"12.5 4\n")

  def test_close_failure_does_not_override_observation_failure(self):
    metadata = types.SimpleNamespace(st_mode=stat.S_IFREG, st_size=0)
    with mock.patch.object(incident.os, "open", return_value=56), \
         mock.patch.object(incident.os, "fstat", return_value=metadata), \
         mock.patch.object(incident.os, "read", side_effect=OSError(errno.EIO, "hidden read failure")), \
         mock.patch.object(incident.os, "close", side_effect=OSError(errno.EIO, "hidden close failure")):
      with self.assertRaises(incident.SectionUnavailable) as caught:
        incident.read_bounded_ascii("/proc/uptime", 4096)
    self.assertEqual(caught.exception.reason, "observation failed")


class StreamFailureRegressionTests(unittest.TestCase):
  def test_fatal_stderr_failure_does_not_escape(self):
    with mock.patch.object(
      incident,
      "collect_snapshot",
      side_effect=incident.ObservationError("runtime", "malformed data"),
    ), mock.patch.object(incident.sys, "stderr", FailingStream()):
      self.assertEqual(incident.main([]), 3)

  def test_unsupported_platform_stderr_failure_does_not_escape(self):
    with mock.patch.object(
      incident,
      "collect_snapshot",
      side_effect=incident.UnsupportedPlatform(),
    ), mock.patch.object(incident.sys, "stderr", FailingStream()):
      self.assertEqual(incident.main([]), 3)

  def test_interrupt_stderr_failure_does_not_escape(self):
    with mock.patch.object(
      incident,
      "collect_snapshot",
      side_effect=KeyboardInterrupt(),
    ), mock.patch.object(incident.sys, "stderr", FailingStream()):
      self.assertEqual(incident.main([]), 130)


if __name__ == "__main__":
  unittest.main()
