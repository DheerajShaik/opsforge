import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from opsforge.diskhound import diskhound


# Real lines from /proc/self/mountinfo on Ubuntu 24.04 under WSL2 (a 9p share, tmpfs, ext4, overlayfs, optional fields).
MOUNTINFO = b"""73 78 0:28 / /usr/lib/modules/5.15.167.4-microsoft-standard-WSL2 rw,nosuid,nodev,noatime - overlay none rw,lowerdir=/modules
74 78 0:31 / /mnt/wsl rw,relatime shared:1 - tmpfs none rw
75 78 0:33 / /usr/lib/wsl/drivers ro,nosuid,nodev,noatime - 9p drivers ro,dirsync,aname=drivers;fmask=222,mmap,access=client
78 63 8:32 / / rw,relatime - ext4 /dev/sdc rw,discard,errors=remount-ro,data=ordered
80 79 8:32 / /mnt/wslg/distro ro,relatime shared:3 - ext4 /dev/sdc rw,discard,errors=remount-ro,data=ordered
"""
FOREIGN = os.makedev(0, 4242)


class ParseMountinfoTests(unittest.TestCase):
  def test_real_lines_map_mount_points_to_device_and_type(self):
    mounts = diskhound.parse_mountinfo(MOUNTINFO)
    self.assertEqual(mounts["/usr/lib/wsl/drivers"], diskhound.Mount(os.makedev(0, 33), "9p"))
    self.assertEqual(mounts["/mnt/wsl"], diskhound.Mount(os.makedev(0, 31), "tmpfs"))
    self.assertEqual(mounts["/mnt/wslg/distro"], diskhound.Mount(os.makedev(8, 32), "ext4"))
    self.assertEqual(len(mounts), 5)

  def test_optional_fields_and_malformed_lines_do_not_break_parsing(self):
    data = b"garbage\n\n36 35 98:0 /root /mnt/a rw master:1 shared:2 - ext4 /dev/x rw\n1 2 3 4\n"
    self.assertEqual(diskhound.parse_mountinfo(data), {"/mnt/a": diskhound.Mount(os.makedev(98, 0), "ext4")})

  def test_octal_escapes_and_later_mounts_covering_earlier_ones(self):
    data = (
      b"40 1 0:10 / /mnt/with\\040space rw - nfs4 server:/x rw\n"
      b"41 1 0:11 / /mnt/tab\\011name rw - tmpfs none rw\n"
      b"42 1 0:12 / /mnt/cover rw - tmpfs none rw\n"
      b"43 1 0:13 / /mnt/cover rw - cifs //server/share rw\n"
    )
    mounts = diskhound.parse_mountinfo(data)
    self.assertEqual(mounts["/mnt/with space"].filesystem_type, "nfs4")
    self.assertIn("/mnt/tab\tname", mounts)
    self.assertEqual(mounts["/mnt/cover"], diskhound.Mount(os.makedev(0, 13), "cifs"))

  def test_remote_filesystem_types(self):
    for kind in ("nfs", "nfs4", "cifs", "smb3", "9p", "autofs", "fuse", "fuseblk", "fuse.sshfs", "fuse.rclone", "ceph", "virtiofs"):
      with self.subTest(kind=kind):
        self.assertTrue(diskhound.Mount(1, kind).remote)
    for kind in ("ext4", "xfs", "btrfs", "tmpfs", "overlay", "proc", "fusectl"):
      with self.subTest(kind=kind):
        self.assertFalse(diskhound.Mount(1, kind).remote)


class ReadNestedMountsTests(unittest.TestCase):
  def test_only_mounts_below_the_target_are_keyed_by_scan_paths(self):
    with tempfile.TemporaryDirectory() as directory:
      table = Path(directory, "mountinfo")
      real = os.path.realpath(directory)
      table.write_bytes(
        f"1 0 0:1 / {real} rw - ext4 /dev/a rw\n2 1 0:2 / {real}/share rw - nfs4 s:/x rw\n3 1 0:3 / {real}-other rw - nfs4 s:/y rw\n".encode()
      )
      with mock.patch.object(diskhound, "MOUNTINFO_PATH", str(table)):
        nested = diskhound.read_nested_mounts(directory + "/")
    self.assertEqual(nested, {directory + "/share": diskhound.Mount(os.makedev(0, 2), "nfs4")})

  def test_oversized_table_is_an_error(self):
    with tempfile.TemporaryDirectory() as directory:
      table = Path(directory, "mountinfo")
      table.write_bytes(b"x" * 70000)
      with mock.patch.object(diskhound, "MOUNTINFO_PATH", str(table)), mock.patch.object(diskhound, "MAX_MOUNTINFO_BYTES", 1024):
        with self.assertRaises(ValueError):
          diskhound.read_nested_mounts(directory)


class RemoteMountScanTests(unittest.TestCase):
  def tree(self, directory):
    Path(directory, "share").mkdir()
    Path(directory, "share", "hidden.bin").write_bytes(b"x" * 10000)
    Path(directory, "local").mkdir()
    Path(directory, "local", "kept.bin").write_bytes(b"y" * 10000)

  def scan(self, directory, *, cross, include=False, mount_type="nfs4"):
    mounts = {os.path.join(directory, "share"): diskhound.Mount(FOREIGN, mount_type)}
    with mock.patch.object(diskhound, "read_nested_mounts", return_value=mounts):
      return diskhound.scan(directory, diskhound.ScanOptions(cross_filesystems=cross, include_remote_mounts=include))

  def test_remote_mount_is_never_statted_or_entered(self):
    with tempfile.TemporaryDirectory() as directory:
      self.tree(directory)
      share = os.path.join(directory, "share")
      real_stat = os.stat
      statted = []

      def recording_stat(path, *args, **kwargs):
        statted.append(str(path))
        return real_stat(path, *args, **kwargs)

      with mock.patch.object(diskhound.os, "stat", side_effect=recording_stat):
        result = self.scan(directory, cross=False)
      self.assertNotIn("share", statted)
      self.assertEqual([branch.path for branch in result.branches], [os.path.join(directory, "local")])
      self.assertEqual(result.cross_device_immediate, 1)
      self.assertEqual(result.remote_mounts_not_entered, ())
      self.assertFalse(result.incomplete)

  def test_cross_filesystems_reports_unentered_remote_mounts_as_partial(self):
    with tempfile.TemporaryDirectory() as directory:
      self.tree(directory)
      result = self.scan(directory, cross=True)
    self.assertEqual(result.remote_mounts_not_entered, (diskhound.RemoteMount(os.path.join(directory, "share"), "nfs4"),))
    self.assertTrue(result.incomplete)
    self.assertIn("1 network, FUSE, or autofs mount(s) were not entered", result.incomplete_reasons())
    self.assertEqual([branch.path for branch in result.branches], [os.path.join(directory, "local")])
    self.assertEqual(diskhound.inspect_result_code(result), diskhound.EXIT_FINDING)
    finding, next_action = diskhound.describe_result(result)
    self.assertIn("--include-remote-mounts", next_action)
    self.assertTrue(any("nfs4 mount not entered" in warning for warning in diskhound.render_warnings(result)))

  def test_opting_in_enters_the_mount(self):
    with tempfile.TemporaryDirectory() as directory:
      self.tree(directory)
      result = self.scan(directory, cross=True, include=True)
    self.assertEqual(result.remote_mounts_not_entered, ())
    self.assertEqual(sorted(os.path.basename(branch.path) for branch in result.branches), ["local", "share"])
    self.assertFalse(result.incomplete)

  def test_local_foreign_device_is_statted_and_skipped_without_being_partial(self):
    with tempfile.TemporaryDirectory() as directory:
      self.tree(directory)
      result = self.scan(directory, cross=False, mount_type="ext4")
    self.assertEqual(result.cross_device_immediate, 0)
    self.assertEqual(sorted(os.path.basename(branch.path) for branch in result.branches), ["local", "share"])

  def test_unreadable_mount_table_is_a_warning_not_a_failure(self):
    with tempfile.TemporaryDirectory() as directory:
      self.tree(directory)
      with mock.patch.object(diskhound, "read_nested_mounts", side_effect=OSError("no mountinfo")):
        result = diskhound.scan(directory)
    self.assertIn("mount table unavailable", result.mount_table_warning)
    self.assertTrue(any("mount table unavailable" in warning for warning in diskhound.render_warnings(result)))


class CommandLineTests(unittest.TestCase):
  def run_main(self, arguments):
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
      try:
        code = diskhound.main(arguments)
      except SystemExit as error:
        code = error.code
    return code, stdout.getvalue(), stderr.getvalue()

  def test_include_remote_mounts_requires_cross_filesystems(self):
    with tempfile.TemporaryDirectory() as directory:
      code, stdout, stderr = self.run_main([directory, "--include-remote-mounts"])
    self.assertEqual((code, stdout), (2, ""))
    self.assertIn("--include-remote-mounts requires --cross-filesystems", stderr)

  def test_json_reports_unentered_mounts_and_partial_status(self):
    with tempfile.TemporaryDirectory() as directory:
      Path(directory, "share").mkdir()
      mounts = {os.path.join(directory, "share"): diskhound.Mount(FOREIGN, "fuse.sshfs")}
      with mock.patch.object(diskhound, "read_nested_mounts", return_value=mounts):
        code, stdout, stderr = self.run_main(["--json", "--cross-filesystems", directory])
    self.assertEqual(code, 1)
    document = json.loads(stdout)
    self.assertEqual(document["status"], "PARTIAL")
    self.assertEqual(document["observations"]["remote_mounts_not_entered_total"], 1)
    self.assertEqual(document["observations"]["remote_mounts_not_entered"][0]["filesystem_type"], "fuse.sshfs")
    self.assertIn("fuse.sshfs mount not entered", stderr)

  def test_output_failure_exits_three(self):
    with tempfile.TemporaryDirectory() as directory:
      code, stdout, stderr = self.run_main(["--output", os.path.join(directory, "missing", "out.txt"), directory])
    self.assertEqual(code, 3)
    self.assertTrue(stderr.startswith("diskhound:"))


if __name__ == "__main__":
  unittest.main()
