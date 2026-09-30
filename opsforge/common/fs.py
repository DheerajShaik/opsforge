"""Regular-file opening that never opens devices, FIFOs, or final-component symlinks."""

from __future__ import annotations

import os
import stat


class NotRegularFileError(OSError):
  """The path does not name a regular file."""


class FileIdentityError(OSError):
  """The file changed between inspection and opening."""


def open_regular_file(path: str, *, dir_fd: int | None = None, follow_symlinks: bool = False) -> tuple[int, os.stat_result]:
  """Open PATH read-only only after stat shows a regular file, then confirm the opened identity."""
  before = os.stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
  if not stat.S_ISREG(before.st_mode):
    raise NotRegularFileError(f"not a regular file: {path}")
  flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY | getattr(os, "O_CLOEXEC", 0)
  if not follow_symlinks:
    flags |= os.O_NOFOLLOW
  descriptor = os.open(path, flags, dir_fd=dir_fd)
  try:
    after = os.fstat(descriptor)
    if not stat.S_ISREG(after.st_mode) or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
      raise FileIdentityError(f"file changed while it was opened: {path}")
  except BaseException:
    os.close(descriptor)
    raise
  return descriptor, after
