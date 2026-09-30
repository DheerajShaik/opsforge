"""Bounded, dependency-free output handling shared by OpsForge utilities."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, is_dataclass
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
import json
import math
import os
import secrets
import stat
import sys
from typing import Any, Mapping, Sequence, TextIO

from .text import sanitize_text


SCHEMA_VERSION = 1
MAX_OUTPUT_BYTES = 16 * 1024 * 1024


class OutputError(Exception):
  """An output destination could not be used safely."""


@dataclass(frozen=True)
class OutputRecord:
  """The stable cross-utility result envelope."""

  tool: str
  status: str
  target: str
  observations: Mapping[str, Any]
  conclusion: str
  next_action: str
  warnings: Sequence[str]
  elapsed_seconds: float

  def as_json_object(self) -> dict[str, Any]:
    return {
      "schema_version": SCHEMA_VERSION,
      "tool": self.tool,
      "status": self.status,
      "target": self.target,
      "observations": to_jsonable(self.observations),
      "conclusion": self.conclusion,
      "next_action": self.next_action,
      "warnings": [self.warnings] if isinstance(self.warnings, str) else [str(item) for item in self.warnings],
      "elapsed_seconds": round(max(0.0, float(self.elapsed_seconds)), 6),
    }


def add_output_arguments(parser: argparse.ArgumentParser) -> None:
  """Add the suite-wide additive output flags to an argparse parser."""
  representation = parser.add_mutually_exclusive_group()
  representation.add_argument(
    "--brief",
    action="store_true",
    help="show essential evidence and the final conclusion only",
  )
  representation.add_argument(
    "--json",
    action="store_true",
    help="emit only the versioned JSON result envelope",
  )
  parser.add_argument(
    "--quiet",
    action="store_true",
    help="suppress ordinary stdout; exit status still reports the result",
  )
  parser.add_argument(
    "--output",
    metavar="FILE",
    help="write the selected representation to a new file",
  )
  parser.add_argument(
    "--force",
    action="store_true",
    help="allow --output to replace an existing regular file",
  )


def validate_output_arguments(parser: argparse.ArgumentParser, arguments: argparse.Namespace) -> None:
  if getattr(arguments, "output", None) == "":
    parser.error("--output requires a non-empty path")
  if getattr(arguments, "force", False) and not getattr(arguments, "output", None):
    parser.error("--force requires --output")


def make_conclusion(status: str, target: object, finding: str, next_action: str) -> str:
  """Build the required deterministic human conclusion line."""
  clean_status = sanitize_text(str(status).upper())
  clean_target = sanitize_text(target)
  clean_finding = _sentence(finding)
  clean_next = _sentence(next_action)
  return f"Conclusion: [{clean_status}] {clean_target} — {clean_finding} Next: {clean_next}"


def _sentence(value: object) -> str:
  text = sanitize_text(value).strip()
  if not text:
    return "no additional action is available."
  return text if text.endswith((".", "!", "?")) else text + "."


def _well_formed(text: str) -> str:
  """Spell lone surrogates (undecodable filename bytes) as visible \\udcXX text so the JSON carries no ill-formed strings."""
  try:
    text.encode("utf-8")
  except UnicodeEncodeError:
    return text.encode("utf-8", "backslashreplace").decode("utf-8")
  return text


def to_jsonable(value: Any) -> Any:
  """Convert known diagnostic values into deterministic JSON-compatible data."""
  if isinstance(value, float) and not math.isfinite(value):
    return None
  if isinstance(value, str):
    return _well_formed(value)
  if value is None or isinstance(value, (bool, int, float)):
    return value
  if isinstance(value, Decimal):
    return str(value)
  if isinstance(value, (datetime, date)):
    return value.isoformat()
  if isinstance(value, Enum):
    return to_jsonable(value.value)
  if is_dataclass(value) and not isinstance(value, type):
    return to_jsonable(asdict(value))
  if isinstance(value, Mapping):
    return {_well_formed(str(key)): to_jsonable(item) for key, item in value.items()}
  if isinstance(value, (tuple, list)):
    return [to_jsonable(item) for item in value]
  raise TypeError(f"unsupported observation value: {type(value).__name__}")


def _json_text(record: OutputRecord) -> str:
  return json.dumps(
    record.as_json_object(),
    ensure_ascii=True,
    sort_keys=True,
    separators=(",", ":"),
    allow_nan=False,
  )


def _bounded_output(text: str) -> tuple[str, bytes]:
  rendered = text.rstrip("\n")
  encoded = (rendered + "\n").encode("utf-8", errors="backslashreplace")
  if len(encoded) > MAX_OUTPUT_BYTES:
    raise OutputError("rendered output exceeds the 16 MiB safety limit")
  return rendered, encoded


def _create_exclusive(path: str) -> int:
  flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
  return os.open(path, flags, 0o600)


def _write_and_sync(descriptor: int, encoded: bytes) -> None:
  view = memoryview(encoded)
  while view:
    view = view[os.write(descriptor, view):]
  os.fsync(descriptor)


def _write_new(path: str, encoded: bytes) -> None:
  try:
    descriptor = _create_exclusive(path)
  except FileExistsError as error:
    raise OutputError(f"output file already exists: {sanitize_text(path)}; use --force to replace it") from error
  except OSError as error:
    raise OutputError(f"could not open output file {sanitize_text(path)}: {sanitize_text(error)}") from error
  try:
    _write_and_sync(descriptor, encoded)
  except BaseException as error:
    os.close(descriptor)
    try:
      os.unlink(path)
    except OSError:
      pass
    if isinstance(error, OSError):
      raise OutputError(f"could not write output file {sanitize_text(path)}: {sanitize_text(error)}") from error
    raise
  os.close(descriptor)


def _replace_atomically(path: str, encoded: bytes) -> None:
  try:
    existing = os.lstat(path)
  except FileNotFoundError:
    existing = None
  except OSError as error:
    raise OutputError(f"could not inspect output file {sanitize_text(path)}: {sanitize_text(error)}") from error
  if existing is not None:
    if stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(existing.st_mode):
      raise OutputError(f"output target is not a regular file: {sanitize_text(path)}")
    if existing.st_nlink != 1:
      raise OutputError(f"refusing to replace multiply-linked output file: {sanitize_text(path)}")
  directory, name = os.path.split(path)
  temporary = os.path.join(directory, f".{name[:128]}.{secrets.token_hex(8)}.tmp")
  try:
    descriptor = _create_exclusive(temporary)
  except OSError as error:
    raise OutputError(f"could not create a temporary file beside {sanitize_text(path)}: {sanitize_text(error)}") from error
  try:
    try:
      _write_and_sync(descriptor, encoded)
    finally:
      os.close(descriptor)
    # A fresh private inode replaces the name, so a pre-existing file's owner never sees the result.
    os.replace(temporary, path)
  except BaseException as error:
    try:
      os.unlink(temporary)
    except OSError:
      pass
    if isinstance(error, OSError):
      raise OutputError(f"could not write output file {sanitize_text(path)}: {sanitize_text(error)}") from error
    raise


def _silence_broken_pipe(stream: TextIO) -> None:
  """Point a closed stdout pipe at /dev/null so interpreter shutdown cannot fail flushing it."""
  try:
    descriptor = stream.fileno()
  except (AttributeError, OSError, ValueError):
    return
  devnull = os.open(os.devnull, os.O_WRONLY)
  try:
    os.dup2(devnull, descriptor)
  finally:
    os.close(devnull)


def emit_output(
  record: OutputRecord,
  *,
  detailed: str,
  brief: str,
  json_mode: bool = False,
  brief_mode: bool = False,
  quiet: bool = False,
  output_path: str | None = None,
  force: bool = False,
  stdout: TextIO | None = None,
) -> None:
  """Render one result, optionally to a safely-created output file."""
  if json_mode:
    rendered = _json_text(record)
  else:
    body = brief if brief_mode else detailed
    rendered = f"{body.rstrip()}\n{record.conclusion}" if body.strip() else record.conclusion
  if quiet and output_path is None:
    return
  rendered, encoded = _bounded_output(rendered)
  if output_path is not None:
    path = os.fspath(output_path)
    if force:
      _replace_atomically(path, encoded)
    else:
      _write_new(path, encoded)
  if not quiet and output_path is None:
    destination = sys.stdout if stdout is None else stdout
    encoding = getattr(destination, "encoding", None)
    if encoding:
      try:
        rendered = rendered.encode(encoding, errors="backslashreplace").decode(encoding)
      except (LookupError, UnicodeError):
        rendered = rendered.encode("ascii", errors="backslashreplace").decode("ascii")
      try:
        stream_bytes = (rendered + "\n").encode(encoding, errors="strict")
      except (LookupError, UnicodeError):
        stream_bytes = (rendered + "\n").encode("ascii", errors="backslashreplace")
      if len(stream_bytes) > MAX_OUTPUT_BYTES:
        raise OutputError("rendered output exceeds the 16 MiB safety limit")
    try:
      print(rendered, file=destination)
      destination.flush()
    except BrokenPipeError:
      # A reader such as `head` closing early is not a diagnostic failure; keep the tool's exit status.
      _silence_broken_pipe(destination)
