"""Bounded, dependency-free output handling shared by OpsForge utilities."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, is_dataclass
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence, TextIO


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
      "warnings": [str(item) for item in self.warnings],
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
  if getattr(arguments, "force", False) and not getattr(arguments, "output", None):
    parser.error("--force requires --output")


def make_conclusion(status: str, target: object, finding: str, next_action: str) -> str:
  """Build the required deterministic human conclusion line."""
  clean_status = _single_line(status).upper()
  clean_target = _single_line(target)
  clean_finding = _sentence(finding)
  clean_next = _sentence(next_action)
  return f"Conclusion: [{clean_status}] {clean_target} — {clean_finding} Next: {clean_next}"


def _single_line(value: object) -> str:
  text = str(value)
  pieces = []
  for character in text:
    codepoint = ord(character)
    if character == "\x1b" or codepoint < 32 or 127 <= codepoint <= 159:
      pieces.append(f"\\x{codepoint:02x}" if codepoint <= 255 else "?")
    else:
      pieces.append(character)
  return "".join(pieces)


def _sentence(value: object) -> str:
  text = _single_line(value).strip()
  if not text:
    return "no additional action is available."
  return text if text.endswith((".", "!", "?")) else text + "."


def to_jsonable(value: Any) -> Any:
  """Convert known diagnostic values into deterministic JSON-compatible data."""
  if value is None or isinstance(value, (bool, int, float, str)):
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
    return {str(key): to_jsonable(item) for key, item in value.items()}
  if isinstance(value, (tuple, list)):
    return [to_jsonable(item) for item in value]
  raise TypeError(f"unsupported observation value: {type(value).__name__}")


def _json_text(record: OutputRecord) -> str:
  return json.dumps(
    record.as_json_object(),
    ensure_ascii=True,
    sort_keys=True,
    separators=(",", ":"),
  )


def _write_new_or_replace(path: str, text: str, *, force: bool) -> None:
  encoded = (text.rstrip("\n") + "\n").encode("utf-8")
  if len(encoded) > MAX_OUTPUT_BYTES:
    raise OutputError("rendered output exceeds the 16 MiB safety limit")
  flags = os.O_WRONLY | os.O_CREAT
  flags |= os.O_TRUNC if force else os.O_EXCL
  if hasattr(os, "O_CLOEXEC"):
    flags |= os.O_CLOEXEC
  if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
  try:
    descriptor = os.open(path, flags, 0o600)
  except FileExistsError as error:
    raise OutputError(f"output file already exists: {_single_line(path)}; use --force to replace it") from error
  except OSError as error:
    raise OutputError(f"could not open output file {_single_line(path)}: {_single_line(error)}") from error
  try:
    with os.fdopen(descriptor, "wb", closefd=True) as handle:
      descriptor = -1
      handle.write(encoded)
  except OSError as error:
    raise OutputError(f"could not write output file {_single_line(path)}: {_single_line(error)}") from error
  finally:
    if descriptor >= 0:
      os.close(descriptor)


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
  if output_path is not None:
    _write_new_or_replace(os.fspath(Path(output_path)), rendered, force=force)
  if not quiet and output_path is None:
    print(rendered, file=sys.stdout if stdout is None else stdout)
