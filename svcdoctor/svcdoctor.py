#!/usr/bin/env python3
"""Report structured systemd evidence for one local system service."""

from __future__ import annotations

from dataclasses import dataclass
import os
import selectors
import subprocess
import sys
import time
import unicodedata
from typing import Mapping, Sequence


PROPERTIES = (
  "Id",
  "LoadState",
  "ActiveState",
  "SubState",
  "Result",
  "ExecMainCode",
  "ExecMainStatus",
)
CORE_PROPERTIES = ("Id", "LoadState", "ActiveState")
OPTIONAL_PROPERTIES = ("SubState", "Result", "ExecMainCode", "ExecMainStatus")
UNIT_SUFFIXES = (
  ".service", ".socket", ".target", ".device", ".mount", ".automount",
  ".swap", ".timer", ".path", ".slice", ".scope", ".snapshot",
)
TIMEOUT_SECONDS = 5
# Seven short properties should be far below this. The limit protects against a
# faulty or substituted systemctl producing unbounded captured output.
MAX_STREAM_BYTES = 64 * 1024
UNAVAILABLE = "-"

HELP = """usage: svcdoctor SERVICE

Report current systemd state and raw execution evidence for one local system service.
Bare names receive .service; only concrete .service units are supported.

exit codes:
  0  help, or ActiveState is not exactly \"failed\"
  1  ActiveState is exactly \"failed\"
  2  invocation, missing-unit, or observation failure
"""


class SvcDoctorError(Exception):
  """A fatal invocation or observation error with stable user-facing text."""


class ResponseTooLargeError(SvcDoctorError):
  """The observation command exceeded a defensive output bound."""


@dataclass(frozen=True)
class CommandResult:
  returncode: int
  stdout: bytes
  stderr: bytes


def display_safe(value: object) -> str:
  """Escape terminal controls and ambiguous separators without losing text."""
  rendered = []
  for character in str(value):
    codepoint = ord(character)
    category = unicodedata.category(character)
    if character == "\\":
      rendered.append("\\\\")
    elif category in {"Cc", "Cf", "Cs", "Zl", "Zp"}:
      if codepoint <= 0xFF:
        rendered.append(f"\\x{codepoint:02x}")
      elif codepoint <= 0xFFFF:
        rendered.append(f"\\u{codepoint:04x}")
      else:
        rendered.append(f"\\U{codepoint:08x}")
    else:
      rendered.append(character)
  return "".join(rendered)


def normalize_target(target: str) -> str:
  """Apply only SvcDoctor's minimal safety and .service scope policy."""
  if not target:
    raise SvcDoctorError("target must not be empty")
  if target.startswith("-"):
    raise SvcDoctorError(f"invalid service target: {display_safe(target)}")
  if "/" in target:
    raise SvcDoctorError(f"service target must not contain '/': {display_safe(target)}")
  if any(character.isspace() for character in target):
    raise SvcDoctorError(f"service target must not contain whitespace: {display_safe(target)}")
  if any(unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"}
         for character in target):
    raise SvcDoctorError(f"service target contains a control character: {display_safe(target)}")

  explicit_suffix = next((suffix for suffix in UNIT_SUFFIXES if target.endswith(suffix)), None)
  if explicit_suffix is not None and explicit_suffix != ".service":
    raise SvcDoctorError(
      f"unsupported unit type {explicit_suffix}; only .service units are supported"
    )
  normalized = target if explicit_suffix == ".service" else f"{target}.service"
  if normalized == ".service":
    raise SvcDoctorError("service target must have a non-empty stem")
  if normalized.endswith("@.service"):
    raise SvcDoctorError("template units are not supported; specify a concrete instance")
  return normalized


def systemctl_arguments(target: str) -> list[str]:
  arguments = ["systemctl", "show", "--system", "--no-pager"]
  arguments.extend(f"--property={property_name}" for property_name in PROPERTIES)
  arguments.extend(("--", target))
  return arguments


def _stop_process(process: subprocess.Popen[bytes]) -> None:
  """Terminate and reap a child after timeout or an output-limit violation."""
  if process.poll() is None:
    process.kill()
  process.wait()


def run_systemctl(target: str) -> CommandResult:
  """Run one bounded, non-shell systemctl query."""
  environment = os.environ.copy()
  environment.update({"LC_ALL": "C", "SYSTEMD_PAGER": "", "SYSTEMD_COLORS": "0"})
  try:
    process = subprocess.Popen(
      systemctl_arguments(target),
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
      env=environment,
    )
  except FileNotFoundError as error:
    raise SvcDoctorError("systemctl is not available") from error
  except OSError as error:
    raise SvcDoctorError("could not execute systemctl") from error

  if process.stdout is None or process.stderr is None:  # pragma: no cover - Popen contract
    _stop_process(process)
    raise SvcDoctorError("could not execute systemctl")

  streams = {process.stdout: bytearray(), process.stderr: bytearray()}
  selector = selectors.DefaultSelector()
  selector.register(process.stdout, selectors.EVENT_READ)
  selector.register(process.stderr, selectors.EVENT_READ)
  deadline = time.monotonic() + TIMEOUT_SECONDS
  try:
    while selector.get_map():
      remaining = deadline - time.monotonic()
      if remaining <= 0:
        _stop_process(process)
        raise SvcDoctorError("systemd query timed out after 5 seconds")
      events = selector.select(remaining)
      if not events:
        _stop_process(process)
        raise SvcDoctorError("systemd query timed out after 5 seconds")
      for key, _ in events:
        chunk = os.read(key.fileobj.fileno(), 8192)
        if not chunk:
          selector.unregister(key.fileobj)
          continue
        captured = streams[key.fileobj]
        captured.extend(chunk)
        if len(captured) > MAX_STREAM_BYTES:
          _stop_process(process)
          raise ResponseTooLargeError("systemd returned a malformed response")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
      _stop_process(process)
      raise SvcDoctorError("systemd query timed out after 5 seconds")
    try:
      returncode = process.wait(timeout=remaining)
    except subprocess.TimeoutExpired as error:
      _stop_process(process)
      raise SvcDoctorError("systemd query timed out after 5 seconds") from error
  finally:
    selector.close()
    process.stdout.close()
    process.stderr.close()

  return CommandResult(returncode, bytes(streams[process.stdout]), bytes(streams[process.stderr]))


def decode_output(output: bytes) -> str:
  try:
    return output.decode("utf-8")
  except UnicodeDecodeError as error:
    raise SvcDoctorError("systemd returned a malformed response") from error


def parse_properties(output: str) -> dict[str, str]:
  """Parse exactly one allowlisted Property=Value record."""
  if not output:
    raise SvcDoctorError("systemd returned an empty response")
  lines = output.splitlines()
  if not lines or not any(line for line in lines):
    raise SvcDoctorError("systemd returned an empty response")

  properties: dict[str, str] = {}
  record_ended = False
  for line in lines:
    if line == "":
      if properties:
        record_ended = True
      continue
    if record_ended or "=" not in line:
      raise SvcDoctorError("systemd returned a malformed response")
    name, value = line.split("=", 1)
    if not name or name not in PROPERTIES or name in properties:
      raise SvcDoctorError("systemd returned a malformed response")
    properties[name] = value
  if not properties:
    raise SvcDoctorError("systemd returned an empty response")
  return properties


def validate_properties(properties: Mapping[str, str]) -> None:
  """Validate core evidence, allowing ActiveState to be absent for not-found."""
  required = ("Id", "LoadState")
  missing = [name for name in required if not properties.get(name)]
  if properties.get("LoadState") != "not-found" and not properties.get("ActiveState"):
    missing.append("ActiveState")
  if missing:
    names = ", ".join(missing)
    raise SvcDoctorError(
      f"incomplete systemd response: missing or empty property {names}"
    )
  if not properties["Id"].endswith(".service"):
    raise SvcDoctorError("systemd returned a malformed response")


def render_diagnostic(target: str, properties: Mapping[str, str]) -> str:
  """Render one accepted observation in the frozen field order."""
  safe = lambda name: display_safe(properties.get(name) or UNAVAILABLE)
  failed = properties["ActiveState"] == "failed"
  return "\n".join((
    "Target",
    f"  Requested: {display_safe(target)}",
    f"  Unit: {safe('Id')}",
    "State",
    f"  Load: {safe('LoadState')}",
    f"  Active: {safe('ActiveState')}",
    f"  Sub: {safe('SubState')}",
    "Execution evidence",
    f"  Result: {safe('Result')}",
    f"  Main code: {safe('ExecMainCode')}",
    f"  Main status: {safe('ExecMainStatus')}",
    "Assessment",
    f'  ActiveState equals "failed": {"yes" if failed else "no"}',
  ))


def inspect_service(target: str) -> tuple[str, int]:
  result = run_systemctl(target)
  if result.returncode != 0:
    raise SvcDoctorError("systemd query failed")
  properties = parse_properties(decode_output(result.stdout))
  validate_properties(properties)
  if properties["LoadState"] == "not-found":
    raise SvcDoctorError(f"service not found: {display_safe(target)}")
  return render_diagnostic(target, properties), 1 if properties["ActiveState"] == "failed" else 0


def main(arguments: Sequence[str] | None = None) -> int:
  argv = list(sys.argv[1:] if arguments is None else arguments)
  if argv in (["-h"], ["--help"]):
    print(HELP, end="")
    return 0
  if len(argv) != 1:
    print("svcdoctor: expected exactly one SERVICE", file=sys.stderr)
    return 2
  try:
    target = normalize_target(argv[0])
    output, exit_code = inspect_service(target)
  except SvcDoctorError as error:
    print(f"svcdoctor: {error}", file=sys.stderr)
    return 2
  print(output)
  return exit_code


if __name__ == "__main__":
  raise SystemExit(main())
