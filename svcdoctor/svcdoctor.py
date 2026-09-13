#!/usr/bin/env python3
"""Report structured systemd evidence for one local system service."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
import selectors
import subprocess
import sys
import time
import unicodedata
from typing import Mapping, Sequence

from opsforge_common import (
  OutputError,
  OutputRecord,
  add_output_arguments,
  emit_output,
  make_conclusion,
  validate_output_arguments,
)


PROPERTIES = (
  "Id",
  "LoadState",
  "ActiveState",
  "SubState",
  "Result",
  "ExecMainCode",
  "ExecMainStatus",
  "FragmentPath",
  "DropInPaths",
  "Requires",
  "Wants",
  "NRestarts",
  "Restart",
  "ActiveEnterTimestamp",
  "CPUUsageNSec",
  "MemoryCurrent",
  "MemoryMax",
  "TasksCurrent",
  "TasksMax",
  "User",
  "Group",
  "DynamicUser",
)
CORE_PROPERTIES = ("Id", "LoadState", "ActiveState")
OPTIONAL_PROPERTIES = tuple(name for name in PROPERTIES if name not in CORE_PROPERTIES)
UNIT_SUFFIXES = (
  ".service", ".socket", ".target", ".device", ".mount", ".automount",
  ".swap", ".timer", ".path", ".slice", ".scope", ".snapshot",
)
SYSTEMD_GLOB_METACHARACTERS = frozenset("*?[]")
TIMEOUT_SECONDS = 5
MAX_STREAM_BYTES = 64 * 1024
MAX_JOURNAL_LINES = 200
MAX_DEPENDENCIES = 32
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


@dataclass(frozen=True)
class ServiceEvidence:
  target: str
  properties: Mapping[str, str]
  journal: tuple[str, ...]
  journal_warning: str | None
  failed_dependencies: tuple[str, ...]


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
  if any(character in SYSTEMD_GLOB_METACHARACTERS for character in target):
    raise SvcDoctorError(
      f"service target must be a concrete unit, not a pattern: {display_safe(target)}"
    )

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

  if process.stdout is None or process.stderr is None:
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


def run_simple_command(arguments: Sequence[str], label: str, timeout: float = TIMEOUT_SECONDS) -> CommandResult:
  environment = os.environ.copy()
  environment.update({"LC_ALL": "C", "SYSTEMD_PAGER": "", "SYSTEMD_COLORS": "0"})
  try:
    process = subprocess.Popen(
      list(arguments), stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
    )
  except FileNotFoundError as error:
    raise SvcDoctorError(f"{label} is not available") from error
  except OSError as error:
    raise SvcDoctorError(f"could not execute {label}") from error
  if process.stdout is None or process.stderr is None:
    _stop_process(process)
    raise SvcDoctorError(f"could not execute {label}")
  streams = {process.stdout: bytearray(), process.stderr: bytearray()}
  selector = selectors.DefaultSelector()
  selector.register(process.stdout, selectors.EVENT_READ)
  selector.register(process.stderr, selectors.EVENT_READ)
  deadline = time.monotonic() + timeout
  try:
    while selector.get_map():
      remaining = deadline - time.monotonic()
      if remaining <= 0:
        _stop_process(process)
        raise SvcDoctorError(f"{label} query timed out")
      events = selector.select(remaining)
      if not events:
        _stop_process(process)
        raise SvcDoctorError(f"{label} query timed out")
      for key, _ in events:
        chunk = os.read(key.fileobj.fileno(), 8192)
        if not chunk:
          selector.unregister(key.fileobj)
          continue
        streams[key.fileobj].extend(chunk)
        if len(streams[key.fileobj]) > MAX_STREAM_BYTES:
          _stop_process(process)
          raise ResponseTooLargeError(f"{label} returned oversized output")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
      _stop_process(process)
      raise SvcDoctorError(f"{label} query timed out")
    try:
      returncode = process.wait(timeout=remaining)
    except subprocess.TimeoutExpired as error:
      _stop_process(process)
      raise SvcDoctorError(f"{label} query timed out") from error
  finally:
    selector.close()
    process.stdout.close()
    process.stderr.close()
  return CommandResult(returncode, bytes(streams[process.stdout]), bytes(streams[process.stderr]))


def collect_journal(target: str, lines: int) -> tuple[tuple[str, ...], str | None]:
  result = run_simple_command(
    ("journalctl", "--system", "--no-pager", "--output=short-iso", "--lines", str(lines), "--unit", target),
    "journalctl",
  )
  if result.returncode != 0:
    return (), "recent journal evidence unavailable"
  try:
    text = result.stdout.decode("utf-8", "strict")
  except UnicodeDecodeError:
    return (), "recent journal evidence was not valid UTF-8"
  rendered = tuple(display_safe(line)[:512] for line in text.splitlines()[:lines])
  return rendered, None


def dependency_names(properties: Mapping[str, str]) -> tuple[str, ...]:
  names = []
  for field in ("Requires", "Wants"):
    for name in properties.get(field, "").split():
      if name.endswith(".service") and name not in names:
        names.append(name)
      if len(names) >= MAX_DEPENDENCIES:
        return tuple(names)
  return tuple(names)


def find_failed_dependencies(names: Sequence[str]) -> tuple[str, ...]:
  if not names:
    return ()
  result = run_simple_command(("systemctl", "is-failed", "--system", "--no-pager", "--", *names), "systemctl")
  try:
    states = result.stdout.decode("ascii", "strict").splitlines()
  except UnicodeDecodeError:
    return ()
  return tuple(name for name, state in zip(names, states) if state.strip() == "failed")


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
  code = properties.get("ExecMainCode", "")
  status = properties.get("ExecMainStatus", "")
  if code == "1":
    interpretation = f"process exited with status {display_safe(status or UNAVAILABLE)}"
  elif code == "2":
    interpretation = f"process was killed by signal {display_safe(status or UNAVAILABLE)}"
  elif code == "3":
    interpretation = f"process dumped core after signal {display_safe(status or UNAVAILABLE)}"
  elif code in {"", "0"}:
    interpretation = "no terminating main-process result was reported"
  else:
    interpretation = f"unrecognized systemd execution code {display_safe(code)}"
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
    f"  Interpretation: {interpretation}",
    f"  Restart policy: {safe('Restart')}",
    f"  Restarts: {safe('NRestarts')}",
    f"  Active since: {safe('ActiveEnterTimestamp')}",
    "Unit configuration",
    f"  Unit file: {safe('FragmentPath')}",
    f"  Drop-ins: {safe('DropInPaths')}",
    f"  Requires: {safe('Requires')}",
    f"  Wants: {safe('Wants')}",
    "Resource evidence",
    f"  CPU usage (ns): {safe('CPUUsageNSec')}",
    f"  Memory current: {safe('MemoryCurrent')}",
    f"  Memory limit: {safe('MemoryMax')}",
    f"  Tasks current: {safe('TasksCurrent')}",
    f"  Tasks limit: {safe('TasksMax')}",
    "Selected execution context",
    f"  User: {safe('User')}",
    f"  Group: {safe('Group')}",
    f"  Dynamic user: {safe('DynamicUser')}",
    "Assessment",
    f'  ActiveState equals "failed": {"yes" if failed else "no"}',
  ))


def render_service_evidence(evidence: ServiceEvidence) -> str:
  lines = [render_diagnostic(evidence.target, evidence.properties)]
  lines.extend([
    "Dependencies",
    f"  Failed dependencies: {', '.join(map(display_safe, evidence.failed_dependencies)) or UNAVAILABLE}",
    "Recent journal evidence",
  ])
  lines.extend(f"  {line}" for line in evidence.journal)
  if not evidence.journal:
    lines.append("  unavailable or empty")
  lines.extend([
    "Next diagnostic command",
    f"  journalctl --system --unit {display_safe(evidence.target)} --lines 50 --no-pager",
  ])
  return "\n".join(lines)


def collect_service(target: str, journal_lines: int) -> ServiceEvidence:
  result = run_systemctl(target)
  if result.returncode != 0:
    raise SvcDoctorError("systemd query failed")
  properties = parse_properties(decode_output(result.stdout))
  validate_properties(properties)
  if properties["LoadState"] == "not-found":
    raise SvcDoctorError(f"service not found: {display_safe(target)}")
  names = dependency_names(properties)
  try:
    failed = find_failed_dependencies(names)
  except SvcDoctorError:
    failed = ()
  try:
    journal, journal_warning = collect_journal(target, journal_lines)
  except SvcDoctorError as error:
    journal, journal_warning = (), str(error)
  return ServiceEvidence(target, properties, journal, journal_warning, failed)


def inspect_service(target: str) -> tuple[str, int]:
  result = run_systemctl(target)
  if result.returncode != 0:
    raise SvcDoctorError("systemd query failed")
  properties = parse_properties(decode_output(result.stdout))
  validate_properties(properties)
  if properties["LoadState"] == "not-found":
    raise SvcDoctorError(f"service not found: {display_safe(target)}")
  return render_diagnostic(target, properties), 1 if properties["ActiveState"] == "failed" else 0


def parse_journal_lines(value: str) -> int:
  if not value.isascii() or not value.isdecimal():
    raise argparse.ArgumentTypeError("journal line count must be from 0 through 200")
  result = int(value, 10)
  if not 0 <= result <= MAX_JOURNAL_LINES:
    raise argparse.ArgumentTypeError("journal line count must be from 0 through 200")
  return result


class Parser(argparse.ArgumentParser):
  def error(self, message):
    self.print_usage(sys.stderr)
    self.exit(2, f"svcdoctor: error: {message}\n")


def build_argument_parser() -> argparse.ArgumentParser:
  parser = Parser(
    prog="svcdoctor",
    description="Report bounded, read-only systemd evidence for one local system service.",
    epilog='Exit codes: 0 not failed; 1 ActiveState is "failed"; 2 invocation or observation failure; 130 interrupted.',
  )
  parser.add_argument("service", help="concrete service unit; bare names receive .service")
  parser.add_argument("--journal-lines", type=parse_journal_lines, default=20, metavar="N")
  add_output_arguments(parser)
  return parser


def main(arguments: Sequence[str] | None = None) -> int:
  parser = build_argument_parser()
  try:
    args = parser.parse_args(arguments)
  except SystemExit as error:
    return int(error.code)
  validate_output_arguments(parser, args)
  started = time.monotonic()
  try:
    target = normalize_target(args.service)
    evidence = collect_service(target, args.journal_lines)
  except SvcDoctorError as error:
    print(f"svcdoctor: {error}", file=sys.stderr)
    return 2
  except KeyboardInterrupt:
    print("svcdoctor: interrupted", file=sys.stderr)
    return 130
  except Exception:
    print("svcdoctor: internal execution failure", file=sys.stderr)
    return 2
  failed = evidence.properties["ActiveState"] == "failed"
  exit_code = 1 if failed else 0
  status = "FAILED" if failed else "ACTIVE" if evidence.properties["ActiveState"] == "active" else "INACTIVE"
  finding = f"ActiveState is {evidence.properties['ActiveState']} and SubState is {evidence.properties.get('SubState') or UNAVAILABLE}"
  next_action = (
    f"inspect the bounded journal and failed dependencies for {target}" if failed
    else "no service failure was established; use the suggested journal command for deeper context"
  )
  conclusion = make_conclusion(status, target, finding, next_action)
  warnings = (evidence.journal_warning,) if evidence.journal_warning else ()
  for warning in warnings:
    print(f"svcdoctor: warning: {display_safe(warning)}", file=sys.stderr)
  record = OutputRecord(
    tool="svcdoctor",
    status=status,
    target=target,
    observations={
      "properties": dict(evidence.properties),
      "failed_dependencies": evidence.failed_dependencies,
      "recent_journal": evidence.journal,
    },
    conclusion=conclusion,
    next_action=next_action + ".",
    warnings=warnings,
    elapsed_seconds=time.monotonic() - started,
  )
  brief = "\n".join([
    f"Service: {display_safe(target)}",
    f"State: {display_safe(evidence.properties['ActiveState'])}/{display_safe(evidence.properties.get('SubState') or UNAVAILABLE)}",
    f"Result: {display_safe(evidence.properties.get('Result') or UNAVAILABLE)}",
    f"Restarts: {display_safe(evidence.properties.get('NRestarts') or UNAVAILABLE)}",
    f"Failed dependencies: {len(evidence.failed_dependencies)}",
  ])
  try:
    emit_output(
      record,
      detailed=render_service_evidence(evidence),
      brief=brief,
      json_mode=args.json,
      brief_mode=args.brief,
      quiet=args.quiet,
      output_path=args.output,
      force=args.force,
    )
  except OutputError as error:
    print(f"svcdoctor: {display_safe(error)}", file=sys.stderr)
    return 2
  return exit_code


if __name__ == "__main__":
  raise SystemExit(main())
