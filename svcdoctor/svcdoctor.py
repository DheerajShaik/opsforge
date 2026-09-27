#!/usr/bin/env python3
"""Report structured systemd evidence for one local system service."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import shlex
import sys
import time
from typing import Mapping, Sequence

from opsforge_common import (
  OutputError,
  OutputRecord,
  add_output_arguments,
  emit_output,
  has_unsafe_characters,
  make_conclusion,
  sanitize_text as display_safe,
  validate_output_arguments,
)
from opsforge_common.process import (
  ProcessNotFoundError,
  ProcessOutputLimitError,
  ProcessResult,
  ProcessSpawnError,
  ProcessTimeoutError,
  child_environment,
  resolve_executable,
  run_bounded,
)
from opsforge_common.systemd import UnitNameError, normalize_service_name


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
  "Requisite",
  "BindsTo",
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
DEPENDENCY_PROPERTIES = ("Requires", "Requisite", "BindsTo", "Wants")
TIMEOUT_SECONDS = 5
MAX_STREAM_BYTES = 64 * 1024
MAX_JOURNAL_BYTES = 256 * 1024
MAX_JOURNAL_LINES = 200
MAX_JOURNAL_LINE_CHARACTERS = 512
MAX_DEPENDENCIES = 32
UNAVAILABLE = "-"
COMMAND_ENVIRONMENT = child_environment(SYSTEMD_PAGER="", SYSTEMD_COLORS="0", TZ="UTC")


class SvcDoctorError(Exception):
  """A fatal invocation or observation error with stable user-facing text."""


class ResponseTooLargeError(SvcDoctorError):
  """The observation command exceeded a defensive output bound."""


@dataclass(frozen=True)
class ServiceEvidence:
  target: str
  properties: Mapping[str, str]
  journal: tuple[str, ...]
  journal_warning: str | None
  failed_dependencies: tuple[str, ...] | None
  dependency_warning: str | None = None
  dependencies_checked: tuple[str, ...] = ()
  dependencies_truncated: bool = False


def normalize_target(target: str) -> str:
  """Apply only SvcDoctor's minimal safety and .service scope policy."""
  try:
    return normalize_service_name(target)
  except UnitNameError as error:
    raise SvcDoctorError(str(error)) from error


def systemctl_arguments(target: str, executable: str = "systemctl") -> list[str]:
  arguments = [executable, "show", "--system", "--no-pager"]
  arguments.extend(f"--property={property_name}" for property_name in PROPERTIES)
  arguments.extend(("--", target))
  return arguments


def require_executable(name: str) -> str:
  executable = resolve_executable(name)
  if executable is None:
    raise SvcDoctorError(f"{name} is not available")
  return executable


def run_systemctl(target: str) -> ProcessResult:
  """Run one bounded, non-shell systemctl query."""
  arguments = systemctl_arguments(target, require_executable("systemctl"))
  try:
    return run_bounded(
      arguments, timeout=TIMEOUT_SECONDS, max_output_bytes=MAX_STREAM_BYTES, environment=COMMAND_ENVIRONMENT,
    )
  except ProcessNotFoundError as error:
    raise SvcDoctorError("systemctl is not available") from error
  except ProcessSpawnError as error:
    raise SvcDoctorError("could not execute systemctl") from error
  except ProcessTimeoutError as error:
    raise SvcDoctorError(f"systemd query timed out after {TIMEOUT_SECONDS:g} seconds") from error
  except ProcessOutputLimitError as error:
    raise ResponseTooLargeError("systemd returned oversized output") from error


def run_simple_command(
  arguments: Sequence[str],
  label: str,
  timeout: float = TIMEOUT_SECONDS,
  *,
  max_output_bytes: int = MAX_STREAM_BYTES,
  truncate_stdout: bool = False,
) -> ProcessResult:
  try:
    return run_bounded(
      arguments,
      timeout=timeout,
      max_output_bytes=max_output_bytes,
      environment=COMMAND_ENVIRONMENT,
      truncate_stdout=truncate_stdout,
    )
  except ProcessNotFoundError as error:
    raise SvcDoctorError(f"{label} is not available") from error
  except ProcessSpawnError as error:
    raise SvcDoctorError(f"could not execute {label}") from error
  except ProcessTimeoutError as error:
    raise SvcDoctorError(f"{label} query timed out after {timeout:g} seconds") from error
  except ProcessOutputLimitError as error:
    raise ResponseTooLargeError(f"{label} returned oversized output") from error


def collect_journal(unit: str, lines: int) -> tuple[tuple[str, ...], str | None]:
  """Return the newest LINES journal lines for UNIT in chronological order, each raw line bounded."""
  if lines == 0:
    return (), None
  result = run_simple_command(
    (
      require_executable("journalctl"), "--system", "--no-pager", "--quiet", "--reverse",
      "--output=short-iso", "--lines", str(lines), "--unit", unit,
    ),
    "journalctl",
    max_output_bytes=MAX_JOURNAL_BYTES,
    truncate_stdout=True,
  )
  if result.returncode != 0 and not result.stdout_truncated:
    return (), "recent journal evidence unavailable"
  segments = result.stdout.decode("utf-8", "surrogateescape").split("\n")
  if result.stdout_truncated:
    # The byte bound may have cut the oldest line part-way.
    segments.pop()
  newest = [segment for segment in segments if segment][:lines]
  entries: list[list[str]] = []
  for line in newest:
    # journalctl indents continuation lines of a multi-line entry; reverse whole entries.
    if entries and line.startswith(" "):
      entries[-1].append(line)
    else:
      entries.append([line])
  journal = tuple(
    line if len(line) <= MAX_JOURNAL_LINE_CHARACTERS
    else line[:MAX_JOURNAL_LINE_CHARACTERS] + "... [truncated]"
    for entry in reversed(entries)
    for line in entry
  )
  if result.stdout_truncated and len(newest) < lines:
    return journal, (
      f"recent journal output exceeded {MAX_JOURNAL_BYTES // 1024} KiB; "
      f"only the newest {len(newest)} lines are shown"
    )
  return journal, None


def dependency_names(properties: Mapping[str, str]) -> tuple[tuple[str, ...], bool]:
  """Return up to MAX_DEPENDENCIES unique direct dependencies of any unit type, and whether more exist."""
  names = tuple(dict.fromkeys(
    name for field in DEPENDENCY_PROPERTIES for name in properties.get(field, "").split()
  ))
  return names[:MAX_DEPENDENCIES], len(names) > MAX_DEPENDENCIES


def find_failed_dependencies(names: Sequence[str]) -> tuple[str, ...]:
  if not names:
    return ()
  result = run_simple_command(
    (require_executable("systemctl"), "is-failed", "--system", "--no-pager", "--", *names), "systemctl",
  )
  try:
    states = result.stdout.decode("ascii", "strict").splitlines()
  except UnicodeDecodeError as error:
    raise SvcDoctorError("non-ASCII systemd response") from error
  known_states = {"active", "reloading", "inactive", "failed", "activating", "deactivating", "maintenance", "refreshing"}
  if len(states) != len(names) or any(state not in known_states for state in states):
    raise SvcDoctorError("malformed or incomplete systemd response")
  failed = tuple(name for name, state in zip(names, states) if state == "failed")
  if result.returncode != (0 if failed else 1):
    raise SvcDoctorError("systemd query failed or returned inconsistent status")
  return failed


def decode_output(output: bytes) -> str:
  try:
    return output.decode("utf-8")
  except UnicodeDecodeError as error:
    raise SvcDoctorError("systemd returned a malformed response") from error


def parse_properties(output: str) -> dict[str, str]:
  """Parse exactly one allowlisted Property=Value record."""
  if not output:
    raise SvcDoctorError("systemd returned an empty response")
  lines = output.split("\n")
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


def assess_service(
  properties: Mapping[str, str], failed_dependencies: tuple[str, ...] | None,
) -> tuple[str, bool, str]:
  """Return (status label, whether a service failure was established, finding); the first matching rule wins."""
  active = properties.get("ActiveState", "")
  load = properties.get("LoadState", "")
  sub = properties.get("SubState", "")
  result = properties.get("Result", "")
  restarts = properties.get("NRestarts", "")
  state = f"ActiveState is {active or UNAVAILABLE} and SubState is {sub or UNAVAILABLE}"
  if active == "failed":
    return "FAILED", True, f"{state}, and Result is {result or UNAVAILABLE}"
  if load in {"bad-setting", "error"}:
    return "LOAD-ERROR", True, f"LoadState is {load}, so systemd could not load the unit configuration"
  if sub == "auto-restart":
    return "RESTARTING", True, (
      f"the service is crash-looping: {state}, Result is {result or UNAVAILABLE}, "
      f"and NRestarts is {restarts or UNAVAILABLE}"
    )
  if active != "active" and result not in {"", "success"}:
    return "DEGRADED", True, f"{state}, but Result is {result}"
  if active != "active" and failed_dependencies:
    return "DEPENDENCY-FAILED", True, f"{state}, and failed dependencies were found: {', '.join(failed_dependencies)}"
  finding = state
  if restarts.isascii() and restarts.isdecimal() and int(restarts, 10) > 0:
    finding += f"; NRestarts is {int(restarts, 10)}"
  return active.upper(), False, finding


def render_diagnostic(target: str, properties: Mapping[str, str]) -> str:
  """Render one accepted observation in the frozen field order."""
  safe = lambda name: display_safe(properties.get(name) or UNAVAILABLE)
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
    f"  Last entered active: {safe('ActiveEnterTimestamp')}",
    "Unit configuration",
    f"  Unit file: {safe('FragmentPath')}",
    f"  Drop-ins: {safe('DropInPaths')}",
    f"  Requires: {safe('Requires')}",
    f"  Requisite: {safe('Requisite')}",
    f"  BindsTo: {safe('BindsTo')}",
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
  ))


def describe_failed_dependencies(evidence: ServiceEvidence) -> str:
  if evidence.failed_dependencies is None:
    return "unavailable"
  if evidence.failed_dependencies:
    description = ", ".join(map(display_safe, evidence.failed_dependencies))
  elif evidence.dependencies_checked:
    description = f"none of {len(evidence.dependencies_checked)} checked"
  else:
    return "none checked (no dependencies)"
  if evidence.dependencies_truncated:
    description += f" (only the first {MAX_DEPENDENCIES} dependencies were checked)"
  return description


def render_service_evidence(evidence: ServiceEvidence) -> str:
  status, failed, _ = assess_service(evidence.properties, evidence.failed_dependencies)
  unit = shlex.quote(evidence.properties["Id"])
  # Escaping backslashes (as in foo\x2dbar.service) would break the copyable command.
  command_unit = display_safe(unit) if has_unsafe_characters(unit) else unit
  lines = [render_diagnostic(evidence.target, evidence.properties)]
  lines.extend([
    "Dependencies",
    f"  Failed dependencies: {describe_failed_dependencies(evidence)}",
    "Recent journal evidence",
  ])
  lines.extend(f"  {display_safe(line)}" for line in evidence.journal)
  if not evidence.journal:
    lines.append("  unavailable or empty")
  lines.extend([
    "Assessment",
    f"  Status: {display_safe(status)}",
    f"  Service failure established: {'yes' if failed else 'no'}",
    "Next diagnostic command",
    f"  journalctl --system --unit {command_unit} --lines 50 --no-pager",
  ])
  return "\n".join(lines)


def collect_service(target: str, journal_lines: int) -> ServiceEvidence:
  result = run_systemctl(target)
  if result.returncode != 0:
    raise SvcDoctorError("systemd query failed")
  properties = parse_properties(decode_output(result.stdout))
  validate_properties(properties)
  # A deleted unit can still be running or failed after daemon-reload.
  if properties["LoadState"] == "not-found" and properties.get("ActiveState", "") in {"", "inactive"}:
    raise SvcDoctorError(f"service not found: {display_safe(target)}")
  names, truncated = dependency_names(properties)
  dependency_warning = None
  try:
    if any(field not in properties for field in DEPENDENCY_PROPERTIES):
      raise SvcDoctorError("systemd response omitted dependency properties")
    failed = find_failed_dependencies(names)
  except SvcDoctorError as error:
    failed = None
    dependency_warning = f"dependency evidence unavailable: {error}"
  try:
    journal, journal_warning = collect_journal(properties["Id"], journal_lines)
  except SvcDoctorError as error:
    journal, journal_warning = (), str(error)
  return ServiceEvidence(
    target, properties, journal, journal_warning, failed, dependency_warning, names, truncated,
  )


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
    self.exit(2, f"svcdoctor: error: {display_safe(message)}\n")


def build_argument_parser() -> argparse.ArgumentParser:
  parser = Parser(
    prog="svcdoctor",
    description="Report bounded, read-only systemd evidence for one local system service.",
    epilog=(
      "Exit codes: 0 no service failure established; 1 service failure established "
      "(FAILED, LOAD-ERROR, RESTARTING crash loop, DEGRADED non-success Result, or DEPENDENCY-FAILED); "
      "2 invocation or observation failure; 130 interrupted."
    ),
  )
  parser.add_argument("service", help="concrete service unit; bare names receive .service")
  parser.add_argument("--journal-lines", type=parse_journal_lines, default=20, metavar="N")
  add_output_arguments(parser)
  return parser


def main(arguments: Sequence[str] | None = None) -> int:
  parser = build_argument_parser()
  try:
    args = parser.parse_args(arguments)
    validate_output_arguments(parser, args)
  except SystemExit as error:
    return int(error.code)
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
  status, failed, finding = assess_service(evidence.properties, evidence.failed_dependencies)
  exit_code = 1 if failed else 0
  next_action = (
    f"inspect the bounded journal and failed dependencies for {evidence.properties['Id']}" if failed
    else "no service failure was established; use the suggested journal command for deeper context"
  )
  conclusion = make_conclusion(status, target, finding, next_action)
  warnings = tuple(item for item in (evidence.journal_warning, evidence.dependency_warning) if item)
  for warning in warnings:
    print(f"svcdoctor: warning: {display_safe(warning)}", file=sys.stderr)
  record = OutputRecord(
    tool="svcdoctor",
    status=status,
    target=target,
    observations={
      "properties": dict(evidence.properties),
      "failed_dependencies": evidence.failed_dependencies,
      "dependencies_observed": evidence.failed_dependencies is not None,
      "dependencies_checked": evidence.dependencies_checked,
      "dependencies_truncated": evidence.dependencies_truncated,
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
    f"Failed dependencies: {describe_failed_dependencies(evidence)}",
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
