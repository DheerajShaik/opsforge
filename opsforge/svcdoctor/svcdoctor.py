#!/usr/bin/env python3
"""Report structured systemd evidence for one local system service."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from fractions import Fraction
import re
import shlex
import signal
import sys
import time
from typing import Mapping, Sequence

from opsforge.common import (
  OutputError,
  OutputRecord,
  add_output_arguments,
  emit_output,
  has_unsafe_characters,
  make_conclusion,
  sanitize_text as display_safe,
  validate_output_arguments,
)
from opsforge.common.process import (
  ProcessNotFoundError,
  ProcessOutputLimitError,
  ProcessResult,
  ProcessSpawnError,
  ProcessTimeoutError,
  child_environment,
  resolve_executable,
  run_bounded,
)
from opsforge.common.status import EXIT_FAILURE, EXIT_FINDING, EXIT_INTERRUPTED, EXIT_OK, EXIT_USAGE, INCOMPLETE
from opsforge.common.systemd import UnitNameError, normalize_service_name


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
  "StateChangeTimestamp",
  "ExecMainExitTimestamp",
  "CPUUsageNSec",
  "MemoryCurrent",
  "MemoryMax",
  "MemoryHigh",
  "CPUQuotaPerSecUSec",
  "TasksCurrent",
  "TasksMax",
  "Slice",
  "User",
  "Group",
  "DynamicUser",
)
DEPENDENCY_PROPERTIES = ("Requires", "Requisite", "BindsTo", "Wants")
LIMIT_PROPERTIES = ("MemoryMax", "MemoryHigh", "CPUQuotaPerSecUSec", "TasksMax")
SLICE_PROPERTIES = ("Id", "Slice", *LIMIT_PROPERTIES)
ROOT_SLICE = "-.slice"
LIMIT_LABELS = {
  "MemoryMax": "Memory max", "MemoryHigh": "Memory high", "CPUQuotaPerSecUSec": "CPU quota per second",
  "TasksMax": "Tasks max",
}
TIMEOUT_SECONDS = 5
MAX_STREAM_BYTES = 64 * 1024
MAX_JOURNAL_BYTES = 256 * 1024
MAX_JOURNAL_LINES = 200
MAX_JOURNAL_LINE_CHARACTERS = 512
MAX_DEPENDENCIES = 32
MAX_STDERR_EXCERPT = 200
UNAVAILABLE = "-"
COMMAND_ENVIRONMENT = child_environment(SYSTEMD_PAGER="", SYSTEMD_COLORS="0", TZ="UTC")
# Lowercased fragments of systemd's C-locale error messages.
PERMISSION_MARKERS = ("access denied", "permission denied", "operation not permitted", "interactive authentication required")
MANAGER_MARKERS = ("not been booted with systemd", "failed to connect to bus")
INVALID_TARGET_MARKERS = ("is neither a valid invocation id nor unit name",)
TIMESPAN_TOKEN = re.compile(r"([0-9]+(?:\.[0-9]+)?)(us|ms|s|min|h)")
TIMESPAN_MICROSECONDS = {"us": 1, "ms": 1_000, "s": 1_000_000, "min": 60_000_000, "h": 3_600_000_000}
# `systemd-analyze exit-status` on systemd 255: the libc and systemd classes that `systemctl status` names.
EXIT_STATUS_NAMES = {
  0: "SUCCESS", 1: "FAILURE", 200: "CHDIR", 201: "NICE", 202: "FDS", 203: "EXEC", 204: "MEMORY", 205: "LIMITS",
  206: "OOM_ADJUST", 207: "SIGNAL_MASK", 208: "STDIN", 209: "STDOUT", 210: "CHROOT", 211: "IOPRIO",
  212: "TIMERSLACK", 213: "SECUREBITS", 214: "SETSCHEDULER", 215: "CPUAFFINITY", 216: "GROUP", 217: "USER",
  218: "CAPABILITIES", 219: "CGROUP", 220: "SETSID", 221: "CONFIRM", 222: "STDERR", 224: "PAM", 225: "NETWORK",
  226: "NAMESPACE", 227: "NO_NEW_PRIVILEGES", 228: "SECCOMP", 229: "SELINUX_CONTEXT", 230: "PERSONALITY",
  231: "APPARMOR", 232: "ADDRESS_FAMILIES", 233: "RUNTIME_DIRECTORY", 235: "CHOWN", 236: "SMACK_PROCESS_LABEL",
  237: "KEYRING", 238: "STATE_DIRECTORY", 239: "CACHE_DIRECTORY", 240: "LOGS_DIRECTORY",
  241: "CONFIGURATION_DIRECTORY", 242: "NUMA_POLICY", 243: "CREDENTIALS", 244: "BPF", 245: "KSM", 255: "EXCEPTION",
}
EXEC_SETUP_STATUSES = range(200, 246)


class SvcDoctorError(Exception):
  """A fatal observation error with stable, display-safe user-facing text."""


class TargetError(SvcDoctorError):
  """The requested service target is invalid or does not exist."""


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
  slice_chain: tuple[Mapping[str, str], ...] | None = None
  effective_limits: Mapping[str, Mapping[str, str | None] | None] | None = None
  limits_warning: str | None = None


def normalize_target(target: str) -> str:
  """Apply only SvcDoctor's minimal safety and .service scope policy."""
  try:
    return normalize_service_name(target)
  except UnitNameError as error:
    raise TargetError(str(error)) from error


def systemctl_arguments(executable: str, *units: str, properties: Sequence[str] = PROPERTIES) -> list[str]:
  arguments = [executable, "show", "--system", "--no-pager"]
  arguments.extend(f"--property={property_name}" for property_name in properties)
  arguments.extend(("--", *units))
  return arguments


def require_executable(name: str) -> str:
  executable = resolve_executable(name)
  if executable is None:
    raise SvcDoctorError(f"{name} is not available")
  return executable


def run_simple_command(
  arguments: Sequence[str],
  label: str,
  *,
  timeout: float,
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
    raise SvcDoctorError(f"{label} returned oversized output") from error


def run_systemctl(target: str) -> ProcessResult:
  """Run one bounded, non-shell systemctl query."""
  return run_simple_command(
    systemctl_arguments(require_executable("systemctl"), target), "systemctl", timeout=TIMEOUT_SECONDS,
  )


def stderr_excerpt(stderr: bytes) -> str:
  """Return the first non-empty raw stderr line, bounded to MAX_STDERR_EXCERPT characters."""
  line = next((line.strip() for line in stderr.decode("utf-8", "replace").split("\n") if line.strip()), "")
  return line if len(line) <= MAX_STDERR_EXCERPT else line[:MAX_STDERR_EXCERPT] + "..."


def systemctl_failure(result: ProcessResult) -> SvcDoctorError:
  """Classify a failed systemctl query by its C-locale stderr and keep a bounded, escaped excerpt."""
  text = result.stderr.decode("utf-8", "replace").lower()
  error_type = SvcDoctorError
  if any(marker in text for marker in PERMISSION_MARKERS):
    message = "permission denied while querying the systemd system manager"
  elif any(marker in text for marker in MANAGER_MARKERS):
    message = "systemd system manager is unavailable"
  elif any(marker in text for marker in INVALID_TARGET_MARKERS):
    error_type, message = TargetError, "systemd rejected the service target"
  else:
    message = "systemd query failed"
  detail = stderr_excerpt(result.stderr)
  return error_type(f"{message}: {display_safe(detail)}" if detail else message)


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
    timeout=TIMEOUT_SECONDS,
    max_output_bytes=MAX_JOURNAL_BYTES,
    truncate_stdout=True,
  )
  if result.returncode != 0 and not result.stdout_truncated:
    detail = display_safe(stderr_excerpt(result.stderr))
    return (), "recent journal evidence unavailable" + (f": {detail}" if detail else "")
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
    timeout=TIMEOUT_SECONDS,
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


def parse_properties(output: str, allowed: Sequence[str] = PROPERTIES) -> dict[str, str]:
  """Parse exactly one allowlisted Property=Value record."""
  lines = output.split("\n")
  if not any(lines):
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
    if name not in allowed or name in properties:
      raise SvcDoctorError("systemd returned a malformed response")
    properties[name] = value
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


def slice_ancestors(slice_name: str) -> tuple[str, ...]:
  """Return SLICE_NAME and its parents as systemd derives them from the dashes in the name, ending at -.slice."""
  names = [slice_name]
  while names[-1] != ROOT_SLICE:
    stem = names[-1][:-len(".slice")]
    names.append(stem.rpartition("-")[0] + ".slice" if "-" in stem else ROOT_SLICE)
  return tuple(names)


def collect_slice_chain(slice_name: str) -> tuple[dict[str, str], ...]:
  """Return Id, Slice, and limits of SLICE_NAME and each parent slice, nearest first, from one systemctl query."""
  if not slice_name:
    return ()
  if not slice_name.endswith(".slice"):
    raise SvcDoctorError("systemd reported a malformed slice name")
  names = slice_ancestors(slice_name)
  result = run_simple_command(
    systemctl_arguments(require_executable("systemctl"), *names, properties=SLICE_PROPERTIES), "systemctl",
    timeout=TIMEOUT_SECONDS,
  )
  if result.returncode != 0:
    raise systemctl_failure(result)
  chain = tuple(parse_properties(record, SLICE_PROPERTIES) for record in decode_output(result.stdout).split("\n\n"))
  # Each level's own Slice= must name the next level, confirming the derived chain.
  expected = tuple(zip(names, (*names[1:], "")))
  if tuple((level.get("Id"), level.get("Slice")) for level in chain) != expected:
    raise SvcDoctorError("systemd returned a malformed slice response")
  return chain


def timespan_microseconds(value: str) -> Fraction:
  """Parse a systemd-formatted time span such as 200ms, 1.500000s, or 1min 4s."""
  total = Fraction(0)
  for token in value.split(" "):
    match = TIMESPAN_TOKEN.fullmatch(token)
    if match is None:
      raise ValueError("unrecognized time span")
    total += Fraction(match.group(1)) * TIMESPAN_MICROSECONDS[match.group(2)]
  return total


def limit_amount(name: str, value: str) -> Fraction | int | None:
  """Return a comparable amount for one systemd limit value; None means no limit (infinity)."""
  if value == "infinity":
    return None
  if name == "CPUQuotaPerSecUSec":
    return timespan_microseconds(value)
  if value.isascii() and value.isdecimal():
    return int(value, 10)
  raise ValueError(f"unrecognized {name} value")


def effective_limits(levels: Sequence[Mapping[str, str]]) -> dict[str, dict[str, str | None] | None]:
  """Return each limit's tightest value across LEVELS (the unit, then its slices) and the nearest level setting it."""
  limits: dict[str, dict[str, str | None] | None] = {}
  for name in LIMIT_PROPERTIES:
    try:
      amounts = [(limit_amount(name, level.get(name, "")), level) for level in levels]
    except ValueError:
      limits[name] = None
      continue
    finite = [(amount, level) for amount, level in amounts if amount is not None]
    if finite:
      level = min(finite, key=lambda item: item[0])[1]
      limits[name] = {"value": level[name], "source": level["Id"]}
    else:
      limits[name] = {"value": "infinity", "source": None}
  return limits


def collect_limits(
  properties: Mapping[str, str],
) -> tuple[tuple[dict[str, str], ...] | None, dict[str, dict[str, str | None] | None] | None, str | None]:
  """Return the slice chain, effective limits, and any warning; parent slices can be tighter than the unit."""
  try:
    if "Slice" not in properties:
      raise SvcDoctorError("systemd response omitted the Slice property")
    chain = collect_slice_chain(properties["Slice"])
  except SvcDoctorError as error:
    return None, None, f"slice limit evidence unavailable: {error}"
  limits = effective_limits((properties, *chain))
  unknown = [name for name, limit in limits.items() if limit is None]
  warning = f"effective limit unavailable for {', '.join(unknown)}: missing or unrecognized value" if unknown else None
  return chain, limits, warning


def assess_service(
  properties: Mapping[str, str], failed_dependencies: tuple[str, ...] | None, dependencies_truncated: bool = False,
) -> tuple[str, int, str]:
  """Return (status label, exit status, finding); the first matching rule wins."""
  active = properties.get("ActiveState", "")
  load = properties.get("LoadState", "")
  sub = properties.get("SubState", "")
  result = properties.get("Result", "")
  restarts = properties.get("NRestarts", "")
  state = f"ActiveState is {active or UNAVAILABLE} and SubState is {sub or UNAVAILABLE}"
  if active == "failed":
    return "FAILED", EXIT_FINDING, f"{state}, and Result is {result or UNAVAILABLE}"
  if load in {"bad-setting", "error"}:
    return "LOAD-ERROR", EXIT_FINDING, f"LoadState is {load}, so systemd could not load the unit configuration"
  if sub == "auto-restart":
    return "RESTARTING", EXIT_FINDING, (
      f"the service is crash-looping: {state}, Result is {result or UNAVAILABLE}, "
      f"and NRestarts is {restarts or UNAVAILABLE}"
    )
  if active != "active" and result not in {"", "success"}:
    return "DEGRADED", EXIT_FINDING, f"{state}, but Result is {result}"
  if active != "active" and failed_dependencies:
    return "DEPENDENCY-FAILED", EXIT_FINDING, (
      f"{state}, and failed dependencies were found: {', '.join(failed_dependencies)}"
    )
  if active != "active" and failed_dependencies is None:
    return INCOMPLETE, EXIT_FAILURE, f"{state}, but dependency evidence is unavailable, so a dependency failure cannot be ruled out"
  if active != "active" and dependencies_truncated:
    return INCOMPLETE, EXIT_FAILURE, (
      f"{state}, but only the first {MAX_DEPENDENCIES} dependencies were checked, "
      "so a dependency failure cannot be ruled out"
    )
  finding = state
  if restarts.isascii() and restarts.isdecimal() and int(restarts, 10) > 0:
    finding += f"; NRestarts is {int(restarts, 10)}"
  return active.upper(), EXIT_OK, finding


def interpret_termination(code: str, status: str) -> str:
  """Interpret ExecMainCode/ExecMainStatus, naming statuses and signals as `systemctl status` does."""
  number = int(status, 10) if status.isascii() and status.isdecimal() else None
  shown = display_safe(status or UNAVAILABLE)
  if code == "1":
    name = EXIT_STATUS_NAMES.get(number)
    interpretation = f"process exited with status {shown}" + (f" ({name})" if name else "")
    if number in EXEC_SETUP_STATUSES:
      interpretation += "; systemd uses this status when it cannot set up or execute the configured command"
    return interpretation
  if code in {"2", "3"}:
    try:
      name = signal.Signals(number).name if number is not None else None
    except ValueError:
      name = None
    action = "was killed by" if code == "2" else "dumped core after"
    return f"process {action} signal {shown}" + (f" ({name})" if name else "")
  if code in {"", "0"}:
    return "no terminating main-process result was reported"
  return f"unrecognized systemd execution code {display_safe(code)}"


def render_diagnostic(target: str, properties: Mapping[str, str]) -> str:
  """Render one accepted observation in the frozen field order."""
  safe = lambda name: display_safe(properties.get(name) or UNAVAILABLE)
  interpretation = interpret_termination(properties.get("ExecMainCode", ""), properties.get("ExecMainStatus", ""))
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
    f"  Last state change: {safe('StateChangeTimestamp')}",
    f"  Main process last exited: {safe('ExecMainExitTimestamp')}",
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
    f"  Tasks current: {safe('TasksCurrent')}",
    "Selected execution context",
    f"  User: {safe('User')}",
    f"  Group: {safe('Group')}",
    f"  Dynamic user: {safe('DynamicUser')}",
  ))


def render_limits(evidence: ServiceEvidence) -> list[str]:
  if evidence.slice_chain is None:
    chain = "unavailable"
  else:
    chain = " -> ".join(display_safe(level["Id"]) for level in evidence.slice_chain) or "none"
  lines = [
    "Resource limits (effective = tightest of the unit and its slices)",
    f"  Slice chain: {chain}",
  ]
  for name in LIMIT_PROPERTIES:
    limit = (evidence.effective_limits or {}).get(name)
    if limit is None:
      effective = "unavailable"
    elif limit["source"] is None:
      effective = f"{display_safe(limit['value'])} (no limit at any level)"
    else:
      effective = f"{display_safe(limit['value'])} (tightest; set by {display_safe(limit['source'])})"
    unit_value = display_safe(evidence.properties.get(name) or UNAVAILABLE)
    lines.append(f"  {LIMIT_LABELS[name]}: unit {unit_value}; effective {effective}")
  return lines


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
  status, exit_code, _ = assess_service(
    evidence.properties, evidence.failed_dependencies, evidence.dependencies_truncated,
  )
  established = {EXIT_FINDING: "yes", EXIT_OK: "no"}.get(exit_code, "undetermined")
  unit = shlex.quote(evidence.properties["Id"])
  # Escaping backslashes (as in foo\x2dbar.service) would break the copyable command.
  command_unit = display_safe(unit) if has_unsafe_characters(unit) else unit
  lines = [render_diagnostic(evidence.target, evidence.properties), *render_limits(evidence)]
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
    f"  Service failure established: {established}",
    "Next diagnostic command",
    f"  journalctl --system --unit {command_unit} --lines 50 --no-pager",
  ])
  return "\n".join(lines)


def collect_service(target: str, journal_lines: int) -> ServiceEvidence:
  result = run_systemctl(target)
  if result.returncode != 0:
    raise systemctl_failure(result)
  properties = parse_properties(decode_output(result.stdout))
  validate_properties(properties)
  # A deleted unit can still be running or failed after daemon-reload.
  if properties["LoadState"] == "not-found" and properties.get("ActiveState", "") in {"", "inactive"}:
    raise TargetError(f"service not found: {display_safe(target)}")
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
  chain, limits, limits_warning = collect_limits(properties)
  return ServiceEvidence(
    target, properties, journal, journal_warning, failed, dependency_warning, names, truncated,
    chain, limits, limits_warning,
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
    self.exit(EXIT_USAGE, f"svcdoctor: error: {display_safe(message)}\n")


def build_argument_parser() -> argparse.ArgumentParser:
  parser = Parser(
    prog="svcdoctor",
    description="Report bounded, read-only systemd evidence for one local system service.",
    epilog=(
      f"Exit codes: {EXIT_OK} no service failure established; {EXIT_FINDING} service failure established "
      "(FAILED, LOAD-ERROR, RESTARTING crash loop, DEGRADED non-success Result, or DEPENDENCY-FAILED); "
      f"{EXIT_USAGE} invalid invocation or a service that does not exist; {EXIT_FAILURE} no trustworthy answer "
      "(systemd unavailable, permission denied, malformed or oversized output, timeout, INCOMPLETE dependency "
      f"evidence, internal or output failure); {EXIT_INTERRUPTED} interrupted."
    ),
  )
  parser.add_argument("service", help="concrete service unit; bare names receive .service")
  parser.add_argument("--journal-lines", type=parse_journal_lines, default=20, metavar="N")
  add_output_arguments(parser)
  return parser


def report(evidence: ServiceEvidence, target: str, args: argparse.Namespace, started: float) -> int:
  """Emit the assessed evidence and return its exit status."""
  status, exit_code, finding = assess_service(
    evidence.properties, evidence.failed_dependencies, evidence.dependencies_truncated,
  )
  unit = evidence.properties["Id"]
  if exit_code == EXIT_FINDING:
    next_action = f"inspect the bounded journal and failed dependencies for {unit}"
  elif exit_code == EXIT_FAILURE:
    next_action = f"check the dependencies of {unit} directly, for example with systemctl list-dependencies"
  else:
    next_action = "no service failure was established; use the suggested journal command for deeper context"
  conclusion = make_conclusion(status, target, finding, next_action)
  warnings = tuple(
    item for item in (evidence.journal_warning, evidence.dependency_warning, evidence.limits_warning) if item
  )
  # Warning texts are built from display-safe error messages; escaping again would double backslashes.
  for warning in warnings:
    print(f"svcdoctor: warning: {warning}", file=sys.stderr)
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
      "slice_chain": evidence.slice_chain,
      "effective_limits": evidence.effective_limits,
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
  return exit_code


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
    return report(collect_service(target, args.journal_lines), target, args, started)
  except TargetError as error:
    print(f"svcdoctor: {error}", file=sys.stderr)
    return EXIT_USAGE
  except SvcDoctorError as error:
    print(f"svcdoctor: {error}", file=sys.stderr)
    return EXIT_FAILURE
  except OutputError as error:
    print(f"svcdoctor: {error}", file=sys.stderr)
    return EXIT_FAILURE
  except KeyboardInterrupt:
    print("svcdoctor: interrupted", file=sys.stderr)
    return EXIT_INTERRUPTED
  except Exception:
    print("svcdoctor: internal execution failure", file=sys.stderr)
    return EXIT_FAILURE


if __name__ == "__main__":
  raise SystemExit(main())
