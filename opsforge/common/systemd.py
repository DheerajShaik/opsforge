"""systemd unit-name validation shared by OpsForge utilities."""

from __future__ import annotations

from .text import has_unsafe_characters, sanitize_text


UNIT_SUFFIXES = (
  ".service", ".socket", ".target", ".device", ".mount", ".automount",
  ".swap", ".timer", ".path", ".slice", ".scope", ".snapshot",
)
GLOB_METACHARACTERS = frozenset("*?[]")


class UnitNameError(ValueError):
  """A service name is not one concrete, safe .service unit."""


def normalize_service_name(target: str) -> str:
  """Return a concrete .service unit name, rejecting options, patterns, templates, and controls."""
  if not target:
    raise UnitNameError("target must not be empty")
  safe = sanitize_text(target)
  if target.startswith("-"):
    raise UnitNameError(f"invalid service target: {safe}")
  if "/" in target:
    raise UnitNameError(f"service target must not contain '/': {safe}")
  if any(character.isspace() for character in target):
    raise UnitNameError(f"service target must not contain whitespace: {safe}")
  if has_unsafe_characters(target):
    raise UnitNameError(f"service target contains a control character: {safe}")
  if any(character in GLOB_METACHARACTERS for character in target):
    raise UnitNameError(f"service target must be a concrete unit, not a pattern: {safe}")
  explicit_suffix = next((suffix for suffix in UNIT_SUFFIXES if target.endswith(suffix)), None)
  if explicit_suffix is not None and explicit_suffix != ".service":
    raise UnitNameError(f"unsupported unit type {explicit_suffix}; only .service units are supported")
  normalized = target if explicit_suffix == ".service" else f"{target}.service"
  if normalized == ".service":
    raise UnitNameError("service target must have a non-empty stem")
  if normalized.endswith("@.service"):
    raise UnitNameError("template units are not supported; specify a concrete instance")
  return normalized
