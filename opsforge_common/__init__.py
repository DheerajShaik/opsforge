"""Small shared primitives for OpsForge command output."""

from .output import (
  OutputError,
  OutputRecord,
  add_output_arguments,
  emit_output,
  make_conclusion,
  to_jsonable,
  validate_output_arguments,
)

__all__ = (
  "OutputError",
  "OutputRecord",
  "add_output_arguments",
  "emit_output",
  "make_conclusion",
  "to_jsonable",
  "validate_output_arguments",
)
