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
from .text import has_unsafe_characters, print_safe, sanitize_text, stream_safe

__all__ = (
  "OutputError",
  "OutputRecord",
  "add_output_arguments",
  "emit_output",
  "has_unsafe_characters",
  "make_conclusion",
  "print_safe",
  "sanitize_text",
  "stream_safe",
  "to_jsonable",
  "validate_output_arguments",
)
