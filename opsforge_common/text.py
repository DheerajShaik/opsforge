"""Terminal-safe text rendering shared by OpsForge utilities."""

from __future__ import annotations

import unicodedata


ESCAPED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})


def sanitize_text(value: object) -> str:
  """Escape `\\`; C0/DEL and surrogate-escaped raw bytes as \\xNN; other controls as \\uNNNN/\\UNNNNNNNN."""
  text = str(value)
  if text.isascii() and text.isprintable() and "\\" not in text:
    return text
  pieces = []
  for character in text:
    codepoint = ord(character)
    if character == "\\":
      pieces.append("\\\\")
    elif 0xDC80 <= codepoint <= 0xDCFF:
      pieces.append(f"\\x{codepoint - 0xDC00:02x}")
    elif unicodedata.category(character) in ESCAPED_CATEGORIES:
      if codepoint < 0x80:
        pieces.append(f"\\x{codepoint:02x}")
      elif codepoint <= 0xFFFF:
        pieces.append(f"\\u{codepoint:04x}")
      else:
        pieces.append(f"\\U{codepoint:08x}")
    else:
      pieces.append(character)
  return "".join(pieces)


def has_unsafe_characters(value: str) -> bool:
  """Return whether VALUE contains control, format, surrogate, or separator characters."""
  return any(unicodedata.category(character) in ESCAPED_CATEGORIES for character in value)


def stream_safe(value: object, stream: object) -> str:
  """Escape characters that the destination text stream cannot encode."""
  text = str(value)
  encoding = getattr(stream, "encoding", None)
  if not encoding:
    return text
  try:
    return text.encode(encoding, errors="backslashreplace").decode(encoding)
  except (LookupError, UnicodeError):
    return text.encode("ascii", errors="backslashreplace").decode("ascii")


def print_safe(value: object, *, file: object) -> None:
  """Print without leaking UnicodeEncodeError for a restrictive text stream."""
  print(stream_safe(value, file), file=file)
