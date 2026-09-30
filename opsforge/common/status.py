"""Exit statuses and status names shared by every OpsForge utility."""

# Clean: the requested observation completed and established the expected or healthy answer.
EXIT_OK = 0
# Finding: a problem or negative answer was established, or an observation-only utility is PARTIAL.
EXIT_FINDING = 1
# Usage: invalid invocation, configuration, or target.
EXIT_USAGE = 2
# Failure: no trustworthy answer, including tool, permission, timeout, malformed-output, and --output failures.
EXIT_FAILURE = 3
EXIT_INTERRUPTED = 130

OBSERVED = "OBSERVED"
PARTIAL = "PARTIAL"
INCOMPLETE = "INCOMPLETE"
ERROR = "ERROR"
SKIPPED = "SKIPPED"
WARNING = "WARNING"
CRITICAL = "CRITICAL"
