#!/usr/bin/env bash
# Compile and unit-test a temporary copy of the working tree, mirroring release-regression.yml.
# Usage: bash scripts/check.sh [all | COMPONENT...]  (COMPONENT is common or a utility directory name)
# Exit status: 0 all selected checks passed, 1 a check failed, 2 usage or environment error.
set -euo pipefail

all_components=(common portlens diskhound certwatch svcdoctor loghound procwatch configdiff netdoctor healthctl incidentsnapshot)
python="${PYTHON:-python3}"
suite_timeout=600
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ "$(uname -s)" != Linux ]; then
  echo "check.sh: run on Linux or WSL; see CONTRIBUTING.md" >&2
  exit 2
fi
if ! git -c safe.directory='*' -C "$root" rev-parse --git-dir >/dev/null 2>&1; then
  echo "check.sh: $root is not a Git checkout" >&2
  exit 2
fi

components=()
if [ "$#" -eq 0 ] || [ "$*" = all ]; then
  components=("${all_components[@]}")
else
  for name in "$@"; do
    case " ${all_components[*]} " in
      *" $name "*) components+=("$name") ;;
      *) echo "check.sh: unknown component '$name'; use all or: ${all_components[*]}" >&2; exit 2 ;;
    esac
  done
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/opsforge-check.XXXXXX")"
trap 'rm -rf "$work"' EXIT

# Tracked and unignored files, so uncommitted edits are tested without writing into the checkout.
"$python" - "$root" "$work/tree" <<'PY'
import os
import subprocess
import sys

root, tree = sys.argv[1], sys.argv[2]
listing = subprocess.run(
  ["git", "-c", "safe.directory=*", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
  check=True, stdout=subprocess.PIPE,
).stdout
for name in filter(None, os.fsdecode(listing).split("\0")):
  source, target = os.path.join(root, name), os.path.join(tree, name)
  if not os.path.lexists(source):
    continue
  os.makedirs(os.path.dirname(target), exist_ok=True)
  if os.path.islink(source):
    os.symlink(os.readlink(source), target)
    continue
  with open(source, "rb") as handle:
    data = handle.read()
  if b"\0" not in data:
    # A Windows checkout with core.autocrlf stores CRLF; CI checks out LF.
    data = data.replace(b"\r\n", b"\n")
  with open(target, "wb") as handle:
    handle.write(data)
PY

cd "$work/tree"
revision="$(git -c safe.directory='*' -C "$root" rev-parse --short HEAD)"
echo "check.sh: $("$python" --version 2>&1), working tree of $revision, suites: ${components[*]}"

if ! "$python" -m compileall -q opsforge >"$work/compile.log" 2>&1; then
  head -n 40 "$work/compile.log"
  echo "RESULT: FAIL (compile)"
  exit 1
fi

failed=()
total=0
for component in "${components[@]}"; do
  log="$work/$component.log"
  status=0
  timeout "$suite_timeout" "$python" -m unittest discover -s "opsforge/$component/tests" >"$log" 2>&1 || status=$?
  ran="$(sed -n 's/^Ran \([0-9][0-9]*\) tests\{0,1\} in .*/\1/p' "$log" | tail -n 1)"
  total=$((total + ${ran:-0}))
  if [ "$status" -eq 0 ]; then
    printf 'PASS %-16s %s tests\n' "$component" "${ran:-?}"
    continue
  fi
  failed+=("$component")
  if [ "$status" -eq 124 ]; then
    printf 'FAIL %-16s timed out after %s s\n' "$component" "$suite_timeout"
  else
    printf 'FAIL %-16s %s tests\n' "$component" "${ran:-?}"
  fi
  # Print only unittest's failure reports, bounded to keep agent context small.
  if grep -q '^=\{70\}$' "$log"; then
    sed -n '/^=\{70\}$/,$p' "$log" | head -n 60
  else
    tail -n 20 "$log"
  fi
done

if [ "${#failed[@]}" -ne 0 ]; then
  echo "RESULT: FAIL (${failed[*]})"
  exit 1
fi
echo "RESULT: PASS (${#components[@]} suites, $total tests)"
