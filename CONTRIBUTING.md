# Contributing to OpsForge

Thank you for your interest in contributing to OpsForge.

OpsForge is a Beta open-source project with ten focused Linux, DevOps, and SRE utilities. The initial roadmap is implemented, and the project continues to evolve through real requirements, release hardening, compatibility evidence, and community feedback. Beta does not imply production readiness or stable interfaces.

## Philosophy

OpsForge utilities should be:

- Practical over theoretical.
- Small useful scope over premature complexity.
- Independent by default.
- Composable when useful.
- Shared when justified.
- Diagnostic before destructive.
- Safe by default.
- Automation-friendly.
- Tests and documentation must accompany behavioral changes.

Contributions should favor practical, focused improvements over premature generalization. Utilities should start with small useful scopes and grow when operational needs justify the added complexity.

## Contribution types

Useful contributions include:

- bug fixes
- regression tests
- compatibility improvements
- documentation corrections
- security and privacy hardening
- portability improvements
- performance improvements justified by evidence
- focused utility enhancements
- new utility proposals with clear operational justification

## Utility boundaries

Each utility should remain independently understandable and usable where practical. A contributor working on one utility should not need deep knowledge of every other utility.

Cross-utility integration is allowed when it solves a real operational problem. Shared abstractions should emerge from genuine duplication, not from speculation. Avoid circular dependencies and do not introduce shared frameworks before they provide clear value.

## Proposing a new utility

A new utility proposal should explain:

- the operational problem it solves
- the intended users
- the smallest useful initial scope
- explicit non-goals
- expected dependencies
- sensitive information the utility may access or emit
- how the functionality could be tested
- overlap with existing or planned OpsForge utilities

A new utility should not be added only because it is common in infrastructure tooling. It should address a clear operational need.

## Development expectations

Keep changes focused and understandable. Contributors should:

- understand the relevant utility or documentation area before changing it
- update documentation when behavior changes
- add or update tests when functionality changes
- consider failure paths and edge cases
- avoid unnecessary dependencies
- avoid destructive defaults
- avoid hidden network behavior
- preserve documented interfaces as tools mature

OpsForge is not tied to one implementation language. Language choices should follow actual technical requirements.

## Documentation expectations

Documentation must describe actual repository behavior accurately.

Clearly distinguish:

- **Implemented**: functionality that exists and works
- **Planned**: functionality accepted into the roadmap but not implemented
- **Possible future direction**: ideas that may be explored later

Do not describe planned behavior as implemented, and do not imply production readiness without evidence.

## Security-sensitive changes

Changes involving the following areas require additional care:

- privileges
- subprocess execution
- filesystem operations
- temporary files
- environment variables
- logs
- network communication
- credentials
- tokens
- sensitive diagnostic information

Avoid hidden telemetry and unexpected outbound communication. Diagnostic tools should minimize unnecessary exposure of operational data.

## Pull request expectations

Pull requests should be scoped and explain the reason for the change. When applicable, include documentation updates and tests with behavior changes.

One GitHub Actions workflow (`release-regression.yml`) compiles the code and runs the `unittest` suite of `opsforge.common` and of every utility across the supported Python range, and validates packaging in a clean environment. Before opening a pull request, run the documented compile and test commands for the code you changed (`python -m unittest discover -s opsforge/<utility>/tests`), and if you change `opsforge.common`, run every utility's suite too. A new utility must be added to that workflow's compile list and test loop.

Status names and exit codes are shared. Use the constants in `opsforge.common.status` (`EXIT_OK`, `EXIT_FINDING`, `EXIT_USAGE`, `EXIT_FAILURE`, `EXIT_INTERRUPTED`, and the status names) rather than integer or string literals, and follow the rules in the README's "Status and exit codes" section: a finding decides exit 1 even when other parts are missing, a gap with no finding is exit 3 (or `PARTIAL` and exit 1 for an observation-only utility), and an `--output` failure is always 3. Resolution, host parsing, and TCP connection code belong in `opsforge.common.net`, not in a utility.

Packaging or release changes should additionally build the wheel and source distribution, install the wheel into a clean environment, exercise every installed command, and run `git diff --check`. Do not add runtime dependencies, install hooks, platform claims, or version declarations without explicit evidence and review.

## Reproducible development commands

Run these Bash commands from the repository root on a supported Linux environment
(including a suitable WSL Linux environment). See the root README for support policy.
The runtime uses only the standard library; packaging checks additionally need build tooling.

```bash
python3 -m venv .venv
. .venv/bin/activate
python --version
```

### Focused utility change

Replace `configdiff` with the affected utility name under `opsforge/`. Source-tree tests do not
require installing the package. Run modules from the repository root.

```bash
python -m compileall -q opsforge/common opsforge/configdiff
python -m unittest discover -s opsforge/configdiff/tests -v
python -m opsforge.configdiff.configdiff --help
git diff --check
```

### Shared behavior or repository-wide validation

Run each suite explicitly: top-level unittest discovery is not a substitute for
the independently structured test directories. This mirrors the release workflow.

```bash
python -m compileall -q opsforge
for component in common portlens diskhound certwatch svcdoctor loghound procwatch configdiff netdoctor healthctl incidentsnapshot; do
  python -m unittest discover -s "opsforge/$component/tests" -v || exit "$?"
done
git diff --check
```

### Packaging changes

Build from a clean checkout or worktree so stale artifacts cannot be mistaken for
new builds. Package-manager installation may contact the package index for build tooling.

```bash
python -m pip install "build==1.2.2.post1"
python -m build
```

Then install each newly built distribution into its own temporary environment and
run checks outside the source tree. For example, in Bash:

```bash
repo_dir="$PWD"
for artifact in "$repo_dir"/dist/*.whl "$repo_dir"/dist/*.tar.gz; do
  package_env="$(mktemp -d)"
  python -m venv "$package_env/venv"
  "$package_env/venv/bin/python" -m pip install --no-deps "$artifact" || exit "$?"
  (
    cd "$package_env" || exit 1
    "$package_env/venv/bin/python" -m pip check || exit "$?"
    for command in portlens diskhound certwatch svcdoctor loghound procwatch configdiff netdoctor healthctl incident-snapshot; do
      "$package_env/venv/bin/$command" --help >/dev/null || exit "$?"
    done
  ) || exit "$?"
  printf 'Packaging environment retained for inspection: %s\n' "$package_env"
done
```

These help/import smoke checks are only part of packaging validation. Follow
[release-regression.yml](.github/workflows/release-regression.yml) for metadata,
empty runtime dependencies, controlled installed JSON invocations, tests from the
extracted sdist, uninstall checks, and both distribution matrices across supported
interpreters. Do not replace
controlled fixtures with unsolicited public-network checks.

### Documentation, plans, and reviews

For documentation-only changes, check relative links, example syntax, and agreement
with current code/CLI help; run `git diff --check`. Run behavioral tests only when
the change affects behavior or reveals an unresolved concern.

Record executed validation with the commit, environment, commands, results, and
limitations. Historical [VALIDATION.md](VALIDATION.md) results remain attached to
their original revisions; do not copy them forward as new execution evidence.

Use [docs/PLANS.md](docs/PLANS.md) for substantial changes and
[docs/decisions/](docs/decisions/README.md) for lasting decisions. Keep utility README
sections discoverable for inputs/examples, evidence, exits, permissions/activity,
bounds, and interpretation limits. Link shared contracts rather than duplicating them.

For requested PR reviews, use
[opsforge-pr-review](.agents/skills/opsforge-pr-review/SKILL.md). Local review records
and private working plans live under ignored `.local/`; review notes are not release
evidence until their specific checks and revisions are verified.
