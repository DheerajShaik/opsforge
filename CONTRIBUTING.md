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

One GitHub Actions workflow (`release-regression.yml`) compiles the code and runs the `unittest` suite of `opsforge.common` and of every utility across the supported Python range, and validates packaging in a clean environment. Before opening a pull request, run the documented compile and test commands for the code you changed (`python -m unittest discover -s <utility>/tests`), and if you change `opsforge.common`, run every utility's suite too. A new utility must be added to that workflow's compile list and test loop.

Status names and exit codes are shared. Use the constants in `opsforge.common.status` (`EXIT_OK`, `EXIT_FINDING`, `EXIT_USAGE`, `EXIT_FAILURE`, `EXIT_INTERRUPTED`, and the status names) rather than integer or string literals, and follow the rules in the README's "Status and exit codes" section: a finding decides exit 1 even when other parts are missing, a gap with no finding is exit 3 (or `PARTIAL` and exit 1 for an observation-only utility), and an `--output` failure is always 3. Resolution, host parsing, and TCP connection code belong in `opsforge.common.net`, not in a utility.

Packaging or release changes should additionally build the wheel and source distribution, install the wheel into a clean environment, exercise every installed command, and run `git diff --check`. Do not add runtime dependencies, install hooks, platform claims, or version declarations without explicit evidence and review.
