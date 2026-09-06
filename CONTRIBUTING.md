# Contributing to OpsForge

Thank you for your interest in contributing to OpsForge.

OpsForge is an early-stage open-source project with ten experimental Linux, DevOps, and SRE utilities. The initial roadmap has been implemented, and the project continues to evolve as real requirements, implementation experience, testing, compatibility evidence, and community feedback shape it.

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

GitHub Actions workflows compile and run the `unittest` suite for each utility. Before opening a pull request, run the relevant utility's documented compile and test commands where practical, and ensure the focused workflow remains representative of the change.
