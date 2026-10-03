# Working on OpsForge

OpsForge is a collection of ten focused Linux diagnostic utilities. Keep changes
within the requested scope and preserve each utility's independent CLI.

## Read the relevant context

- Start with [README.md](README.md) for scope and current support policy.
- Read [CONTRIBUTING.md](CONTRIBUTING.md) for setup, test commands, and PR expectations.
- Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) when locating code or changing boundaries.
- Read the affected utility's README before changing its behavior; read
  [docs/CONTRACTS.md](docs/CONTRACTS.md) for output, exit-code, or integration changes.
- Read [SECURITY.md](SECURITY.md) for filesystem, subprocess, privilege, network,
  and sensitive-data changes. Read [docs/AI_USAGE.md](docs/AI_USAGE.md) when using
  OpsForge to investigate a system.
- [VALIDATION.md](VALIDATION.md) records historical evidence. It does not prove
  the current checkout passed those checks.

## Verify the baseline before editing

Check the branch, working-tree changes, and local HEAD. Query the remote default
branch when network access is available; compare against fresh remote metadata,
not a cached tracking ref. State if the checkout is behind or remote access is
unavailable. Preserve local edits before updating a checkout. Scope documentation
and validation claims to the revision actually inspected.

## Development expectations

- Preserve diagnostic-first behavior, explicit network targets, bounded work,
  and the standard-library-only runtime unless the task explicitly changes that contract.
- Keep Python syntax and APIs compatible with the supported range in
  `pyproject.toml`. Windows is an editing environment, not evidence of Linux support.
- Code lives under `opsforge/`. Shared output, status/exit policy, network handling,
  and bounded helpers live in `opsforge/common/`; utility-specific collection and
  interpretation belong in `opsforge/<utility>/`.
- Use `opsforge.common.status` constants and the shared `opsforge.common.net` host,
  resolver, and connection behavior. Preserve finding precedence over evidence gaps;
  output failure always exits 3. See docs/CONTRACTS.md for observation-only exceptions.
- Preserve CLI defaults, utility-specific exit meanings, JSON evidence semantics,
  and output protections. Update documentation and regression tests together when
  behavior changes. Do not replace unknown/unavailable evidence with zero or empty success.
- Run the affected utility suite; shared behavior needs all consumers checked.
  Use the exact commands in CONTRIBUTING.md. Do not run live public-network probes
  merely to validate a documentation or unit-test change.
- Report commands actually run, results, and environment limitations. Keep planned
  work, observed evidence, and inferred explanations distinct.

## Plans and decisions

For substantial cross-utility changes, maintain a short plan using
[docs/PLANS.md](docs/PLANS.md). Record lasting architectural choices under
[docs/decisions/](docs/decisions/README.md). Routine edits do not need a plan or ADR.

## Code review rules

For requested OpsForge PR reviews and re-reviews, use the repository skill
[opsforge-pr-review](.agents/skills/opsforge-pr-review/SKILL.md).
If skill discovery is unavailable, read that file directly.

Prioritize reproducible correctness, compatibility, privacy, and safety regressions.
Check incomplete evidence, resource limits, races, helper cleanup, and documented
exit semantics where the diff touches them. Anchor findings to the reviewed commit
and relevant lines. Recheck old findings before carrying them forward. Existing
validation counts and green checks on older commits do not establish current readiness.
