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

## Work in a verified loop

Carry a task to a verified result without pausing for confirmation between
routine steps:

1. Orient: confirm the baseline, then read the task, any active plan, and the
   affected README, code, and tests.
2. Plan: keep a checklist; use a plan file for cross-utility or multi-session work.
3. Change: make the smallest coherent edit for the next item, with a regression
   test for any behavior change.
4. Verify: run `bash scripts/check.sh <utility>` and read its `RESULT:` line.
5. Repair: fix the cause the output shows. After three failed attempts at the same
   problem, stop and report the evidence and your best hypothesis.
6. Record progress and continue with the next item.

Never delete, skip, or weaken a test or acceptance criterion to get a pass. Finish
with `bash scripts/check.sh all` when shared code or several utilities changed,
run `git diff --check` with the Git that manages the checkout, and report the
changes, commands, results, and remaining gaps.

Make reasonable assumptions for routine choices, record them in the plan or final
report, and keep going. Stop and ask only when the next step would:

- push, merge, tag, publish, or post to GitHub, rewrite history, or delete
  branches or files this task did not create;
- change a documented CLI default, exit code, status name, JSON field, or support
  policy, or add a runtime dependency;
- contact a public or production target, need elevated privileges, or touch
  shared infrastructure;
- expand beyond the requested scope.

On Windows, run checks through WSL from the repository root:
`wsl.exe --cd "$PWD" -e bash scripts/check.sh all`. The script tests an LF copy of
the working tree on the Linux filesystem and never writes into the checkout.

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
  Use `bash scripts/check.sh <utility>` (or `all`), which mirrors the commands in
  CONTRIBUTING.md. Do not run live public-network probes merely to validate a
  documentation or unit-test change.
- Report commands actually run, results, and environment limitations. Keep planned
  work, observed evidence, and inferred explanations distinct.

## Plans and decisions

For substantial cross-utility changes or work that will span sessions, keep a plan
using [docs/PLANS.md](docs/PLANS.md). Record lasting architectural choices under
[docs/decisions/](docs/decisions/README.md). Routine edits do not need a plan or ADR.

Keep cross-session state in the plan and Git history, not in chat. A resumed
session reads the plan's Progress section and `git log --oneline -10`, then
reruns the checks before changing code.

## Code review rules

For requested OpsForge PR reviews, re-reviews, and repository audits, use the repository skill
[opsforge-pr-review](.agents/skills/opsforge-pr-review/SKILL.md).
If skill discovery is unavailable, read that file directly.

Prioritize reproducible correctness, compatibility, privacy, and safety regressions.
Check incomplete evidence, resource limits, races, helper cleanup, and documented
exit semantics where the diff touches them. Anchor findings to the reviewed commit
and relevant lines. Recheck old findings before carrying them forward. Existing
validation counts and green checks on older commits do not establish current readiness.

Split review work across subagents only with the relevant contract rules, a bounded
scope, and the required evidence format. Their findings are hypotheses: confirm each
in code or with a focused test before reporting it, and list unconfirmed items separately.
