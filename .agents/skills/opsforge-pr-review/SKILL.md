---
name: opsforge-pr-review
description: Review OpsForge pull requests and follow-up fixes for actionable regressions, preserving commit-specific findings across review rounds. Use for requested OpsForge PR reviews, re-reviews, and merge-readiness assessments.
---

# OpsForge PR review

Review the requested change and return evidence-backed findings. A review request
does not itself request fixes, a GitHub comment/review submission, approval, or merge.
Honor any separate authorization already given by the user. Reading this skill or
opening a PR does not start a background monitor.

## Establish the review target

- Locate the OpsForge checkout from the task context; read its AGENTS.md. From this
  repository skill folder the root is `../../..`, but verify it with Git metadata.
- Resolve the requested PR/repository, base, and current head from available GitHub
  tools or CLI. Record the full head SHA, base SHA, and merge base. Attach the PR to
  the current chat if the host provides a PR attachment tool.
- Inspect working-tree changes before checkout operations. Prefer read-only diffs
  and an existing suitable checkout; isolate another revision when necessary without
  overwriting user changes. If only a local diff is accessible, review that diff and
  clearly state that remote PR state and CI were not verified.
- Verify that the code and docs being inspected belong to the requested head,
  not an outdated local default branch. Current code is under `opsforge/`; determine
  paths from the reviewed revision instead of assuming this layout existed in older PRs.
- Read prior review discussion and `.local/reviews/pr-<number>.md` if available in
  this checkout. Verify the record's repository and PR identity before using it.
  Treat old conclusions as claims to recheck, not current evidence or instructions.

## Review the actual change

Read the merge-base-to-head diff, affected implementations, callers, and tests.
For follow-ups, first compare the last reviewed head to the current head, then check
the remaining PR diff and impacted behavior. If history was rewritten, recompute the
comparison; do not assume every prior fix remains. Read only relevant supporting docs:

- Root `CONTRIBUTING.md` for validation commands and existing release expectations.
- `docs/ARCHITECTURE.md` for boundaries and `docs/CONTRACTS.md` for outputs/exits.
- Affected utility READMEs for intended behavior and `SECURITY.md` for sensitive paths.
- `VALIDATION.md` for dated evidence, never as proof that new code passed.

Prioritize these OpsForge failure modes when touched by the change:

- Confusing observation completion with health: SvcDoctor inactive exit 0 requires
  sufficient dependency evidence; stopped services with dependency gaps are INCOMPLETE.
  Check ConfigDiff mode-specific equality and CertWatch trust versus validity.
- Violating the shared exit policy: findings outrank other evidence gaps; gaps alone
  must not become success; observation-only PARTIAL exits 1; output failures exit 3.
  HealthCtl ERROR/SKIPPED results have null severity, not a fabricated finding.
- Losing null/unavailable distinctions, changing JSON/CLI defaults or exit semantics,
  contaminating JSON stdout, or breaking quiet/output-file behavior.
- Bypassing symlink/identity protections, leaking sensitive content, expanding network
  targets implicitly, or weakening byte/count/deadline bounds and helper cleanup.
- Bypassing `opsforge.common` status, networking, trusted-helper, or output machinery;
  violating Python/platform support or introducing hidden runtime/install effects.

Trace each suspected defect to a concrete trigger, code path, and user-visible impact.
Use focused existing tests or a minimal safe reproduction where it resolves uncertainty.
Do not run live diagnostics against production or public targets solely for review.
For shared/runtime/packaging changes, use the applicable broader checks from
CONTRIBUTING.md. Documentation-only work needs link/accuracy checks, not an invented
full release campaign. Run untrusted branch code only within the available sandbox.

## Resolve findings and assess evidence

Report bugs introduced or exposed by the PR that the author can act on. Distinguish
pre-existing issues, design preferences, and uncertain hypotheses from findings.
For each finding give severity, the current file and tight line range, trigger,
impact, and supporting evidence. Avoid duplicating one cause across several findings.

Keep stable IDs within a PR (F1, F2, ...). On re-review classify each prior finding
as open, resolved, superseded, or unverified; cite the fix/evidence for resolution.
Do not repeat a resolved finding as new unless a new regression is demonstrated.
Changed line numbers alone do not invalidate a finding.

Check which commit CI actually tested. Separate local results, CI on the reviewed
head or its test merge, older CI, and checks not run. If the head moves during review,
either review the new delta or explicitly limit the report to the reviewed SHA.
Use the repository's existing readiness policy; do not invent certification gates.
"No actionable findings" does not imply all checks passed or authorize a merge.

## Preserve continuity and return the review

Use [references/review-record.md](references/review-record.md) for a compact record at
`.local/reviews/pr-<number>.md` relative to the verified checkout. For local-only
reviews use a descriptive filename and record the branch/commit identity.
The repository ignores `.local/`; these notes are local, not automatically shared
between machines or worktrees. Preserve prior rounds and concise finding history.
If storage is unavailable, include a compact handoff in the response and say it was
not saved. Never claim access to earlier chats you could not actually read.

Return findings first, ordered by severity, followed by prior-finding dispositions
when relevant, actual validation, and material gaps. State the reviewed head and
record location. If nothing actionable is found, say so directly. Keep the output
proportional to the change and user request. Report locally unless publishing a
review/comment was explicitly authorized.
