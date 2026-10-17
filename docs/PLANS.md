# Plans for substantial changes

Use a plan for a cross-utility feature, contract migration, substantial refactor,
or any task likely to outlast one agent session. Small fixes and documentation
edits do not require one. Store a shared plan as `docs/plans/<short-topic>.md`
when collaboration benefits from versioned context; use `.local/plans/` for
private working notes. Create directories only when needed.

A plan is a living, self-contained instruction set: someone with only the
repository and the plan must be able to continue the work. Update it when scope
changes. A plan is not authorization to publish, deploy, or merge.

## Executing a plan

- Work checkpoint by checkpoint without asking for next steps. Stop only for the
  decisions listed in [AGENTS.md](../AGENTS.md) or a blocker you cannot resolve.
- Tick a checkpoint only after its verification command passes, and note the
  command and result.
- Update Progress at every stopping point, including interruptions, so a fresh
  session can resume from the plan and `git log` alone.
- Add a Surprises entry for unexpected evidence and a dated decision for every
  change of approach.
- Never edit or delete an acceptance criterion or test to make it pass; record the
  conflict and stop for a decision.

## Suggested plan format

```markdown
# <Change title>

Status: proposed / in progress / complete / blocked
Updated: <date>
Baseline: <commit>

## Objective and scope
Describe the user-visible outcome and explicit non-goals.

## Current behavior and affected areas
Link relevant implementation, contracts, tests, and decisions so a new session
can start without the original conversation.

## Acceptance
Observable behavior that defines done, and the exact commands that show it,
for example `bash scripts/check.sh configdiff`.

## Checkpoints
Small ordered steps, each independently verifiable.

## Progress
- [x] <date> <checkpoint> (verified: <command>, <result>)
- [ ] <next checkpoint>

## Surprises
Unexpected behavior or evidence, and how it was found.

## Validation
Record commands, environment, commit/working-tree state, actual results, and limits.
Separate planned checks from executed checks.

## Decisions and open questions
- <date>: <decision> because <reason>.

Record remaining blockers and the next action.

## Completion
State what changed, evidence supporting completion, and any remaining work.
```

Link lasting architectural choices to [decision records](decisions/README.md).
Use the PR review skill's local review record for review rounds rather than creating
a second list of findings in a plan.
