# Plans for substantial changes

Use a plan for a cross-utility feature, contract migration, or substantial refactor.
Small fixes and documentation edits do not require one. Store a shared plan as
`docs/plans/<short-topic>.md` when collaboration benefits from versioned context;
use `.local/plans/` for private working notes. Create directories only when needed.

Keep the plan understandable from the repository alone. Record the actual objective,
constraints, affected code, observable acceptance criteria, progress, and evidence.
Update it when scope changes. A plan is not authorization to publish, deploy, or merge.

## Suggested plan format

```markdown
# <Change title>

Status: proposed / in progress / complete / blocked
Updated: <date>
Baseline: <commit>

## Objective and scope
Describe the user-visible outcome and explicit non-goals.

## Current behavior and affected areas
Link relevant implementation, contracts, tests, and decisions.

## Approach and checkpoints
List the small implementation steps and observable acceptance criteria.

## Validation
Record commands, environment, commit/working-tree state, actual results, and limits.
Separate planned checks from executed checks.

## Decisions and open questions
Record material tradeoffs, resolved questions, remaining blockers, and next action.

## Completion
State what changed, evidence supporting completion, and any remaining work.
```

Link lasting architectural choices to [decision records](decisions/README.md).
Use the PR review skill's local review record for review rounds rather than creating
a second list of findings in a plan.
