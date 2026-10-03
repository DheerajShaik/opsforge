# Review record format

Store one compact Markdown record per PR at `.local/reviews/pr-<number>.md` in the
verified OpsForge checkout. This is evidence for future review rounds, not a rule
file or a substitute for inspecting current code. Avoid raw logs, credentials,
private diagnostic payloads, and unnecessary copied discussion.

Use this structure, replacing example fields with actual observations:

```markdown
# OpsForge PR <number>: <title>

Repository: <verified repository identity>
PR: <URL, or local-only>
Updated: <timestamp including timezone>
Base SHA: <full SHA>
Merge-base SHA: <full SHA>
Reviewed head SHA: <full SHA>
Working tree: <clean, or describe relevant uncommitted changes>
Remote head verified: <timestamp/SHA, or unavailable>

## Scope and remaining questions
<Requested scope, meaningful constraints, and unresolved questions>

## Findings
| ID | Severity | State | Trigger and impact | Current location | Resolution/evidence |
| --- | --- | --- | --- | --- | --- |
| F1 | P2 | open | <concrete defect> | <path:line at SHA> | <reproduction or code evidence> |

## Validation
| Check | Environment | Commit or working-tree state | Result | Evidence |
| --- | --- | --- | --- | --- |
| <actual command or CI job> | <OS/Python> | <SHA> | passed / failed / not run | <concise result or link> |

## Review rounds
- <date, reviewed SHA>: <new/resolved findings, key evidence, remaining gaps>

## Next review
<Relevant delta to inspect or unresolved finding to verify; none if complete>
```

Delete the example finding row when no findings exist. Keep stable finding IDs and
preserve earlier round summaries. Record "unverified" when evidence is unavailable;
do not mark a finding resolved merely because a contributor says it is fixed.

For a different checkout or machine, the user can provide this record as context.
Recheck its identity and evidence against the current PR. A copied record does not
transfer authorization for publishing, merging, or running live diagnostics.
