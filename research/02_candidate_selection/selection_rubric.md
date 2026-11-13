# Candidate Selection Rubric

Each candidate received 0–2 points on five criteria. Maximum score: 10. Scores are prioritization judgments, not empirical detection results.

| Criterion | 0 | 1 | 2 |
|---|---|---|---|
| Patch/source availability | Source or fix not established | Partially located or needs confirmation | Source and relevant patch available for comparison |
| Root-cause clarity | Cause unclear | Partly understood | Plausible cause explainable from source and patch |
| Typestate/API rule fit | Weak fit | Possible, but uncertain | Strong fit with a state, ownership, lifecycle, or API-contract invariant |
| Recurrence potential | Appears isolated | Recurrence possible | Reusable pattern plausibly occurs elsewhere |
| Time feasibility | Not feasible in scope | Significant uncertainty/effort | Manageable for the current project phase |

The totals used for selection are in `candidate_register.csv`. CVE-2023-0216 had an arithmetic discrepancy in an earlier table: its components sum to 8, so the working register uses 8/10 (not 7/10). This reconciliation should be preserved in the audit record.

## Why the top three won

- CVE-2023-0215 (10/10): BIO chain state and resource lifetime on an error path; also had a feasible runtime investigation route.
- CVE-2022-4450 (10/10): output-pointer ownership after failure cleanup.
- CVE-2024-4741 (9/10): TLS buffer lifetime and state-dependent release behavior.

The cases are complementary: chain ownership, output-pointer state after failure, and dependent packet/buffer state. We did not select solely by severity.

## Caveat

Some secondary-candidate information in the initial register was explicitly provisional. Recheck official source records before repeating exact version ranges, source functions, or fixing commits in a formal submission. The primary three are linked to the project worktree revision ledger in the per-CVE notes.
