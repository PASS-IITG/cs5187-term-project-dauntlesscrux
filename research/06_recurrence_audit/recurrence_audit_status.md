# Recurrence Audit — Status and Next Actions

## Current status: incomplete / needs source restoration

A prior `recurrence_investigation_v2.md` draft described ten candidate locations and assigned classifications such as safe control, rejected, and unresolved. However, its table has missing file names, functions, and invariant/source-location values. Without those identifiers, the audit cannot be independently reproduced. This pack does **not** promote those entries to fully verified source-level findings.

## What can be said now

- Recurrence analysis is a planned and necessary step: a similar-looking pattern in another function is only a lead.
- The notes reported no confirmed additional vulnerability in the available BIO recurrence review.
- Ten candidate records were described in the draft, but the exact source-pinned evidence must be restored before treating that as a completed ten-location audit.

## Required fields for each candidate

1. Stable candidate ID.
2. Exact repository revision/commit.
3. Relative source file path and function name.
4. Exact relevant line range or a minimal code excerpt.
5. Which invariant was tested (TS-BIO-01, TS-PEM-02, TS-SSL-03, or unrelated).
6. Expected behavior and observed source behavior.
7. Classification: safe control, rejected / out of scope, potential finding, or unresolved.
8. Reasoning and counter-evidence.
9. Reproducible command or code review note.
10. Reviewer and review date, if used for a formal audit.

## Classification rules

- **Safe control:** source was inspected and the relevant invariant is satisfied on the examined path.
- **Rejected / out of scope:** superficially similar, but the target object/API/state condition is not the same.
- **Potential finding:** apparent invariant violation requiring full path, alias, ownership, and caller review.
- **Unresolved:** current evidence cannot classify it either way.
- **Confirmed vulnerability:** only after manual validation and sufficient technical evidence; do not assign from pattern matching alone.

Use `recurrence_audit_template.csv` to restore the missing rows from the actual source checkout. Keep the earlier draft out of any claim that the audit is complete until the missing data are fixed.
