# OpenSSL CVE tool comparison

Date: 2026-11-05  
Scope: CVE-2022-4450, CVE-2023-0215, and CVE-2024-4741, each at the pinned vulnerable and fixed revision in `WORKTREE_REVISION_MANIFEST.csv`.

## Results

All six worktree HEADs matched the source revision ledger. The frozen Python checker was rerun on all six affected source files and distinguished every vulnerable/fixed pair. Clang Static Analyzer 18, the five pre-existing Coccinelle rules, and Cppcheck 2.13.0 completed analysis on both sides of all three pairs. The comparison contains **24 source-level tool/revision rows** (four tools × six source revisions), with paired classifications shown on both sides of each pair.

| Tool | CVE-2022-4450 | CVE-2023-0215 | CVE-2024-4741 |
|---|---|---|---|
| Python typestate checker | DETECTED_AND_DISTINGUISHED | DETECTED_AND_DISTINGUISHED | DETECTED_AND_DISTINGUISHED |
| Clang Static Analyzer 18 | NOT_DETECTED | NOT_DETECTED | NOT_DETECTED |
| Coccinelle 1.1.1, existing rules | NOT_DETECTED | NOT_DETECTED | NOT_DETECTED |
| Cppcheck 2.13.0 | NOT_DETECTED | NOT_DETECTED | NOT_DETECTED |

No final tool/source combination was NOT_EVALUABLE. Clang had two earlier setup attempts that were NOT_EVALUABLE; after building generated headers in temporary copies, the final six Clang analyses completed successfully. Earlier failed attempts and logs are preserved and excluded from the result matrix.

## What the outputs mean

- **Python:** vulnerable source produced VIOLATION and fixed source CONFORMING for each CVE. The checker emits its targeted source-pattern result; this is a regression result and does not prove runtime exploitability.
- **Clang:** all six affected translation units compiled/analyzed with revision-specific OpenSSL configuration and generated include files. No analyzer diagnostics were emitted in any of the six runs. No setup error is counted as a negative result.
- **Coccinelle:** all 30 invocations (five frozen rules × six files) parsed and exited 0. Rule 02’s generic release-event output for BIO_new_NDEF is present in both versions but does not inspect BIO_pop or linked BIO state. For PEM, its one-identifier argument pattern does not match `pem_free(*header)`/`pem_free(*data)`. Allocation/return events for SSL do not correlate allocation with packet-state resets. Generic events were therefore not counted as detections.
- **Cppcheck:** all 12 text/XML runs exited 0. PEM produced 12 unrelated style diagnostics in each version; BIO produced none; SSL buffer source produced two unrelated style diagnostics in each version (28 total). Every emitted item was reviewed in `CPPCHECK_DIAGNOSTIC_REVIEW.csv`. No finding represented the selected pointer/ownership mechanism, and no relevant diagnostic disappeared in the fixed source.

The manual source review and raw evidence are in `MANUAL_REVIEW_EVIDENCE.csv`, `CPPCHECK_DIAGNOSTIC_REVIEW.csv`, and `runs/`. The side-by-side 24-row inventory is `COMPARISON_MATRIX.csv`.

A separate Clang positive control in `runs/clang/control/` produced the expected use-after-free diagnostic (`Use of memory after it is freed`) with exit 0. This confirms the analyzer was active for the clean affected-TU runs.

## Reproducibility and state

Tool versions, binary/checker/rule hashes, and frozen configurations are in `TOOL_FREEZE.csv`; detailed invocations are in `TOOL_CONFIGURATION.md` and `REPRODUCE.md`. Clang used temporary Git-archive source copies under `/tmp` because the original source worktrees lacked generated build configurations. Cppcheck used the corresponding configured temporary copies. Coccinelle and Python ran against the original worktree source files read-only.

No OpenSSL source, analyzer, or test files were modified for this comparison. No stage, commit, reset, clean, or checkout operation was performed. Existing staged, unstaged, and untracked state was preserved. Git revision verification is recorded in `WORKTREE_REVISION_MANIFEST.csv`.

This experiment is limited to three CVEs selected in advance; it does not establish accuracy, precision, recall, general typestate capability, or tool superiority. See `TOOL_LIMITATIONS.md`.
