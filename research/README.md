# Research Folder Index

This folder preserves the reasoning and evidence behind **CVE-Guided Typestate Analysis for Recurring Vulnerability Detection in OpenSSL**. The executable checker and actual OpenSSL source trees remain at the project root; this folder is for research, derivation, provenance, evaluation, and reproducibility.

## Directory guide

| Path | Purpose | Current status |
|---|---|---|
| `01_project_motivation.md` | Research question, project choice, scope, milestone | Drafted from the project notes |
| `02_candidate_selection/` | Eight-candidate register, scoring rubric, selection rationale | Scores preserved; secondary-candidate metadata should be checked before formal publication |
| `03_cve_analysis/` | Per-CVE root cause, patch logic, rule hypothesis, validation status | Three selected cases documented; only CVE-2023-0215 has recorded runtime ASan evidence |
| `04_typestate_rules/` | Formal rule models and mapping to checker code | Initial rule models; implementation is heuristic, not a complete analyzer |
| `05_related_work/` | Official advisories, commits, supporting background | Official-source links supplied; add papers found during literature review |
| `06_recurrence_audit/` | Recurrence-search status and audit template | Incomplete: restore exact source path/function/commit/evidence before counting findings as audited |
| `07_evaluation/` | Benchmark, script, log, interpretation | 16 synthetic/hand-written cases; do not generalize results beyond this suite |
| `08_meeting_notes/` | Milestone and decisions | Progress Meeting 1 summary |
| `09_reproducibility/` | Commands, environment notes, evidence checklist | Commands are recorded; re-run in the final repository before submission |

## Evidence labels used throughout

- **Source-verified:** supported by inspection of the specified source revision or official patch.
- **Regression-tested:** the checker was run against the recorded vulnerable/fixed source pattern and returned the expected outcomes.
- **Runtime-tested:** a compiled OpenSSL program was executed and a runtime diagnostic was observed.
- **Provisional:** the item needs verification against source/advisory evidence.
- **Unresolved:** available notes are insufficient to support a conclusion.

Do not promote a provisional or unresolved item to a confirmed vulnerability simply because it resembles a known pattern.
