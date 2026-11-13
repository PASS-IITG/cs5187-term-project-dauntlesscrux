# Resumed Cppcheck phase status

Status: **whole-tree text and XML passes completed; initial review and evidence validation completed**.

- Pinned checkout: `/mnt/d/CVE-Typestate-Project-clang-analysis` at `ed57129cd43b77e077c68fd5f7ea951976766f38`.
- Cppcheck: 2.13.0 (installed manually by the user; no installation was attempted during resume).
- Eligible tracked C files: 1,695.
- Text pass: 17 batches, all exit 0; 1695/1,695 files scanned.
- XML pass: 17 batches, all exit 0; 1695/1,695 files scanned; XML parses.
- Diagnostics: 6,897 raw entries in both text/XML and raw diagnostic CSV; 6,806 deduplicated entries.
- Manual triage: 14 curated finding groups/rows (3 source-level TP groups, 11 FP groups); no runtime confirmations. Remaining inventory is pending manual review.
- Evidence validation: all CSV schemas parse with consistent row widths; full manifest coverage reconciles; raw XML parses and counts match.
- Original invalid-option attempt is retained and explicitly excluded from completed coverage.

The checked-out source status remained detached HEAD at the pinned revision; this phase changed research artifacts under the main project research directory only. No source code, analyzer or tests were modified; no staging, commit, reset, installation, or history operation was performed during this resumed phase.
