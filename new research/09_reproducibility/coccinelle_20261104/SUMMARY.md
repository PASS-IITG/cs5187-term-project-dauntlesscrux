# Coccinelle exploratory lifecycle scan

## Scope and method

Pinned OpenSSL source revision `ed57129cd43b77e077c68fd5f7ea951976766f38` (detached HEAD) was inspected with Coccinelle 1.1.1. There are 1,695 tracked C translation units in `tracked_c_files.txt`. Four separately sample-tested semantic patches cover same-pointer use after selected release calls, repeated same-callee `*free*` calls, BIO release after `SSL_set0_rbio/wbio` ownership transfer, and allocation followed by a return. API ownership conventions and rule caveats are recorded in `source_and_tool.txt` and `RULES.md`. Each sample rule has dedicated sample input and stdout/stderr logs.

## Scan status and inventory

Rule 01 completed on 910 prefiltered files (exit 0): zero matches. Rule 03 completed on 10 files (exit 0): 14 raw matches, deduplicated as nine function-level candidates; all are in tests and were source-reviewed as FP heuristic matches. Rule 02 did not finish (exit 130 after a prolonged no-output run); rule 04 timed out after 180 seconds (exit 124), and its longer retry was interrupted (130) after no usable progress. Empty stdout for rules 02 and 04 is partial output and **does not** establish no candidates. Therefore the requested complete whole-tree scan is **not complete**; no total whole-tree candidate count or negative claim is made.

`raw_matches.csv` preserves each Coccinelle emission and original rule identifier; `candidate_inventory.csv` groups same rule/file/function/transfer-site matches without losing the raw data. `coccinelle_manual_review.csv` records the initial manual review.

## Initial manual review

The nine rule 03 function-level candidates in `test/dtlsv1listentest.c`, `test/dtlsssllistenertest.c`, `test/dtlstest.c`, and `test/sslapitest.c` are FP for the heuristic: transferred locals are nulled before cleanup, or a separately incremented BIO reference is deliberately restored and then released. The candidate is a syntactic ownership-transfer/free sequence; source control flow and reference accounting explain it. No TP is established. This review is limited to these matches and is not runtime validation.

## Research dataset comparison

Datasets remain distinct: (1) the original three CVE regression tests (CVE-2022-4450, CVE-2023-0215, CVE-2024-4741); (2) Clang inventory `research/09_reproducibility/clang_scan_20261103/clang_report_inventory.csv` and its manual triage; (3) this Coccinelle inventory; and (4) historical fix register `research/02_candidate_selection/historical_fix_register.csv`. The completed rules 01 and 03 produced no demonstrated retrospective match to a historical production fix; rule 02 and rule 04 are incomplete, so retrospective comparison for those rules is pending. No precision, recall, or accuracy statistics are appropriate. The rule 03 findings are in tests and are not independent production discoveries.

## Limits

SmPL here is intraprocedural and primarily syntactic. It does not generally prove path feasibility, aliasing, refcount semantics, cleanup dominance, or ownership contracts. Lexical necessary-condition filters reduce scanning cost and are documented with manifests; they still depend on conservative matching and function-boundary recognition. Rules 01 and 04 cover only selected allocation/free APIs; rule 02 conflates any function containing `free`; rule 03 handles only SSL_set0 BIO APIs and is especially prone to expected cleanup matches. Coccinelle output is a review queue, not a vulnerability verdict.

## Evidence files

See `REPRODUCE.md`, `final_scan_status.csv`, `final_scan_commands.txt`, `logs/`, rules under `rules/`, test inputs under `samples/`, `raw_matches.csv`, `candidate_inventory.csv`, and `coccinelle_manual_review.csv`. Rule hashes are in `REPRODUCE.md`.
