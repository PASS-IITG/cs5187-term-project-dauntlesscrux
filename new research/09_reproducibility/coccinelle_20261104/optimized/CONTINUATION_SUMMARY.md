# Coccinelle scan continuation — 2026-11-04

## Result

Rules 02 and 04 now completed optimized event-extraction passes over all 1,695 tracked C files at OpenSSL revision `ed57129cd43b77e077c68fd5f7ea951976766f38`. Every final batch exited 0; no source files or existing project tests were changed. Rule 01 and Rule 03 remain complete for their documented filtered scopes. This supersedes the earlier incomplete status for Rules 02 and 04, while preserving the original failed attempt logs and status.

Rule 02 emitted 11,673 direct release events and produced 1,011 deduplicated same-file/function/callee/pointer candidates. Rule 04 emitted 288 allocations and 44,510 raw return positions; explicit-source return filtering produced 288 allocation-before-return candidates. Raw Rule 03 remains 14 matches / 9 test-function candidates. These are heuristic candidate counts, not defect counts.

## Initial review

The initial review in `manual_review_all_rules.csv` covers the strongest candidates and retrospective overlaps, not every syntactic candidate. Rule 03’s nine test-only findings remain FP. Of reviewed Rule 02/04 candidates, the repeated-release signals in `a2i_ASN1_STRING`, `tls_construct_client_hello`, `derive_kdk`, `add_file_cert_subjects_to_stack`, `psk_use_session_cb`, OSSL_STORE/UI cleanup, `m_sigver` local destructor calls, and the reviewed allocation-return cases are FP for their Coccinelle heuristic. The repeated call pair to `evp_pkey_ctx_free_old_ops(locpctx)` in `do_sigver_init` is INCONCLUSIVE: the cleanup helper does not clear a key-generation context, but a feasible provider/error path that reaches the second call before the operation transition was not established. No TP is claimed and no runtime confirmation was performed.

The `m_sigver.c::do_sigver_init` function is a retrospective overlap with the historical fix register. The current pinned source contains pointer resets after the previously fixed frees. The helper-call pair is a distinct candidate within that same previously reviewed function, so it is not an independent blind discovery.

## Coverage and completeness

`file_coverage_manifest.csv` accounts for every intended file in the completed Rules 01–04 scopes. Rules 02 and 04 use all tracked C files; Rule 04 has separate allocation and return passes. Rule 01 covers its 910-file lexical necessary-condition list, and Rule 03 its 10-file API-pattern list. Rule 02’s 43 raw events with unresolved lexical function attribution were cross-checked by the original rule on all six affected files (exit 0; no repeated-release matches). Rule 04’s unresolved return positions are retained and cross-checked as detailed in `RULES_OPTIMIZED.md`; all allocation events are mapped, and no candidate was missing after explicit-return and context validation.

## Dataset comparison

See `dataset_comparison.md`. Rule 02 shares one file/function pair with the historical fix register (`crypto/evp/m_sigver.c::do_sigver_init`); Rule 04 shares none. There are no source/function pairs shared with the broad Clang report inventory by exact file/function key, but Coccinelle candidates overlap three manually triaged Clang functions (two Rule 02, one Rule 04); those source patterns are separately reviewed and do not resolve the Clang labels. The original three-CVE tests, Clang inventory, Coccinelle inventory and historical fix register remain distinct. No accuracy metrics are reported.

## Evidence

- `continuation_status.csv` and `file_coverage_manifest.csv`
- `*_batch_status.csv`, `*_file_status.csv`, `manifests/`, and raw logs under `logs/`
- `raw_events_02.csv`, `raw_events_04a.csv`, `raw_events_04b.csv`, `raw_events_04b_explicit.csv`, and `raw_events_04b_nonliteral_position.csv`
- `candidate_inventory_02.csv`, `candidate_inventory_04_explicit.csv`, `candidate_inventory_all_rules.csv`
- `manual_review_all_rules.csv`, `dataset_comparison.md`
- `RULES_OPTIMIZED.md`, `REPRODUCE_OPTIMIZED.md`, optimized sample inputs and logs

Original experiment artifacts remain alongside this continuation and have not been overwritten.
