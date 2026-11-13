# Cppcheck whole-tree comparison — completed scan

Date: 2026-11-05 (UTC)  
Source: `/mnt/d/CVE-Typestate-Project-clang-analysis`  
Pinned revision: `ed57129cd43b77e077c68fd5f7ea951976766f38`  
Tool: `Cppcheck 2.13.0`  
Environment: `Linux Rutvij 6.18.54.1-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Tue Oct  6 19:13:07 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux`

## Result

The completed Cppcheck pass covered all **1,695 tracked C source files** in both text and XML passes. Each pass used 17 batches; all batches completed with exit code 0. XML parsed successfully and contains 6,897 diagnostics. The text output contains 6,897 parsed diagnostics; the raw diagnostic CSV contains 6,897 rows. These counts agree. The deduplicated inventory contains 6,806 entries, retaining diagnostic IDs and raw occurrence counts; deduplication grouped repeated same-key diagnostics and did not collapse distinct IDs. Source-domain counts are recorded in the refined inventory.

This is a static-analysis inventory, not a count of defects. Of the 6,806 deduplicated entries, 6,583 are style, 98 error, 95 warning, and 30 portability diagnostics. A source-level initial review recorded 14 entries/groups in `cppcheck_manual_triage.csv`: the two ML-KEM report locations are one callback issue; two additional findings are in an optional demo; remaining selected diagnostics were assessed as false positives. None was runtime-tested. All other inventory rows remain unreviewed.

## Reviewed source findings

- **ML-KEM provider callback (`ml_kem_load`, lines 534 and 542): TP, high source-level confidence.** Cppcheck reports two dereference locations for one underlying null-key path. The opaque reference bytes are loaded as a pointer and dereferenced without a null check. This is a provider-callback robustness defect based on source inspection; no runtime reproduction or exploitability claim is made.
- **Optional HTTP/3 demo (`ossl-nghttp3-demo.c`, lines 203 and 205): TP, high source-level confidence.** The realloc result is dereferenced without a failure check, and an unbounded `%s` conversion targets a `PATH_MAX` buffer. These findings are limited to an optional demo and are not production-library findings.
- The other reviewed entries in the manual triage file are FP with high confidence and cite the initialization, range guards, target configuration, ownership, or control-flow that makes the specific diagnostic infeasible or non-defective.
- No runtime validation was performed. A separate unchecked floating-to-integer conversion concern noticed while examining `OSSL_PARAM_set_double` is explicitly not attributed to Cppcheck’s two guarded-cast diagnostics; it is outside the reviewed Cppcheck finding set and needs an independent focused assessment.

## Tool comparison

`tool_overlap_exact_locations.csv` compares exact normalized file and line locations across the Cppcheck inventory, the Clang inventory, and Coccinelle candidates. At exact location, 233 Cppcheck groups overlap Clang and 1 overlap Coccinelle. This matching is intentionally location-based: reports may refer to the same function at nearby lines, and analyzer source scopes/semantics differ. The historical register comparison is exact file plus function, not proof of discovery. The known-CVE test crosswalk is kept in `known_cve_scope_crosswalk.csv` and reports no exact Cppcheck file/function overlap with the three regression targets in this pinned whole-tree inventory. These datasets are descriptive and do not support precision, recall, accuracy, or superiority claims.

The Cppcheck scan used a configured OpenSSL checkout with generated `configdata.pm`, Makefile and configuration header; no `compile_commands.json` was available. The captured configuration identifies `linux-x86_64`, `CC=clang`; the invocation used C11, unix64, `-DNDEBUG`, and explicit include roots. Optional/generated configuration and alternate-platform branches may therefore produce parser/configuration diagnostics. There were 27 such diagnostics (`unknownMacro`, `preprocessorErrorDirective`, `internalAstError`), separated in their own CSV. No blanket suppressions were added; `--inline-suppr` was enabled, and no tracked C/H `cppcheck-suppress` comments were found in the prior scan preparation.

## Coverage and records

`scan_manifest.csv` maps every tracked input to both completed passes. `cppcheck_text_batch_status.csv` and `cppcheck_xml_batch_status.csv` record start/end, duration, command, exit status and log paths. `cppcheck_text_file_status.csv` and `cppcheck_xml_file_status.csv` account for each file. The original failed first text attempt is retained in its original status/log files and is not treated as a scan result. The source tree remains at the pinned revision and was clean at final inspection (`## HEAD (no branch)`).

See `REPRODUCE_CPPcheck.md` for commands and interpretation limits.
