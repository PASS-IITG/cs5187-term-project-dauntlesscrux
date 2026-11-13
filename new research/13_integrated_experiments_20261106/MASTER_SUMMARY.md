# Integrated CVE-guided OpenSSL typestate experiments

## Scope and outcome

This is a bounded comparison of the project checker, Clang Static Analyzer 18, frozen Coccinelle 1.1.1 rules and Cppcheck 2.13.0 against three CVE mechanisms. Correct source pairs are defined in `01_cve_revision_audit/CVE_VULNERABLE_FIXED_MANIFEST.csv`; notably CVE-2024-4741's official fix commit was mislabeled as the vulnerable worktree in the old ledger. The actual vulnerable revision is its parent `ec559c2a6cca3fd4cedae5c47f2dfa38e5e24865`; official fix is `b3f0eb0a295f58f16ba43ba99dad70d4ee5c437d`.

The Python checker distinguished CVE-2022-4450 and CVE-2023-0215. It flags both sides of the corrected CVE-2024-4741 pair, so it does not distinguish that CVE's actual fix. The frozen generic Coccinelle rules and Cppcheck did not identify the reviewed mechanisms for CVE-2022/2023. Clang's source-TU checks completed for the corrected pairs and did not report the CVE mechanisms. Corrected CVE-2024 Cppcheck analysis completed on `ssl/ssl_lib.c` for both sides and found no diagnosis of the mechanism; the related translation units were not included in that corrected-pair scan. CodeQL and Infer were unavailable (see below).

AddressSanitizer reproduced the vulnerable behavior for all three selected CVEs on exact vulnerable snapshots. The exact official fixed snapshots did not reproduce the corresponding memory error in the exercised paths. CVE-2023's fixed CMS command returned an unsupported DES cipher error after reaching the relevant callback path; it is not a successful end-to-end CMS operation. These are focused runtime demonstrations, not broad proof of exploitability or absence of other defects.

Short bounded LibFuzzer runs completed on existing OpenSSL CMS DER and X.509 harnesses. They found no sanitizer failure during those runs. The CMS DER harness does not cover the CVE-2023 BIO streaming path. No security-rate or coverage metric is inferred from the short campaigns.

## Mechanism-level conclusions

- **CVE-2022-4450:** on an error path, PEM parsing frees caller-visible `*header`/`*data` without resetting both pointers. A subsequent caller cleanup can free stale values. ASan confirms the double-free in the minimal test-shaped harness. The official fixed pair resets outputs; ASan run was clean.
- **CVE-2023-0215:** `BIO_new_NDEF` can free a BIO while it remains linked in the caller's BIO chain; later chain operations traverse it. ASan confirms UAF in CMS streaming on the vulnerable snapshot. The official fix detaches before free. Fixed validation reached an unsupported cipher error path without ASan report.
- **CVE-2024-4741:** `SSL_free_buffers` must not release the read buffer while record-layer state still refers to it. The official fix guards release with `RECORD_LAYER_data_present`. ASan confirms UAF after reading one byte from a TLS application record, freeing buffers, and reading the remainder on the vulnerable parent. On fixed, `SSL_free_buffers` returns 0 and the remainder is read cleanly.

## Tool comparison

`08_final_comparison/FINAL_TOOL_COMPARISON.csv` contains 24 rows (4 tools × 3 corrected CVEs × 2 sides) and uses the required categories. Only a pair-level category is repeated on both side rows. `NOT_EVALUABLE` means the analysis did not complete with usable coverage. Historical comparison data for CVE-2024 using the mislabeled pair is superseded and excluded.

The Clang API ownership model was validated on synthetic positive/negative controls and a real-header probe. It demonstrates Clang recognizes the annotations used, but the isolated CVE translation-unit checks still did not report these interprocedural/stateful mechanisms. This does not establish that the overlay is complete or that Clang's whole-program analysis is sound.

## Availability limits

CodeQL CLI was absent. An attempt to access the official CodeQL bundle was blocked by DNS/network resolution; no download or installation occurred. CodeQL results are NOT_EVALUABLE for all six source snapshots. Infer was absent and was not installed; all Infer results are NOT_EVALUABLE. No Valgrind run was possible. `TOOL_VERSION_FREEZE.csv` and `02_codeql/INSTALLATION_ATTEMPT.md` record these conditions.

## Independent evaluation and broad search

The existing historical fix register includes development candidates, including CVE-2026-45447, and is not an independent holdout. No independent positive labels or blind human-review labels were established in this run. The prior candidate inventories are preserved as separate populations; no precision, recall, accuracy, superiority or general typestate-analysis claim is made. A valid independent sample requires a predeclared complete function frame, blinded packet review and independently adjudicated labels; no such metric is reported here.

## Repository state

No OpenSSL source, analyzer or existing test was modified. New artifacts are confined to this integrated research directory. Baseline repository statuses and revisions are recorded under `00_baseline_and_freeze/`; some `git status` invocations timed out due the mounted worktree. Do not interpret a timeout as a clean result. No staging, commits, resets, checkouts or cleanup operations were performed.
