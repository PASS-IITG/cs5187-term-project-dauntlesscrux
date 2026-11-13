# Reproduction guide

## Preconditions and snapshots

Use Python 3, Clang 18, Coccinelle 1.1.1 and Cppcheck 2.13.0. Exact source revisions and archive locations are listed in `01_cve_revision_audit/CVE_VULNERABLE_FIXED_MANIFEST.csv`. The source snapshots used for runtime work were extracted under `/tmp/openssl-integrated-validation/`; regenerate them from the recorded Git revisions if that temporary directory is unavailable. Do not use the original mislabeled CVE-2024 pair.

## Runtime reproductions

Each OpenSSL snapshot was configured and built in its temporary extracted directory with `CC=clang-18 ./Configure linux-x86_64 no-shared no-asm enable-asan no-ubsan`, followed by `make -j4 build_libs` (and `build_apps` where needed). The CVE-2022 run compiles `05_fuzzing/harnesses/cve2022_pem_empty_payload.c` against the corresponding static libraries and runs with `ASAN_OPTIONS=halt_on_error=1:detect_leaks=0`. CVE-2024 similarly uses `cve2024_partial_appdata.c` with the test certificate and key named in the logs. CVE-2023 uses the CMS streaming command recorded verbatim in its raw log. See `05_fuzzing/logs/` for complete commands, build output and run status.

## Static analysis

`03_clang_api_model/CLANG_MODEL_COMPARISON.csv` records the per-TU source analyzer commands and logs for default and ownership-annotated configurations. `03_clang_api_model/openssl_api_ownership_model.h` is an analysis-only overlay; no OpenSSL source/header was changed. Synthetic annotation controls and exact command are in `03_clang_api_model/synthetic/`.

Frozen Coccinelle rules are in `research/11_cve_tool_comparison/frozen/coccinelle_rules/`; corrected CVE-2024 results are recorded in `08_final_comparison/CVE2024_COCCI_RUNS.csv`. Previous CVE-2022/2023 corrected-pair runs remain in `research/11_cve_tool_comparison/`. Cppcheck prior corrected-pair runs for CVE-2022/2023 are likewise in that directory. Corrected CVE-2024 `ssl/ssl_lib.c` runs for both sides are preserved in `08_final_comparison/cppcheck_cve2024_*_ssl_lib.log`; other related files were not analyzed in this pair.

## Bounded fuzz

The two short LibFuzzer commands are preserved at the top of `05_fuzzing/logs/fuzz_cms_run.log` and `fuzz_x509_run.log`; they use the OpenSSL harnesses from the fixed snapshot, the adapter in `05_fuzzing/harnesses/libfuzzer_adapter.c`, existing test-derived seed files under `05_fuzzing/corpora/`, and 8-second requested budgets. The process logs show actual elapsed time and execution count.

## Checker

The corrected revision run and outputs are in `01_cve_revision_audit/CORRECTED_PYTHON_RESULTS.csv`. The legacy suite log is preserved but is not a valid CVE-2024 official-pair test.
