# Phase status checkpoint

| Phase | Status | Evidence / limitation |
|---|---|---|
| Baseline and tool freeze | Complete with status timeouts recorded | `00_baseline_and_freeze/`; no timeout interpreted as clean |
| Correct CVE source pair audit | Complete | `01_cve_revision_audit/`; CVE-2024 original labels were reversed/mislabeled |
| Python checker rerun | Complete | `CORRECTED_PYTHON_RESULTS.csv`; two distinguish, CVE-2024 does not |
| CodeQL | NOT_EVALUABLE | CLI absent; official download blocked by DNS; no installation |
| Clang ownership model | Complete, bounded | Synthetic controls + overlay; 16 affected TU baseline/model comparisons |
| Infer | NOT_EVALUABLE | Not installed; optional tool not installed |
| Focused ASan runtime tests | Complete for vulnerable and official fixed pairs | CVE-2023 fixed command reaches unsupported cipher error; see logs |
| Bounded broad fuzz | Complete, exploratory | CMS DER and X.509 harnesses, about 9 seconds each; not targeted coverage of every CVE |
| Coccinelle corrected CVE-2024 | Complete | Frozen rules × relevant source files; 30 invocations, no mechanism-level detection |
| Cppcheck corrected CVE-2024 | Complete on `ssl/ssl_lib.c` in both pair sides | Other source files not scanned in corrected pair; no target mechanism detected in analyzed file |
| Independent holdout labels / metrics | Not completed | Selected CVEs and historical register are biased; no independent blind adjudicator or established frame |
| Final evidence validation | Complete | All generated CSV parse and row counts validated; empty stdout/stderr files are retained where silence is expected |
