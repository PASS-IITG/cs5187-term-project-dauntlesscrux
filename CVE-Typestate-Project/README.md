# CVE-Guided Typestate Analysis for Recurring Vulnerability Detection in OpenSSL

## 1. Project Overview

This project explores whether source-code patterns derived from known
OpenSSL vulnerabilities can identify similar unsafe states in vulnerable
source revisions.

The prototype uses Python to check three CVE-specific source patterns.
It is a targeted research prototype, not a general-purpose static analyzer.

## 2. CVEs Studied

| CVE | Component | Pattern checked |
|---|---|---|
| CVE-2023-0215 | ASN.1 BIO handling | BIO chain cleanup and missing BIO_pop |
| CVE-2022-4450 | PEM parsing | Failure cleanup and output-pointer resets |
| CVE-2024-4741 | SSL/TLS record layer | Read-buffer release and packet-state resets |

## 3. Project Files

- `typestate_check.py` — Python source-pattern checker.
- `tests/test_cve_2023_0215.sh` — CVE-2023-0215 regression test.
- `tests/test_cve_2022_4450.sh` — CVE-2022-4450 regression test.
- `tests/test_all_cves.sh` — Combined regression test.
- `CVE-2023-0215-asan-result.txt` — AddressSanitizer reproduction evidence.
- `CVE-2023-0215-fixed-result.txt` — Fixed-version test evidence.
- `CVE-2023-0215-notes.md` — Investigation notes.
- `CVE-2023-0215-recurrence-notes.md` — Related-pattern review.
- `CVE-2023-0215-evidence.txt` — CVE-2023-0215 evidence.
- `CVE-2022-4450-evidence.txt` — CVE-2022-4450 evidence.
- `CVE-2024-4741-evidence.txt` — CVE-2024-4741 evidence.

## 4. Requirements

- Linux or WSL
- Python 3
- Bash

## 5. Running the Tests

From the project root, run:

    cd /mnt/d/CVE-Typestate-Project
    bash tests/test_all_cves.sh

Individual regression tests:

    bash tests/test_cve_2023_0215.sh
    bash tests/test_cve_2022_4450.sh

For each selected pair, the expected result is ALERT for the vulnerable
source and NO ALERT for the fixed source.

## 6. Results

The combined regression test passed for all three selected vulnerable/fixed
source pairs:

- CVE-2023-0215: vulnerable ALERT; fixed NO ALERT.
- CVE-2022-4450: vulnerable ALERT; fixed NO ALERT.
- CVE-2024-4741: vulnerable ALERT; fixed NO ALERT.

For CVE-2023-0215, AddressSanitizer reported a heap-use-after-free in the
vulnerable checkout. The fixed checkout produced no AddressSanitizer
memory-safety report in the corresponding run, although the command
returned an error.

For CVE-2022-4450 and CVE-2024-4741, the current results establish
source-pattern regression detection, not runtime exploit reproduction.

## 7. Limitations and Future Work

- The checker uses targeted heuristics for three known CVEs.
- String matching and simple function extraction are not equivalent to
  full control-flow, data-flow, or typestate analysis.
- Three passing regression pairs do not establish general precision,
  recall, or false-positive and false-negative rates.
- Runtime validation is documented for CVE-2023-0215 only.
- Future work should evaluate more revisions and unrelated source files,
  and measure false positives and false negatives.

## 8. Conclusion

The prototype distinguishes three selected vulnerable OpenSSL revisions
from their fixed counterparts using CVE-guided source patterns. Broader
evaluation and stronger program analysis are needed before claiming
general vulnerability-detection effectiveness.
