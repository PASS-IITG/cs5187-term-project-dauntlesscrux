<<<<<<< HEAD
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
=======
# CS-5187 — Term Project

This repository is your starting point for the CS-5187 term project. It has two
parts:

```
paper/    the report, in FSE (ACM acmsmall) LaTeX format  ← write here
src/      your code (tool, scripts, experiments, data)     ← code here
```

Your project can be in **any** area of the course: static analysis, dynamic
analysis / testing, or software engineering more broadly (empirical studies,
program repair, refactoring, build systems, …). The template does not assume a
particular topic.

## What to do

1. **Put your code in `src/`.** Everything that produces a result or a number in
   your paper goes there, with a note on how to build and run it. See
   [`src/README.md`](src/README.md).
2. **Write your report in `paper/`.** Edit the section files in
   `paper/sections/`. Build the PDF with:
   ```sh
   cd paper
   make          # builds paper/main.pdf
   make check    # checks for leftover TODOs, banned words, undefined refs, page limit
   ```
3. **Address the five graded parts.** In `paper/`, each is flagged with a red
   `FOCUS` box that says what it must contain. Write the section, then **delete
   that `\focus{...}` line** (keep the section). The graded parts are:

   | Part | Where |
   |------|-------|
   | Motivating example | `sections/introduction.tex` |
   | Workflow | `sections/approach.tex` |
   | Research questions | `sections/evaluation.tex` |
   | Related work | `sections/related.tex` |
   | Threats to validity | `sections/threats.tex` |

4. **Finish clean.** A submittable report has **zero** red `\focus` and **zero**
   `\todo`, and `make check` passes. Use
   [`paper/CHECKLIST.md`](paper/CHECKLIST.md) before you submit.

## Rules that matter (see `paper/STYLE.md`)

- Every number in the paper comes from a real run of your code in `src/` — never
  invented or rounded from memory.
- The motivating example must be **real**, with exact numbers.
- Cite only papers you have verified; fabricated citations are not accepted.
- Write in plain, simple English.# CS-5187 Term Project: CVE-Guided Typestate Analysis for Recurring Vulnerability Detection in OpenSSL

## 1. Project Overview

This project explores whether source-code patterns derived from known OpenSSL vulnerabilities can identify similar unsafe states in vulnerable source revisions.

The prototype uses Python to check three CVE-specific source patterns. It is a targeted research prototype, not a general-purpose static analyzer.

## 2. CVEs Studied

| CVE | Component | Pattern Checked |
|---|---|---|
| CVE-2023-0215 | ASN.1 BIO handling | BIO chain cleanup and missing `BIO_pop` |
| CVE-2022-4450 | PEM parsing | Failure cleanup and output-pointer resets |
| CVE-2024-4741 | SSL/TLS record layer | Read-buffer release and packet-state resets |

## 3. Repository Structure

The course repository includes the following areas:

- `src/` — project code, scripts, experiments, and data.
- `paper/` — research report in the provided ACM LaTeX format.
- `typestate_check.py` — Python source-pattern checker.
- `tests/` — regression tests for selected CVEs.
- `CVE-2023-0215-asan-result.txt` — AddressSanitizer reproduction evidence.
- `CVE-2023-0215-fixed-result.txt` — fixed-version test evidence.
- `CVE-2023-0215-notes.md` — investigation notes.
- `CVE-2023-0215-recurrence-notes.md` — related-pattern review.
- `CVE-2023-0215-evidence.txt` — CVE-2023-0215 evidence.
- `CVE-2022-4450-evidence.txt` — CVE-2022-4450 evidence.
- `CVE-2024-4741-evidence.txt` — CVE-2024-4741 evidence.

See `src/README.md` for the code's build and execution instructions, if available.

## 4. Requirements

- Linux or WSL
- Python 3
- Bash

## 5. Running the Tests

From the project root in WSL, run:

```bash
bash tests/test_all_cves.sh
```

Individual regression tests:

```bash
bash tests/test_cve_2023_0215.sh
bash tests/test_cve_2022_4450.sh
```

For each selected vulnerable/fixed source pair, the expected result is `ALERT` for the vulnerable source and `NO ALERT` for the fixed source.

## 6. Results

The recorded combined regression test passed for all three selected vulnerable/fixed source pairs:

- CVE-2023-0215: vulnerable `ALERT`; fixed `NO ALERT`.
- CVE-2022-4450: vulnerable `ALERT`; fixed `NO ALERT`.
- CVE-2024-4741: vulnerable `ALERT`; fixed `NO ALERT`.

For CVE-2023-0215, AddressSanitizer reported a heap-use-after-free in the vulnerable checkout. The fixed checkout produced no AddressSanitizer memory-safety report in the corresponding run, although the command returned an error.

For CVE-2022-4450 and CVE-2024-4741, the current results establish source-pattern regression detection, not runtime exploit reproduction.

## 7. Limitations and Future Work

- The checker uses targeted heuristics for three known CVEs.
- String matching and simple function extraction are not equivalent to full control-flow, data-flow, or typestate analysis.
- Three passing regression pairs do not establish general precision, recall, or false-positive and false-negative rates.
- Runtime validation is documented for CVE-2023-0215 only.
- Future work should evaluate more revisions and unrelated source files, and measure false positives and false negatives.

## 8. Course Report and Submission Requirements

The course repository provides a LaTeX report template in `paper/`. Complete the required sections, including:

- Motivating example — `paper/sections/introduction.tex`
- Workflow — `paper/sections/approach.tex`
- Research questions — `paper/sections/evaluation.tex`
- Related work — `paper/sections/related.tex`
- Threats to validity — `paper/sections/threats.tex`

Remove the template's `\focus{...}` markers and unresolved `\todo` items as required. Verify citations and ensure that every reported number comes from an actual experiment.

Build and check the report from WSL:

```bash
cd paper
make
make check
```

Before submission, consult `paper/CHECKLIST.md`. The course instructions require committing the `src/` code and `paper/` sources; the built PDF is gitignored.

## 9. Conclusion

The prototype distinguishes three selected vulnerable OpenSSL revisions from their fixed counterparts using CVE-guided source patterns. Broader evaluation and stronger program analysis are needed before claiming general vulnerability-detection effectiveness.


## Submitting

Commit both your `src/` code and your `paper/` sources (not the built PDF — it is
gitignored). Make sure the repository builds from a clean checkout:

```sh
cd paper && make
```
>>>>>>> 60c206a183404b0d403c65d703fe97bf3aabbc0f
