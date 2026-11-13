# Handoff: CVE-Guided Typestate Analysis for OpenSSL (CS-5187 Term Project), state on 2026-10-30

Read this first in a new session (human or Claude). Keep it current: it
replaces the conversation history.

## 1. The project in one paragraph

Public OpenSSL CVE fixes reveal lifecycle rules (who owns an object, when it is released, what must be reset).
We write such a rule as data (`src/tsck/specs/outparam_reset.json`), check it with a tree-sitter parser and path
analysis over a per-function control-flow graph, and look for other places that break the same rule.
Protocol B (output pointer must be reset after release, from CVE-2022-4450) works on real OpenSSL: it flags
`PEM_read_bio_ex` before the fix and not after, each of two real fixes removes exactly the expected sites and
adds none, and a scan of current master flags 10 sites of which none is a confirmed bug (2 latent, 6 harmless,
2 unclear). Protocol A (BIO chain, CVE-2023-0215) is not implemented. The Part 1 patch matcher is kept as a baseline.

## 2. Venue

| Item | Value |
|---|---|
| Venue / track | FSE (CS-5187 Term Project) |
| CFP | https://conf.researchr.org/home/fse-2026 (checked 2026-09-30) |
| Format | acmart acmsmall,screen,review,anonymous |
| Page limit | 12 pages main text (`paper.conf`: PAGE_LIMIT=12) |
| Deadline | Fri 13 Nov 2026, 23:59 IST (paper and public repo) |
| Final presentation | 12 Nov or 14-21 Nov: confirm with the TA |
| Submission | Overleaf link, PDF, public GitHub repo with reproducibility steps |

## 3. Where things are

* Paper: this directory (`sections/`, `macros.tex`, `figures/`, `tables/`). Not started: 52 `\todo`, 5 `\focus` boxes.
* Tool: `../src/tsck` (see its README). Reproduce everything with `bash ../src/tsck/run_scan.sh`.
* Raw data behind every number: `../src/tsck/results/` (unedited logs, JSON, `environment.txt`), labels in `../src/tsck/triage.csv`.
* Latest status report: `../reports/progress_meeting_2.md`.

## 4. Numbers in the paper and their sources

Reference environment: Linux, Python 3.13, tree-sitter 0.26.0, tree-sitter-c 0.24.2, git 2.43 (`results/environment.txt`).

| Claim | Value | Source file |
|---|---|---|
| PEM_read_bio_ex at `8e257b86e5` | 2 violations (`*header`, `*data`), lines 991-998 | `results/pem_read_bio_ex_pre.log` |
| PEM_read_bio_ex at `63bcf189be` | 2 sites, both conforming | `results/pem_read_bio_ex_post.log` |
| Whole tree before / after CVE-2022-4450 fix | 108 sites: 99 / 101 conforming, 7 / 5 violations, 2 suppressed | `results/cve4450_pre.log`, `cve4450_post.log` |
| Violations removed by that fix | exactly 2, none added | `results/diff_cve4450_pre_vs_cve4450_post.log` |
| KDF fix `d2217c88df` | 4 removed, none added | `results/diff_kdf_pre_vs_kdf_post.log` |
| master `949fe8b5f4` | 144 sites, 132 conforming, 10 violations, 2 suppressed | `results/master_2026_10_30.log` |
| Triage of 18 unique violations | 7 upstream-fixed, 2 latent, 6 benign, 2 unclear, 1 false positive | `src/tsck/check_triage.py` |

Keep synthetic-snippet results (unit tests, the old 16-snippet benchmark) in a separate table from real-source results.

## 5. Open decisions (ask the authors)

1. Who owns the engine, triage and paper (the Part 1 report lists two members)?
2. Does the professor accept a triaged candidate list, or does he expect a confirmed new bug?
3. Final presentation date.
4. Protocol A: build it, or spend the time on 6+ more historical pairs (RQ1) and the paper? The plan favours RQ1 and the paper.

## 6. Paper TODOs

`grep -n '\\todo\|\\num{' sections/*.tex`. Graded parts to write: motivating example (`introduction.tex`),
workflow (`approach.tex`), research questions (`evaluation.tex`), related work (`related.tex`), threats (`threats.tex`).
Related work: cite only papers that have been opened and checked.

## 7. Lessons / pitfalls

* The CVE-2024-4741 revision pair was wrong in Part 1 (it compared the fix with its own follow-up). Verify every pair with `git log` and `git show`.
* A checker that matches patch text gives ALERT/NO ALERT by construction and proves nothing about recurrences.
* Triage takes days. Label every flagged site and keep the evidence in `triage.csv`.
* Refinements chosen after reading output (deref suppression, NULL-guard pruning) must be disclosed as such.
