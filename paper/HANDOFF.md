# Handoff: CVE-Guided Typestate Analysis for OpenSSL (CS-5187 Term Project), state on 2026-11-13

Read this first in a new session (human or Claude). Keep it current: it
replaces the conversation history. This replaces the 2026-10-30 version,
which predates Protocol A, the exploratory Protocol C sweep, the triage
corrections, and the named-submission decision below -- do not use the
old version's numbers or open-decisions list.

## 1. The project in one paragraph

Public OpenSSL CVE fixes reveal lifecycle rules (who owns an object, when
it is released, what must be reset). We write such a rule as data and
check it with a tree-sitter parser and path analysis over a per-function
control-flow graph, then look for other places that break the same rule.
**Protocol B** (output pointer must be reset after release, from
CVE-2022-4450, `specs/outparam_reset.json`) works end to end on real
OpenSSL. **Protocol A** (BIO-chain detach-before-release, CVE-2023-0215,
`specs/bio_chain_pop.json`, `protocol_a.py`) is implemented and
integrated into the paper as RQ5. **Protocol C** (struct-field
release/reset, `protocol_c.py`, `specs/structfield_reset.json`) is a
third, exploratory rule built this week; it is validated against 4 real
historical pairs but is *not* integrated into the paper and is explicitly
marked "exploratory, not as thoroughly unit-tested as Protocol A/B" in
its own spec file. The Part 1 patch matcher (`typestate_check.py`) is
kept as a baseline, not the method.

## 2. Venue

| Item | Value |
|---|---|
| Venue / track | FSE (CS-5187 Term Project) |
| CFP | https://conf.researchr.org/home/fse-2026 (checked 2026-09-30) |
| Format | acmart acmsmall,screen,review -- **named, not anonymous** (see §5) |
| Page limit | 12 pages main text (`paper.conf`: PAGE_LIMIT=12) |
| Deadline | Fri 13 Nov 2026, 23:59 IST (paper and public repo) |
| Final presentation | During end-semester week, 14-21 Nov 2026, 10-15 min + Q&A; Calendly link was "coming soon" as of the rubric text -- confirm it got booked |
| Submission | Overleaf project link + PDF + public GitHub repo + reproducibility instructions, via Teams |

## 3. Where things are

* Paper: `paper/` (`sections/`, `macros.tex`, `figures/`, `tables/`).
  `implementation.tex` and `pilot.tex` exist as files but are commented
  out of `main.tex`'s `\input` list -- they are not part of the compiled
  paper and their `\todo`s don't count.
* Tool: `src/tsck/` (`cfg.py`, `outparam.py`, `protocol_a.py`,
  `protocol_c.py`, `compare.py`). Reproduce with `bash src/tsck/run_scan.sh`
  (Protocol B) and `bash src/tsck/run_protocol_a.sh` (Protocol A).
* Raw data behind every number: `src/tsck/results/` (logs, JSON,
  `environment.txt`, plus the written analyses below), labels in
  `src/tsck/triage.csv`/`triage.md`.
* Key written analyses, all in `src/tsck/results/`:
  `protocol_a_triage.md` (11 whole-tree Protocol A sites),
  `reachability_rq1_candidates.md` (the 2 potential-recurrence sites,
  corrected reachability argument),
  `unclear_sites_recheck.md` (the 2 formerly-unclear sites, now
  reclassified as convention deviation),
  `historical_recurrence_search.md` (10 independently-authored OpenSSL
  fixes of the same shape, 2023-2026),
  `rsa_finish_candidate.md` (the one open bug candidate -- see §5).

## 4. Numbers in the paper and their sources (current, not the 30 Oct set)

| Claim | Value | Source file |
|---|---|---|
| Protocol B whole-tree (master) | 10 sites: 7 upstream-confirmed... wait, see below | `src/tsck/triage.csv`, `triage.md` |
| Protocol B master triage breakdown | 2 potential recurrence, 8 convention deviation, 0 unclear (reclassified from 6+2 this week), plus 7 confirmed-by-upstream-fix and 1 false positive and 2 suppressed across all snapshots combined -- read `triage.md`'s own summary table, don't recompute by hand | `src/tsck/triage.md` |
| Protocol A whole-tree (master) | 11 flagged sites, 0 confirmed, all false positives (no ownership tracking) | `src/tsck/results/protocol_a_triage.md` |
| 2 potential-recurrence sites | both need an unsynchronized-race precondition; `CRYPTO_UP_REF`/`X509_up_ref`/`EVP_PKEY_up_ref` dead-code correction documented | `src/tsck/results/reachability_rq1_candidates.md` |
| 2 formerly-unclear sites | reclassified to convention deviation; the one real caller (`apps/cmp.c`) discards the dangling output on every failure path | `src/tsck/results/unclear_sites_recheck.md` |
| Historical recurrence | 10 independent OpenSSL fixes of the same shape, 2023-2026, across 9 files | `src/tsck/results/historical_recurrence_search.md` |
| RSA candidate | `rsa_ossl_finish` has the same unreset-free shape as the already-fixed `dh_finish`/`dsa_finish`; concrete trigger via `RSA_set_method`/`RSA_free`, no race needed; NOT compiled, NOT run, NOT reported upstream | `src/tsck/results/rsa_finish_candidate.md` |

Always read the actual numbers from the cited file before writing them into the paper again -- do not propagate this table's prose without checking, especially the Protocol B breakdown line, which is summarized above rather than quoted exactly.

## 5. Open decisions -- status as of 2026-11-13

1. ~~Who owns the engine, triage and paper~~ -- not formally resolved, but moot given both authors are now named on the paper and jointly accountable.
2. **Anonymous vs named: RESOLVED. Named**, confirmed directly with the professor. `main.tex` has no `anonymous` class option, both authors and the affiliation are present, and `data.tex` contains a task-level Author Contributions section. Both authors must confirm that the allocation accurately describes their work before submission.
3. **Candidate list vs confirmed bug: RESOLVED, and this is the hard one.** The professor confirmed he wants a **confirmed upstream bug** for full marks on the 50% implementation component, not a triaged candidate list. As of this writing: zero bugs are confirmed, zero are reported to OpenSSL, let alone accepted. The `rsa_ossl_finish` candidate (§4, `rsa_finish_candidate.md`) is the only concrete lead, and it is unconfirmed: no compiled reproducer, no observed crash, no report filed. Getting an upstream *acceptance* by the deadline is not realistically achievable (maintainer review isn't on an hours-long SLA); the only thing achievable in the remaining time is building the reproducer and filing a report, which gives something concrete to show even if unresolved by submission. This is a real, acknowledged shortfall against the grading bar, not something to paper over in the writeup.
4. Final presentation date -- confirm the Calendly booking actually happened; the rubric text as of 13 Nov still said the link was "coming soon."

## 6. Paper TODOs and citation status (updated 2026-11-13)

The active paper build no longer contains `\todo{...}` or unmeasured
`\num{...}` placeholders. The optional `implementation.tex` and `pilot.tex`
files are not included by `main.tex`; their former TODO markers were replaced
with comments explaining their exclusion. The foundational typestate citation
is now Strom and Yemini (1986), DOI 10.1109/TSE.1986.6312929. NVD records are
cited for CVE-2022-4450, CVE-2023-0215, and CVE-2024-4741. The related-work
bibliography includes VulPA, recurring-vulnerability detection, similar-but-
patched code, vulnerability-introducing commit identification, and Mystique.

The ACM CCS identifiers in `main.tex` have been changed to the taxonomy paths
for Automated static analysis and Software and application security. The
BibTeX recipe no longer ignores a failed bibliography run. A clean build has
been completed in the current environment and the rendered PDF was inspected.

Still requires author action before submission:
1. Both authors must independently review the AI-assisted source triage,
   reachability arguments, and historical commit examples. The disclosure
   states explicitly that independent human re-verification is not yet
   established by the available project records.
2. Both authors must confirm that the Author Contributions and AI-use
   disclosures are factually accurate.
3. The configured page limit is 12; the current build is 15 pages, with
   references beginning on page 15. Reduce the main text with author approval.
4. Inspect the final PDF after page reduction, including fonts, grayscale
   legibility, and all remaining layout warnings.
5. Fill in an author email only if the course format requires it; there is no
   longer an active placeholder requiring an invented email address.

## 7. Lessons / pitfalls

* The CVE-2024-4741 revision pair was wrong in Part 1 (it compared the
  fix with its own follow-up). Verify every pair with `git log` and
  `git show`.
* A checker that matches patch text gives ALERT/NO ALERT by construction
  and proves nothing about recurrences.
* Triage takes days. Label every flagged site and keep the evidence in
  `triage.csv`.
* Refinements chosen after reading output (deref suppression, NULL-guard
  pruning, Protocol C's whole-object-teardown and pointer-identifier
  suppressions) must be disclosed as such, not presented as if they
  pre-dated the data that motivated them.
* A sync between collaborators (tar extraction + `git add`, or switching
  between Windows cmd.exe and WSL git on the same `/mnt/d` drive) silently
  dropped 9 files from `paper/` at least once this project, undetected
  until someone diffed content directly against the remote rather than
  trusting `git status`/`git commit` output. If anything in `paper/`
  looks wrong again, diff file-by-file against `origin/main` before
  assuming the working tree is right.
* Getting a genuinely new, confirmed vulnerability accepted by an
  upstream project within a fixed deadline is largely out of your
  control once a report is filed -- budget for the realistic version of
  this (a well-evidenced, filed-but-unresolved candidate), not the
  optimistic one.
