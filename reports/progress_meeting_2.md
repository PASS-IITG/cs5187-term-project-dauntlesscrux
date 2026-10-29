# CS-5187 term project: report for Progress Meeting 2 (26-30 Oct 2026)

*Status as of Fri 30 Oct 2026. Previous status: "Project Status and Defence Guide", 20 Oct. Every number below comes from a committed log in `src/tsck/results/` or from `python3 src/tsck/check_triage.py`.*

## 1. Bottom line

- The method now works on real OpenSSL, end to end, from one command (`bash src/tsck/run_scan.sh`, about 20 s after the first clone). One rule family (Protocol B, output-pointer reset) is done. Protocol A (BIO chain) is not started.
- On two real fix commits the rule flags the pre-fix code and stays quiet on the fix, and each fix removes exactly the expected sites and adds none: CVE-2022-4450 (2 sites) and a non-CVE KDF fix by a different author (4 sites).
- The whole-tree scan of current OpenSSL master flags 10 sites. **None is a confirmed bug.** Two are real latent defects with the CVE-2022-4450 shape whose failure branch is not reachable in normal builds; six are harmless convention deviations; two are unclear.
- The paper has not been started: 52 `\todo` and 5 `\focus` markers remain. That is now the biggest risk, not the engine.

## 2. The six problems from the 20 Oct guide

| # | Problem | State now |
|---|---|---|
| 1 | CVE-2024-4741 pair wrong | **Fixed.** Vulnerable `ec559c2a6c`, fix `b3f0eb0a29`, hardening `2d05959073`. Worktrees, evidence file, ledger, CVE notes and the regression test were corrected and the trees re-verified blob-by-blob against git. 4741 is now a stated limitation. |
| 2 | Checker only matches patches | **Addressed for one rule family.** `src/tsck` parses C, builds a CFG and applies a rule stored as data. Old checker kept as baseline. |
| 3 | Benchmark is circular | **Partly.** Real-source results are kept separate from the engine's 19 synthetic unit tests. The 16-snippet benchmark is no longer cited as evidence. Real historical pairs: 2 of the 8 targeted. |
| 4 | Recurrence audit not reproducible | **Rebuilt from tool output.** 20 flagged sites with file, function, parameter, snapshot SHA and evidence (`triage.csv`, `triage.md`). The old 10-row table is superseded. |
| 5 | Repo not submission-ready | **Mostly fixed.** README merge conflict resolved and rewritten, `/mnt/d` path gone, backup files and `__pycache__` removed, `.gitignore`, `make check` (code), `src/` documented, stale "pending" evidence updated. Paper still a template. |
| 6 | Date conflict (12 Nov vs 14-21 Nov) | **Open.** Ask the TA. Paper and repo deadline is Fri 13 Nov, 23:59 IST either way. |

## 3. Results on real OpenSSL

All scans cover `crypto/`, `ssl/`, `providers/` at pinned commits. A *release site* is a call that frees `*P` for a pointer-to-pointer parameter `P`.

### 3.1 The motivating function

`PEM_read_bio_ex` in `crypto/pem/pem_lib.c`:

| Commit | Result |
|---|---|
| `8e257b86e5` (pre-fix) | 2 violations, `*header` and `*data`, witness path lines 991-998 |
| `63bcf189be` (CVE-2022-4450 fix) | 2 release sites, both conforming |

### 3.2 Whole-tree scans

| Snapshot | C files | Release sites | Conforming | Violation | Suppressed |
|---|---|---|---|---|---|
| CVE-2022-4450 pre-fix `8e257b86e5` | 1001 | 108 | 99 | 7 | 2 |
| CVE-2022-4450 fix `63bcf189be` | 1001 | 108 | 101 | 5 | 2 |
| KDF fix parent `29a27cb2c5` | 1005 | 107 | 93 | 12 | 2 |
| KDF fix `d2217c88df` (2021-11-30, not a CVE) | 1005 | 107 | 97 | 8 | 2 |
| OpenSSL 3.0.0 `89cd17a031` | 999 | 104 | 92 | 10 | 2 |
| master `949fe8b5f4` (30 Oct 2026) | 1155 | 144 | 132 | 10 | 2 |

These numbers match the 20 Oct guide exactly (99 / 9 flagged before, 101 / 7 after, the same seven sites). The guide's `tsck/` folder was not in the repository, so the engine was rebuilt from the guide's description; agreement of the two builds is a consistency check, not independent proof.

**What each fix changed** (`results/diff_*.log`):

| Fix | Violations removed | Violations added |
|---|---|---|
| CVE-2022-4450, `63bcf189be` | `PEM_read_bio_ex` `*header`, `*data` | none |
| KDF, `d2217c88df` | `pbkdf1`, `pbkdf2`, `pkcs12kdf`, `scrypt` `*_set_membuf` `*buffer` | none |

The KDF fix is a different author, a different directory, and a year earlier than the CVE. The rule was not changed after seeing it. It is the first evidence that the rule is more than a rewrite of one patch.

**Convention conformance:** 101 of 108 sites (93.5%) in the CVE-2022-4450 fix tree, 132 of 144 (91.7%) on master. This depends on the name-based release heuristic.

### 3.3 Time-travel hit (weak, one site)

The tree at `d2217c88df` still flags `pvk_set_membuf` in `pvkkdf.c`. Upstream fixed it in `a632bfaa4e`, a direct child of `d2217c88df` committed the next day, with the same change. So the rule finds a sibling that the original fix missed. It is one site, and the rule came from a different bug, so treat it as an encouraging anecdote, not a rate.

### 3.4 Manual triage of every flagged site (18 unique violations, 2 correctly suppressed)

| Label | Sites | Meaning |
|---|---|---|
| Confirmed by an upstream fix | 7 | PEM x2, four KDFs, `pvk_set_membuf`. OpenSSL later changed exactly these sites. |
| Potential recurrence (latent) | 2 | `X509_PUBKEY_set`, `ossl_ml_kem_i2d_pubkey` |
| Convention deviation, no impact | 6 | `LP_find_file_end` x2, `ssl_cipher_get_evp` x2, `extract_keyshares` x2 |
| Unclear | 2 | `OSSL_CMP_get1_rootCaKeyUpdate` x2 |
| False positive | 1 | `load_common` (releases only an ENGINE structural reference) |
| Suppressed by the tool, correct | 2 | `evp_pkey_copy_downgraded`, `EVP_PKEY_generate` |

15 of 18 flagged sites (83%) really leave the pointer dangling on some path; 7 of 18 correspond to something upstream fixed; 0 are confirmed new bugs. **On master alone: 10 flagged = 2 latent, 6 benign, 2 unclear, 0 confirmed.**

### 3.5 The two latent candidates (read this before the meeting)

- **`X509_PUBKEY_set`** (`crypto/x509/x_pubkey.c`, present from 3.0.0 to master). Frees `*x`, then if `EVP_PKEY_up_ref` fails it jumps to the error label and returns 0 with `*x` dangling. Callers pass embedded fields, for example `X509_set_pubkey` passes `&x->cert_info.key`, so a later `X509_free` would free the stale pointer again. Reaching it needs `EVP_PKEY_up_ref` to fail, which does not happen in normal builds.
- **`ossl_ml_kem_i2d_pubkey`** (`providers/implementations/encode_decode/ml_kem_codecs.c`, master only). On encode failure it frees `*out` and returns 0; its caller `key_to_pubkey` then also calls `OPENSSL_free(der)`. That would be a double free, but the failure branch is unreachable by code reading: the preconditions are checked and the length is derived just before the call.

Say "potential recurrence needing reachability review", not "bug". No runtime test exists for either.

## 4. What we may and may not claim

| Say | Do not say |
|---|---|
| The rule is an invariant in a spec file; the tool found CVE-2022-4450 and a non-CVE KDF fix without any function names in the rule. | The tool works for all of OpenSSL. |
| Each of two real fixes removes exactly the expected sites and adds none. | 100% precision and recall. |
| 7 of 18 flagged sites match upstream fixes; the rest are latent defects, harmless deviations, unclear, or one false positive. | We found new vulnerabilities. |
| Two latent sites with the CVE-2022-4450 shape exist on master and need reachability review. | We found a bug in `X509_PUBKEY_set`. |
| CVE-2024-4741 is a case study: its fix is a state guard that a code-shape rule cannot express. | The checker detects CVE-2024-4741. |

## 5. Honest weaknesses

1. **Tuning on seen data.** Deref-after-release suppression (from the guide) and NULL-guard pruning (added after the master scan showed one infeasible-path false positive) were chosen after looking at outputs. The master numbers are therefore not a blind test of those two refinements. The rule itself was not changed after the KDF result.
2. **Small and non-independent sample.** The 20 sites over 6 snapshots are largely the same long-lived functions, so the effective sample is closer to 20 than to 6 x 10.
3. **Our own triage.** The people who built the tool assigned the labels. A second reader should label a sample.
4. **No runtime evidence** for any candidate. One CVE (2023-0215) has an ASan reproduction; Protocol B has none.
5. **Parser coverage.** 39% of files have a tree-sitter parse error somewhere (macros). Only 7 to 8 release sites per snapshot sit in a function with an error, and no flagged violation does, but the sites we cannot parse are invisible.
6. **One protocol.** Protocol A and the other 6+ historical pairs are still to do.
7. **Paper not started.** 52 `\todo`, 5 `\focus`. The course `make check` cannot be run here because `acmart.cls` is missing in this environment, so only its static counts were checked.
8. Not re-verified: advisory dates and severities for CVE-2023-0215 and CVE-2022-4450, and metadata of the 5 unselected CVEs. CVE-2024-4741's advisory (28 May 2024, Low) was confirmed through secondary sources, not the openssl.org page, which could not be fetched.

## 6. One-page evaluation plan

| RQ | Question | Done | To do |
|---|---|---|---|
| RQ1 | Does the rule flag pre-fix code and stay quiet on the fix, on real historical pairs? | 2 pairs (CVE-2022-4450, KDF `d2217c88df`) | Mine at least 6 more with `git log --grep` (dangling, double free, use after free, reset pointer). Target 8+. Report each as true positive, false positive, or unclear. |
| RQ2 | Does a rule written from one bug flag a site that was fixed later? | One weak hit (`pvk_set_membuf`) | Systematic time-travel: older tree, rule fixed, list sites later fixed by upstream; count hits and misses. |
| RQ3 | On the whole tree, how many sites conform, deviate, and what is precision after triage? | 6 snapshots, 20 sites labelled | Second labeller on a sample; resolve the 2 unclear; reachability review for the 2 latent sites. |
| Baseline | What does a general tool add? | not started | If time allows, `scan-build` or `cppcheck` on the same pre-fix snapshots. |

## 7. Plan to submission

| When | Work | Output |
|---|---|---|
| 31 Oct - 6 Nov (Meeting 3: 2-6 Nov) | Protocol A with alias tracking. 6+ more historical pairs. Systematic time-travel. Resolve unclear sites. Start the paper: motivating example and workflow first. | Labelled results table; paper skeleton with real numbers |
| 7-10 Nov | Freeze code. Rerun from a clean checkout. Every paper number traceable to a committed log. | Frozen tag, `results/` regenerated |
| 11-13 Nov | Write remaining sections, `make check`, README steps, submit by Fri 13 Nov 23:59 IST. | PDF, public repo |
| To confirm | Final presentation date (12 Nov or 14-21 Nov). Who owns engine, triage, paper (is Udayraj on the team?). Does the professor accept a triaged candidate list instead of a confirmed new bug? | Ask at Meeting 2 |

If time runs short, drop Protocol A before dropping the extra historical pairs or the paper: a second protocol adds less than a larger RQ1 table and a finished paper.

## 8. Likely questions, with the new facts

- **"Did you find a new bug?"** No. Two latent sites with the CVE-2022-4450 shape exist on master (`X509_PUBKEY_set`, `ossl_ml_kem_i2d_pubkey`); neither failure branch is reachable in normal builds. We would need a reachability argument or a fault-injection test before calling either one a bug.
- **"Is this just matching the patch?"** The rule has no function names. A second, unrelated fix (`d2217c88df`) is detected without changing the rule, and a sibling that fix missed is flagged.
- **"How do you know it is correct?"** 19 unit tests on synthetic C, and the unit tests were mutation-checked (five deliberate engine breakages are each caught). Real-source results are kept separate.
- **"What about false positives?"** 1 of 18 flagged sites is a false positive (`load_common`, a reference-count release). 2 more were removed by suppression rules.

## 9. Reproduce

```sh
pip install tree-sitter tree-sitter-c
make check       # offline: baseline tests, engine unit tests, triage cross-check
make scan        # reruns all OpenSSL scans; rewrites src/tsck/results/
```
