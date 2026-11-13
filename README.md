# CS-5187 Term Project: CVE-Guided Typestate Analysis for OpenSSL

Public OpenSSL CVE fixes teach us rules about object state, ownership and cleanup. This project writes such a
rule as data, checks it with a parser and path analysis, and looks for places that break the same convention.

**Status (13 Nov 2026, submission; paper: 11 pages in `paper/`).** Two rule families are implemented and integrated into the paper: Protocol B
(output-pointer reset, from CVE-2022-4450) works end to end on real OpenSSL; Protocol A (BIO-chain detach-before-release,
from CVE-2023-0215) is implemented and independently triaged. A third, exploratory rule, Protocol C (struct-field
release/reset), was built this week and is validated on 4 historical pairs but is not part of the paper's results.
One new-bug candidate (`rsa_ossl_finish`, a double-free shaped like the already-fixed `dh_finish`/`dsa_finish`) is
written up in `src/tsck/results/rsa_finish_candidate.md`; it is **not compiled, not run, and not reported upstream** --
no new vulnerability has been confirmed by an upstream maintainer. See [`paper/HANDOFF.md`](paper/HANDOFF.md) for the
full current state and open decisions, and [`reports/progress_meeting_2.md`](reports/progress_meeting_2.md) for the
30 Oct numbers (since superseded).

## Layout

| Path | Contents |
|---|---|
| `src/tsck/` | The method: `cfg.py` (shared parser/CFG); Protocol B (`outparam.py`, `specs/outparam_reset.json`, `run_scan.sh`); Protocol A (`protocol_a.py`, `specs/bio_chain_pop.json`, `run_protocol_a.sh`, `test_protocol_a_logic.py`); exploratory Protocol C (`protocol_c.py`, `specs/structfield_reset.json`); `compare.py`; `results/`; `triage.md`. See [`src/tsck/README.md`](src/tsck/README.md). |
| `typestate_check.py`, `tests/` | Part 1 patch matcher and its regression tests. Kept as a **baseline**, not as the method. |
| `research/`, `new research/` | Candidate register (8 CVEs), CVE notes, rule notes, evaluation notes, reproducibility ledger. `new research/` is a later, independent bounded tool-comparison (Clang/Coccinelle/Cppcheck + ASan) against all 3 CVEs; it finds no new candidate (`NEW_CANDIDATE_REGISTER.csv` is empty) and is not cited by the paper, but documents the same CVE-2024-4741 pair correction noted below. |
| `case-studies/` | Small file copies for case studies (CVE-2024-4741 hardening commit). |
| `reports/` | Progress reports. |
| `paper/` | The report, named submission (see `paper/HANDOFF.md`). |
| `CVE-*-evidence.txt`, `CVE-2023-0215-*.txt/md` | Per-CVE evidence, including the AddressSanitizer reproduction for CVE-2023-0215. |
| `openssl-cve-*-{vulnerable,fixed}/` | Part 1 source checkouts of the three selected CVEs. |

## CVEs and revision pairs (checked against OpenSSL git history)

| CVE | Vulnerable | Fixed | Role |
|---|---|---|---|
| CVE-2022-4450 (PEM) | `8e257b86e5` | `63bcf189be` | Protocol B: the motivating example |
| CVE-2023-0215 (BIO_new_NDEF) | `cbafa34b5a` | `8818064ce3` | Protocol A (paper RQ5): implemented; distinguishes vulnerable from fixed. Has an ASan reproduction |
| CVE-2024-4741 (SSL_free_buffers) | `ec559c2a6c` | `b3f0eb0a29` | Case study and stated limitation: the fix is a state guard, not a code shape |

The CVE-2024-4741 pair was wrong in Part 1 and was corrected on 2026-10-30; see `CVE-2024-4741-evidence.txt`.

## Reproduce

```sh
pip install tree-sitter tree-sitter-c
make check        # baseline tests + engine unit tests + triage cross-check (offline)
make scan         # rerun the OpenSSL scans (clones github.com/openssl/openssl, writes src/tsck/results/)
bash src/tsck/run_protocol_a.sh   # rerun Protocol A (motivating pair + whole-tree master scan)
```

Requirements: Linux or WSL, Python 3, Bash, git 2.25+.

## Limits

- Intraprocedural analysis, no alias or ownership tracking, release detected by name. Two protocols are implemented (A and B); Protocol A's whole-tree run flags 11 sites, all false positives.
- The rule is derived from a single CVE and validated on that pair, one further non-CVE fix, and a whole-tree scan.
- Protocol B triage labels were assigned by the authors; Protocol A's initial triage and the reachability/caller re-checks were produced with AI assistance, as disclosed in the paper. No runtime tests exist for the candidates.
- The Part 1 benchmark (16 hand-written snippets) is a unit test of the old rules, not an evaluation.
