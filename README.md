# CS-5187 Term Project: CVE-Guided Typestate Analysis for OpenSSL

Public OpenSSL CVE fixes teach us rules about object state, ownership and cleanup. This project writes such a
rule as data, checks it with a parser and path analysis, and looks for places that break the same convention.

**Status (30 Oct 2026, Progress Meeting 2).** One rule family (Protocol B, output-pointer reset) works end to end on real
OpenSSL. Protocol A (BIO chain, CVE-2023-0215) is not implemented yet. No new vulnerability has been confirmed.
See [`reports/progress_meeting_2.md`](reports/progress_meeting_2.md) for the numbers.

## Layout

| Path | Contents |
|---|---|
| `src/tsck/` | The method: `cfg.py`, `outparam.py`, `specs/outparam_reset.json`, `run_scan.sh`, `results/`, `triage.md`. See [`src/tsck/README.md`](src/tsck/README.md). |
| `typestate_check.py`, `tests/` | Part 1 patch matcher and its regression tests. Kept as a **baseline**, not as the method. |
| `research/` | Candidate register (8 CVEs), CVE notes, rule notes, evaluation notes, reproducibility ledger. |
| `case-studies/` | Small file copies for case studies (CVE-2024-4741 hardening commit). |
| `reports/` | Progress reports. |
| `paper/` | The report in the course LaTeX template. Still to be written. |
| `CVE-*-evidence.txt`, `CVE-2023-0215-*.txt/md` | Per-CVE evidence, including the AddressSanitizer reproduction for CVE-2023-0215. |
| `openssl-cve-*-{vulnerable,fixed}/` | Part 1 source checkouts of the three selected CVEs. |

## CVEs and revision pairs (checked against OpenSSL git history)

| CVE | Vulnerable | Fixed | Role |
|---|---|---|---|
| CVE-2022-4450 (PEM) | `8e257b86e5` | `63bcf189be` | Protocol B: the motivating example |
| CVE-2023-0215 (BIO_new_NDEF) | `cbafa34b5a` | `8818064ce3` | Protocol A: planned. Has an ASan reproduction |
| CVE-2024-4741 (SSL_free_buffers) | `ec559c2a6c` | `b3f0eb0a29` | Case study and stated limitation: the fix is a state guard, not a code shape |

The CVE-2024-4741 pair was wrong in Part 1 and was corrected on 2026-10-30; see `CVE-2024-4741-evidence.txt`.

## Reproduce

```sh
pip install tree-sitter tree-sitter-c
make check        # baseline tests + engine unit tests + triage cross-check (offline)
make scan         # rerun the OpenSSL scans (clones github.com/openssl/openssl, writes src/tsck/results/)
```

Requirements: Linux or WSL, Python 3, Bash, git 2.25+.

## Limits

- Intraprocedural analysis, release detected by name, two protocols planned (one done).
- The rule is derived from a single CVE and validated on that pair, one further non-CVE fix, and a whole-tree scan.
- Triage labels were assigned by the authors; no runtime tests exist for the candidates.
- The Part 1 benchmark (16 hand-written snippets) is a unit test of the old rules, not an evaluation.
