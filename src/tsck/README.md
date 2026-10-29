# tsck: invariant-based typestate checker for OpenSSL (Protocol B)

`tsck` checks one lifecycle rule that was learned from a CVE fix, using a parser and
path analysis instead of string search.

**Rule (Protocol B, from CVE-2022-4450, fix `63bcf189be`).** If a function releases the object that an
output parameter points to (`*P`), it must reset `*P` on every path to function exit.
The object moves through three states: `Valid`, then `Released`, then `Reset`. A path that reaches
the function exit while the object is still `Released` is a violation.

The rule lives in data (`specs/outparam_reset.json`), not in code. It contains no OpenSSL function names;
the only name-based part is the regular expression `(?i)free` that recognises release calls.

## Files

| File | Role |
|---|---|
| `cfg.py` | tree-sitter parse of C, per-function control-flow graph (`if`, loops, `switch`, labels, `goto`, `#if`) |
| `outparam.py` | reads the spec, finds release sites, searches for a path to exit that avoids every reset, prints a witness |
| `specs/outparam_reset.json` | the rule as data |
| `compare.py` | diff of two runs: which violations did a fix remove or add |
| `run_scan.sh` | reproduces every number: clones OpenSSL, checks out pinned SHAs, runs the scans, writes `results/` |
| `triage.csv`, `triage.md`, `check_triage.py` | manual labels for every flagged site, and a script that fails if a flagged site has no label |
| `tests/test_engine.py` | 19 unit tests on synthetic C (gotos, branches, loops, switch, guards). Not evidence about OpenSSL |
| `results/` | unedited logs, JSON, and `environment.txt` (versions, dates, `git rev-parse` of every snapshot) |

## Install and run

```sh
pip install tree-sitter tree-sitter-c        # add --break-system-packages if pip refuses
bash run_scan.sh                             # about 20-35 s after the first clone; needs github.com
python3 check_triage.py                      # numbers cited in the report, cross-checked against the logs
python3 -m unittest discover -s tests        # engine unit tests
```

Tested with Python 3.13, tree-sitter 0.26.0, tree-sitter-c 0.24.2, git 2.43 on Linux (WSL works).
`run_scan.sh` uses full commit SHAs, never branch names, so reruns are identical.

One function or a folder:

```sh
python3 outparam.py --func PEM_read_bio_ex ossl/snap_cve4450_pre/crypto/pem/pem_lib.c
python3 outparam.py --json out.json ossl/snap_master_2026_10_30/crypto ossl/snap_master_2026_10_30/ssl ossl/snap_master_2026_10_30/providers
```

Exit status is 0 when nothing is flagged, 1 when there is a violation.

## What a release site is classified as

| Status | Meaning |
|---|---|
| `conforming` | every path from the release to exit assigns `*P` (or hands `P` to a call that may reset it) |
| `violation` | some path reaches exit with `*P` still `Released` |
| `suppressed` | the path rule fires, but `*P` is read again after the release before any reset, which means a partial release or reuse. Reported separately, never hidden |

Two refinements were added after looking at real output, and both should be disclosed as such:

1. **Deref-after-release suppression** (specified in the Part 2 plan). Removes `evp_pkey_copy_downgraded`
   and `EVP_PKEY_generate`, which free key internals and reuse `*dest` or `*ppkey`.
2. **NULL-guard pruning.** After a release, `*P` has been dereferenced, so `P` is non-NULL. A branch that
   only runs when a guard says `P == NULL` is dead. Removes the `cmp_asn.c` site on master, whose reset sits
   under `if (keySpec != NULL)`. Unit-tested.

## Known limits (state them in the paper)

- Intraprocedural only: no aliasing (`char *q = *P; free(q)` is missed), no interprocedural reasoning.
- Release detection is name-based. It cannot see reference counts, so `load_common` (releases only the
  structural reference of an `ENGINE`) is a false positive.
- `&&` / `||` inside one condition is a single CFG node. `#if` blocks keep both variants.
- tree-sitter parses unexpanded macros. About 39% of files have a tree-sitter parse error somewhere, but only
  7 to 8 of the 104 to 144 release sites per snapshot sit inside a function with a parse error (`results/*.log`,
  field `sites_in_functions_with_parse_errors`). No flagged violation is among them, except the suppressed `EVP_PKEY_generate` site.
- Only functions that take a pointer-to-pointer parameter are looked at. Out-parameters hidden behind a struct
  member (`ctx->buf`) are not.
- The engine detects a missing reset. It does not model guard conditions such as the CVE-2024-4741 fix.

## Reading the results

`results/environment.txt` records versions and the `git rev-parse` of every snapshot. Each `results/<name>.log` is the raw output of one scan. `results/diff_*.log` shows what each fix changed. Do not edit these by hand; rerun `run_scan.sh` and keep failures rather than replacing them.
