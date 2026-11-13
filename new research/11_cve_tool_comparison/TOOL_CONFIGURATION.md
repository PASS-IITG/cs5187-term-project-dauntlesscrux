# Frozen tools and run configuration

Tool versions, executable hashes, the Python checker hash, and hashes of the five Coccinelle semantic patches used in this experiment are recorded in `TOOL_FREEZE.csv`. A byte-for-byte frozen checker and frozen rule copies are under `frozen/`. `clang-18-version.txt`, `scan-build-18-help.txt`, `spatch-version.txt`, `cppcheck-version.txt`, and `cppcheck-help.txt` preserve tool identification/help output. The comparison was run in WSL Ubuntu 24.04 with Python 3.12.3, Clang/Clang Static Analyzer 18.1.3, Coccinelle 1.1.1, and Cppcheck 2.13.0.

## Python checker

The frozen `frozen/typestate_check.py` is the exact current `src/typestate_check.py` at experiment start (SHA-256 in `TOOL_FREEZE.csv`). It was invoked once for each of the six pinned affected source files. Exit 1 means VIOLATION, exit 0 CONFORMING, exit 2 UNKNOWN. Exact commands, output status, and raw stdout/stderr are in `python_run_status.csv` and `runs/python/`.

## Clang Static Analyzer 18

The original source worktrees have no generated Makefile, `configdata.pm`, or compilation database. To avoid modifying them, each pinned Git commit was exported to `/tmp/openssl-cve-tool-comparison/clang/<case>/`. There, the command `CC=clang-18 ./Configure linux-x86_64` generated the OpenSSL configuration, followed by `make -j8 build_generated` to generate headers. The per-revision `configdata.pm --dump` is preserved with the run.

For each affected object target, `make -n V=1 <object-target>` yielded the exact compiler command with target-specific include paths, configuration defines and platform flags. The runner removed compile output/dependency-generation switches, retained those source flags, and ran the same `clang-18` command with `--analyze -Xanalyzer -analyzer-output=text -fno-color-diagnostics`. It analyzed only the affected translation unit, not the entire OpenSSL build. The exact dry-run and analyzer commands, stdout/stderr, configuration, duration and exit code are under `runs/clang/attempt2/` and `clang_run_status_attempt2.csv`.

To check that the analyzer was active, `clang-18 --analyze` was also run on a minimal temporary use-after-free control; it emitted `Use of memory after it is freed` and exited 0 (`runs/clang/control/`).

Two earlier setup attempts are retained in `clang_run_status.csv`, `clang_run_status_attempt1.csv`, and corresponding run directories. They failed to decode the binary Git archive and then lacked generated headers, respectively. Those attempts are NOT_EVALUABLE and are not counted as negative results. The successful final attempt generated the required headers in `/tmp` and completed all six translation-unit analyses.

## Coccinelle 1.1.1

Before running the CVE comparison, the existing completed optimized rule set was frozen byte-for-byte: Rule 01 use-after-release, Rule 02 release-event enumeration, Rule 03 BIO transfer/free, Rule 04a allocation-event enumeration, and Rule 04b return-event enumeration. No CVE-specific SmPL was created. For every source revision, each frozen rule was invoked as:

```sh
spatch --jobs 2 --very-quiet --sp-file <frozen-rule.cocci> <pinned-worktree-source.c>
```

There are 30 rule/source invocations. Exact commands, exit codes, times, stdout and stderr are in `coccinelle_run_status.csv` and `runs/coccinelle/`. The generic allocation/return/release events are manually separated from detection of each CVE's invariant.

## Cppcheck 2.13.0

Cppcheck ran against each configured temporary source copy at the matching pinned commit, using the generated headers and source-local include roots. No compile database exists for these original source trees. The recorded options match the earlier whole-tree experiment:

```sh
cppcheck -j 4 --quiet --enable=warning,style,performance,portability \
  --inconclusive --inline-suppr --platform=unix64 --std=c11 -DNDEBUG \
  -I<SOURCE>/include -I<SOURCE>/crypto -I<SOURCE>/ssl \
  -I<SOURCE>/providers/common/include \
  -I<SOURCE>/providers/implementations/include \
  -I<SOURCE>/apps -I<SOURCE>/test --template=gcc <SOURCE_FILE>
```

Each source was run once in text mode and once with `--xml`. Full argument JSON and exit/duration status are in `cppcheck_run_status.csv`; raw text/XML and captured stdout/stderr are under `runs/cppcheck/`. XML is emitted on stderr by Cppcheck and was parsed for manual review.

All commands were read-only with respect to the six original OpenSSL worktrees. Configuration and generated files were written only to `/tmp`; evidence was written only to `research/11_cve_tool_comparison/`.
