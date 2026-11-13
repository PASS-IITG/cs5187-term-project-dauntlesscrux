# Reproducing the CVE tool comparison

The comparison used the six source revisions in `WORKTREE_REVISION_MANIFEST.csv`; verify each HEAD against that file before rerunning. Tool versions and hashes are frozen in `TOOL_FREEZE.csv`. All run commands and options are described in `TOOL_CONFIGURATION.md`.

The commands below were used from the project root:

```sh
python3 research/11_cve_tool_comparison/run_python_coccinelle.py
python3 research/11_cve_tool_comparison/run_cppcheck.py
python3 research/11_cve_tool_comparison/run_clang_sa.py
python3 research/11_cve_tool_comparison/build_comparison.py
python3 research/11_cve_tool_comparison/finalize_evidence.py
```

The Python and Coccinelle runner checks all six source files and five frozen rules. Cppcheck runs text and XML for each source file. The Clang runner exports each exact Git commit into `/tmp`, runs `CC=clang-18 ./Configure linux-x86_64`, generates headers with `make -j8 build_generated`, extracts the target compile line with `make -n V=1 <object>`, and invokes Clang `--analyze` with those flags. It does not build or modify the original source worktrees.

The runners use fixed output paths under `research/11_cve_tool_comparison/`; copy this evidence directory before rerunning if you need to retain the existing byte-for-byte run results. The three prior Clang setup attempts are preserved in separate status/log files. The complete successful Clang results are `clang_run_status_attempt2.csv` and `runs/clang/attempt2/`.

The baseline Python checker results were run from the frozen byte-for-byte checker copy; outputs are in `python_run_status.csv` and `runs/python/`. The comparison builder joins run statuses and parses Cppcheck XML; manually inspect all raw logs before changing any classifications.
