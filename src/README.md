# `src/`: project code

Everything that produces a number in the paper is here or in the repository root.

| Path | What it is |
|---|---|
| `tsck/` | The current method. A parser-based, invariant-driven checker (Protocol B so far). Start with [`tsck/README.md`](tsck/README.md). |
| `../typestate_check.py` | The Part 1 patch matcher. Kept as a **baseline** only: it recognises the text of three patches and cannot find recurrences. |

## Build and run

```sh
pip install tree-sitter tree-sitter-c         # add --break-system-packages if pip refuses
cd src/tsck && bash run_scan.sh               # reproduces results/ (needs git >= 2.25 and github.com)
python3 check_triage.py                       # cross-checks the manual labels against the logs
python3 -m unittest discover -s tests         # engine unit tests (synthetic C)
```

From the repository root, `make check` runs the baseline tests, the engine unit tests and the triage cross-check without needing the network.
`make scan` reruns the OpenSSL scans.

## Versions used for the recorded results

Python 3.13, tree-sitter 0.26.0, tree-sitter-c 0.24.2, git 2.43, Linux. The exact versions, dates and
`git rev-parse` of every OpenSSL snapshot are written to `tsck/results/environment.txt` on every run.

Do not commit OpenSSL source trees you can regenerate: `run_scan.sh` fetches them at pinned SHAs into `tsck/ossl/`, which is git-ignored.
