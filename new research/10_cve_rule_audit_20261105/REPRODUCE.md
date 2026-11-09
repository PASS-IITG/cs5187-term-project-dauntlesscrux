# Reproducing the CVE rule audit

Run from the project root. This audit does not invoke or modify the OpenSSL builds; the checker reads source files only. Adversarial fixtures are written to a `TemporaryDirectory` and removed automatically when the test exits.

```sh
bash tests/test_all_cves.sh
bash tests/test_cve_2022_4450.sh
bash tests/test_cve_2023_0215.sh
python3 tests/test_bio_adversarial.py
python3 tests/test_bio_alias.py
python3 tests/test_unknown_state.py
python3 tests/test_pem_ssl_adversarial.py
```

Expected recorded status: each command exits 0. The combined script expects exit 1 from each vulnerable source checker invocation and exit 0 from each fixed source invocation. The unsupported-source test expects checker exit 2 (UNKNOWN). Per-test raw stdout/stderr is saved under `logs/final_*.log`; exact script exit codes are in `logs/final_exit_codes.csv`. The pre-change baseline is retained under `logs/baseline_*`.

The focused new tests can be run independently with `python3 tests/test_pem_ssl_adversarial.py`. No temporary fixture is required by hand. The stable OpenSSL source revisions, plus read-only status snapshots, are in `worktree_status_final.txt`.

Do not interpret these source-pattern checks as runtime reproductions. They validate rule behavior against source snippets and pinned vulnerable/fixed files.
