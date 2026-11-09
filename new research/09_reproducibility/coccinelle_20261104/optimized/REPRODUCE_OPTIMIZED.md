# Reproduce optimized scan

Source: `/mnt/d/CVE-Typestate-Project-clang-analysis` at `ed57129cd43b77e077c68fd5f7ea951976766f38`. Tool: `spatch --version` reports Coccinelle 1.1.1.

The exact per-batch commands, file lists, UTC start/end times, exit codes, stdout and stderr paths are recorded in the three `*_batch_status.csv` files and adjacent manifests/logs. The runner adaptively splits a batch on a nonzero result; all final batches completed without splitting. Full file status is in `file_coverage_manifest.csv`.

Equivalent runner commands (run from any directory):

```sh
OUT=/mnt/d/CVE-Typestate-Project/research/09_reproducibility/coccinelle_20261104
python3 "$OUT/optimized/run_batches.py" "$OUT" 02_events "$OUT/rules/02_repeated_release_events.cocci" "$OUT/files_02_events_all_tracked.txt"
python3 "$OUT/optimized/run_batches.py" "$OUT" 04a_alloc_events "$OUT/rules/04a_alloc_events.cocci" "$OUT/files_04_events_all_tracked.txt"
python3 "$OUT/optimized/run_batches.py" "$OUT" 04b_return_events "$OUT/rules/04b_return_events.cocci" "$OUT/files_04_events_all_tracked.txt"
python3 "$OUT/optimized/postprocess_events.py" "$OUT"
python3 "$OUT/optimized/filter_explicit_returns.py"
```

Rule hashes at evidence freeze:

- `01_use_after_release.cocci`: `8b5945b2eeb390f263a622bc81fe90599a919f186e80a68c34c3d4175d1b9558`
- `02_context_debug.cocci`: `df0dd23292dc706d75c1608a516a2f96784f2303fa52baf5b45d719594418d4b`
- `02_release_events_with_function.cocci`: `724b89e22aa617c985dad22d573b62b1b142589c9f917eb87dbfb01c614d6bcb`
- `02_repeated_release.cocci`: `a2cde7147584ffa8cd1c8388abb7ab9e364f6829c4f4bf014082036df6d79ab4`
- `02_repeated_release_events.cocci`: `80ef06270d4732986fe8ef7a21091a296a36fe9bfdc347e150601ce2fa8a61bb`
- `03_release_after_transfer.cocci`: `5f18a9dad84e099da1d8baaffe3016b0a948157a23d30d637b6f67b1d6ef0aae`
- `04_acquire_early_return.cocci`: `9e36d44257a749a6c4e3b9d7de6e5c25560f604fe11420bd016e5bc89424c81e`
- `04a_alloc_events.cocci`: `b861aeffb7403c07ef4dc2bdaa3072d662ecd786eabd408cf871bea4ecdc8655`
- `04a_alloc_events_with_function.cocci`: `53311d7dc959773c2f2d64f5a81e2cae134aa42429cf7c4084d296985f9c3a64`
- `04b_return_events.cocci`: `6fc0a9d41700b9f03869bd751baa638f9e89813f45c4669846113750c05f104a`
- `04b_return_events_with_function.cocci`: `02d2befbcfd6f3e1fa76d1814d1c42801ef48ae82f56a598559b1bb55a0d2987`

The batch runner command template is `timeout 120 spatch --jobs 8 --tmp-dir <research>/tmp --very-quiet --sp-file <rule> --file-groups <batch manifest>`, with stdout/stderr redirected to unique files. `run_batches.py` performs 100-file initial batches and recursively halves a failed/timed-out group; no final group failed. Coccinelle stdout is not interpreted as zero matches unless the batch status is exit 0.

The original failed/interrupted attempts remain in `../final_scan_commands.txt`, `../final_scan_status.csv`, and `../logs/`; they are historical attempts, not final status.
