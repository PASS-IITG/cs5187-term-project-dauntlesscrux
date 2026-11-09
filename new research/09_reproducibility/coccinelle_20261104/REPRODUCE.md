# Reproduction and scan status

Pinned source: `/mnt/d/CVE-Typestate-Project-clang-analysis`
Revision: `ed57129cd43b77e077c68fd5f7ea951976766f38`
Coccinelle: `spatch version 1.1.1` (Python scripting enabled).

All input manifests are tracked C translation units filtered by documented necessary lexical conditions. Rule 01: `files_01_use_after_release.txt` (910); rule 02: `files_02_repeated_release.txt` (430, after conservative exact-callee/identifier/function-body prefilter); rule 03: `files_03_release_after_transfer.txt` (10); rule 04: `files_04_acquire_early_return.txt` (332). `tracked_c_files.txt` records 1,695 tracked C files. Rule 02 filter details are in `rule02_prefilter_notes.txt`; RULES.md describes rule intent/limitations.

Run from any directory (output paths remain in this research directory):

```sh
OUT=/mnt/d/CVE-Typestate-Project/research/09_reproducibility/coccinelle_20261104
spatch --jobs 4 --tmp-dir "$OUT/tmp" --very-quiet --sp-file "$OUT/rules/01_use_after_release.cocci" --file-groups "$OUT/files_01_use_after_release.txt" >"$OUT/logs/final_01_use_after_release.stdout" 2>"$OUT/logs/final_01_use_after_release.stderr"
spatch --jobs 4 --tmp-dir "$OUT/tmp" --very-quiet --sp-file "$OUT/rules/02_repeated_release.cocci" --file-groups "$OUT/files_02_repeated_release.txt" >"$OUT/logs/final_02_repeated_release.stdout" 2>"$OUT/logs/final_02_repeated_release.stderr"
spatch --jobs 4 --tmp-dir "$OUT/tmp" --very-quiet --sp-file "$OUT/rules/03_release_after_transfer.cocci" --file-groups "$OUT/files_03_release_after_transfer.txt" >"$OUT/logs/final_03_release_after_transfer.stdout" 2>"$OUT/logs/final_03_release_after_transfer.stderr"
spatch --jobs 4 --tmp-dir "$OUT/tmp" --very-quiet --sp-file "$OUT/rules/04_acquire_early_return.cocci" --file-groups "$OUT/files_04_acquire_early_return.txt" >"$OUT/logs/final_04_acquire_early_return.stdout" 2>"$OUT/logs/final_04_acquire_early_return.stderr"
```

The completed accepted runs are rules 01 and 03. Rule 02 was interrupted (exit 130) after a prolonged run with no output; rule 04 hit a 180-second timeout (124), and a later extended attempt was interrupted (130) after no usable progress. Their empty partial logs are not valid negative results. Exact status and log paths are in `final_scan_status.csv`; historical attempts are retained in `attempt_history.md` and `logs/`. Rule 04 extended attempt used `timeout 600` and `--jobs 8`; its terminal interruption was 130.

Rule SHA-256 values at evidence freeze:

- `01_use_after_release.cocci`: `8b5945b2eeb390f263a622bc81fe90599a919f186e80a68c34c3d4175d1b9558`
- `02_repeated_release.cocci`: `a2cde7147584ffa8cd1c8388abb7ab9e364f6829c4f4bf014082036df6d79ab4`
- `03_release_after_transfer.cocci`: `5f18a9dad84e099da1d8baaffe3016b0a948157a23d30d637b6f67b1d6ef0aae`
- `04_acquire_early_return.cocci`: `9e36d44257a749a6c4e3b9d7de6e5c25560f604fe11420bd016e5bc89424c81e`
