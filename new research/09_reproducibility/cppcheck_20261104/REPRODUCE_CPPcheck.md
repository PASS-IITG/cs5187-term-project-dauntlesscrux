# Reproducing the Cppcheck scan

The scan was run from WSL against the pinned checkout `/mnt/d/CVE-Typestate-Project-clang-analysis` at `ed57129cd43b77e077c68fd5f7ea951976766f38` using `Cppcheck 2.13.0`. `tracked_c_files.txt` is the tracked-C input manifest. `run_scan.py` creates 100-file batches, uses eight Cppcheck jobs per batch, and records per-batch commands/status/logs. The corrected Cppcheck CLI uses `-j 8`; the original attempt with `--jobs=8` is preserved as a failed attempt and must not be interpreted as coverage.

## Commands

From this research directory:

```sh
python3 run_scan.py --mode text --attempt retry1 --batch-size 100 --jobs 8 --timeout 1800
python3 run_scan.py --mode xml --attempt first --batch-size 100 --jobs 8 --timeout 1800
```

The recorded corrected invocations use:

```text
cppcheck -j 8 --quiet --enable=warning,style,performance,portability \
  --inconclusive --inline-suppr --platform=unix64 --std=c11 -DNDEBUG \
  -I<SOURCE>/include -I<SOURCE>/crypto -I<SOURCE>/ssl \
  -I<SOURCE>/providers/common/include \
  -I<SOURCE>/providers/implementations/include \
  -I<SOURCE>/apps -I<SOURCE>/test \
  --file-list=<RESEARCH>/manifests/<PASS>/batch_NNN.list
```

For XML, append `--xml`; Cppcheck writes XML to stderr, which the runner saves as each batch `.xml` and combines as `cppcheck_raw_xml_first.xml`. Text batch diagnostics are saved in `logs/text_retry1/` and aggregated to `cppcheck_raw_text_retry1.txt`. XML/text aggregate and per-batch files are preserved. `--enable=style` also enables the style category; warning, performance and portability were requested explicitly. No compile database was present. Includes/configuration are approximated with the generated OpenSSL config and listed include roots; this is not equivalent to compiling each file with its exact build command. No additional suppression rules were applied.

## Validation checks

```sh
cppcheck --version
git -C <SOURCE> rev-parse HEAD
python3 - <<'PY'
import csv, xml.etree.ElementTree as ET
from pathlib import Path
p=Path('.')
for name in ('cppcheck_text_batch_status.csv','cppcheck_xml_batch_status.csv',
             'cppcheck_text_file_status.csv','cppcheck_xml_file_status.csv',
             'scan_manifest.csv','cppcheck_diagnostics_raw.csv',
             'cppcheck_inventory_deduplicated_refined.csv','cppcheck_manual_triage.csv'):
    with (p/name).open(newline='') as f: list(csv.DictReader(f))
root=ET.parse(p/'cppcheck_raw_xml_first.xml').getroot()
print('XML diagnostic count:',len(root.findall('errors/error')))
PY
```

Expected for the archived completed pass: revision `ed57129cd43b77e077c68fd5f7ea951976766f38`; 1,695 eligible/tracked files and 1,695 scanned rows for each pass; 17 completed batches and exit code 0 in each pass; XML parses and contains 6897 diagnostics; text parser count 6897; raw diagnostic CSV count 6897; deduplicated inventory count 6806. The runner writes outputs, so rerunning would create new or replace same-named run outputs; archive this directory first if retaining a byte-for-byte evidence snapshot is required.
