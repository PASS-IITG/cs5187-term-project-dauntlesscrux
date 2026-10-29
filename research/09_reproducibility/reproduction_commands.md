# Reproducibility Commands

Run these from the WSL project root:

```bash
cd /mnt/d/CVE-Typestate-Project
```

## Verify revisions

```bash
for d in \
  openssl-cve-2023-0215-vulnerable \
  openssl-cve-2023-0215-fixed \
  openssl-cve-2022-4450-vulnerable \
  openssl-cve-2022-4450-fixed \
  openssl-cve-2024-4741-vulnerable \
  openssl-cve-2024-4741-fixed
do
  echo "=== $d ==="
  git -C "$d" rev-parse HEAD
  git -C "$d" show --no-patch --format='%H%n%P%n%s' HEAD
done
```

Compare the output with `source_revision_ledger.csv`. Resolve any mismatch before keeping the final evidence.

## Python and shell syntax

```bash
python3 -m py_compile typestate_check.py
bash -n tests/test_all_cves.sh
```

## Combined regression

```bash
bash tests/test_all_cves.sh
```

Expected *recorded* outcome: CVE-2023-0215 vulnerable = ALERT and fixed = NO ALERT; same pattern for CVE-2022-4450 and CVE-2024-4741; overall PASS. Re-run now to confirm this still holds in the current repo, and save the actual output. Do not use this text in place of fresh logs.

## CVE-2023-0215 runtime command

Run in the built vulnerable checkout:

```bash
./apps/openssl cms -encrypt -in test/smcont.txt -stream -recip test/smime-certs/smec1.pem -des
```

The command is expected to enter an error path in the documented reproduction setup. Preserve the actual return status, ASan stderr/stdout, and build configuration. A command returning an error is not by itself a successful runtime reproduction; the memory-safety diagnostic is the relevant evidence.

## Benchmark harness

```bash
python3 research/07_evaluation/typestate_checker_eval_v2.py | tee research/07_evaluation/eval_latest_stdout.log
```

The current harness is a hand-written snippet benchmark and includes a known PEM reset-coverage limitation documented in `benchmark_protocol.md`.
