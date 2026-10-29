# Rule-to-Code and Test Mapping

| Rule ID | Selected CVE | Checker function | Source area in notes | Regression evidence | Current implementation type |
|---|---|---|---|---|---|
| `TS-BIO-01` | CVE-2023-0215 | `check_bio_ndef()` | `crypto/asn1/bio_ndef.c`, BIO-chain error cleanup | `tests/test_cve_2023_0215.sh`; `tests/test_all_cves.sh` | Targeted source-pattern heuristic |
| `TS-PEM-02` | CVE-2022-4450 | `check_pem_read()` | `crypto/pem/pem_lib.c`, `PEM_read_bio_ex()` | `tests/test_cve_2022_4450.sh`; `tests/test_all_cves.sh` | Targeted source-pattern heuristic |
| `TS-SSL-03` | CVE-2024-4741 | `check_ssl_read_buffer()` | `ssl/record/ssl3_buffer.c`, `ssl3_release_read_buffer()`, related record-layer state | `tests/test_all_cves.sh` | Targeted source-pattern heuristic |

## How to verify locally

From the project root:

```bash
python3 -m py_compile typestate_check.py
bash -n tests/test_all_cves.sh
bash tests/test_all_cves.sh
```

The expected recorded result is `ALERT` for each vulnerable source and `NO ALERT` for each matching fixed source. Re-run before the next meeting and save the real current output to the evidence folder.

## Specification vs implementation

The formal rule describes the semantic condition we care about. The current Python code looks for a limited source pattern. These are not equivalent levels of analysis. Every formal requirement that is not actually checked by code should be listed as a limitation or future implementation item.
