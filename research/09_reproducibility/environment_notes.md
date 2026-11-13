# Environment and Repository Notes

## Known project root

- WSL/Linux: `/mnt/d/CVE-Typestate-Project`
- Windows: `D:\CVE-Typestate-Project`
- Main OpenSSL checkout: `/mnt/d/CVE-Typestate-Project/openssl`

## Known project files

- `typestate_check.py` — Python checker.
- `tests/test_cve_2023_0215.sh` — individual regression pair.
- `tests/test_cve_2022_4450.sh` — individual regression pair.
- `tests/test_all_cves.sh` — combined regression.
- Per-CVE evidence files were documented in the progress report.

This pack cannot see or verify the contents of the user's live WSL checkout. Re-run the commands in `reproduction_commands.md` in that checkout and update logs to match the final repository before submission.
