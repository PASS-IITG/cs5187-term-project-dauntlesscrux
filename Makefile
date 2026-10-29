# Top-level checks. The paper has its own Makefile (paper/Makefile: `make`, `make check`).
.PHONY: check scan unit baseline triage clean-scan

check: baseline unit triage
	@echo "ALL CODE CHECKS PASSED"

baseline:
	bash tests/test_all_cves.sh

unit:
	cd src/tsck && python3 -m unittest discover -s tests

# Cross-checks triage.csv against the committed results/*.json (offline).
triage:
	cd src/tsck && python3 check_triage.py

# Re-run every OpenSSL scan from scratch (needs network access to github.com).
scan:
	cd src/tsck && bash run_scan.sh

clean-scan:
	rm -rf src/tsck/ossl
