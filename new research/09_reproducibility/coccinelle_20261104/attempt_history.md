# Scan attempt history

This file distinguishes preliminary tool failures from final accepted scan runs.

- A parallel `spatch --jobs 4` run without `--tmp-dir` attempted to create worker files in the read-only source worktree and failed. Raw stderr is retained as `logs/*attempt1*` and `logs/*failed-temp-attempt*`.
- The initial repeated-release rule with a seven-way destructor disjunction was prohibitively slow on the broad input and terminated with a nonzero signal/was interrupted. Its partial logs are not included in candidate counts. The rule was simplified to a same-callee `.*free.*` identifier matcher, re-tested on samples, and its input prefilter was tightened only to files that can contain the exact same-callee/same-identifier pair demanded by the rule.
- Final scan outputs and statuses are named `final_*`; only these files feed the final inventory. `final_scan_commands.txt` and `final_scan_status.csv` are authoritative for final run commands and exit codes.
