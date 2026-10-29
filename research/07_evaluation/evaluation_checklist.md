# Evaluation Checklist

## Current evidence

- [x] Three vulnerable/fixed source-pair regression results recorded.
- [x] One CVE-2023-0215 AddressSanitizer experiment recorded.
- [x] 16-case hand-written snippet benchmark and stdout log included.
- [x] Metrics caveat documented.

## Still to do before final results

- [ ] Re-run `python3 typestate_checker_eval_v2.py` and archive the output from the final repo.
- [ ] Fix the PEM benchmark condition to require both `*header` and `*data` resets.
- [ ] Add adversarial/edge cases so tests do more than restate the rules.
- [ ] Check root-level checker results against actual source files in each worktree.
- [ ] Restore exact source identifiers for each recurrence candidate.
- [ ] Decide whether runtime tests for the other two CVEs are required or feasible.
- [ ] Avoid reporting 100% benchmark accuracy as general detection accuracy.
