# Evidence Checklist for Final Submission

For each selected CVE, verify and preserve:

- [ ] Official advisory URL and exact CVE wording.
- [ ] Exact vulnerable revision and fixed commit (verified using Git in the worktrees).
- [ ] Source file/function and minimal relevant before/after diff.
- [ ] Written invariant and explicit rule ID.
- [ ] Checker function that implements the rule.
- [ ] Test invocation and raw output for vulnerable/fixed source.
- [ ] Runtime details, only if a runtime test was actually executed.
- [ ] Known limitations and untested paths.

For the recurrence audit:

- [ ] Every candidate has a revision, file path, function, line range, rule, classification, and evidence.
- [ ] Safe controls have supporting source evidence.
- [ ] Potential matches have manual path/ownership/caller review.
- [ ] No pattern-only alert is called a confirmed vulnerability.

For evaluation:

- [ ] Labeling methodology is described.
- [ ] Test set includes edge/adversarial cases and is not only the exact snippets that guided rule design.
- [ ] Confusion-matrix calculations are reproducible.
- [ ] Metrics are scoped to the tested dataset.
