# Final conclusions

1. Corrected source revision pairing materially changes CVE-2024-4741 results. The exact official fix is `b3f0eb0a295f58f16ba43ba99dad70d4ee5c437d`; its vulnerable parent is `ec559c2a6cca3fd4cedae5c47f2dfa38e5e24865`. The prior “fixed” worktree was a later descendant, while the prior “vulnerable” worktree already contained the fix.
2. Focused ASan runtime scenarios reproduced the defect mechanism on each vulnerable snapshot and did not reproduce it on the corresponding official fixed snapshot. CVE-2023 fixed validation reaches an unsupported cipher failure rather than completing CMS encryption.
3. The Python checker distinguished CVE-2022-4450 and CVE-2023-0215 but flagged both the vulnerable and official fixed CVE-2024 snapshots. Its CVE-2024 rule is a related local buffer-reset heuristic, not the actual SSL_free_buffers state guard.
4. Generic frozen Coccinelle and Cppcheck runs did not detect the reviewed mechanisms where their scans completed. Corrected CVE-2024 Cppcheck scans are incomplete; no negative result is claimed there. Clang's completed isolated translation-unit checks produced no diagnosis of the target mechanisms.
5. CodeQL/Infer comparisons are NOT_EVALUABLE because the tools were unavailable; the CodeQL bundle download was blocked by DNS. No packages were installed.
6. Short CMS DER and X.509 LibFuzzer runs completed with ASan enabled and no reported issue. They are bounded exploratory tests, not coverage of the specific mechanisms in all cases.
7. No independent evaluation labels were established, so no classifier metrics or comparative superiority claim is warranted.
