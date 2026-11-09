# Known limitations

- CodeQL was unavailable and network DNS prevented fetching the official bundle; no CodeQL database/query run exists.
- Infer and Valgrind were unavailable and not installed.
- Clang checks used isolated affected translation units and a lightweight ownership annotation overlay, not a complete interprocedural OpenSSL ownership model. Unrelated warnings do not establish the CVE mechanism.
- Coccinelle's frozen rules are syntactic/event-oriented and do not model all BIO chain or SSL record-layer states.
- Corrected CVE-2024 Cppcheck completed for `ssl/ssl_lib.c` on both sides, but did not cover all related translation units; conclusion is limited to that file.
- CVE-2023 fixed runtime command hit unsupported DES cipher configuration after reaching the operation's error path; absence of ASan output there is weaker than a fully successful paired operation.
- Focused ASan harnesses demonstrate the memory errors on the exercised path, not remote exploitability or all build configurations.
- LibFuzzer budgets were only about nine seconds per target. CMS DER parsing does not execute CMS streaming/BIO_new_NDEF. Corpus quality and reached code are limited.
- No independently labeled blind evaluation set was completed. Historical fixes and selected CVEs are biased examples; metrics are inappropriate.
- Some read-only `git status` commands timed out on mounted source worktrees. Their revision data were captured, but timed-out statuses cannot support a clean-worktree statement.
