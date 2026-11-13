# Official Sources and Reading List

This is the initial primary-source list. Add research papers on typestate, static analysis, API misuse detection, and recurring vulnerability detection after locating and reading them. Do not cite a paper as read merely because it appears on a list.

## OpenSSL advisories

- OpenSSL vulnerability index: <https://www.openssl-library.org/news/vulnerabilities/>
- OpenSSL 3.0 vulnerability index (includes CVE-2023-0215 and CVE-2022-4450 records): <https://www.openssl-library.org/news/vulnerabilities-3.0/>
- OpenSSL 3.3 vulnerability index (includes CVE-2024-4741 record): <https://www.openssl-library.org/news/vulnerabilities-3.3/>
- OpenSSL security advisory dated 2023-02-07: <https://www.openssl.org/news/secadv/20230207.txt>
- OpenSSL security advisory dated 2023-10-24: <https://www.openssl.org/news/secadv/20231024.txt>

## Recorded fixing commits

- CVE-2023-0215: <https://github.com/openssl/openssl/commit/8818064ce3c3c0f1b740a5aaba2a987e75bfbafd>
- CVE-2022-4450: <https://github.com/openssl/openssl/commit/63bcf189be73a9cc1264059bed6f57974be74a83>
- CVE-2024-4741 (primary fix): <https://github.com/openssl/openssl/commit/b3f0eb0a295f58f16ba43ba99dad70d4ee5c437d>
- CVE-2024-4741 (follow-on hardening, not the root cause): <https://github.com/openssl/openssl/commit/2d05959073c4bf8803401668b9df85931a08e020>
- OpenSSL advisory dated 2024-05-28: <https://www.openssl.org/news/secadv/20240528.txt>

## Source-revision notes

The exact project worktree ledger is reproduced in `research/09_reproducibility/source_revision_ledger.csv`. Verify each hash using Git before formal submission. The revision ledger is the project-specific record; public advisories explain the vulnerability scope, while the commit diff explains the code change.

## Research-paper work still needed

The current pack does not pretend that a peer-reviewed literature review has been completed. For the next literature pass, search and read work on:

- typestate systems and protocol-state verification;
- static analysis of C/C++ resource lifetime and use-after-free;
- API misuse detection and error-path analysis;
- clone/pattern-based recurring vulnerability discovery;
- evaluation practices for static analyzers (ground truth, independent test cases, false positives/negatives).

For every paper added, record authors, title, venue/year, DOI or stable URL, what method it presents, how it differs from this project, and which claim in the report it supports.
