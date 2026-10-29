# Progress Meeting 1 — Work Completed and Decisions

**Project:** CVE-Guided Typestate Analysis for Recurring Vulnerability Detection in OpenSSL
**Meeting milestone:** Scope firmed up; target OSS accessible; initial pipeline running.

## Decisions

- Target OpenSSL C source code.
- Investigate lifecycle, ownership, error-cleanup, and state-consistency defects.
- Use a candidate register and a five-criterion rubric rather than selecting only by severity.
- Select CVE-2023-0215, CVE-2022-4450, and CVE-2024-4741 as the first cases.
- Start with separate targeted checker rules, not one overly broad rule.

## Work recorded

- Main source checkout at `/mnt/d/CVE-Typestate-Project/openssl`.
- Vulnerable/fixed worktrees documented for all three selected CVEs.
- Python prototype `typestate_check.py` and shell regression scripts documented.
- Combined test result recorded as alert/no-alert distinction for all three pairs.
- CVE-2023-0215 ASan runtime result recorded for vulnerable and fixed checkouts.
- Research notes and rule specifications assembled.

## Important limitations communicated

- Two selected CVEs currently have source-pattern regression only, not recorded runtime reproduction.
- Hand-written evaluation snippets are not a general accuracy study.
- The recurrence audit needs source-pinned identifiers restored.
- No new vulnerability is currently claimed as confirmed.

## Next milestone preparation

- Strengthen evaluation and handle adversarial cases.
- Restore exact recurrence locations and evidence.
- Keep a reproducible log of every test and exact commit.
- Review the rule specification against what the Python implementation truly checks.
