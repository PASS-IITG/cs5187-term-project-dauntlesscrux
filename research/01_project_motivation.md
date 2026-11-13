# Project Motivation, Research Question, and Scope

## Project title

**CVE-Guided Typestate Analysis for Recurring Vulnerability Detection in OpenSSL**

## Why we chose this project

The idea is to start from documented vulnerabilities rather than hypothetical examples. A CVE and its fixing patch provide concrete evidence of what went wrong and what change was made. We can compare the vulnerable and fixed code, state the safety condition that was violated, write a candidate rule, and then investigate whether similar mistakes might appear elsewhere.

OpenSSL was selected because it is a substantial C codebase with public vulnerability advisories, source history, and patches that can be compared. The project was deliberately narrowed to resource-lifecycle, ownership, output-pointer, and state-consistency errors so the first implementation could be feasible within the course timeline.

## Research question

Can source-level invariants derived from known OpenSSL vulnerabilities be written as reusable checks that distinguish the known vulnerable versions from their fixed versions and help guide a careful search for similar mistakes elsewhere?

## What the title means

- **CVE-guided:** use known, documented vulnerabilities as the starting point.
- **Typestate:** reason about which state an object/resource is in and which operations are valid in that state.
- **Recurring vulnerability detection:** use the invariant from a known defect to search for potentially similar defects in other locations.
- **In OpenSSL:** test the approach on OpenSSL source code and historical revisions.

## Method

1. Register plausible CVE candidates.
2. Score them using patch/source availability, root-cause clarity, rule fit, recurrence potential, and time feasibility.
3. Select the three highest-scoring cases.
4. record vulnerable and fixed commits/worktrees.
5. inspect each patch and formulate a rule hypothesis.
6. implement the first source-pattern checks.
7. test vulnerable/fixed pairs and preserve outputs.
8. inspect other locations as recurrence candidates; manually validate before making a vulnerability claim.

## Scope of the first milestone

The Progress Meeting 1 target was: (1) scope firmed up, (2) target open-source software accessible, and (3) an initial pipeline running. The first milestone was not defined as runtime reproduction of every selected CVE or a complete general-purpose static analyzer.

## What the current project can claim

- Eight candidates were collected and scored, and three were chosen for the first implementation.
- Separate vulnerable and fixed OpenSSL worktrees were recorded for all three selected CVEs.
- Three CVE-specific checks exist in the Python prototype.
- The combined source-pattern regression reported ALERT for each vulnerable case and NO ALERT for each fixed case.
- One runtime experiment for CVE-2023-0215 produced an AddressSanitizer heap-use-after-free report on the vulnerable checkout; the recorded fixed checkout run had no corresponding ASan memory-safety report, but the command still returned an error.

## What is not established yet

- This is not a complete typestate analyzer or full C parser.
- The 16-case snippet benchmark does not demonstrate general accuracy across OpenSSL or other C codebases.
- Runtime reproductions were not recorded for CVE-2022-4450 and CVE-2024-4741.
- A new vulnerability has not been confirmed by the current recurrence notes.
- The recurrence audit needs exact source-pinned evidence restored before its locations can be treated as a reproducible audit.
