# Why These Three CVEs Were Selected

## Decision summary

We narrowed the initial set of eight candidate CVEs to three because they had the strongest combination of source/patch availability, understandable root cause, fit with a state/ownership/lifecycle rule, plausible recurrence, and time feasibility.

### CVE-2023-0215 — score 10/10

This case concerns a use-after-free following `BIO_new_NDEF()` and error-path BIO-chain cleanup. It provides a concrete invariant involving the consistency of chain links and object lifetime. An AddressSanitizer experiment was recorded for the vulnerable checkout, giving it stronger runtime evidence than the other two cases so far.

### CVE-2022-4450 — score 10/10

This case concerns `PEM_read_bio_ex()` returning failure after output buffers have been freed while caller-visible output pointers can still contain stale addresses. It provides a concrete failure-path output-pointer/ownership rule and differs from the BIO chain case.

### CVE-2024-4741 — score 9/10

This case concerns use-after-free associated with `SSL_free_buffers()` under certain record-layer conditions. It provides a state-dependent buffer-lifetime example in the TLS subsystem. The project checker focuses on a source-level buffer-release/state-reset pattern; the exact relationship between that heuristic and the full API precondition must remain documented as a limitation.

## Why the other five were not selected for the first implementation

- CVE-2023-5363: the reported issue may be predominantly cipher parameter validation/configuration.
- CVE-2023-0401: a NULL dereference by itself does not prove a generalizable typestate rule.
- CVE-2023-0216: may be a narrower decoding/pointer-validity issue; rubric total reconciled to 8/10.
- CVE-2026-45447 and CVE-2026-35188: kept as provisional discovery candidates but not prioritized without a fully pinned source/patch investigation.

“Not selected” does not mean “not important.” It means that the cases were a less suitable first fit for this project's specific research question and schedule.
