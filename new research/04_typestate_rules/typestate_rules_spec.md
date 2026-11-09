# Typestate-Inspired Rule Specification

**Status:** Initial formal models for a source-pattern prototype. These are hypotheses derived from known cases, not proof that the checker reasons about every state path correctly.

## Terminology

- **State:** the abstract condition of an object/resource (allocated, linked, freed, pointer cleared, data pending, etc.).
- **Ownership:** which function/object is responsible for retaining, transferring, or releasing a resource.
- **Lifecycle:** the valid sequence of creation, use, transfer, cleanup, and release.
- **API-use contract:** preconditions and postconditions expected when calling a function, including failure-path behavior.
- **Invariant:** a condition that must remain true for the program to be safe.

## TS-BIO-01 — BIO chain lifetime and cleanup

**Object(s):** BIO filter object and chain membership/links.

**Abstract states:** `UNALLOCATED -> ALLOCATED -> LINKED_IN_CHAIN -> DETACHED_OR_CHAIN_RESTORED -> FREED`.

**Core invariant:** a filter BIO must not be freed while chain structure or ownership still depends on it. On the relevant error path, restore the chain before freeing the BIO.

**Forbidden transition (abstract):** `LINKED_IN_CHAIN -> FREED` when the chain still contains/requires that BIO.

**Observed patch idea:** the fix restores BIO-chain state on the relevant error path before releasing the associated BIO. The exact `BIO_pop()` target matters and must be checked in the patch; do not replace this semantic condition with the overly broad rule “every BIO_free must have a BIO_pop.”

**Current implementation mapping:** `check_bio_ndef()` checks for a targeted BIO push/new-NDEF and cleanup/free pattern without the expected pop/restoration pattern.

**Potential false positives/negatives:** helper functions, aliases, ownership transfer, different chain roots, conditionally executed pop operations, macro expansions, comments/strings, and unusual cleanup blocks may defeat text matching.

## TS-PEM-02 — output-pointer reset after error cleanup

**Object(s):** caller-visible `*header` and `*data` output parameters and the allocated buffers they reference.

**Abstract states:** `UNINITIALIZED_OR_NULL -> ALLOCATED_INTERNAL -> (SUCCESS: RETURNED_TO_CALLER) OR (FAILURE: FREED_ON_ERROR -> OUTPUT_POINTERS_CLEARED)`.

**Core invariant:** after a failure path frees an output buffer, the corresponding output pointer must reflect the API's post-failure ownership contract. In the selected fix, both `*header` and `*data` are reset to `NULL` after their respective buffers are freed.

**Forbidden transition (abstract):** `FREED_ON_ERROR -> RETURN_FAILURE_WITH_STALE_OUTPUT_POINTER`.

**Current implementation mapping:** `check_pem_read()` inspects cleanup of `PEM_read_bio_ex()` and the reset of both outputs.

**Potential false positives/negatives:** return-path differences, API-specific contracts where an output is undefined on failure, aliases, cleanup wrappers/macros, and checks that notice only one reset instead of verifying both.

## TS-SSL-03 — SSL buffer lifetime and dependent packet state

**Object(s):** SSL read buffer, record-layer packet pointer, packet length, and API conditions controlling buffer release.

**Abstract states:** `BUFFER_ALLOCATED -> RECORD_DATA_PENDING_OR_IN_USE -> (DATA_NO_LONGER_DEPENDS_ON_BUFFER) -> RELEASE_PERMITTED -> BUFFER_RELEASED`, with dependent pointer/length fields brought into a consistent cleared state where required.

**Core invariant:** do not release a buffer when record-layer state still depends on it; after release, dependent pointer/length state must not describe freed memory.

**Forbidden transition (abstract):** `RECORD_DATA_PENDING_OR_IN_USE -> BUFFER_RELEASED` without satisfying the release precondition and restoring dependent state.

**Current implementation mapping:** `check_ssl_read_buffer()` checks the selected release/reset pattern, including whether `s->rlayer.packet` and `s->rlayer.packet_length` are reset.

**Important boundary:** the official CVE concerns `SSL_free_buffers()` under particular record-layer conditions. The project's selected-source heuristic is not a complete proof of that API's precondition; reconcile the guard and resets with the exact patch and callers before claiming comprehensive detection.

## Shared design principle

These three rules are not a single universal “freeing is bad” rule. Correctness depends on object state, ownership, related pointers, the API contract, and the path through cleanup. The present implementation checks a few source patterns to establish an initial pipeline; a more complete analyzer would need stronger parsing and path-sensitive reasoning.
