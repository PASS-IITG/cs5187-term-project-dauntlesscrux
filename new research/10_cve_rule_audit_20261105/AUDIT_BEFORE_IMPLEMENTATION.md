# CVE rule audit — source findings and proposed changes

Audit scope: the current `src/typestate_check.py`, project regression tests, and the six vulnerable/fixed OpenSSL worktrees. Source checkouts were read only. This report records the audit before analyzer/test changes.

## CVE-2022-4450 — PEM output-pointer state

**Source behavior and invariant.** In the vulnerable `crypto/pem/pem_lib.c::PEM_read_bio_ex` (lines 918-1000), the four output locations are initialized at lines 928-930. Once decoded output allocations are made at 974-976, partial allocation or subsequent read failures jump to `out_free` (977-983); cleanup frees `*header` and `*data` at 991-992 in the vulnerable source, then returns failure at 1000. The fixed source inserts `*header = NULL` and `*data = NULL` immediately after their corresponding frees (fixed lines 990-1000). A caller-visible output must not retain a stale address after its allocation is freed on this failure path.

`pem_bytes_read_bio_flags` has local `nm`, `header`, and `data` outputs (lines 241-243), calls `PEM_read_bio_ex` at 250, and returns immediately on failure at 251-254. Public callers can likewise retain the output argument values, so cleanup state belongs to the callee's API boundary. This audit does not claim the downstream caller will double-free without inspecting its behavior.

**Checker mapping.** `check_pem_read` extracts the exact function signature and `out_free:` to `end:` text, then searches for exact free and clear substrings. It detects the pinned vulnerable/fixed delta. It does not prove statements are unconditional, ordered, reachable, paired with the same allocation, or on every exit path. For example, a reset hidden under `if (0)` currently satisfies its substring check; a conditional/multiple cleanup path is not modeled. Exact spelling/labels make aliases and refactoring unsupported. A missing function/label yields UNKNOWN, but finding the expected fragments is treated as sufficient evidence.

**Assessment.** Appropriate only as a narrow regression-pattern check for the pinned implementation; overly broad as a general typestate conclusion because it accepts nested/unreachable resets and does not establish control-flow coverage. It is also narrow for alternate cleanup layouts and pointer aliases.

## CVE-2023-0215 — BIO chain ownership and cleanup

**Source behavior and invariant.** In vulnerable `crypto/asn1/bio_ndef.c::BIO_new_NDEF` (lines 53-103), `asn_bio` is allocated (64-67), then `BIO_push(asn_bio, out)` links the caller's output BIO under the ASN.1 filter (69-72). A later error (notably the ASN.1 callback at 86-87) reaches `err`, where `BIO_free(asn_bio)` destroys only the filter object and does not repair the linked BIO's `prev_bio`. `BIO_push` links both directions and returns the head (`crypto/bio/bio_lib.c:649-664`); `BIO_pop` detaches the head and repairs the next BIO's back-link (`667-684`); `BIO_free` frees one BIO (`126-157`), while `BIO_free_all` is the chain operation (`752-763`). The fixed function saves the head in `pop_bio` only after successful insertion (fixed lines 75-80), and error cleanup calls `BIO_pop(pop_bio)` before freeing the filter (121-125). Its documented success/failure ownership contract is at fixed lines 52-55.

The callback may prepend digest/cipher BIOs, so the saved initial head matters. The fixed source explicitly assumes `asn1_cb` has not mutated the chain on an error return (fixed lines 95-105), and states no further failure should occur after successful callback mutation (108-111). CMS and PKCS7 call paths reach `BIO_new_NDEF` through `crypto/cms/cms_io.c:61` and `crypto/pkcs7/bio_pk7.c:23`; ownership on success/failure is part of this helper contract.

**Checker mapping.** `check_bio_ndef` looks for the exact `BIO_push(asn_bio, out)` text and `err:`/`BIO_free(asn_bio)` cleanup. `has_unconditional_bio_pop` recognizes a top-level `BIO_pop(asn_bio)` or one direct top-level alias, rejects a conditional/nested pop, and rejects an alias it sees reassigned. Existing tests cover comment stripping, unreachable conditional pop, direct alias, conditional alias pop and reassignment. It does not perform CFG or points-to analysis; it can miss equivalent aliases/expressions, macros, different variable names, paths with multiple pushes/cleanup labels, or callback mutation. Before this audit it also counted a push in an unreachable/nested branch as an established chain insertion.

**Assessment.** Narrow and conservative for this one helper's expected spelling. It can overstate VIOLATION on unsupported/infeasible setup paths and is overly narrow for semantically equivalent ownership operations. BIO_push's return value is not itself the ownership invariant; the chain links and `BIO_pop` semantics are.

## CVE-2024-4741 — SSL read-buffer lifetime and record-layer state

**Source behavior and invariant.** Vulnerable `ssl/record/ssl3_buffer.c::ssl3_release_read_buffer` frees `RECORD_LAYER_get_rbuf(&s->rlayer)->buf` and nulls `b->buf` (lines 185-195) but leaves `s->rlayer.packet` and `packet_length` unchanged. The fixed source additionally sets `s->rlayer.packet = NULL` and `packet_length = 0` (fixed lines 185-196). The packet pointer and length describe bytes in the read buffer: `ssl/record/rec_layer_s3.c::ssl3_read_n` documents this at 194-202, initializes `packet` and zeroes length at 223-230, then accumulates length at 257-263. Record parsing reads through the packet pointer and resets packet length when consuming a packet (`ssl/record/ssl3_record.c:442-482`). `SSL_free_buffers` refuses release while read/write data is pending or record-layer data is present, then calls `RECORD_LAYER_release` (`ssl/ssl_lib.c:5488-5501`); `RECORD_LAYER_release` calls the read-buffer release only for an initialized buffer (`ssl/record/rec_layer_s3.c:69-76`). Other read paths release when the buffer is empty (`rec_layer_s3.c:325-330, 1499-1503`).

The complete API safety condition includes the pending-data precondition in `SSL_free_buffers`; the current checker does not inspect that caller or prove the precondition. It checks only a local post-free reset pattern.

**Checker mapping.** `check_ssl_read_buffer` searches the extracted function for a free and anywhere in that function for three assignment substrings. It does not check order, conditional reachability, or that a reset follows the free. Thus resets before the free or under an unreachable branch currently make the function CONFORMING. It cannot establish the `SSL_free_buffers` precondition, aliases, helper-based release, or other read-buffer lifetime paths.

**Assessment.** The intended fields are source-supported, but the current string-presence implementation is overly broad as evidence of the invariant and overly narrow for alternative cleanup implementations. It is not a full CVE-2024-4741 detector.

## Tests inspected and missing coverage

Existing tests: `tests/test_all_cves.sh`, per-CVE shell scripts for CVE-2022-4450 and CVE-2023-0215, `test_bio_adversarial.py`, `test_bio_alias.py`, and `test_unknown_state.py`. The baseline run is recorded in `logs/baseline_*`. The existing BIO suite deliberately expects an unreachable `BIO_pop` to leave VIOLATION, which is correct for that fixture because the literal false branch cannot detach the chain. There were no PEM- or SSL-specific adversarial tests.

Proposed focused improvements:

1. Add a small lexical top-level/unconditional statement check for the supported cleanup forms. Do not infer arbitrary branch feasibility. If target state changes occur only in nested/conditional/unsupported forms, return UNKNOWN. If a required direct unconditional reset is absent in the supported cleanup, retain VIOLATION. This prevents dead or conditional assignments from proving CONFORMING.
2. Require the target SSL resets to occur after the buffer release, and require PEM pointer clears to be present as unconditional cleanup after their corresponding frees. Return UNKNOWN for alternate/conditional cleanup layouts rather than claiming a result.
3. For BIO, distinguish a top-level insertion from a nested/conditional insertion. If only a nested insertion is found, return UNKNOWN; retain existing definite handling of unconditional push plus missing/conditional pop and preserve the existing alias tests.

These changes are deliberately bounded source heuristics. They add no interprocedural, symbolic, or formal soundness claim. New tests will exercise each real vulnerable/fixed pair, missing/reset-order cases, conditional cleanup, unreachable setup operations, and unsupported alias forms. Existing tests remain in the regression run.
