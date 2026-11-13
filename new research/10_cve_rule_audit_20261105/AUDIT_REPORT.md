# CVE-guided typestate rule audit

Date: 2026-11-05  
Analyzer: `src/typestate_check.py`  
OpenSSL source trees: six pinned vulnerable/fixed worktrees listed in `worktree_status_final.txt`.

## Outcome

The audit confirmed three distinct lifecycle invariants and found that the current implementation is a small source-pattern checker rather than a general typestate engine. I made bounded checker changes for cases where the previous code could treat mere textual presence as proof: conditional/dead PEM or SSL resets, incorrect reset ordering, conditional/dead BIO insertion, and BIO insertion through an unrecognized alias. These unsupported forms now return UNKNOWN instead of an unjustified CONFORMING or VIOLATION result. The rules remain specific to each CVE.

All vulnerable/fixed source pairs remain distinguished. The combined regression `bash tests/test_all_cves.sh` passed after the changes. Every existing individual regression/adversarial test and the new adversarial suite also passed. The new suite has **17/17** passing outcomes. This is source-pattern regression evidence, not a new runtime reproduction.

## Per-CVE findings

### CVE-2022-4450: PEM output-pointer lifetime

The vulnerable implementation initializes `*header` and `*data` to NULL, allocates output buffers, and on partial/output-read failure frees the pointed-to allocations without clearing the caller-visible pointers (`crypto/pem/pem_lib.c:928-930, 974-983, 990-993`). A caller then has stale output addresses on the failure return. The fixed source clears each output immediately after freeing it (`fixed/crypto/pem/pem_lib.c:990-1000`). The relevant invariant is per output: on this failure cleanup, a freed caller-visible output pointer must be reset after the free.

`check_pem_read` now requires one direct, unconditional free of each output and a direct unconditional reset of each output after its free. Missing resets in the supported cleanup produce VIOLATION. Conditional, nested, duplicated, aliased, or reordered operations produce UNKNOWN. This still does not analyze every function exit or caller contract.

### CVE-2023-0215: BIO chain ownership

`BIO_push` links the filter and caller output in both directions (`crypto/bio/bio_lib.c:649-664`). `BIO_free` releases one BIO, whereas `BIO_free_all` walks a chain (`126-157, 752-763`). `BIO_pop` detaches the head and repairs the next node's back-link (`667-684`). Vulnerable `BIO_new_NDEF` pushes `asn_bio` over caller-owned `out` (lines 69-72), then its error path frees `asn_bio` without detaching it (99-102); the caller's `out->prev_bio` can be left pointing to freed storage. The fixed path saves the inserted head after successful push and pops it before freeing on failure (`fixed/crypto/asn1/bio_ndef.c:75-80, 121-126`).

`check_bio_ndef` requires the supported top-level `BIO_push(asn_bio, out)` and cleanup shape; a different push target/alias or nested/conditional insertion returns UNKNOWN. `has_unconditional_bio_pop` accepts a limited direct alias and checks that a pop is unconditional and precedes the free. It is not a points-to analysis and does not model arbitrary callback mutations. The fixed implementation itself documents that the ASN.1 callback must not mutate the chain on error (`fixed/crypto/asn1/bio_ndef.c:95-105`).

### CVE-2024-4741: SSL read-buffer lifetime and packet state

The packet pointer and `packet_length` describe bytes in the read buffer (`ssl/record/rec_layer_s3.c:194-202, 223-263`). Parsing dereferences packet data and updates/reset packet state (`ssl/record/ssl3_record.c:442-482`). The vulnerable `ssl3_release_read_buffer` frees and clears only `b->buf` (`ssl/record/ssl3_buffer.c:185-195`); the fixed version also clears `s->rlayer.packet` and `packet_length` (`fixed/ssl/record/ssl3_buffer.c:185-196`). `SSL_free_buffers` refuses release while read/write data or record-layer data is pending before calling `RECORD_LAYER_release` (`ssl/ssl_lib.c:5488-5501`); the record layer calls the read-buffer release for initialized buffers (`ssl/record/rec_layer_s3.c:69-76`).

`check_ssl_read_buffer` now requires the buffer free and all three direct top-level state resets, with resets following the free. A missing reset in the supported local pattern is VIOLATION; conditional, nested, duplicated, or reordered forms are UNKNOWN. The checker still does not analyze `SSL_free_buffers` preconditions or caller state. It should not be described as a complete CVE-2024-4741 detector.

Detailed mapping: `CHECKER_INVARIANT_MAPPING.csv`. Pre-change assessment and rationale: `AUDIT_BEFORE_IMPLEMENTATION.md`.

## Test results

| Test command | Result |
|---|---|
| `bash tests/test_all_cves.sh` | Exit 0; all three vulnerable sources VIOLATION, all fixed sources CONFORMING |
| `bash tests/test_cve_2022_4450.sh` | Exit 0 |
| `bash tests/test_cve_2023_0215.sh` | Exit 0 |
| `python3 tests/test_bio_adversarial.py` | Exit 0; 4/4 |
| `python3 tests/test_bio_alias.py` | Exit 0; 3/3 |
| `python3 tests/test_unknown_state.py` | Exit 0 |
| `python3 tests/test_pem_ssl_adversarial.py` | Exit 0; 17/17 |

The new adversarial cases cover each vulnerable/fixed pair, one missing PEM reset, conditional/dead/reordered PEM cleanup, an unsupported PEM output alias, missing/conditional/dead/reordered SSL state resets, and dead/alias-based BIO insertion. The existing BIO suite continues to cover unreachable pop, comment-only push, direct alias, conditional pop, and reassigned alias. See `TEST_COVERAGE_MATRIX.csv` and the captured logs in `logs/`.

## State preservation

The main repository had pre-existing staged deletions and rename, unstaged modifications, and untracked research/test files. Each of the six OpenSSL worktrees had a pre-existing unstaged modification to `test/smime-eml/SignedInvalidMappingFromanyPolicyTest7.eml`; their pinned HEAD hashes did not change. These states are recorded in `baseline_git_state.txt` and `worktree_status_final.txt`. No OpenSSL source file was edited. No staging, commit, reset, checkout, clean, or history operation was performed.

This audit added only checker logic in the already modified `src/typestate_check.py`, a new `tests/test_pem_ssl_adversarial.py`, and evidence under `research/10_cve_rule_audit_20261105/`. The original staged and unstaged states were not staged or reverted.

## Claims and limits

The test outcomes validate only that these source fixtures exercise the supported rules as expected. They do not establish general C typestate analysis, formal soundness, comprehensive CWE coverage, or runtime behavior for every CVE. Runtime evidence previously recorded for CVE-2023-0215 remains separate and was not rerun here. Additional limits are listed in `KNOWN_LIMITATIONS.md`.
