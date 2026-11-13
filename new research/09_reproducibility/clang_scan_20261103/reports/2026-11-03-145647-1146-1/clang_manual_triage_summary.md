# Clang Static Analyzer manual triage

## Scope and outcome

Manually reviewed the 31 production-filtered reports in this scan against pinned source revision `ed57129cd43b77e077c68fd5f7ea951976766f38`. The triage CSV contains 24 FP, 2 TP report rows, and 5 INCONCLUSIVE. The two TP rows (`report-3db729.html` and `report-71c964.html`) are **two analyzer paths to one source-level candidate**, not two independent defects. Both reach a scratch-buffer read before initialization in `bn_mod_add_fixed_top()` (`crypto/bn/bn_mod.c:76,80`) for valid zero-operand states.

For those paths, the zero BIGNUM produces an initialized zero mask, so the uninitialized operand value is ANDed with zero. The focused harness used the instrumented OpenSSL implementation for `a=0,b=0,m=17` and `a=1,b=0,m=17`; both returned expected results and MemorySanitizer emitted no diagnostic. MSan uses bit-level definedness propagation, under which an uninitialized value ANDed with an initialized zero becomes initialized zero. A negative-control uninitialized read did trigger MSan, confirming instrumentation was active. This runtime result does not disprove the source-level read-before-initialization, but **runtime impact remains unconfirmed**. These TP labels describe the source-level analyzer candidate; they do not confirm a vulnerability, security impact, or exploitability. Valgrind/Memcheck was unavailable.

The five inconclusive reports are `report-5cdb68.html`, `report-91ffc7.html`, `report-efbbbe.html`, `report-f5f1a2.html`, and `report-fda1e4.html`. They remain open because API contract, malformed-input handling, or a full allocation/control-flow invariant was not established. The remaining 24 reports were classified FP where the reported state conflicts with reviewed initialization, ownership, capacity, or control-flow invariants.

## Follow-up priorities

1. Keep the BIGNUM case as one source-level candidate and assess whether a read masked to zero violates the applicable C/OpenSSL correctness or security requirements. Do not count the two analyzer reports as two defects or as runtime-confirmed findings.
2. Resolve the five inconclusive cases by checking documented contracts and valid caller states for ASN.1 string setters, GF(2^m) polynomial arrays, ASN.1 object encoding, and pointer-valued OSSL_PARAM builder entries.
3. Treat the remaining FPs as lower-priority unless new evidence challenges their source invariants. Runtime reproduction was not performed for those reviews.

## Methodology limits

This is a manual, source-level review of a production-filtered set of analyzer reports, not a measurement of Clang or the companion Python analyzer's soundness, completeness, or overall detection accuracy. The Python analyzer uses three CVE-specific heuristics; CVE regression results must be reported separately from whole-tree discovery and this manual evaluation. No broad test suite was run. Labels are conditional on the source revision and invariants stated in each CSV evidence/limitations field.

The focused MSan harness, negative control, reproduction instructions, manifest, and raw logs are archived in [`bn_mod_add_msan`](../../bn_mod_add_msan/README.md).
