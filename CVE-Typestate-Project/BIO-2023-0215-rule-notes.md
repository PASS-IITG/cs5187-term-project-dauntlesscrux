# Manual Rule Derivation: CVE-2023-0215

## 1. Evidence from the vulnerable source

- `BIO_push(asn_bio, out)` links the ASN.1 BIO into the output BIO chain.
- If a later operation fails, execution can jump to the `err:` label.
- The vulnerable cleanup calls `BIO_free(asn_bio)` and then frees
  `ndef_aux`, without first detaching `asn_bio` from the chain.
- `BIO_push()` establishes the `next_bio` and `prev_bio` links.
  `BIO_free()` does not perform the link-repair operations implemented
  by `BIO_pop()`.

## 2. Evidence from the fixed source

- The patch adds `BIO *pop_bio = NULL`.
- After a successful push, it records `pop_bio = asn_bio`.
- The error cleanup calls `BIO_pop(pop_bio)` before `BIO_free(asn_bio)`.
- The patch documents the ownership contract: on success, the returned
  BIO owns the input BIO as part of its chain; on failure, NULL is
  returned and the input BIO remains caller-owned.
- The patch also changes other error handling. The BIO cleanup change
  should therefore be interpreted together with the source diff and
  runtime evidence, not as an isolated textual difference.

## 3. Evidence from runtime testing

- The vulnerable historical checkout produced an AddressSanitizer
  heap-use-after-free report.
- The recorded use site was `BIO_pop()` in
  `crypto/bio/bio_lib.c:678`.
- The recorded free site was `BIO_free()` in `BIO_new_NDEF()` in
  `crypto/asn1/bio_ndef.c:100`.
- The fixed checkout did not produce the corresponding
  AddressSanitizer memory-safety report under the recorded command.
- The fixed command returned an error because DES-CBC cipher
  initialization was unsupported. The result supports the fix for
  this reproduction but does not prove the entire operation succeeded
  or that all related vulnerabilities are absent.

## 4. Proposed rule

Rule identifier: TS-BIO-01

Scope:
Investigate cleanup paths in which a BIO has been linked into a chain
and may be released while another live BIO still refers to it.

Required condition:
Establish that the relevant BIO was linked into a chain and that a
failure path can reach cleanup after the link was established.

Violation:
A cleanup path releases the linked BIO without first restoring the
chain links when the remaining chain continues to exist.

Expected safe behaviour:
Detach the BIO using the appropriate chain operation, such as
BIO_pop(), before releasing it, consistent with the API ownership
contract and the actual control-flow path.

Important qualification:
A text occurrence of BIO_pop() is not sufficient evidence of safe
cleanup. The call must be reachable on the relevant path and must
operate on the relevant BIO.

## 5. Limitations

- The existing checker extracts a specifically named function and
  searches for exact strings. It is not a general C parser.
- It does not adequately model control flow, aliases, ownership,
  or all error paths.
- A BIO_pop() in an unreachable branch can cause a false negative.
- A BIO_push() inside a comment can cause a false positive.
- The current checker skips other functions, including
  B64_write_ASN1(), rather than checking analogous lifecycle patterns.
- A NO ALERT result does not prove that a function is safe.
- The current rule does not detect all use-after-free, double-free,
  memory ownership, or typestate violations in OpenSSL.

## 6. Current conclusion

The vulnerable/fixed comparison and the recorded AddressSanitizer
reproduction support the proposed BIO-chain ownership explanation
for CVE-2023-0215.

The existing checker distinguishes the selected vulnerable and fixed
source files, but adversarial tests demonstrate that its string-based
logic is not reliable enough for broad detection claims.

The next research task is to improve the bounded BIO lifecycle check,
evaluate it against independently selected real-source examples,
and manually review candidate recurrences. No new vulnerability is
claimed by this analysis.
