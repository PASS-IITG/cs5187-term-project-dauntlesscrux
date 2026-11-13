# Candidate: `rsa_ossl_finish` has the same unreset-free shape as the fixed `dh_finish`/`dsa_finish` bug

Written by Claude (this session), in response to the authors' explicit
request to actively hunt for a new, currently-unfixed bug, not just
re-triage known sites. Found via Protocol C (`src/tsck/protocol_c.py`,
exploratory, see `specs/structfield_reset.json`), manually prioritized out
of its 146-site master-tree candidate set because its name and role
(`*_finish`, the `finish` slot of an `RSA_METHOD`) exactly match the shape
of two bugs already confirmed and fixed elsewhere in this codebase.

**Status: candidate, not a confirmed vulnerability.** This write-up
establishes the source-level shape and a concrete trigger path by reading
real code; it does not include a built/run proof-of-concept, a fault
injection, or any confirmation from the OpenSSL team. Treat it the same
way the paper treats the two Protocol B candidates in
`reachability_rq1_candidates.md`: a specific, falsifiable claim, not a
finding.

## The motivating, already-fixed pair

`crypto/dh/dh_lib.c` (`dh_finish`) and `crypto/dsa/dsa_lib.c` (`dsa_finish`)
each freed a cached `BN_MONT_CTX *` field (`method_mont_p`) with no reset
to `NULL`. Both were fixed the same day, by the same author, in commits
`a32df28664` (DH) and `73f3bd8871` (DSA) — see
`results/historical_recurrence_search.md`, row 2026-08-27. (Those two
specific commit objects are not present in this session's shallow
checkout, so I did not re-diff them directly here; their existence and
shape are taken from the historical-recurrence search already done and
cross-checked this session, not re-verified a second time.)

## The RSA sibling, read directly from the pinned master snapshot

`crypto/rsa/rsa_local.h:91-93` declares the exact same kind of field on
`struct rsa_st`:

```c
BN_MONT_CTX *_method_mod_n;
BN_MONT_CTX *_method_mod_p;
BN_MONT_CTX *_method_mod_q;
```

`crypto/rsa/rsa_ossl.c:1179-1194`, `rsa_ossl_finish`:

```c
static int rsa_ossl_finish(RSA *rsa)
{
#ifndef FIPS_MODULE
    int i;
    RSA_PRIME_INFO *pinfo;

    for (i = 0; i < sk_RSA_PRIME_INFO_num(rsa->prime_infos); i++) {
        pinfo = sk_RSA_PRIME_INFO_value(rsa->prime_infos, i);
        BN_MONT_CTX_free(pinfo->m);
    }
#endif

    BN_MONT_CTX_free(rsa->_method_mod_n);
    BN_MONT_CTX_free(rsa->_method_mod_p);
    BN_MONT_CTX_free(rsa->_method_mod_q);
    return 1;
}
```

All three fields are freed. None is reset to `NULL`. `rsa` itself is not
freed, is not zeroed, and is returned alive (`return 1`). This is
registered as the `finish` slot of `rsa_pkcs1_ossl_meth`
(`crypto/rsa/rsa_ossl.c`, the struct literal just above `rsa_ossl_init`):

```c
static const RSA_METHOD rsa_pkcs1_ossl_meth = {
    ...
    rsa_ossl_init,
    rsa_ossl_finish,
    ...
};
```

`rsa_ossl_init` (`crypto/rsa/rsa_ossl.c:1173-1177`) is the paired `init`
slot. I read its full body:

```c
static int rsa_ossl_init(RSA *rsa)
{
    rsa->flags |= RSA_FLAG_CACHE_PUBLIC | RSA_FLAG_CACHE_PRIVATE;
    return 1;
}
```

It does **not** reset `_method_mod_n`/`_method_mod_p`/`_method_mod_q`.
There is no other code path in `rsa_ossl.c` that resets them after
`rsa_ossl_finish` runs; a `grep` for all three field names in
`crypto/rsa/*.c` shows every other use is a read (passed to
`BN_MONT_CTX_set_locked`'s double-checked-lazy-init pattern, or to a
modular-exponentiation call), none of which null-checks or reinitializes
a dangling pointer — `BN_MONT_CTX_set_locked` only *sets* the field if it
is currently `NULL`; since `rsa_ossl_finish` leaves it non-`NULL` (just
freed), the lazy-init path is also bypassed, so the first subsequent use
of `rsa->_method_mod_n` after a `finish` call is a stale-pointer
**use**, not just a future double-free.

## The trigger: the same mechanism as the confirmed `dh_finish`/`dsa_finish` bug

`crypto/rsa/rsa_lib.c`, `RSA_set_method`:

```c
int RSA_set_method(RSA *rsa, const RSA_METHOD *meth)
{
    const RSA_METHOD *mtmp;
    mtmp = rsa->meth;
    if (mtmp->finish)
        mtmp->finish(rsa);
    rsa->meth = meth;
    if (meth->init)
        meth->init(rsa);
    return 1;
}
```

This is a public API (`RSA_set_method`, declared in `include/openssl/rsa.h`,
unchanged in meaning since at least 2014 per
`f8c03d4dbf43cadb14abffbe4d69eb6b4bdff50f`). It calls the *old* method's
`finish` on the live object, reassigns `rsa->meth`, then calls the *new*
method's `init`. It does not clear or reset anything on `rsa` itself
beyond what the two method callbacks do.

Concretely, for an `RSA *rsa` currently using `rsa_pkcs1_ossl_meth` (the
default — i.e. essentially every `RSA` object that has not had a
non-default engine/provider method installed):

1. `RSA_set_method(rsa, meth2)` is called, where `meth2` is anything.
   `mtmp->finish` is `rsa_ossl_finish`; it runs, freeing
   `rsa->_method_mod_n/p/q` without resetting them. `rsa->meth` becomes
   `meth2`.
2. `RSA_set_method(rsa, meth3)` is called again on the *same* `rsa`
   (`meth3` can be `meth2` again, a third method, or back to
   `RSA_PKCS1_OpenSSL()`), where `meth3`'s old method — i.e. `meth2` — also
   has `rsa_ossl_finish` as its `finish` slot (true whenever `meth2` is
   `RSA_PKCS1_OpenSSL()` itself, or any method built by copying/wrapping
   `rsa_pkcs1_ossl_meth` without overriding `finish`, a common engine
   pattern). `rsa_ossl_finish` runs a second time on the same, still-live
   `rsa`, calling `BN_MONT_CTX_free` on the same three pointers it already
   freed in step 1 and never reset — a double free on all three fields,
   fully attacker/caller-reachable with no race, no threading, and no
   internal OpenSSL bug required: just two ordinary calls to a public,
   documented API on one object from one thread.

This is a strictly simpler trigger than the two Protocol B candidates in
`reachability_rq1_candidates.md`, which both require an unsynchronized
second thread. Here, sequential single-threaded misuse is sufficient. It
is also the *exact* trigger shape the historical search's table already
attributes to the fixed `dh_finish` bug ("a subsequent finish call -- e.g.
via `DH_free()` after `DH_set_method()` -- frees it again"): `RSA_free()`
itself is an equally valid second trigger, since (`crypto/rsa/rsa_lib.c`,
`RSA_free`) it also calls `r->meth->finish(r)` unconditionally during
teardown — so `RSA_set_method(rsa, meth2)` once, followed by
`RSA_free(rsa)`, double-frees the same three fields if `meth2`'s `finish`
is also `rsa_ossl_finish`.

**Correction after checking in-tree callers (see below): `RSA_set_method`
is `OSSL_DEPRECATEDIN_3_0`**, not a current-generation API —
`include/openssl/rsa.h:311`. It is still compiled, exported, and used (by
the three in-tree test call sites below), just discouraged for new
application code. "Public and callable" still holds; "current,
undeprecated API" does not, and the write-up above overstated this before
I checked `rsa.h`.

## What I checked, and what I did not

**In-tree callers, checked.** `grep -rn "RSA_set_method"` across this
checkout's `crypto/`, `ssl/`, `providers/`, `test/`, and every header finds
exactly one definition (`rsa_lib.c`) and three call sites, all in
`test/evp_extra_test.c` (lines 1766, 8979, 9040). I read all three. Two of
them (`test_low_level_rsa_method`, line ~8946, and the KEM variant at line
~9040) do exactly this:

```c
const RSA_METHOD *def = RSA_get_default_method();
RSA_METHOD *method = RSA_meth_dup(def);   /* memcpy of the whole struct -- rsa_meth.c:45-57 */
...
RSA_meth_set_priv_enc(method, tst_rsa_priv_enc);   /* overrides ONLY priv_enc (or pub_enc) */
...
rsa = RSA_new();
RSA_generate_key_ex(rsa, 1024, e, NULL);
...
RSA_set_method(rsa, method);   /* old method (default) -> finish = rsa_ossl_finish runs HERE */
```

`RSA_meth_dup` is a `memcpy` of the entire `RSA_METHOD` struct
(`crypto/rsa/rsa_meth.c:45-57`), so `method`'s `finish` slot is still
`rsa_ossl_finish`, byte-for-byte copied from the default method — these
tests never override `finish`. So **this existing, currently-passing test
already executes exactly half of the trigger path** described above: a
live `RSA` object switches away from the default method, which calls
`rsa_ossl_finish` once, and is later freed through a method whose `finish`
is still `rsa_ossl_finish` (triggering it a second time via `RSA_free`).

It does not crash, and I can explain why from the code, not just assume
it: `RSA_generate_key_ex` (pure prime generation) does not call
`rsa_ossl_mod_exp` or anything that populates `_method_mod_n/p/q` via the
lazy `BN_MONT_CTX_set_locked` pattern, and the custom `method` only
overrides `priv_enc`/`pub_enc` with test stubs (`tst_rsa_priv_enc` /
`tst_rsa_pub_enc`) that do not touch those fields either. So at both
`finish` calls in this specific test, all three fields are still `NULL`,
and `BN_MONT_CTX_free(NULL)` is a documented no-op. The test exercises the
*mechanism* (switch-then-free-through-a-dup) without ever populating the
pointers that would make it a real double free.

**The missing step, concretely.** The actual bug needs one more thing
this test doesn't do: at least one RSA private- or public-key operation
performed through the *original* default method (an `RSA_private_decrypt`,
`RSA_sign`, etc., or anything that reaches `rsa_ossl_mod_exp`'s
`BN_MONT_CTX_set_locked(&rsa->_method_mod_n, ...)` call) *before*
`RSA_set_method` is called. That single extra operation populates
`_method_mod_n` (and, for CRT-capable keys, `_method_mod_p`/`_method_mod_q`
too) with a real, non-`NULL` `BN_MONT_CTX *`. Everything after that is
exactly the existing test's sequence. I have not located an in-tree
caller that does this specific thing (operation, then
`RSA_set_method`/second `finish`); the three in-tree call sites above do
not. I have not searched `apps/`, external engine implementations, or
application code outside this tree for this exact ordering, and I have
not written or run the ~15-line reproducer that would force it. **This
remains the single most important open step before treating this as more
than a sound-but-unexercised argument.**

- **No built reproducer.** I have not compiled OpenSSL and written the
  ~15-line C program (generate a key, do one `RSA_private_decrypt` or
  `RSA_sign` through the default method, then `RSA_set_method` to a dup
  of the default, then free) that would turn this from a source-level
  argument into an observed crash/ASan report.
- **No check of whether upstream already knows.** I searched
  `openssl/openssl`'s commit history for `rsa_ossl_finish`,
  `_method_mod`, and `RSA_set_method` (via `gh api search/commits`) and
  found no fix, no issue reference, and no test addressing this specific
  double-free — only unrelated documentation and test commits. This is
  not the same as confirming no open GitHub issue or private advisory
  exists; I did not search GitHub Issues/Security Advisories for this
  repository (the `gh` access available in this session is for commit
  search and public git fetch, not issue search, and I did not attempt to
  route around that).
- **Whether this is exploitable for more than a crash** (use-after-free
  read into attacker-influenced data, vs. a clean double-free abort) is
  not analyzed here.

## Why this is being reported as a candidate, not written into the paper as a finding

Per the paper's own stated discipline (Section~\ref{sec:threats},
construct threats: "a violation is a source-pattern property, not a proven
vulnerability"), this needs the same two things the two Protocol B
candidates still need before anyone calls it a bug: a check of whether the
precondition is reachable from any *actual* call site (not just "the API
permits it"), and ideally a running reproducer. The source-level argument
above is strong enough to be worth the authors' attention, for two
reasons that go beyond the two existing candidates: it needs no race (a
single thread, two ordinary calls, is enough), and OpenSSL's own test
suite already exercises half of the exact trigger mechanism today without
crashing, for a reason I verified from source rather than assumed. It is
weaker on one axis the two existing candidates are not: `RSA_set_method`
is a deprecated-since-3.0 API, so the realistic population of callers
still invoking it (legacy engine integrations, not new code) is smaller
than for an undeprecated API. Whether to report this to the OpenSSL
security team is the authors' call, not mine to make unilaterally -- it
would mean naming a specific, currently-unfixed double-free in a
widely-deployed library to a third party, which needs the authors'
explicit sign-off regardless of how sound the argument reads here.
