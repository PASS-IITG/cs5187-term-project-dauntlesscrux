# Reachability re-check: the 2 "potential recurrence" sites from Observation 2 (master triage)

Written by Claude (this session), independently re-deriving reachability for
`X509_PUBKEY_set` (`crypto/x509/x_pubkey.c`) and `ossl_ml_kem_i2d_pubkey`
(`providers/implementations/encode_decode/ml_kem_codecs.c`) against the real
source at the pinned master commit `949fe8b5f48c4c82bff6be7fb23de473ab6945a0`,
fetched fresh via `git fetch --depth 1 origin <sha>` from `openssl/openssl`
(not reused from any earlier checkout). This supersedes part of the existing
reasoning in `triage.md`/`triage.csv` for these two rows: one of the two
claims there is **factually wrong**, found by reading the real code, not by
assumption.

## X509_PUBKEY_set: the existing "needs EVP_PKEY_up_ref to fail (lock/atomic
failure)" claim is wrong

`X509_PUBKEY_set` (`crypto/x509/x_pubkey.c:334`):

```c
X509_PUBKEY_free(*x);
if (!EVP_PKEY_up_ref(pkey)) {
    ERR_raise(ERR_LIB_X509, ERR_R_INTERNAL_ERROR);
    goto error;
}
*x = pk;
...
error:
    X509_PUBKEY_free(pk);
    return 0;
```

`*x` is freed, then the function may `goto error` without ever resetting
`*x` -- the `error:` label frees `pk` (the newly built replacement), never
`*x` again, and never sets `*x = NULL`. This is the correct violation shape
(same as Protocol B flags it).

The existing triage note says this needs "EVP_PKEY_up_ref to fail
(lock/atomic failure)". That is checked against the real implementation and
is **wrong**: `EVP_PKEY_up_ref` (`crypto/evp/p_lib.c:1594`) is

```c
int EVP_PKEY_up_ref(EVP_PKEY *pkey)
{
    int i;
    if (!CRYPTO_UP_REF(&pkey->references, &i))
        return 0;
    REF_PRINT_COUNT("EVP_PKEY", i, pkey);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}
```

`CRYPTO_UP_REF` (`include/internal/refcount.h`) has six platform variants in
this codebase (C11 atomics, GCC/Clang builtins, MSVC intrinsics x2, a
lock-based fallback, and a no-threads fallback) and **every single one of
them always returns `true`** -- none can report an "atomic/lock failure".
So `!CRYPTO_UP_REF(...)` is dead code in every build this codebase ships;
the real triage note's premise does not hold.

The real and only way `EVP_PKEY_up_ref` returns 0 is the second line:
`return ((i > 1) ? 1 : 0);`, where `i` is the *post-increment* reference
count. This is 0 exactly when `i == 1`, i.e. the reference count was already
0 immediately before this call -- `pkey` had already lost its last reference.
`REF_ASSERT_ISNT(i < 2)` is a debug-only assertion (compiled out in a normal,
non-`REF_DEBUG` build) guarding exactly this condition, which tells us the
authors consider "a 0-refcount object is about to be up-ref'd" to be an
internal-consistency violation, not a designed runtime-failure path.

**Corrected reachability argument:** the violation triggers only if a caller
passes an `EVP_PKEY *pkey` whose reference count has already reached 0 at
the moment `X509_PUBKEY_set` dereferences it. Checking every in-tree caller
(`crmf_lib.c`, `ct_sct.c` x2, `v3_akid.c`, `x509_set.c`, `x509spki.c`,
`x_req.c`, `x509rset.c`) -- all are public-API entry points
(`X509_set_pubkey`, `X509_REQ_set_pubkey`, etc.) that forward an
application-supplied `pkey` straight through; none of them manufacture a
0-refcount `pkey` internally. So within this codebase, reaching this branch
requires the *calling application* to already have a bug: either (a) it has
already dropped its last reference to `pkey` before calling (a
use-after-free on `pkey` that exists before `X509_PUBKEY_set` is ever
entered), or (b) a second thread concurrently drops `pkey`'s last reference
while this thread is inside `X509_PUBKEY_set`, with no external
synchronization protecting the shared `pkey` (a data race, which is itself
undefined behavior and a caller contract violation -- OpenSSL's reference
counting is thread-safe for concurrent up/down-ref calls themselves, but
does not make it safe to call `X509_PUBKEY_set` on a `pkey` another thread
may simultaneously free to zero).

Neither (a) nor (b) is "a lock/atomic op failing on some platform" as
originally written -- that claim is now retracted as checked-and-wrong.
Both (a) and (b) require a pre-existing bug or data race in the *caller*,
not something `X509_PUBKEY_set` can trigger on its own through any valid,
single-threaded sequence of public-API calls. We did not find an in-tree
(same-codebase) caller that creates this precondition. We therefore do not
upgrade this from "candidate" to "confirmed": it remains a site whose own
cleanup is wrong (a real instance of the same release-without-reset shape)
but whose trigger requires a bug that must already exist one level up the
call stack, not something reachable from a single corrected entry point.

## ossl_ml_kem_i2d_pubkey: the existing "unreachable by code reading" claim
is right, but for a more precise reason than stated

`ossl_ml_kem_i2d_pubkey` (`ml_kem_codecs.c:279`):

```c
int ossl_ml_kem_i2d_pubkey(const ML_KEM_KEY *key, unsigned char **out)
{
    size_t publen;
    if (!ossl_ml_kem_have_pubkey(key)) { ... return 0; }
    publen = key->vinfo->pubkey_bytes;
    if ((*out = OPENSSL_malloc(publen)) == NULL)
        return 0;
    if (!ossl_ml_kem_encode_public_key(*out, publen, key)) {
        ...
        OPENSSL_free(*out);
        return 0;      /* *out not reset -- the flagged violation */
    }
    return (int)publen;
}
```

and `ossl_ml_kem_encode_public_key` (`crypto/ml_kem/ml_kem.c:2133`):

```c
int ossl_ml_kem_encode_public_key(uint8_t *out, size_t len,
                                   const ML_KEM_KEY *key)
{
    if (!ossl_ml_kem_have_pubkey(key) || len != key->vinfo->pubkey_bytes)
        return 0;
    encode_pubkey(out, key);
    return 1;
}
```

`ossl_ml_kem_have_pubkey(key)` is `#define ossl_ml_kem_have_pubkey(key)
((key)->t != NULL)` (`include/crypto/ml_kem.h:247`) -- a plain field read
with no side effect. `len` is passed in as `publen`, which was set by the
caller to `key->vinfo->pubkey_bytes` immediately before, from the same
`key`. So inside a single-threaded, straight-line call, both conditions in
`ossl_ml_kem_encode_public_key`'s guard are provably true (identical to the
values just checked in the caller), and the function cannot return 0 --
unless `key->t` or `key->vinfo->pubkey_bytes` changes between the caller's
check and the callee's check. `key` is `const ML_KEM_KEY *` throughout this
call chain and nothing in `ossl_ml_kem_i2d_pubkey` (an `OPENSSL_malloc` call)
can mutate it. As with the `X509_PUBKEY_set` case, the only way to reach
this branch is a second thread concurrently clearing the same `ML_KEM_KEY`'s
public-key state while this thread is encoding it -- again a data race
across threads sharing one key object without external synchronization, not
a deterministic path through any single call.

## Bottom line

Both of the master snapshot's 2 "potential recurrence" sites have the same
real shape, once checked precisely: the dangling-pointer cleanup bug itself
is real and matches CVE-2022-4450's pattern, but triggering it requires a
*second*, independent bug or an unsynchronized data race in code we did not
find anywhere in this codebase (reachable only from a buggy or racing
caller, not from any single corrected call site in-tree). This is a
materially more precise statement than either original note, and it
corrects one factual error (`EVP_PKEY_up_ref` cannot fail from a lock/atomic
op; that is dead code on every platform OpenSSL supports). We did not
attempt a multithreaded fault-injection build to force the race window --
that is future work, noted honestly rather than assumed to be either
impossible or demonstrated.
