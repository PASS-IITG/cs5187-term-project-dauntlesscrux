# Re-check of the 2 "Unclear" sites: `OSSL_CMP_get1_rootCaKeyUpdate`'s `*newWithOld`/`*newWithNew`

Written by Claude (this session). `triage.md` labeled these two sites
"Unclear... callers or contract not yet read" -- an open item
`threats.tex` named explicitly as not independently re-derived, unlike
the 2 "potential recurrence" sites. This closes that gap the same way:
by reading the real pinned-commit source and every real caller, not by
guessing from the function's shape.

## The function, read in full

`crypto/cmp/cmp_genm.c:307-368`, `OSSL_CMP_get1_rootCaKeyUpdate`. Three
output parameters (`newWithNew`, `newWithOld`, `oldWithNew`) are borrowed
from `itav` via `OSSL_CMP_ITAV_get0_rootCaKeyUpdate` (a `get0`, so no
ownership yet), then the function tries to upgrade each to an owned
reference with `X509_up_ref`. On success for all three needed, it returns
1 with every requested output owned and set.

On a partial failure -- `X509_up_ref(*newWithOld)` fails (line 354) or
`X509_up_ref(*oldWithNew)` fails (line 356) after `*newWithNew` was
already up-ref'd (line 352) -- the function frees what it already took a
reference to (`X509_free(*newWithNew)` at the `free:` label, and
`X509_free(*newWithOld)` just above it when that path is taken) but never
resets either output pointer to `NULL` before returning 0. This matches
the triage note: both can be left holding a pointer to a now-freed `X509`
on a failure return.

## Is the failure branch reachable?

`X509_up_ref` (`crypto/x509/x509_set.c:116-126`):

```c
int X509_up_ref(X509 *x)
{
    int i;
    if (!CRYPTO_UP_REF(&x->references, &i))
        return 0;
    REF_ASSERT_ISNT(i < 2);
    return i > 1;
}
```

Same shape, same primitive, as `EVP_PKEY_up_ref` in
`reachability_rq1_candidates.md`: `CRYPTO_UP_REF` itself is already shown
there to always return `true` on every platform this codebase builds for
(all 6 variants), so that branch is dead code here too, for the same
reason, not re-derived twice. The only way `X509_up_ref` returns 0 is `i
<= 1` after incrementing, i.e. the object's reference count was already
`<= 0` *before* this call -- the same "pre-existing caller bug or a data
race" precondition as the two potential-recurrence sites.

Here, that precondition is harder to construct than for the other two
sites, not easier: `my_newWithOld`/`my_oldWithNew` are references into
`itav`, an `OSSL_CMP_ITAV` freshly built from the just-received GENP
message a few lines earlier in the same call (`get_genm_itav`, line 323)
-- nothing else in this process has had a chance to hold or drop a
reference to these specific certificate objects yet, let alone race one
down to a non-positive count, within a single synchronous protocol
exchange. So this failure branch needs the same class of precondition as
the other two candidates, with less plausible machinery to create it.

## The one real caller

```
grep -rn "OSSL_CMP_get1_rootCaKeyUpdate" .   (whole tree: crypto/, ssl/, providers/, apps/, test/)
```

finds exactly two hits: the definition itself, and one call site,
`apps/cmp.c:3547-3550`:

```c
if (!OSSL_CMP_get1_rootCaKeyUpdate(ctx, oldwithold, &newwithnew,
        &newwithold, &oldwithnew))
    goto end_upd;
...
X509_free(newwithnew);
X509_free(newwithold);
X509_free(oldwithnew);
end_upd:
X509_free(oldwithold);
return res;
```

On failure, the caller jumps straight to `end_upd:`, which frees only
`oldwithold` (a separate local the caller itself owns) -- the three
`X509_free` calls that would act on `newwithnew`/`newwithold`/`oldwithnew`
are on the success-path side of that `goto` and are skipped entirely.
Whatever value `OSSL_CMP_get1_rootCaKeyUpdate` left in those three local
variables on a failure return is never read or freed again; the function
returns shortly after and the locals go out of scope. There is no second
free and no later dereference in the only real call site in this tree,
and no caller exists in `test/` either (the same `grep` found none),
so there is no unit test exercising this path.

## Conclusion: convention deviation, no impact -- same category as the 6 existing sites, not potential recurrence

This resolves the "unclear" label. The release-without-reset pattern is
real (confirmed from source, same as before), and the failure branch has
the same theoretical reachability profile as the two potential-recurrence
sites (a pre-existing race on a reference count), but the one real caller
discards the possibly-dangling output entirely rather than acting on it
-- the same shape `triage.md` already uses for `ssl_cipher_get_evp` and
`extract_keyshares`'s convention-deviation sites ("every caller discards
it or documents that behaviour"). I did not find a second caller anywhere
in this tree, in `apps/` or `test/`, so "no impact" here rests on there
being exactly one caller to check, not on checking many and finding all
of them safe.
