# Protocol A whole-tree triage (master snapshot, 949fe8b5f48c4c82bff6be7fb23de473ab6945a0)

Run by Claude (this session) against a real, independently-cloned copy of the
pinned master snapshot (`git worktree` + sparse-checkout, same SHA as
`environment.txt`), using `protocol_a.py` after the alias-through-return-value
fix. Command: `python3 protocol_a.py ossl/snap_master_2026_10_30/{crypto,ssl,providers}`.
Result reproduced exactly: `files=1155 release-sites: conforming=10 violation=11`.

Every one of the 11 flagged sites was individually checked against the real
source at this exact commit (cloned separately via `git fetch` to
`openssl/openssl` at the pinned SHA). None is a confirmed recurrence of
CVE-2023-0215. All 11 are false positives, for one of two distinct reasons.

## Reason A: tool cannot correlate a guard flag with an earlier branch

| # | Site | Reason |
|---|------|--------|
| 1 | `crypto/asn1/asn1_parse.c:81` `asn1_print_info()` | The function DOES call `BIO_pop(bp)` correctly, guarded by `if (pop_f_prefix)`. `pop_f_prefix` is set to 1 in the exact same branch as the earlier successful push, so on every path where the push actually happened, the pop always runs. The checker has no boolean-flag/branch correlation (same class of approximation already disclosed for Protocol B's lack of alias analysis), so it sees a path through the `if (pop_f_prefix)` false-branch that looks reachable from establish but in practice cannot occur together with a real push. |

## Reason B: the released chain is entirely self-contained; no caller-owned BIO is ever spliced in before the release

CVE-2023-0215's actual danger requires an *externally-owned* BIO (the caller's
own, still alive after the function returns) to be linked into a chain whose
head is then released. Protocol A's rule, as derived, has no notion of
ownership or escape, so it also flags functions that build a chain entirely
from freshly-allocated, purely local BIOs and clean the whole thing up with
`BIO_free_all` on error -- a completely ordinary and safe OpenSSL idiom. In
every case below, the variable released at the flagged site, and every BIO
reachable from it via `->next`, was allocated inside the same function and
never escapes to a caller before the release.

| # | Site | Why it's self-contained |
|---|------|--------------------------|
| 2 | `crypto/bio/bio_lib.c:932` `BIO_dup_chain()` | `eoc`/`ret` is a brand-new chain of `BIO_new()` copies; the caller's original chain `in` is only read (`bio->method`, `bio->next_bio`, ...), never linked into `ret`, and is untouched by the `err:` cleanup. |
| 3 | `crypto/cms/cms_sd.c:1422` `ossl_cms_SignedData_init_bio()` | `chain` is built only from `mdbio` values returned by `ossl_cms_DigestAlgorithm_init_bio()`, all freshly allocated inside the loop; nothing caller-owned is linked before `err:`. |
| 4 | `crypto/pkcs7/pk7_doit.c:412` `PKCS7_dataInit()` | `out` is built only from local `btmp` pieces; the caller-owned parameter `bio` is pushed onto `out` only in the final success-path line, strictly after every `goto err` in the function, so `out` never holds `bio` at the point `BIO_free_all(out)` runs. |
| 5 | `crypto/pkcs7/pk7_doit.c:685` `PKCS7_dataDecode()` | Same shape as #4: `out` is built from local `etmp` pieces; the caller-owned `in_bio` is aliased into `bio` and pushed onto `out` only in the success tail, with no `goto err` in between. |
| 6 | `crypto/pkcs7/pk7_smime.c:542` `PKCS7_decrypt()` (the `bread` site) | `tmpmem` (from `PKCS7_dataDecode`, locally owned) and `tmpbuf` (freshly allocated) are pushed together into `bread`, then `BIO_free_all(bread)` on the normal return path intentionally frees the whole, fully local chain at once. No external reference survives; nothing needed popping first. |
| 7 | `ssl/bio_ssl.c:478` `BIO_new_buffer_ssl_connect()` | `buf` and `ssl` are both freshly created (`BIO_new`, `BIO_new_ssl_connect`) inside this function; no caller-owned BIO is involved at all (`ctx` is an `SSL_CTX`, not a `BIO`). |
| 8 | `ssl/bio_ssl.c:504` `BIO_new_ssl_connect()` | Same shape as #7: `ssl` and `con` are both freshly created locally. |
| 9 | `ssl/ech/ech_store.c:644` `ech_read_priv_echconfiglist()` | `btmp`/`btmp1` both wrap a local memory buffer (`BIO_new_mem_buf`, `BIO_new(BIO_f_base64())`); neither the function's `in` parameter nor anything else escapes into this chain before the `BIO_free_all`. |

## Reason A/C: push-failure branch is not reachable in normal builds

| # | Site | Reason |
|---|------|--------|
| 10 | `crypto/bio/bss_acpt.c:331` `acpt_state()` | The flagged free happens only if `BIO_push(b, bio)` returns NULL, which per the documented contract of `BIO_push` cannot happen once its first argument (`b`) is already proven non-NULL, as it is here. If this branch were ever reached, freeing `dbio` with plain `BIO_free` (not `_all`) would leak the duplicated chain's tail rather than cause a use-after-free -- a different defect class (resource leak) than the one this rule checks for, and likely unreachable regardless. |
| 11 | `crypto/pkcs7/pk7_smime.c:533` `PKCS7_decrypt()` (the push-failure site) | Flagged free happens only if `BIO_push(tmpbuf, tmpmem)` returns NULL, which again requires `tmpbuf` (just allocated and checked non-NULL two lines above) to be NULL -- not reachable in a normal build. |

## Bottom line

0 of 11 whole-tree violations are confirmed or even plausible recurrences of
CVE-2023-0215. This is a real, useful result: it shows precisely where the
single-object, no-ownership-tracking rule derived from one CVE breaks down
when generalized across a codebase that idiomatically builds and tears down
self-contained local BIO chains -- exactly the multi-object/ownership
correlation gap already predicted (without evidence) in `related.tex`'s
comparison to VulPA. The motivating pair (CVE-2023-0215 itself) is correctly
distinguished (violation pre-fix, conforming post-fix); the generalization
claim stops there, and we did not find grounds to claim more.
