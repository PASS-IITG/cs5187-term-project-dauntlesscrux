# Independent evidence the release-without-reset convention recurs broadly in OpenSSL

Written by Claude (this session). Goal: address "is this really a recurring
problem, or did we just pick one lucky CVE" independently of anything the
team built, by searching OpenSSL's real commit history for other,
unrelated fixes of the exact same shape this paper studies (free a
tracked pointer, fail to reset it, a later path double-frees or
use-after-frees it).

## Method

Searched GitHub's commit-message index for `openssl/openssl` via
`gh api search/commits -f q='repo:openssl/openssl double-free'`
(104 total hits at time of search, 2026-11-10), then read the real diff
of each of the ten most recent, most clearly on-topic hits (by commit
message) against the actual commit at GitHub, fetched fresh via
`git fetch --depth 2 origin <full 40-char sha>` from `openssl/openssl` (not
reused from any existing local checkout). This is a commit **message**
search, so it is biased toward fixes whose author described them as a
double-free; it is not an exhaustive or random sample of all
release-without-reset fixes in this codebase's history, and we do not
claim it is.

## What we found: 10 independently-authored fixes of the same shape, 2023-2026

| Date | Commit | File(s) | Shape |
|---|---|---|---|
| 2023-11-14 | `82a13a1f50` | `crypto/pkcs7/pk7_doit.c` | `add_attribute()`: an attribute object is freed, then an error path could free it again; fixed by restructuring so the stale `attr` is never reused without being reassigned. |
| 2024-10-09 | `792b2c8da2` | `crypto/srp/srp_vfy.c` | `SRP_user_pwd_set1_ids()`: `OPENSSL_free(vinfo->id); OPENSSL_free(vinfo->info);` with no reset; adds `vinfo->id = NULL; vinfo->info = NULL;` right after. Struct-field shape, not a `T**` parameter. |
| 2026-01-15 | `72029afd91` | `providers/implementations/kdfs/tls1_prf.c` | `EVP_MAC_CTX_free(ctx->P_sha1);` with no reset on a digest-change path; adds `ctx->P_sha1 = NULL;`. A second KDF fix of this shape, independent of `d2217c88df` (the KDF fix Protocol B already reproduces unchanged). |
| 2026-03-20 | `aeea7dfaff` | `providers/implementations/keymgmt/mlx_kmgmt.c` | `mlx_kem_dup()`: a duplicated key's two component pointers are nulled immediately after allocation so every later failure path can free them safely; the pre-fix code left this until much later, after several paths could already double-free. |
| 2026-05-23 | `ecb4757b37` | `crypto/evp/m_sigver.c` | `do_sigver_init()`: a retry loop frees `signature`/`tmp_keymgmt` on one iteration and reuses the (now-dangling) variables on the next if a later step fails; adds a reset right after each free. |
| 2026-05-23 | `82befaf246` | `providers/implementations/storemgmt/file_store_any2obj.c` | `raw2obj_decode()`: `BIO_free(in);` with no reset; a later failure branch (currently believed unreachable, explicitly caveated as such by OpenSSL's own security team) would double-free `in`. **This is the closest analogue to Protocol A's shape in this list**: a local BIO variable, freed, with a (currently dead) later free of the same variable on a different branch. The security team asked for the defensive reset anyway, "to future-proof the function" -- the same justification this paper makes for checking lifecycle rules beyond what is reachable today. |
| 2026-05-27 | `a21f77dbc9` | `crypto/evp/{asymcipher,kem,signature}.c` | The same retry-loop shape as `ecb4757b37`, independently fixed two days later in three sibling files (asymmetric cipher, KEM, and signature init) that share the same iteration structure. Four files, one shared bug shape, fixed in two commits four days apart. |
| 2026-08-27 | `a32df28664` + `73f3bd8871` | `crypto/dh/dh_lib.c` (dh_finish), `crypto/dsa/dsa_lib.c` (dsa_finish) | `dh->method_mont_p`/`dsa->method_mont_p` freed with no reset; both fixed the same day by the same author, for the same reason, in two unrelated algorithm modules. |
| 2026-09-01 | `aee3523489` | `ssl/statem/statem_srvr.c` | `tls_process_client_certificate()`: a local `X509 *x` is pushed onto a stack (ownership transferred) but not reset; a later loop iteration or error path could act on the stale, no-longer-owned pointer. Ships with a new regression test in `sslapitest.c`. |

## What this is, and is not, evidence of

This is independent, externally-verifiable evidence (real commits, real
dates, real diffs, all re-fetched fresh from `openssl/openssl` for this
check, not produced or curated by this project beforehand) that the
release-without-reset convention this paper studies is not an artifact of
one well-chosen CVE: it has recurred, independently, across at least 9
distinct files in `crypto/`, `providers/`, and `ssl/`, authored by
different people, over very nearly three years, as recently as six weeks
before this evaluation's pinned master snapshot.

It is **not** evidence that Protocol A or Protocol B currently detects any
of these sites. We checked: none of the ten is a `T**`-typed function
parameter (Protocol B's exact scope) and none involves a tracked local
variable established via `BIO_push` (Protocol A's exact scope). Eight are
struct-field resets (`vinfo->id`, `ctx->P_sha1`, `dh->method_mont_p`, ...)
or bare local-variable resets inside ordinary control flow, which is
precisely the "scope of what is tracked" limitation already disclosed in
Section~7 (Threats to Validity) -- this search independently confirms that
limitation is not hypothetical: real, recent fixes sit exactly in the gap
it describes. The `file_store_any2obj.c` and `statem_srvr.c` cases are the
closest in spirit to a trackable shape (a local variable whose ownership
changes) but neither uses the `BIO_push`/`BIO_pop` API Protocol A's rule is
keyed on. Extending either protocol's rule to cover plain local-variable
release/reset (not only `T**` parameters or `BIO_push` chains) is a
concrete, well-evidenced next rule to write -- we did not attempt it in
the time available, to avoid shipping an untested third rule under
deadline pressure.
