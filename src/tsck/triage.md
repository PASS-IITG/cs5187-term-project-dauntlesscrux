# Triage of every tool-flagged site

Generated from `triage.csv` (do not edit by hand; edit the CSV and rerun this snippet). Labels come from reading the code and its callers. No runtime tests were run, so **nothing here is a confirmed new vulnerability**. The labels were assigned by the same people who built the tool, which is a threat to validity.

`python3 check_triage.py` verifies that every site flagged in `results/*.json` has a label and prints the counts below.

| Label | Sites |
|---|---|
| Confirmed by an upstream fix | 7 |
| Potential recurrence (latent) | 2 |
| Convention deviation, no impact | 8 |
| Unclear | 0 |
| False positive | 1 |
| Suppressed by the tool (correctly) | 2 |

## Confirmed by an upstream fix (7)

Tool flagged the pre-fix code; OpenSSL later changed exactly this site.

| Site | Evidence |
|---|---|
| `crypto/pem/pem_lib.c` `PEM_read_bio_ex()` `*header` | CVE-2022-4450; fixed by 63bcf189be (adds *header = NULL). Pre-fix witness lines 991-998. |
| `crypto/pem/pem_lib.c` `PEM_read_bio_ex()` `*data` | CVE-2022-4450; fixed by 63bcf189be (adds *data = NULL). |
| `providers/implementations/kdfs/pbkdf1.c` `kdf_pbkdf1_set_membuf()` `*buffer` | Fixed by d2217c88df (2021-11-30, not a CVE): adds *buffer = NULL; *buflen = 0 after OPENSSL_clear_free. Flagged in 3.0.0 and in parent 29a27cb2c5; quiet after. |
| `providers/implementations/kdfs/pbkdf2.c` `pbkdf2_set_membuf()` `*buffer` | Fixed by d2217c88df, same change as pbkdf1. |
| `providers/implementations/kdfs/pkcs12kdf.c` `pkcs12kdf_set_membuf()` `*buffer` | Fixed by d2217c88df, same change as pbkdf1. |
| `providers/implementations/kdfs/scrypt.c` `scrypt_set_membuf()` `*buffer` | Fixed by d2217c88df, same change as pbkdf1. |
| `providers/implementations/kdfs/pvkkdf.c` `pvk_set_membuf()` `*buffer` | Missed by d2217c88df; fixed one commit later by a632bfaa4e (direct child, committed 2021-12-01). Our rule flags it in the d2217c88df tree. |

## Potential recurrence (latent) (2)

Same shape as CVE-2022-4450, but the failure branch is not reachable from
any single-threaded, straight-line call through the public API. Not a
confirmed vulnerability. **Reasoning corrected** by Claude (this session)
against the real pinned-commit source; see
`results/reachability_rq1_candidates.md` for the full derivation,
including one factual error in the original note below (struck through).

| Site | Evidence |
|---|---|
| `crypto/x509/x_pubkey.c` `X509_PUBKEY_set()` `*x` | Frees *x, then if EVP_PKEY_up_ref(pkey) fails goes to error: and returns 0 with *x dangling. Same shape as CVE-2022-4450. Present from 3.0.0 to master 949fe8b5f4. Callers pass embedded fields (e.g. X509_set_pubkey passes &x->cert_info.key), so X509_free after a failure would free the stale pointer again. ~~Failure needs EVP_PKEY_up_ref to fail (lock/atomic failure)~~ -- checked against real source: `CRYPTO_UP_REF` always returns `true` on every platform this codebase builds for, so that premise is wrong. The real trigger is `EVP_PKEY_up_ref`'s own `(i > 1) ? 1 : 0` check returning 0, which requires `pkey`'s reference count to already be 0 at entry -- only possible if the calling application already has a use-after-free on `pkey`, or a data race with another thread dropping `pkey`'s last reference concurrently. No in-tree caller creates this precondition. No runtime test; not independently reachable without a pre-existing caller bug. |
| `providers/implementations/encode_decode/ml_kem_codecs.c` `ossl_ml_kem_i2d_pubkey()` `*out` | On encode failure: OPENSSL_free(*out); return 0 with *out not reset. Caller key_to_pubkey (encode_key2any.c) then calls OPENSSL_free(der) on k2d failure: double free if reached. Confirmed unreachable from a single-threaded call: `ossl_ml_kem_have_pubkey` is a plain field read (`(key)->t != NULL`) with no side effect, and `len`/`pubkey_bytes` are read from the same `key` moments apart with nothing in between that could mutate it; the inner check in `ossl_ml_kem_encode_public_key` is therefore provably true when the outer one was. Reachable only if a second thread concurrently clears the same `ML_KEM_KEY`'s public-key state mid-call -- again an unsynchronized data race across threads sharing one key object, not a deterministic path. Master only. |

## Convention deviation, no impact (8)

The pointer is left dangling on a failure path, but every caller discards it or documents that behaviour.

| Site | Evidence |
|---|---|
| `crypto/LPdir_unix.c` `LP_find_file_end()` `*ctx` | free(*ctx) without reset. LPdir_win.c resets *ctx = NULL, so the tree is inconsistent. Every caller discards or frees the context afterwards (conf_def.c:584 local, conf_def.c:871 resets itself, ssl_cert.c:1013 local, file_store.c:796 then free_file_ctx). |
| `crypto/LPdir_vms.c` `LP_find_file_end()` `*ctx` | Same as LPdir_unix.c (VMS variant). |
| `ssl/ssl_ciph.c` `ssl_cipher_get_evp()` `*enc` | Releases *enc on md up_ref failure and returns 0 without reset. All callers (s3_enc.c/t1_enc.c/tls13_enc.c; ssl_txt.c passes NULL) return 0 immediately and never read the output on failure. |
| `ssl/ssl_ciph.c` `ssl_cipher_get_evp()` `*snenc` | Same function, second output parameter (master only); callers t1_enc.c:276 and tls13_enc.c:383 return 0 immediately. |
| `ssl/statem/extensions_srvr.c` `extract_keyshares()` `*keyshares_arr` | Failure path frees both arrays; caller (line ~880) returns 0 immediately: comment says memory is already freed. Documented contract. Master only. |
| `ssl/statem/extensions_srvr.c` `extract_keyshares()` `*encoded_pubkey_arr` | Same as keyshares_arr. |
| `crypto/cmp/cmp_genm.c` `OSSL_CMP_get1_rootCaKeyUpdate()` `*newWithOld` | **Reclassified from "Unclear"** by Claude (this session) after reading the real source and the one real caller; see `results/unclear_sites_recheck.md`. Rollback path frees *newWithOld after a failed X509_up_ref; output stays set, not reset. The one in-tree caller, `apps/cmp.c:3547`, jumps straight to `end_upd` on failure, which frees only its own `oldwithold` local -- the frees that would touch `newwithold` are on the skipped success-path side of that jump. No caller anywhere in `apps/` or `test/` reads or frees this output on a failure return. Master only. |
| `crypto/cmp/cmp_genm.c` `OSSL_CMP_get1_rootCaKeyUpdate()` `*newWithNew` | Same function and same caller as `*newWithOld`, same reclassification and evidence. Master only. |

## Unclear (0)

Both sites in this category were reclassified above after reading their
one real caller; see `results/unclear_sites_recheck.md`.

## False positive (1)

Name-based release detection mistakes a reference release for a free.

| Site | Evidence |
|---|---|
| `providers/common/provider_util.c` `load_common()` `*engine` | ENGINE_free(*engine) at line 85 drops only the structural reference (comment says so); the functional reference from ENGINE_init is still held and *engine stays valid. Name-based release detection cannot see reference counts. Not present on master or in 3.0.0 (older snapshots only). |

## Suppressed by the tool (correctly) (2)

Partial release; `*P` is reused afterwards.

| Site | Evidence |
|---|---|
| `crypto/evp/p_lib.c` `evp_pkey_copy_downgraded()` `*dest` | evp_pkey_free_it(*dest) frees key internals only; *dest is passed to EVP_PKEY_set_type next. Suppressed by the deref-after-release rule. |
| `crypto/evp/pmeth_gn.c` `EVP_PKEY_generate()` `*ppkey` | evp_pkey_free_legacy(*ppkey) frees legacy internals only; (*ppkey)->type is written right after. Suppressed by the deref-after-release rule. |
