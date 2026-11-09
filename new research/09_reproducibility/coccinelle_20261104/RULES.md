# Semantic patch design notes

## Source and tool boundary

The scan source is `/mnt/d/CVE-Typestate-Project-clang-analysis` at `ed57129cd43b77e077c68fd5f7ea951976766f38`. The OpenSSL tree has first-party C code across `crypto/`, `ssl/`, `providers/`, `apps/`, `engines/`, `test/`, and supporting `include/`/`util/` areas; it also has generated/configuration and auxiliary content. The pinned Git index lists 1,695 `*.c` translation units. `tracked_c_files.txt` records the exact scan boundary. API-token prefilter lists limit which of those tracked files are passed to each Coccinelle rule; these are transparent lexical prefilters for APIs that the corresponding rule matches, not CVE-specific filters.

`spatch` is Coccinelle 1.1.1 (OCaml 4.14.1, Python scripting enabled). The experiment uses SmPL structural matching plus `coccilib.report` output, `--file-groups` for explicit tracked-file lists, `--jobs` for parallel scanning, and `--very-quiet` to keep scanner chatter out of findings. Coccinelle parses source structure but these rules do not perform general interprocedural ownership analysis, symbolic alias analysis, or proof of path feasibility.

## OpenSSL lifecycle conventions consulted

- `OPENSSL_malloc()`/`OPENSSL_zalloc()` results are generally released with `OPENSSL_free()`; `OPENSSL_clear_free()` additionally cleanses sensitive contents. This rule set only matches selected direct spellings and is not an exhaustive allocator pairing checker.
- Typed OpenSSL objects have type-specific destruction APIs such as `BN_free`, `BIO_free[_all]`, `EVP_MD_CTX_free`, `EVP_CIPHER_CTX_free`, and `X509_free`. Ref-counted objects can have more than one valid reference, so a syntactic repeated release is not automatically a double free.
- `BN_CTX_start()`/`BN_CTX_get()` temporaries are borrowed and become invalid at `BN_CTX_end()`. The current patches do not cover this family; adding it needs a separate rule that accounts for nested scopes and pointer reuse.
- `SSL_set0_rbio()` and `SSL_set0_wbio()` transfer ownership of one BIO reference to the SSL object. `SSL_set_bio()` has nuanced same-pointer/reference-count rules, so it is intentionally omitted from the transfer rule. `BIO_push()` links chains; it is not treated as a simple ownership-transfer operation.

## Rules

### `rules/01_use_after_release.cocci`

**Invariant sought:** a direct release of a pointer followed in the same function by a member dereference through the same identifier may indicate use-after-release.

**APIs:** `OPENSSL_free`, `BN_free`, `BIO_free`, `BIO_free_all`, `EVP_MD_CTX_free`, `EVP_CIPHER_CTX_free`, and `X509_free`.

**Limitations / likely false positives:** tracks only identical identifier spelling and `p->member` uses; misses aliases, `*p`, calls that consume `p`, and uses through fields. It does not understand branches, reassignment, refcounts, or whether a later operation reinitializes the object. The reset/reassignment sample deliberately demonstrates a false positive.

### `rules/02_repeated_release.cocci`

**Invariant sought:** the same identifier passed twice to the same selected destructor in one function may indicate repeated release.

**APIs:** one-argument calls whose identifier contains `free` (including common OpenSSL destructors and C `free`).

**Limitations / likely false positives:** cannot prove both calls execute on one path; the pointer may be reacquired, reassigned, or represent distinct references. It matches only the same callee spelling and misses different destructor spellings for the same allocation and cleanup split across functions. The `*free*` name filter can also match project-local functions whose names contain `free` but are not destructors. The scan input is further reduced only by a necessary textual condition: a same-callee/same-identifier pair must occur in an inferred function body; files with unrecognized function boundaries are retained conservatively. The sample demonstrates the direct positive shape; mutually exclusive branches are a known review case.

### `rules/03_release_after_transfer.cocci`

**Invariant sought:** after `SSL_set0_rbio()` or `SSL_set0_wbio()` transfers a BIO reference to an SSL object, a same-function `BIO_free()` of the same identifier may consume a reference still owned by SSL.

**APIs:** `SSL_set0_rbio`, `SSL_set0_wbio`, and `BIO_free` only.

**Limitations / likely false positives:** does not track `BIO_up_ref()`, aliases, prior SSL state, `SSL_set_bio()` rules, or whether the freed reference is distinct from the transferred one. The sample includes a prior `BIO_up_ref()` case that is a likely false positive.

### `rules/04_acquire_early_return.cocci`

**Invariant sought:** a pointer assigned directly from `OPENSSL_malloc()` before a same-function `return` merits inspection for cleanup, ownership transfer, and null-check/error-path behavior.

**APIs:** direct `OPENSSL_malloc` assignment only.

**Limitations / likely false positives:** intentionally broad and low-specificity: it reports the first syntactic return after an allocation, including the normal `p == NULL` allocation-failure return, returns after cleanup, caller-owned return values, and transfers. It does not establish a missing release. The sample includes both candidate and properly cleaned-up functions.

## Sample validation

The small C files under `samples/` exercise each rule before whole-tree use. Commands and raw stdout/stderr are in `logs/sample_commands.log` and `logs/sample-*.stdout`/`.stderr`. Each command exited 0. Expected false positives are retained as a record of rule limits; a successful sample match validates syntax/behavior only, not detection correctness on OpenSSL.
