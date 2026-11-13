# Manual review evidence for selected mechanisms

## CVE-2022-4450

- Correct pair: vulnerable parent `8e257b86e5812c6e1cfa9e8e5f5660ac7bed899d`; official fix `63bcf189be73a9cc1264059bed6f57974be74a83`.
- In `crypto/pem/pem_lib.c`, the vulnerable error cleanup frees caller-visible `*header`/`*data` but leaves their values available to caller cleanup. The fix clears the output pointers after freeing. The minimal harness mirrors the existing PEM empty-payload failure shape. Runtime ASan stack and exact commands are in `05_fuzzing/logs/cve2022_vulnerable_asan_run.*` and fixed build/run log.
- Classification for the exercised implementation: runtime-confirmed double-free on vulnerable parent; corresponding exact fixed run clean.
- Checker: distinguishes the selected pair. Clang/Coccinelle/Cppcheck did not flag this mechanism in the prior completed focused comparison.

## CVE-2023-0215

- Correct pair: vulnerable parent `cbafa34b5a057794c5c08cd4657038e1f643c1ac`; official fix `8818064ce3c3c0f1b740a5aaba2a987e75bfbafd`.
- In `crypto/asn1/bio_ndef.c`, `BIO_new_NDEF` installs a BIO into an existing chain and its vulnerable cleanup can free that BIO without detaching it. `BIO_pop` later traverses the chain. The fix retains the inserted BIO and pops it before free. ASan identifies the later chain operation as a UAF on vulnerable CMS streaming.
- Classification for the exercised implementation: runtime-confirmed UAF on vulnerable parent. Fixed command reached a CMS cipher setup error because DES-CBC is unavailable; no ASan report occurred on that error path. This is limited evidence for fixed behavior.
- The existing DER CMS fuzz harness only parses/serializes CMS and does not reproduce streaming BIO ownership.

## CVE-2024-4741

- Correct pair: vulnerable parent `ec559c2a6cca3fd4cedae5c47f2dfa38e5e24865`; official fix `b3f0eb0a295f58f16ba43ba99dad70d4ee5c437d`.
- Official fix adds a `RECORD_LAYER_data_present()` precondition in `ssl/ssl_lib.c` before freeing buffers. This covers record-layer states where data/buffer remains live after a partial application read. `ssl/record/rec_layer_s3.c` consumes the record-layer read buffer. The exact harness handshakes TLS 1.2 over a BIO pair, reads one byte, calls `SSL_free_buffers`, then reads the remainder.
- Classification for the exercised implementation: runtime-confirmed UAF on vulnerable parent; official fixed version returns 0 from `SSL_free_buffers` and reads remaining bytes without ASan report.
- Python checker flags both corrected sides; its local pointer-reset heuristic is not the official lifecycle precondition.

These reviews establish the named behavior in the exact tested snapshots and harness paths. They do not assess exploitability over every transport/application configuration.
