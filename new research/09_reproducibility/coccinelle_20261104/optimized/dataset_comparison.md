# Dataset comparison (descriptive overlap only)

Pinned source revision: `ed57129cd43b77e077c68fd5f7ea951976766f38`. These source/function overlaps are retrospective/descriptive and do not estimate precision, recall or accuracy. The four datasets remain separate.

## Rule 02
- Shared file/function pairs with historical fix register: 1 — crypto/evp/m_sigver.c::do_sigver_init
- Shared file/function pairs with Clang report inventory: 0
- Shared file/function pairs with Clang manual triage: 2 — crypto/asn1/f_string.c::a2i_ASN1_STRING, ssl/statem/statem_clnt.c::tls_construct_client_hello

## Rule 04
- Shared file/function pairs with historical fix register: 0
- Shared file/function pairs with Clang report inventory: 0
- Shared file/function pairs with Clang manual triage: 1 — crypto/param_build.c::OSSL_PARAM_BLD_to_param

## Original three-CVE regression tests

The existing three-CVE pair-test dataset remains separate from both Coccinelle inventories. It was not used as a discovery prefilter and no metric is calculated from it. A function overlap in a regression-test file would be a retrospective match, not an independent discovery.
