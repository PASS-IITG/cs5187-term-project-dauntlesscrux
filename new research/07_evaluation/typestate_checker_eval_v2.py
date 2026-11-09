#!/usr/bin/env python3
import sys, os

TEST_CASES = [
    {
        "id": "TC-01",
        "name": "CVE-2023-0215 Vulnerable (bio_ndef.c :: BIO_new_NDEF)",
        "rule": "TS-BIO-01",
        "file": "crypto/asn1/bio_ndef.c",
        "func": "BIO_new_NDEF",
        "code": "BIO *BIO_new_NDEF(...) { BIO *ndef_bio = BIO_new(BIO_f_asn1()); BIO_push(val->chain, ndef_bio); if (err) { BIO_free(ndef_bio); return NULL; } return ndef_bio; }",
        "expected": "ALERT",
        "label": "Positive Vulnerable CVE-2023-0215"
    },
    {
        "id": "TC-02",
        "name": "CVE-2023-0215 Fixed (bio_ndef.c :: BIO_new_NDEF)",
        "rule": "TS-BIO-01",
        "file": "crypto/asn1/bio_ndef.c",
        "func": "BIO_new_NDEF",
        "code": "BIO *BIO_new_NDEF(...) { BIO *ndef_bio = BIO_new(BIO_f_asn1()); BIO_push(val->chain, ndef_bio); if (err) { BIO_pop(ndef_bio); BIO_free(ndef_bio); return NULL; } return ndef_bio; }",
        "expected": "NO_ALERT",
        "label": "Negative Fixed CVE-2023-0215"
    },
    {
        "id": "TC-03",
        "name": "CVE-2022-4450 Vulnerable (pem_lib.c :: PEM_read_bio_ex)",
        "rule": "TS-PEM-02",
        "file": "crypto/pem/pem_lib.c",
        "func": "PEM_read_bio_ex",
        "code": "int PEM_read_bio_ex(...) { if (err) { pem_free(*header, flags, 0); pem_free(*data, flags, 0); return 0; } return 1; }",
        "expected": "ALERT",
        "label": "Positive Vulnerable CVE-2022-4450"
    },
    {
        "id": "TC-04",
        "name": "CVE-2022-4450 Fixed (pem_lib.c :: PEM_read_bio_ex)",
        "rule": "TS-PEM-02",
        "file": "crypto/pem/pem_lib.c",
        "func": "PEM_read_bio_ex",
        "code": "int PEM_read_bio_ex(...) { if (err) { pem_free(*header, flags, 0); *header = NULL; pem_free(*data, flags, 0); *data = NULL; return 0; } return 1; }",
        "expected": "NO_ALERT",
        "label": "Negative Fixed CVE-2022-4450"
    },
    {
        "id": "TC-05",
        "name": "CVE-2024-4741 Vulnerable (ssl3_buffer.c :: ssl3_release_read_buffer)",
        "rule": "TS-SSL-03",
        "file": "ssl/record/ssl3_buffer.c",
        "func": "ssl3_release_read_buffer",
        "code": "int ssl3_release_read_buffer(...) { OPENSSL_free(b->buf); b->buf = NULL; return 1; }",
        "expected": "ALERT",
        "label": "Positive Vulnerable CVE-2024-4741"
    },
    {
        "id": "TC-06",
        "name": "CVE-2024-4741 Fixed (ssl3_buffer.c :: ssl3_release_read_buffer)",
        "rule": "TS-SSL-03",
        "file": "ssl/record/ssl3_buffer.c",
        "func": "ssl3_release_read_buffer",
        "code": "int ssl3_release_read_buffer(...) { if (RECORD_LAYER_data_present(&s->rlayer)) return 0; OPENSSL_free(b->buf); b->buf = NULL; s->rlayer.packet = NULL; s->rlayer.packet_length = 0; return 1; }",
        "expected": "NO_ALERT",
        "label": "Negative Fixed CVE-2024-4741"
    },
    {
        "id": "TC-07",
        "name": "Safe Control: B64_write_ASN1 (asn_mime.c)",
        "rule": "TS-BIO-01",
        "file": "crypto/asn1/asn_mime.c",
        "func": "B64_write_ASN1",
        "code": "BIO *B64_write_ASN1(...) { BIO_push(b64, out); if (err) { BIO_pop(b64); BIO_free(b64); return NULL; } return out; }",
        "expected": "NO_ALERT",
        "label": "Safe Control TN"
    },
    {
        "id": "TC-08",
        "name": "Safe Control: PEM_X509_INFO_read_bio (pem_lib.c)",
        "rule": "TS-PEM-02",
        "file": "crypto/pem/pem_lib.c",
        "func": "PEM_X509_INFO_read_bio",
        "code": "STACK_OF(X509_INFO) *PEM_X509_INFO_read_bio(...) { if (err) { sk_X509_INFO_pop_free(ret, X509_INFO_free); ret = NULL; return NULL; } return ret; }",
        "expected": "NO_ALERT",
        "label": "Safe Control TN"
    },
    {
        "id": "TC-09",
        "name": "Safe Control: ssl3_setup_read_buffer (rec_layer_s3.c)",
        "rule": "TS-SSL-03",
        "file": "ssl/record/rec_layer_s3.c",
        "func": "ssl3_setup_read_buffer",
        "code": "int ssl3_setup_read_buffer(...) { s->rlayer.packet = NULL; s->rlayer.packet_length = 0; b->buf = OPENSSL_malloc(len); return 1; }",
        "expected": "NO_ALERT",
        "label": "Safe Control TN"
    },
    {
        "id": "TC-10",
        "name": "Safe Control: OSSL_DECODER_from_bio (decoder_lib.c)",
        "rule": "TS-BIO-01",
        "file": "crypto/encode_decode/decoder_lib.c",
        "func": "OSSL_DECODER_from_bio",
        "code": "int OSSL_DECODER_from_bio(...) { BIO_push(filter, in); if (err) { BIO_pop(filter); BIO_free(filter); return 0; } return 1; }",
        "expected": "NO_ALERT",
        "label": "Safe Control TN"
    },
    {
        "id": "TC-11",
        "name": "Safe Control: CMS_dataInit (cms_smime.c)",
        "rule": "TS-BIO-01",
        "file": "crypto/cms/cms_smime.c",
        "func": "CMS_dataInit",
        "code": "BIO *CMS_dataInit(...) { BIO_push(cmsbio, icont); if (err) { BIO_pop(cmsbio); BIO_free(cmsbio); return NULL; } return cmsbio; }",
        "expected": "NO_ALERT",
        "label": "Safe Control TN"
    },
    {
        "id": "TC-12",
        "name": "Safe Control: acpt_state (bss_acpt.c)",
        "rule": "TS-BIO-01",
        "file": "crypto/bio/bss_acpt.c",
        "func": "acpt_state",
        "code": "int acpt_state(...) { BIO *child = BIO_new_socket(s, BIO_NOCLOSE); c->param_addr = child; if (err) { BIO_free(child); return -1; } return 1; }",
        "expected": "NO_ALERT",
        "label": "Safe Control TN"
    },
    {
        "id": "TC-13",
        "name": "Expanded Safe Control: PKCS12_item_decrypt_d2i (p12_decr.c)",
        "rule": "TS-BIO-01",
        "file": "crypto/pkcs12/p12_decr.c",
        "func": "PKCS12_item_decrypt_d2i",
        "code": "void *PKCS12_item_decrypt_d2i(...) { BIO_push(dbio, in_bio); if (err) { BIO_pop(dbio); BIO_free(dbio); return NULL; } return res; }",
        "expected": "NO_ALERT",
        "label": "Expanded Safe Control TN"
    },
    {
        "id": "TC-14",
        "name": "Expanded Safe Control: cms_EncryptedContent_init_bio (cms_enc.c)",
        "rule": "TS-BIO-01",
        "file": "crypto/cms/cms_enc.c",
        "func": "cms_EncryptedContent_init_bio",
        "code": "BIO *cms_EncryptedContent_init_bio(...) { BIO_push(ebio, chain); if (err) { BIO_pop(ebio); BIO_free(ebio); return NULL; } return ebio; }",
        "expected": "NO_ALERT",
        "label": "Expanded Safe Control TN"
    },
    {
        "id": "TC-15",
        "name": "Non-Typestate Control: EVP_EncryptInit_ex2 (evp_enc.c)",
        "rule": "TS-PEM-02",
        "file": "crypto/evp/evp_enc.c",
        "func": "EVP_EncryptInit_ex2",
        "code": "int EVP_EncryptInit_ex2(...) { if (cipher != NULL) { ctx->cipher = cipher; } return 1; }",
        "expected": "NO_ALERT",
        "label": "Non-Typestate Control TN"
    },
    {
        "id": "TC-16",
        "name": "Non-Typestate Control: d2i_PKCS7 (pk7_asn1.c)",
        "rule": "TS-BIO-01",
        "file": "crypto/pkcs7/pk7_asn1.c",
        "func": "d2i_PKCS7",
        "code": "PKCS7 *d2i_PKCS7(...) { if (in == NULL || *in == NULL) return NULL; return (PKCS7 *)ASN1_item_d2i(...); }",
        "expected": "NO_ALERT",
        "label": "Non-Typestate Control TN"
    },

    {
        "id": "TC-17",
        "name": "PEM Adversarial: Only header reset",
        "rule": "TS-PEM-02",
        "file": "crypto/pem/pem_lib.c",
        "func": "PEM_read_bio_ex",
        "code": "int PEM_read_bio_ex(...) { if (err) { pem_free(*header, flags, 0); *header = NULL; pem_free(*data, flags, 0); return 0; } return 1; }",
        "expected": "ALERT",
        "label": "Adversarial Positive: data pointer remains dangling"
    },
    {
        "id": "TC-18",
        "name": "PEM Adversarial: Only data reset",
        "rule": "TS-PEM-02",
        "file": "crypto/pem/pem_lib.c",
        "func": "PEM_read_bio_ex",
        "code": "int PEM_read_bio_ex(...) { if (err) { pem_free(*header, flags, 0); pem_free(*data, flags, 0); *data = NULL; return 0; } return 1; }",
        "expected": "ALERT",
        "label": "Adversarial Positive: header pointer remains dangling"
    },
    {
        "id": "TC-19",
        "name": "PEM Adversarial: Only unrelated ptr reset",
        "rule": "TS-PEM-02",
        "file": "crypto/pem/pem_lib.c",
        "func": "PEM_read_bio_ex",
        "code": "int PEM_read_bio_ex(...) { if (err) { pem_free(*header, flags, 0); pem_free(*data, flags, 0); *ptr = NULL; return 0; } return 1; }",
        "expected": "ALERT",
        "label": "Adversarial Positive: unrelated pointer reset is insufficient"
    },
]

def analyze_code(case):
    code = case["code"]
    rule = case["rule"]
    if rule == "TS-BIO-01":
        has_push = "BIO_push(" in code or "BIO_new_NDEF(" in code
        has_free = "BIO_free(" in code or "BIO_free_all(" in code
        has_pop = "BIO_pop(" in code
        if has_push and has_free and not has_pop:
            return "ALERT"
        return "NO_ALERT"
    elif rule == "TS-PEM-02":
        has_header_free = (
            "pem_free(*header" in code or "OPENSSL_free(*header" in code
        )
        has_data_free = (
            "pem_free(*data" in code or "OPENSSL_free(*data" in code
        )
        has_header_reset = "*header = NULL" in code
        has_data_reset = "*data = NULL" in code

        if (has_header_free or has_data_free) and not (
            has_header_reset and has_data_reset
        ):
            return "ALERT"
        return "NO_ALERT"
    elif rule == "TS-SSL-03":
        has_buf_free = "OPENSSL_free(b->buf)" in code
        has_packet_zero = "s->rlayer.packet = NULL" in code
        if has_buf_free and not has_packet_zero:
            return "ALERT"
        return "NO_ALERT"
    return "NO_ALERT"

def run_evaluation():
    print("=" * 80)
    print("OPENSSL TYPESTATE REGRESSION TEST SUITE")
    print("=" * 80)
    print(
        "Executing " + str(len(TEST_CASES))
        + " engineered test cases across 3 typestate rules..."
    )
    print()

    matched = 0
    mismatched = 0

    for case in TEST_CASES:
        observed = analyze_code(case)
        expected = case["expected"]
        passed = observed == expected

        if passed:
            matched += 1
            result = "PASS"
        else:
            mismatched += 1
            result = "FAIL"

        print("[" + result + "] " + case["id"] + ": " + case["name"])
        print("      File/Func: " + case["file"] + " :: " + case["func"])
        print(
            "      Expected: " + expected
            + " | Observed: " + observed
        )
        print()

    total = len(TEST_CASES)

    print("=" * 80)
    print("ENGINEERED REGRESSION SUMMARY")
    print("=" * 80)
    print("Expected-label matches : " + str(matched))
    print("Mismatches              : " + str(mismatched))
    print("Total test cases        : " + str(total))
    print(
        "Regression pass rate    : "
        + f"{(matched / total) * 100.0:.1f}%"
        if total else "Regression pass rate: N/A"
    )
    print("=" * 80)
    print("IMPORTANT EVALUATION LIMITATION:")
    print(
        "These cases were manually constructed after the target"
    )
    print(
        "vulnerability patterns were known. They test rule"
    )
    print(
        "implementation and regression behaviour, not independent"
    )
    print(
        "detection performance on unseen OpenSSL code."
    )
    print(
        "No real-world FP, FN, precision, or recall estimate can"
    )
    print(
        "be derived from this suite."
    )
    print("=" * 80)



if __name__ == "__main__":
    run_evaluation()