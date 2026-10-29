#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECKER="$ROOT/typestate_check.py"
FAILED=0

check_pair() {
    local cve="$1"
    local vulnerable="$2"
    local fixed="$3"

    echo
    echo "=== Testing $cve ==="

    python3 "$CHECKER" "$vulnerable"
    local vulnerable_status=$?

    python3 "$CHECKER" "$fixed"
    local fixed_status=$?

    if [ "$vulnerable_status" -eq 1 ] && [ "$fixed_status" -eq 0 ]; then
        echo "PASS: $cve"
    else
        echo "FAIL: $cve (vulnerable=$vulnerable_status, fixed=$fixed_status)"
        FAILED=1
    fi
}

check_pair "CVE-2023-0215" \
    "$ROOT/openssl-cve-2023-0215-vulnerable/crypto/asn1/bio_ndef.c" \
    "$ROOT/openssl-cve-2023-0215-fixed/crypto/asn1/bio_ndef.c"

check_pair "CVE-2022-4450" \
    "$ROOT/openssl-cve-2022-4450-vulnerable/crypto/pem/pem_lib.c" \
    "$ROOT/openssl-cve-2022-4450-fixed/crypto/pem/pem_lib.c"

check_pair "CVE-2024-4741" \
    "$ROOT/openssl-cve-2024-4741-vulnerable/ssl/record/ssl3_buffer.c" \
    "$ROOT/openssl-cve-2024-4741-fixed/ssl/record/ssl3_buffer.c"

echo
if [ "$FAILED" -eq 0 ]; then
    echo "PASS: all three vulnerable/fixed pairs were distinguished."
    exit 0
else
    echo "FAIL: one or more CVE checks failed."
    exit 1
fi
