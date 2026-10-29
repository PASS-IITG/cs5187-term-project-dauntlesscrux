#!/usr/bin/env bash

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VULNERABLE="$ROOT/openssl-cve-2023-0215-vulnerable/crypto/asn1/bio_ndef.c"
FIXED="$ROOT/openssl-cve-2023-0215-fixed/crypto/asn1/bio_ndef.c"
CHECKER="$ROOT/typestate_check.py"

echo "Testing vulnerable version..."
python3 "$CHECKER" "$VULNERABLE"
vulnerable_status=$?

if [ "$vulnerable_status" -ne 1 ]; then
    echo "FAIL: expected an alert for vulnerable source (exit 1)"
    exit 1
fi

echo
echo "Testing fixed version..."
python3 "$CHECKER" "$FIXED"
fixed_status=$?

if [ "$fixed_status" -ne 0 ]; then
    echo "FAIL: expected no alert for fixed source (exit 0)"
    exit 1
fi

echo
echo "PASS: vulnerable and fixed versions were distinguished."
