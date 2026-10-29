#!/usr/bin/env bash

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VULNERABLE="$ROOT/openssl-cve-2022-4450-vulnerable/crypto/pem/pem_lib.c"
FIXED="$ROOT/openssl-cve-2022-4450-fixed/crypto/pem/pem_lib.c"
CHECKER="$ROOT/typestate_check.py"

echo "Testing vulnerable CVE-2022-4450 source..."
python3 "$CHECKER" "$VULNERABLE"
vulnerable_status=$?

if [ "$vulnerable_status" -ne 1 ]; then
    echo "FAIL: expected an alert for vulnerable source"
    exit 1
fi

echo
echo "Testing fixed CVE-2022-4450 source..."
python3 "$CHECKER" "$FIXED"
fixed_status=$?

if [ "$fixed_status" -ne 0 ]; then
    echo "FAIL: expected no alert for fixed source"
    exit 1
fi

echo
echo "PASS: vulnerable and fixed versions were distinguished."
