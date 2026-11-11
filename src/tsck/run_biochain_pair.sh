#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOL="$ROOT/src/tsck/biochain.py"
RESULTS="$ROOT/src/tsck/results"

VULNERABLE="$ROOT/openssl-cve-2023-0215-vulnerable/crypto/asn1/bio_ndef.c"
FIXED="$ROOT/openssl-cve-2023-0215-fixed/crypto/asn1/bio_ndef.c"

mkdir -p "$RESULTS"

for file in "$TOOL" "$VULNERABLE" "$FIXED"; do
    if [ ! -f "$file" ]; then
        echo "ERROR: Missing file: $file"
        exit 2
    fi
done

echo "Scanning vulnerable CVE-2023-0215..."
python3 "$TOOL" "$VULNERABLE" \
    > "$RESULTS/biochain_cve2023_vulnerable.log" 2>&1
V=$?

echo "Scanning fixed CVE-2023-0215..."
python3 "$TOOL" "$FIXED" \
    > "$RESULTS/biochain_cve2023_fixed.log" 2>&1
F=$?

{
    echo "Protocol A - CVE-2023-0215 validation"
    echo "Date: $(date -Is)"
    echo "Repository HEAD: $(git -C "$ROOT" rev-parse HEAD)"
    echo "Python: $(python3 --version 2>&1)"
    echo
    echo "Checker and source checksums:"
    sha256sum "$TOOL" "$VULNERABLE" "$FIXED"
    echo
    echo "Vulnerable exit status: $V (expected 1)"
    echo "Fixed exit status: $F (expected 0)"
    echo
    echo "Vulnerable log: biochain_cve2023_vulnerable.log"
    echo "Fixed log: biochain_cve2023_fixed.log"
} > "$RESULTS/biochain_cve2023_validation.txt"

echo
echo "========== VULNERABLE =========="
cat "$RESULTS/biochain_cve2023_vulnerable.log"

echo
echo "========== FIXED =========="
cat "$RESULTS/biochain_cve2023_fixed.log"

echo
cat "$RESULTS/biochain_cve2023_validation.txt"

if [ "$V" -eq 1 ] && [ "$F" -eq 0 ]; then
    echo
    echo "PASS: Protocol A distinguishes the vulnerable and fixed versions."
    exit 0
fi

echo
echo "FAIL: Unexpected detection result."
exit 1
