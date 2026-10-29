#!/usr/bin/env bash
# Legacy baseline: the Part 1 patch matcher (typestate_check.py).
#
# CVE-2023-0215 and CVE-2022-4450: the checker must alert on the vulnerable file and stay quiet on the fix.
# CVE-2024-4741: corrected pair (2026-10-30). The checker is NOT expected to separate the vulnerable
# commit from the real fix; it only recognises the follow-on hardening commit. This script asserts that
# documented limitation so a silent change in behaviour is noticed.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECKER="$ROOT/typestate_check.py"
FAILED=0

status() { python3 "$CHECKER" "$1" > /dev/null 2>&1; echo $?; }

check_pair() {
    local cve="$1" vulnerable="$2" fixed="$3"
    echo
    echo "=== Testing $cve ==="
    python3 "$CHECKER" "$vulnerable"; local v=$?
    python3 "$CHECKER" "$fixed";      local f=$?
    if [ "$v" -eq 1 ] && [ "$f" -eq 0 ]; then
        echo "PASS: $cve (vulnerable=ALERT, fixed=NO ALERT)"
    else
        echo "FAIL: $cve (vulnerable=$v, fixed=$f)"
        FAILED=1
    fi
}

check_pair "CVE-2023-0215" \
    "$ROOT/openssl-cve-2023-0215-vulnerable/crypto/asn1/bio_ndef.c" \
    "$ROOT/openssl-cve-2023-0215-fixed/crypto/asn1/bio_ndef.c"

check_pair "CVE-2022-4450" \
    "$ROOT/openssl-cve-2022-4450-vulnerable/crypto/pem/pem_lib.c" \
    "$ROOT/openssl-cve-2022-4450-fixed/crypto/pem/pem_lib.c"

echo
echo "=== CVE-2024-4741 (documented limitation) ==="
V="$(status "$ROOT/openssl-cve-2024-4741-vulnerable/ssl/record/ssl3_buffer.c")"   # ec559c2a6c, vulnerable
F="$(status "$ROOT/openssl-cve-2024-4741-fixed/ssl/record/ssl3_buffer.c")"        # b3f0eb0a29, real fix
H="$(status "$ROOT/case-studies/cve-2024-4741/2d05959073-hardening/ssl/record/ssl3_buffer.c")"  # 2d05959073, hardening
echo "vulnerable ec559c2a6c exit=$V | real fix b3f0eb0a29 exit=$F | hardening 2d05959073 exit=$H"
if [ "$V" -eq 1 ] && [ "$F" -eq 1 ] && [ "$H" -eq 0 ]; then
    echo "EXPECTED LIMITATION: the checker alerts on the vulnerable commit and on the real fix, and is quiet only"
    echo "on the later hardening commit. It matches the hardening pattern, not the advisory's root cause."
else
    echo "FAIL: CVE-2024-4741 behaviour changed (expected 1/1/0). Re-read CVE-2024-4741-evidence.txt before updating."
    FAILED=1
fi

echo
if [ "$FAILED" -eq 0 ]; then
    echo "PASS: 2 of 3 pairs distinguished (0215, 4450); 4741 behaves as the documented limitation."
    exit 0
else
    echo "FAIL: one or more checks failed."
    exit 1
fi
