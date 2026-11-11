#!/usr/bin/env bash
# run_protocol_a.sh - reproduce Protocol A (BIO-chain detach-before-release,
# CVE-2023-0215) checks: the motivating vulnerable/fixed pair, plus a
# whole-tree scan of the master snapshot already cloned by run_scan.sh.
#
# Run from the repo root (not from inside src/tsck).
# Needs: python3, tree-sitter, tree-sitter-c (same as run_scan.sh).
# If src/tsck/ossl/snap_master_2026_10_30 is missing, run run_scan.sh first.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"       # .../src/tsck
ROOT="$(cd "$HERE/../.." && pwd)"            # repo root
R="$HERE/results"
mkdir -p "$R"

echo "== BIO_new_NDEF @ CVE-2023-0215 vulnerable"
python3 "$HERE/protocol_a.py" --func BIO_new_NDEF \
  "$ROOT/openssl-cve-2023-0215-vulnerable/crypto/asn1/bio_ndef.c" \
  | tee "$R/protocol_a_vulnerable.log"

echo "== BIO_new_NDEF @ CVE-2023-0215 fixed"
python3 "$HERE/protocol_a.py" --func BIO_new_NDEF \
  "$ROOT/openssl-cve-2023-0215-fixed/crypto/asn1/bio_ndef.c" \
  | tee "$R/protocol_a_fixed.log"

SNAP="$HERE/ossl/snap_master_2026_10_30"
if [ -d "$SNAP" ]; then
  echo "== whole tree: master_2026_10_30 (same snapshot as Protocol B RQ1)"
  python3 "$HERE/protocol_a.py" --json "$R/protocol_a_master.json" \
    "$SNAP/crypto" "$SNAP/ssl" "$SNAP/providers" \
    | tee "$R/protocol_a_master.log"
else
  echo "== whole tree: SKIPPED ($SNAP not found -- run run_scan.sh first if you want this)"
fi

echo "Done. Logs in $R/protocol_a_*.log (+ protocol_a_master.json if the whole-tree scan ran)."
