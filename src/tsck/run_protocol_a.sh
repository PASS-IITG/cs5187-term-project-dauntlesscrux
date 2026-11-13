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
if ! grep -q "^VIOLATION" "$R/protocol_a_vulnerable.log"; then
  echo "FAIL: expected a VIOLATION on the vulnerable revision, got none" >&2
  exit 1
fi

echo "== BIO_new_NDEF @ CVE-2023-0215 fixed"
python3 "$HERE/protocol_a.py" --func BIO_new_NDEF \
  "$ROOT/openssl-cve-2023-0215-fixed/crypto/asn1/bio_ndef.c" \
  | tee "$R/protocol_a_fixed.log"
if grep -q "^VIOLATION" "$R/protocol_a_fixed.log"; then
  echo "FAIL: expected no VIOLATION on the fixed revision, got one" >&2
  exit 1
fi
echo "PASS: vulnerable=VIOLATION, fixed=clean (motivating pair distinguished)"

SNAP="$HERE/ossl/snap_master_2026_10_30"
if [ -d "$SNAP" ]; then
  echo "== whole tree: master_2026_10_30 (same snapshot as Protocol B RQ1)"
  python3 "$HERE/protocol_a.py" --json "$R/protocol_a_master.json" \
    "$SNAP/crypto" "$SNAP/ssl" "$SNAP/providers" \
    | tee "$R/protocol_a_master.log"
  N=$(grep -oE 'violation=[0-9]+' "$R/protocol_a_master.log" | cut -d= -f2)
  if [ "$N" != "11" ]; then
    echo "WARNING: whole-tree scan flagged $N sites, paper reports 11 -- the" >&2
    echo "         snapshot, tree-sitter version, or tool itself has drifted" >&2
    echo "         from results/protocol_a_triage.md. Do not ignore this." >&2
    exit 1
  fi
  echo "PASS: whole-tree scan flags 11 sites, matching protocol_a_triage.md"
else
  echo "== whole tree: SKIPPED ($SNAP not found -- run run_scan.sh first if you want this)"
fi

echo "Done. Logs in $R/protocol_a_*.log (+ protocol_a_master.json if the whole-tree scan ran)."
