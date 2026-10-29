#!/usr/bin/env bash
# run_scan.sh - reproduce every Protocol B number from a clean checkout.
#
#   bash run_scan.sh [WORKDIR]        (default WORKDIR = ./ossl, git-ignored)
#
# Needs: git >= 2.25, python3, pip install tree-sitter tree-sitter-c, network access to github.com.
# Clones OpenSSL without file contents, checks out only crypto/ ssl/ providers/ at fixed SHAs,
# runs outparam.py and writes unedited logs + JSON + an environment record to ./results/.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
W="${1:-$HERE/ossl}"
R="$HERE/results"
mkdir -p "$W" "$R"
OUT="python3 $HERE/outparam.py"

# name -> full commit SHA (pinned; never a branch or tag, so reruns are identical)
declare -A SHA=(
  [cve4450_pre]=8e257b86e5812c6e1cfa9e8e5f5660ac7bed899d     # parent of 63bcf189be
  [cve4450_post]=63bcf189be73a9cc1264059bed6f57974be74a83    # CVE-2022-4450 fix
  [kdf_pre]=29a27cb2c5c1757831f42117871f8c59058343a9         # parent of d2217c88df
  [kdf_post]=d2217c88df6e65c756013417e5ee4f470dd12470        # "various kdfs: Always reset buflen..." (not a CVE)
  [v3_0_0]=89cd17a031e022211684eb7eb41190cf1910f9fa          # tag openssl-3.0.0
  [master_2026_10_30]=949fe8b5f48c4c82bff6be7fb23de473ab6945a0  # master when this work was done
)
ORDER=(cve4450_pre cve4450_post kdf_pre kdf_post v3_0_0 master_2026_10_30)

[ -d "$W/repo/.git" ] || git clone --filter=blob:none --no-checkout https://github.com/openssl/openssl.git "$W/repo" || exit 2
git -C "$W/repo" config gc.auto 0
git -C "$W/repo" config advice.detachedHead false

for n in "${ORDER[@]}"; do
  d="$W/snap_$n"
  if [ ! -d "$d" ]; then
    git -C "$W/repo" worktree add --no-checkout --detach "$d" "${SHA[$n]}" >/dev/null 2>&1 || { echo "cannot create $d"; exit 2; }
    ( cd "$d" && git sparse-checkout init --cone >/dev/null && git sparse-checkout set crypto ssl providers && git checkout -q "${SHA[$n]}" ) || exit 2
  fi
done

{
  echo "date_utc: $(date -u +%FT%TZ)"
  echo "python: $(python3 --version 2>&1)"
  echo "tree-sitter: $(python3 -c 'import importlib.metadata as m; print(m.version("tree-sitter"), "tree-sitter-c", m.version("tree-sitter-c"))')"
  echo "git: $(git --version)"
  echo "uname: $(uname -sr)"
  echo "spec_sha256: $(sha256sum "$HERE/specs/outparam_reset.json" | cut -d' ' -f1)"
  for n in "${ORDER[@]}"; do echo "snapshot $n: $(git -C "$W/snap_$n" rev-parse HEAD) c_files=$(find "$W/snap_$n"/crypto "$W/snap_$n"/ssl "$W/snap_$n"/providers -name '*.c' | wc -l)"; done
} > "$R/environment.txt"

# Run from $W with relative paths so the saved logs contain no machine-specific paths.
cd "$W" || exit 2

# 1. the motivating function, pre and post fix
$OUT --func PEM_read_bio_ex snap_cve4450_pre/crypto/pem/pem_lib.c  > "$R/pem_read_bio_ex_pre.log"  2>&1; echo "exit=$?" >> "$R/pem_read_bio_ex_pre.log"
$OUT --func PEM_read_bio_ex snap_cve4450_post/crypto/pem/pem_lib.c > "$R/pem_read_bio_ex_post.log" 2>&1; echo "exit=$?" >> "$R/pem_read_bio_ex_post.log"

# 2. whole-tree scans
for n in "${ORDER[@]}"; do
  $OUT --json "$R/$n.json" snap_$n/crypto snap_$n/ssl snap_$n/providers > "$R/$n.log" 2>&1
  echo "exit=$?" >> "$R/$n.log"
done

# 3. what did each fix change?
for p in "cve4450_pre cve4450_post" "kdf_pre kdf_post"; do
  set -- $p
  python3 "$HERE/compare.py" "$R/$1.json" "$R/$2.json" --prefix-pre "snap_$1" --prefix-post "snap_$2" > "$R/diff_$1_vs_$2.log"
done

echo "== environment";  cat "$R/environment.txt"
echo; echo "== PEM_read_bio_ex @ pre-fix";  grep -v '^SUPPRESSED' "$R/pem_read_bio_ex_pre.log"
echo "== PEM_read_bio_ex @ post-fix"; cat "$R/pem_read_bio_ex_post.log"
for n in "${ORDER[@]}"; do echo "== whole tree $n"; tail -n 2 "$R/$n.log" | head -1; done
for f in "$R"/diff_*.log; do echo "== $(basename "$f" .log)"; cat "$f"; done
