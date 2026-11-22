#!/usr/bin/env bash
# check_vendored.sh FUZZ_DIR — check harness files vendored into a project's fuzz directory.
#
# A project may vendor fuzz/LeanOracle.cmake, fuzz/diff_oracle_template.cpp, fuzz/fv_classify.hpp and the
# Rust driver fuzz/rust/fv_diff.rs (as fv_diff.rs) (the fuzz directory
# lies outside the spec lock, in the agent-writable tree). Each vendored copy must be a regular
# file whose leading comment header names "Vendored from fv-harness <commit or release tag vX.Y.Z>",
# and whose content
# from the harness file's first line on hashes to that commit's line in fuzz/VENDORED.sha256.
# Prints a JSON object {file: {cited_commit, file_sha256, body_sha256, pinned_sha256, match}} for
# the files present (absent files are not vendored: the build then uses the harness's own copy).
# Exit 0 if every present file matches, 1 otherwise.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
dir="${1:?usage: $0 FUZZ_DIR}"
out="{}"; rc=0
for name in LeanOracle.cmake diff_oracle_template.cpp fv_classify.hpp fv_diff.rs; do
  f="$dir/$name"
  [ -e "$f" ] || [ -L "$f" ] || continue
  src="$HERE/$name"; [ "$name" = fv_diff.rs ] && src="$HERE/rust/fv_diff.rs"  # the Rust driver
  first=$(head -1 "$src")
  n=""; commit=""; body=""; pinned=""; hdr_ok=0
  if [ -f "$f" ] && [ ! -L "$f" ]; then
    n=$(grep -n -m1 -Fx -- "$first" "$f" | cut -d: -f1)
  fi
  if [ -n "$n" ]; then
    commit=$(head -n $((n - 1)) "$f" | sed -n 's/.*Vendored from fv-harness \([0-9a-f]\{7,40\}\|v[0-9][0-9.]*[0-9]\).*/\1/p' | head -1)
    body=$(tail -n +"$n" "$f" | sha256sum | cut -d' ' -f1)
    [ -z "$(head -n $((n - 1)) "$f" | grep -vE '^[[:space:]]*(#|//)')" ] && hdr_ok=1
    pinned=$(awk -v c="$commit" -v f="$name" '!/^#/ && $2 == f && c != "" && (c ~ /^v/ ? $1 == c : (index($1, c) == 1 || index(c, $1) == 1)) { print $3; exit }' "$HERE/VENDORED.sha256")
  fi
  match=false
  [ -n "$commit" ] && [ "$hdr_ok" = 1 ] && [ -n "$pinned" ] && [ "$body" = "$pinned" ] && match=true
  [ "$match" = true ] || rc=1
  out=$(jq -c --arg k "$name" --arg c "$commit" --arg b "$body" --arg p "$pinned" \
    --arg fs "$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)" --argjson m "$match" \
    '. + {($k): {cited_commit: $c, file_sha256: $fs, body_sha256: $b, pinned_sha256: $p, match: $m}}' <<< "$out")
  echo "vendored $name: commit=${commit:--} body=${body:--} pinned=${pinned:--} match=$match" >&2
done
echo "$out"
exit $rc
