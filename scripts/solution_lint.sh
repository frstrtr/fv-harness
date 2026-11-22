#!/usr/bin/env bash
# solution_lint.sh PROJECT — policy lint over spec/solution/ (defence in depth; the kernels and
# comparator are the real judges). Exit 0 clean, 1 violations.
#
# Rules: only regular *.lean files under Solution.lean or Solution/; no file over 1000 lines;
# none of the escape hatches below outside comments.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

proj="$1"; sol="$proj/$FV_SOLUTION_REL"
bad=0
flag() { echo "LINT: $*"; bad=1; }

[ -d "$sol" ] || { flag "missing $FV_SOLUTION_REL"; exit 1; }

while IFS= read -r -d '' f; do
  rel="${f#"$sol"/}"
  if [ -L "$f" ] || [ ! -f "$f" ]; then flag "$rel: not a regular file"; continue; fi
  case "$rel" in
    Solution.lean|Solution/*.lean) ;;
    *) flag "$rel: outside Solution.lean / Solution/**.lean"; continue ;;
  esac
  n=$(wc -l < "$f")
  [ "$n" -le 1000 ] || flag "$rel: $n lines (limit 1000, split the file)"
  # Strip block comments and line comments, then look for forbidden constructs.
  # (Nested block comments go innermost-first; newlines are kept so line numbers stay right.)
  hits=$(perl -0777 -pe '1 while s{/-(?:(?!/-|-/).)*-/}{my $s=$&; "\n" x ($s =~ tr/\n//)}gse; s{--[^\n]*}{}g' "$f" |
    grep -nE '\b(sorry|admit|axiom|native_decide|implemented_by|extern|unsafe|trustCompiler|ofReduceBool|ofReduceNat|reduceBool|reduceNat|skipKernelTC|debug\.skip|elab|elab_rules|macro|macro_rules|syntax|initialize|builtin_initialize|run_cmd|run_elab|run_meta|import\s+Lean)\b|#eval|#exit|@\[\s*(extern|implemented_by|export|csimp|init)' || true)
  [ -z "$hits" ] || while IFS= read -r h; do flag "$rel:$h"; done <<< "$hits"
done < <(find "$sol" -mindepth 1 ! -type d -print0)

[ -f "$sol/Solution.lean" ] || flag "Solution.lean missing"
[ "$bad" -eq 0 ] && echo "lint clean"
exit "$bad"
