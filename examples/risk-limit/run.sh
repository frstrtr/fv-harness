#!/usr/bin/env bash
# run.sh [OUTDIR] — the pre-trade risk-check example through the same gate and fuzzer as any
# project. Expected:
#   gate on lean/ (signed lock, 5 statements)            PASS (exit 0)
#   fuzz, correct C++ (cpp/impl), 10^6 runs              PASS (exit 0)
#   fuzz, buggy C++ (cpp/impl-buggy), 10 s budget        FAIL (exit 1): a huge buy order wraps the
#                                                        buggy limit sum and is accepted; the model rejects it
# Exit 0 iff all three behave as expected.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT/scripts/lib.sh"
E="$ROOT/examples/risk-limit"; LOCK="$ROOT/locks/risk-limit.sha256"
OUT="${1:-$FV_ROOT/runs/risk-limit-$(date +%Y%m%dT%H%M%S)}"; mkdir -p "$OUT"
W="$OUT/lean"; cp -r "$E/lean" "$W"; rm -rf "$W/.lake"   # never build in the repository
fails=0
"$ROOT/scripts/verify_proof.sh" --project "$W" --lock "$LOCK" --out "$OUT/gate" > "$OUT/gate.out" 2>&1
rc=$?; echo "gate: exit $rc ($(jq -r .verdict "$OUT/gate/verdict.json" 2>/dev/null))"; [ $rc -eq 0 ] || fails=1
fz() { # fz NAME IMPL ARGS...
  local n="$1" impl="$2"; shift 2
  cp -r "$E/cpp/fuzz/corpus" "$OUT/corpus-$n"
  "$ROOT/fuzz/run_fuzz.sh" --lean-project "$W" --lock "$LOCK" --cmake-dir "$E/cpp/fuzz" --target diff_risk \
    --impl-dir "$impl" --corpus "$OUT/corpus-$n" --no-merge --out "$OUT/fuzz-$n" "$@" > "$OUT/fuzz-$n.out" 2>&1
}
fz correct "$E/cpp/impl" --runs 1000000; rc=$?
echo "fuzz correct: exit $rc ($(jq -r '.verdict + " " + .stats' "$OUT/fuzz-correct/fuzz.json" 2>/dev/null))"; [ $rc -eq 0 ] || fails=1
fz buggy "$E/cpp/impl-buggy" --time 10; rc=$?
echo "fuzz buggy: exit $rc ($(jq -r '.verdict + ": " + .mismatch' "$OUT/fuzz-buggy/fuzz.json" 2>/dev/null))"; [ $rc -eq 1 ] || fails=1
grep -A6 'diff-oracle: MISMATCH' "$OUT/fuzz-buggy/campaign.log" 2>/dev/null | grep -E 'oracle|impl|op ' | sed 's/^/    /'
exit $fails
