#!/usr/bin/env bash
# run_dry_run.sh TASK — the end-to-end dry run on the conservation fixture (deliverable 5).
#
# A fresh working copy gets the DECOMPOSE skeleton (tests/dry_run/skeleton, written by the Tier-1
# planner), then scripts/formal_task.py drives SPEC_LOCK -> DECOMPOSE -> DISCHARGE (Tier 2,
# config/tier2.env endpoint) -> AUDIT (scripts/verify_proof.sh) -> COUPLE (fuzz/run_fuzz.sh,
# 10^6 runs) -> CLOSE. Output: $FV_ROOT/tasks/TASK (state.json, closure.json, closure.md, logs).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT/scripts/lib.sh"
T="${1:?usage: $0 TASK}"
W="$FV_ROOT/work/$T"
FT="python3 -I $ROOT/scripts/formal_task.py"
[ -e "$FV_ROOT/tasks/$T" ] && die "task $T exists"
rm -rf "$W"; mkdir -p "$(dirname "$W")"
cp -r "$ROOT/fixtures/conservation" "$W"; rm -rf "$W/.lake"
cp "$ROOT/tests/dry_run/skeleton/Solution.lean" "$W/spec/solution/Solution.lean"

note "dry run $T: Tier-2 endpoint $(. "$ROOT/config/tier2.env"; echo "$TIER2_BASE_URL $TIER2_MODEL")"
$FT init "$T" --project "$W" --lock "$ROOT/locks/conservation.sha256" \
  --cmake-dir "$ROOT/fixtures/conservation_cpp/fuzz" --target diff_transfer \
  --budget "${DRY_BUDGET:-8}" --max-attempts "${DRY_MAX_ATTEMPTS:-2}" --fuzz-runs 1000000 || exit 3
$FT spec-lock "$T" || exit $?
$FT decompose "$T" --by "Tier-1 planner: tests/dry_run/skeleton/Solution.lean" || exit $?
$FT run "$T"
rc=$?
$FT status "$T"
exit $rc
