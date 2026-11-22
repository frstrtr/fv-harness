#!/usr/bin/env bash
# state_machine_rehearsal.sh — exercise every transition of scripts/formal_task.py with the mock
# Tier-2 endpoint (no GPU): an early same-failure wall (every sample fails alike: DISCHARGE ->
# DECOMPOSE after 1 of 3 attempts), a budget wall (samples fail differently: all attempts spent),
# then a re-decomposition that closes, AUDIT, COUPLE (10 s fuzz) and CLOSE. Then a second task where the challenge is
# tampered after SPEC_LOCK (DECOMPOSE -> BLOCKED). Exit 0 iff every step lands where expected.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib.sh"
FT="python3 -I $ROOT/scripts/formal_task.py"
W="$FV_ROOT/work/rehearsal"; TASKS="$FV_ROOT/tasks"
fails=0
expect() { # expect WANT_RC WANT_STATE TASK LABEL CMD...
  local want_rc="$1" want_state="$2" task="$3" label="$4"; shift 4
  "$@" > "$TASKS/.rehearsal-$label.out" 2>&1; local rc=$?
  local state; state=$(jq -r .state "$TASKS/$task/state.json")
  if [ "$rc" -eq "$want_rc" ] && [ "$state" = "$want_state" ]; then echo "OK    $label: exit $rc, state $state"
  else echo "WRONG $label: exit $rc (want $want_rc), state $state (want $want_state)"; tail -5 "$TASKS/.rehearsal-$label.out"; fails=1; fi
}
check() { # check LABEL JQ-EXPR TASK: the expression must be true on the task's state.json
  if jq -e "$2" "$TASKS/$3/state.json" > /dev/null; then echo "OK    $1"
  else echo "WRONG $1: $2 is false"; jq -c '{stubs, tier2_stats}' "$TASKS/$3/state.json"; fails=1; fi
}
mock() { python3 -I "$ROOT/tests/prover_mock_endpoint.py" "$@" > /dev/null 2>&1 & echo $!; }  # detach stdout, or $(mock) waits forever

rm -rf "$W" "$TASKS/rehearse-loop" "$TASKS/rehearse-tamper"; mkdir -p "$TASKS"
cp -r "$ROOT/fixtures/conservation" "$W"; cp "$ROOT/tests/dry_run/skeleton/Solution.lean" "$W/spec/solution/"
export TIER2_CASCADE=main TIER2_BASE_URL=http://127.0.0.1:8099/v1 TIER2_SLOTS=1  # the mock only

T=rehearse-loop
$FT init $T --project "$W" --lock "$ROOT/locks/conservation.sha256" --cmake-dir "$ROOT/fixtures/conservation_cpp/fuzz" \
  --target diff_transfer --budget 2 --max-attempts 3 --fuzz-time 10 > /dev/null
expect 0 DECOMPOSE $T spec-lock $FT spec-lock $T
expect 0 DISCHARGE $T decompose-1 $FT decompose $T --by rehearsal
pid=$(mock 8099 fail); sleep 1
expect 10 DECOMPOSE $T discharge-same-failure-wall $FT discharge $T
kill "$pid"; wait "$pid" 2>/dev/null
check "same-failure wall after 1 of 3 attempts" \
  '([.stubs[] | .attempts == 1 and (.wall_reason | startswith("same failure in every sample: no-code"))] | all)
   and .tier2_stats.walls_same_failure == 2 and .tier2_stats.attempts_saved == 4 and .tier2_stats.walls_budget == 0' $T
expect 0 DISCHARGE $T decompose-2 $FT decompose $T --by rehearsal
expect 0 DISCHARGE $T set-budget $FT set $T --max-attempts 2 --budget 2
pid=$(mock 8099 vary); sleep 1
TIER2_ROUNDS=1 expect 10 DECOMPOSE $T discharge-budget-wall $FT discharge $T
kill "$pid"; wait "$pid" 2>/dev/null
check "budget wall after 2 of 2 attempts (samples failed differently)" \
  '([.stubs[] | .attempts == 2 and (.wall_reason | startswith("budget spent: 2 x K=2"))] | all)
   and .tier2_stats.walls_budget == 2 and .tier2_stats.dispatches == 6' $T
expect 0 DISCHARGE $T decompose-3 $FT decompose $T --by rehearsal
pid=$(mock 8099); sleep 1
expect 0 CLOSED $T run-to-close $FT run $T
kill "$pid"; wait "$pid" 2>/dev/null
[ -s "$TASKS/$T/closure.json" ] && [ -s "$TASKS/$T/closure.md" ] && echo "OK    closure bundle present" || { echo "WRONG closure bundle missing"; fails=1; }
jq -e '.tier2.stats.closed == 2 and .tier2.stats.walls_same_failure == 2 and .tier2.stats.walls_budget == 2' \
  "$TASKS/$T/closure.json" > /dev/null && grep -q '^## Tier 2' "$TASKS/$T/closure.md" \
  && echo "OK    closure records the Tier-2 escalation counters" || { echo "WRONG Tier-2 counters missing from closure"; fails=1; }
expect 3 CLOSED $T illegal-transition $FT audit $T

T=rehearse-tamper
cp "$ROOT/tests/dry_run/skeleton/Solution.lean" "$W/spec/solution/"
$FT init $T --project "$W" --lock "$ROOT/locks/conservation.sha256" --cmake-dir "$ROOT/fixtures/conservation_cpp/fuzz" \
  --target diff_transfer > /dev/null
expect 0 DECOMPOSE $T spec-lock $FT spec-lock $T
sed -i 's/(transfer l amt bps).total = l.total := by/(transfer l amt bps).total ≤ l.total + amt := by/' "$W/spec/challenge/Challenge.lean"
expect 11 BLOCKED $T tamper-blocked $FT decompose $T --by rehearsal
exit $fails
