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
# A tree the closure can name: the rehearsal copy as a git repository (.git is outside the lock).
git -C "$W" init -q && git -C "$W" -c user.name=rehearsal -c user.email=rehearsal@localhost add -A \
  && git -C "$W" -c user.name=rehearsal -c user.email=rehearsal@localhost commit -q -m "rehearsal tree" 
ct0=$(python3 -I "$ROOT/scripts/formal_task.py" tree "$W")
jq -e '.content_equals_commit == true and .content_tree == .commit_tree' <<< "$ct0" > /dev/null \
  && echo "OK    content tree equals the commit's tree before any change ($(jq -r .content_tree <<< "$ct0" | cut -c1-12))" \
  || { echo "WRONG content tree differs from an unchanged commit: $ct0"; fails=1; }
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
jq -e '(.closed_tree.commit // "" | length) > 0 and (.harness_commit // "" | length) > 0 and .harness_commit != "unknown"
       and .closed_tree.content_equals_commit == false and (.closed_tree.content_tree | length) == 40' \
  "$TASKS/$T/closure.json" > /dev/null && grep -q '^Closed tree: `.*content tree `' "$TASKS/$T/closure.md" \
  && echo "OK    closure names the closed tree ($(jq -r .closed_tree.commit "$TASKS/$T/closure.json" | cut -c1-12)), its content tree ($(jq -r .closed_tree.content_tree "$TASKS/$T/closure.json" | cut -c1-12), differs: Solution.lean written after the commit) and the harness commit ($(jq -r .harness_commit "$TASKS/$T/closure.json"))" \
  || { echo "WRONG closure lacks closed_tree / harness_commit"; fails=1; }
# Harness cleanliness: a deployment with a manifest is clean, a changed file makes it DIRTY, an added
# file is deployment data (not dirty).
HX="$W-harness"; rm -rf "${HX:?}"; mkdir -p "$HX"; (cd "$ROOT" && tar -cf - --exclude=./DEPLOYED_COMMIT --exclude=./DEPLOYED_MANIFEST.sha256 .) | tar -xf - -C "$HX"
bash "$HX/scripts/deploy_manifest.sh" rehearsal-deploy > /dev/null
h1=$(python3 -I "$HX/scripts/formal_task.py" harness)
printf '\n# changed\n' >> "$HX/fuzz/run_fuzz.sh"; echo 'FV_JOBS=1' > "$HX/config/hosts.env.rehearsal"
h2=$(python3 -I "$HX/scripts/formal_task.py" harness); rm -rf "${HX:?}"
if jq -e '.dirty == false and .commit == "rehearsal-deploy"' <<< "$h1" > /dev/null \
   && jq -e '.dirty == true and .changed == ["fuzz/run_fuzz.sh"] and (.extra | index("config/hosts.env.rehearsal"))' <<< "$h2" > /dev/null; then
  echo "OK    harness record: clean deployment = clean; a changed file = DIRTY (fuzz/run_fuzz.sh); an added file = deployment data"
else
  echo "WRONG harness record: clean=$h1 changed=$h2"; fails=1
fi
# Exclusions are exact generated paths: a source directory named build/ counts, the project's .lake does not.
for mode in git archive; do
  X="$W-tree-$mode"; rm -rf "${X:?}"; mkdir -p "$X/p/build"; echo 'int keep;' > "$X/p/build/keep.c"; echo x > "$X/p/lakefile.toml"
  if [ $mode = git ]; then git -C "$X" init -q && git -C "$X" -c user.name=r -c user.email=r@l add -A && git -C "$X" -c user.name=r -c user.email=r@l commit -q -m t
  else echo 0123abc > "$X/.source-commit"; fi
  c0=$(python3 -I "$ROOT/scripts/formal_task.py" tree "$X/p" | jq -r .content_tree)
  mkdir -p "$X/p/.lake"; echo junk > "$X/p/.lake/junk"; c1=$(python3 -I "$ROOT/scripts/formal_task.py" tree "$X/p" | jq -r .content_tree)
  echo 'int changed;' > "$X/p/build/keep.c"; c2=$(python3 -I "$ROOT/scripts/formal_task.py" tree "$X/p" | jq -r .content_tree)
  ex=$(python3 -I "$ROOT/scripts/formal_task.py" tree "$X/p" | jq -c .excluded); rm -rf "${X:?}"
  if [ "$c0" = "$c1" ] && [ "$c1" != "$c2" ] && [ "$ex" = '["p/.lake"]' ]; then
    echo "OK    $mode: the project's .lake is excluded ($ex), a source build/ directory is not (content changes with it)"
  else
    echo "WRONG $mode exclusions: c0=$c0 c1=$c1 c2=$c2 excluded=$ex"; fails=1
  fi
done
expect 3 CLOSED $T illegal-transition $FT audit $T

T=rehearse-tamper
cp "$ROOT/tests/dry_run/skeleton/Solution.lean" "$W/spec/solution/"
$FT init $T --project "$W" --lock "$ROOT/locks/conservation.sha256" --cmake-dir "$ROOT/fixtures/conservation_cpp/fuzz" \
  --target diff_transfer > /dev/null
expect 0 DECOMPOSE $T spec-lock $FT spec-lock $T
sed -i 's/(transfer l amt bps).total = l.total := by/(transfer l amt bps).total ≤ l.total + amt := by/' "$W/spec/challenge/Challenge.lean"
expect 11 BLOCKED $T tamper-blocked $FT decompose $T --by rehearsal
exit $fails
