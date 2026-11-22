#!/usr/bin/env bash
# run_fuzz.sh — differential fuzz campaign (COUPLE stage, Module 5).
#
#   fuzz/run_fuzz.sh --lean-project DIR --lock LOCKFILE --cmake-dir DIR --target NAME
#                    [--impl-dir DIR] [--runs N | --time SECONDS] [--corpus DIR]
#                    [--no-merge] [--out RUNDIR]
#
# 1. The spec project must match its lock (else BLOCKED). The oracle is built from a copy that
#    holds only the locked files, so it comes from spec/challenge and never from spec/solution.
#    Harness files vendored into the fuzz directory (LeanOracle.cmake, diff_oracle_template.cpp)
#    must equal, below their "Vendored from fv-harness <commit>" header, the harness's copy at
#    that commit (fuzz/VENDORED.sha256), else FAIL before anything is built.
# 2. Configure and build the fuzzer (clang, libFuzzer + ASan + UBSan) against that copy.
# 3. Regression replay: every file in the persisted corpus must pass.
# 4. Campaign: -runs=N (default 1000000) or -max_total_time=SECONDS (CI: 60).
# 5. On PASS, merge new coverage into the persisted corpus (unless --no-merge).
#
# Exit: 0 PASS, 1 FAIL (mismatch or sanitizer report), 2 BLOCKED, 3 ERROR. Summary: RUNDIR/fuzz.json.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/../scripts/lib.sh"

proj=""; lock=""; cmake_dir=""; target=""; impl=""; runs=""; secs=""; corpus=""; merge=1; out=""
while [ $# -gt 0 ]; do
  case "$1" in
    --lean-project) proj="$2"; shift 2 ;;
    --lock) lock="$2"; shift 2 ;;
    --cmake-dir) cmake_dir="$2"; shift 2 ;;
    --target) target="$2"; shift 2 ;;
    --impl-dir) impl="$2"; shift 2 ;;
    --runs) runs="$2"; shift 2 ;;
    --time) secs="$2"; shift 2 ;;
    --corpus) corpus="$2"; shift 2 ;;
    --no-merge) merge=0; shift ;;
    --out) out="$2"; shift 2 ;;
    *) die "unknown argument $1" ;;
  esac
done
[ -d "$proj" ] && [ -f "$lock" ] && [ -d "$cmake_dir" ] && [ -n "$target" ] || die "missing required arguments (see header)"
proj="$(cd "$proj" && pwd)"; cmake_dir="$(cd "$cmake_dir" && pwd)"
lock="$(cd "$(dirname "$lock")" && pwd)/$(basename "$lock")"
[ -n "$runs" ] || [ -n "$secs" ] || runs=1000000
corpus="${corpus:-$cmake_dir/corpus}"; mkdir -p "$corpus"
RUN="${out:-$FV_ROOT/runs/fuzz-$target-$(date +%Y%m%dT%H%M%S)-$$}"
mkdir -p "$RUN"; RUN="$(cd "$RUN" && pwd)"
LOG="$RUN/fuzz.log"; : > "$LOG"
verdict() { # verdict EXIT VERDICT DETAIL
  jq -n --arg v "$2" --argjson e "$1" --arg d "$3" --arg t "$target" --arg runs "${runs:-}" \
    --arg secs "${secs:-}" --arg corpus "$corpus" --arg impl "${impl:-default}" \
    --arg lock "$(sha256sum "$lock" | cut -d' ' -f1)" --arg el "${elapsed:-}" \
    --arg mm "$(grep -m1 'diff-oracle: MISMATCH' "$RUN/campaign.log" 2>/dev/null)" \
    --arg art "$(ls "$RUN"/artifacts/ 2>/dev/null | head -1)" \
    --arg stats "$(grep -E '^(stat::number_of_executed_units|stat::average_exec_per_sec|stat::new_units_added)' "$RUN/campaign.log" 2>/dev/null | tr '\n' ' ')" \
    --argjson vend "${VENDORED_JSON:-{\}}" \
    '{verdict:$v, exit:$e, detail:$d, target:$t, runs:$runs, max_total_time:$secs, impl_dir:$impl,
      corpus:$corpus, lock_digest:$lock, campaign_seconds:$el, mismatch:$mm, artifact:$art, stats:$stats,
      vendored:$vend}' \
    > "$RUN/fuzz.json"
  note "fuzz verdict $2 (exit $1): $3"
  exit "$1"
}

# 1. Lock and trusted oracle copy.
if ! "$HERE/../scripts/spec_lock.sh" check "$proj" "$lock" >> "$LOG" 2>&1; then
  verdict 2 BLOCKED "spec project differs from its lock; oracle not built"
fi
# 1b. Vendored harness files in the fuzz directory.
VENDORED_JSON=$("$HERE/check_vendored.sh" "$cmake_dir" 2>> "$LOG"); vrc=$?
[ -n "$VENDORED_JSON" ] || VENDORED_JSON="{}"
if [ $vrc -ne 0 ]; then
  verdict 1 FAIL "vendored harness file differs from the harness copy at its cited commit: $(jq -r 'to_entries[] | select(.value.match | not) | "\(.key) (commit \(.value.cited_commit | if . == "" then "none" else . end))"' <<< "$VENDORED_JSON" | tr '\n' ' ')"
fi

mkdir -p "$RUN/oracle_project"
(cd "$proj" && cut -d' ' -f3- "$lock" | tr '\n' '\0' | xargs -0 cp --parents -t "$RUN/oracle_project")

# 2. Build.
cfg=(-S "$cmake_dir" -B "$RUN/build" -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=RelWithDebInfo
     -DFV_HARNESS_DIR="$FV_HARNESS_DIR" -DLEAN_PROJECT="$RUN/oracle_project" -DLEAN_BIN_DIR="$LEAN_TC/bin")
[ -n "$impl" ] && cfg+=(-DIMPL_DIR="$(cd "$impl" && pwd)")
if ! { capped cmake "${cfg[@]}" && capped cmake --build "$RUN/build" --target "$target" -j "$FV_JOBS"; } >> "$LOG" 2>&1; then
  verdict 3 ERROR "fuzzer build failed (see $LOG)"
fi
BIN="$RUN/build/$target"
mkdir -p "$RUN/artifacts" "$RUN/new_corpus"
export LSAN_OPTIONS="detect_leaks=1"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"
export FV_FUZZ_ARTIFACT_DIR="$RUN/artifacts"

keep_reproducers() { # a failing input joins the persisted corpus, so replay fails until it is fixed
  [ "$merge" -eq 1 ] || return 0
  for f in "$RUN"/artifacts/*; do [ -f "$f" ] && cp "$f" "$corpus/"; done
}

# 3. Regression replay of the persisted corpus.
if ! capped "$BIN" -runs=0 -artifact_prefix="$RUN/artifacts/" "$corpus" > "$RUN/replay.log" 2>&1; then
  cp "$RUN/replay.log" "$RUN/campaign.log"
  verdict 1 FAIL "regression replay failed on the persisted corpus"
fi
rm -f "$RUN"/artifacts/*

# 4. Campaign.
limit=(); [ -n "$secs" ] && limit+=(-max_total_time="$secs"); [ -n "$runs" ] && limit+=(-runs="$runs")
t0=$(date +%s.%N)
capped "$BIN" "${limit[@]}" -print_final_stats=1 -artifact_prefix="$RUN/artifacts/" \
  "$RUN/new_corpus" "$corpus" > "$RUN/campaign.log" 2>&1
rc=$?
elapsed=$(echo "$(date +%s.%N) - $t0" | bc)
if [ $rc -ne 0 ]; then
  keep_reproducers
  if [ $rc -eq 86 ] && grep -q 'diff-oracle: MISMATCH' "$RUN/campaign.log"; then
    verdict 1 FAIL "oracle/implementation mismatch"
  elif grep -qE 'ERROR: (AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer|libFuzzer)|runtime error:' "$RUN/campaign.log"; then
    verdict 1 FAIL "sanitizer or fuzzer crash"
  else verdict 3 ERROR "fuzzer exited $rc"; fi
fi

# 5. Corpus persistence.
if [ "$merge" -eq 1 ]; then
  capped "$BIN" -merge=1 "$corpus" "$RUN/new_corpus" > "$RUN/merge.log" 2>&1 || verdict 3 ERROR "corpus merge failed"
fi
verdict 0 PASS "no mismatch"
