#!/usr/bin/env bash
# run_fuzz.sh — differential fuzz campaign (COUPLE stage, Module 5).
#
#   fuzz/run_fuzz.sh --lean-project DIR --lock LOCKFILE --cmake-dir DIR --target NAME [--lang cpp|rust]
#                    [--impl-dir DIR] [--runs N | --time SECONDS] [--corpus DIR]
#                    [--no-merge] [--out RUNDIR]
#
# 1. The spec project must match its lock (else BLOCKED). The oracle is built from a copy that
#    holds only the locked files, so it comes from spec/challenge and never from spec/solution.
#    Harness files vendored into the fuzz directory (LeanOracle.cmake, diff_oracle_template.cpp)
#    must equal, below their "Vendored from fv-harness <commit>" header, the harness's copy at
#    that commit (fuzz/VENDORED.sha256), else FAIL before anything is built.
# 2. Configure and build the fuzzer (clang, libFuzzer + ASan + UBSan) against that copy.
#    --lang rust: CMAKE_DIR's CMakeLists.txt builds only <target>_oracle, the oracle as a shared
#    library (lean_oracle_shared); then `cargo fuzz build -a` (ASan, debug assertions and overflow
#    checks ON) builds the cargo-fuzz target <target> in CMAKE_DIR with FV_ORACLE_LIB_DIR pointing at
#    it, FV_IMPL_DIR at --impl-dir and FV_DIFF_RS at the harness's driver (fuzz/rust/fv_diff.rs),
#    which the target must use (fv_diff_main!, no fuzz_target! of its own). RUSTFLAGS forces
#    overflow checks and debug assertions on; a project setting either off (Cargo.toml, any
#    .cargo/config cargo would read) is ERROR. Toolchain: $FV_RUST_HOME (default $FV_ROOT/rust). Rust runs
#    are not classified yet (labels only).
# 3. Regression replay: every file in the persisted corpus must pass.
# 4. Campaign: -runs=N (default 1000000) or -max_total_time=SECONDS (CI: 60).
# 5. On PASS, merge new coverage into the persisted corpus (unless --no-merge).
# 6. Edge-case classification, labels only (fuzz/fv_classify.hpp, classify_report.py): a separate
#    replay of the corpus through the oracle alone counts each class (generic boundary classes from
#    the binding's describe(), domain classes from classes.hpp next to the binding), lists the
#    classes never hit as NOT EXERCISED and writes RUNDIR/classify/review_deck.md. On FAIL, the
#    reproducers are classified instead. It never changes the verdict; FV_NO_CLASSIFY=1 skips it.
#
# Limits per project, from [fuzz] in CMAKE_DIR/fv.toml (defaults in brackets), applied to the replay,
# the campaign, the merge and the classification replay:
#   timeout = seconds per input [10]       -> FAIL "HANG: input exceeded N s" (infinite or runaway loops)
#   rss_limit_mb [2048], malloc_limit_mb [= rss_limit_mb] -> FAIL "OOM: ..." (unbounded growth, huge mallocs)
#   report_slow_units = seconds [2]        -> slow inputs are listed in fuzz.json (slow_units), not a failure
# Leaks (LeakSanitizer, per input and at exit) FAIL as "LEAK: ...". A leak is memory no longer
# reachable; memory that stays reachable while it grows is not a leak, and only the RSS limit stops it.
#
# Exit: 0 PASS, 1 FAIL (mismatch, sanitizer, leak, hang or OOM), 2 BLOCKED, 3 ERROR. Summary: RUNDIR/fuzz.json.
set -uo pipefail
# The verdict binary contains no classify code (see diff_oracle_template.cpp); these variables only
# matter to the separate classify build, and are cleared so nothing inherited can reach either.
unset FV_CLASSIFY FV_CLASSIFY_RENDER FV_CLASSIFY_TIME_IMPL
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/../scripts/lib.sh"

proj=""; lock=""; cmake_dir=""; target=""; impl=""; runs=""; secs=""; corpus=""; merge=1; out=""; lang=cpp
while [ $# -gt 0 ]; do
  case "$1" in
    --lean-project) proj="$2"; shift 2 ;;
    --lock) lock="$2"; shift 2 ;;
    --cmake-dir) cmake_dir="$2"; shift 2 ;;
    --target) target="$2"; shift 2 ;;
    --impl-dir) impl="$2"; shift 2 ;;
    --lang) lang="$2"; shift 2 ;;
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
cfg() { # cfg KEY DEFAULT -> [fuzz] KEY from CMAKE_DIR/fv.toml, or DEFAULT
  python3 -I -c 'import sys, tomllib
try: print(tomllib.load(open(sys.argv[1], "rb")).get("fuzz", {}).get(sys.argv[2], sys.argv[3]))
except OSError: print(sys.argv[3])' "$cmake_dir/fv.toml" "$1" "$2"
}
T_OUT=$(cfg timeout 10); RSS_MB=$(cfg rss_limit_mb 2048); MAL_MB=$(cfg malloc_limit_mb "$RSS_MB"); SLOW_S=$(cfg report_slow_units 2)
BAD_LIMIT=""  # 0 means "no limit" to libFuzzer, so it would silently switch HANG/OOM off: refused
for kv in "timeout=$T_OUT" "rss_limit_mb=$RSS_MB" "malloc_limit_mb=$MAL_MB" "report_slow_units=$SLOW_S"; do
  [[ "${kv#*=}" =~ ^[1-9][0-9]*$ ]] || BAD_LIMIT+="${kv} "
done
[ -z "$BAD_LIMIT" ] || { T_OUT=0; RSS_MB=0; MAL_MB=0; SLOW_S=0; }
LIMITS=(-timeout="$T_OUT" -rss_limit_mb="$RSS_MB" -malloc_limit_mb="$MAL_MB" -report_slow_units="$SLOW_S")
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
    --argjson vend "${VENDORED_JSON:-{\}}" --argjson cls "${CLASSES_JSON:-null}" \
    --argjson lim "{\"timeout_s\":$T_OUT,\"rss_limit_mb\":$RSS_MB,\"malloc_limit_mb\":$MAL_MB,\"report_slow_units_s\":$SLOW_S}" \
    --arg slow "$(ls "$RUN"/artifacts/ 2>/dev/null | grep '^slow-unit-' | tr '\n' ' ')" \
    '{verdict:$v, exit:$e, detail:$d, target:$t, runs:$runs, max_total_time:$secs, impl_dir:$impl,
      corpus:$corpus, lock_digest:$lock, campaign_seconds:$el, mismatch:$mm, artifact:$art, stats:$stats,
      vendored:$vend, classes:$cls, limits:$lim, slow_units:($slow | split(" ") | map(select(. != "")))}' \
    > "$RUN/fuzz.json"
  note "fuzz verdict $2 (exit $1): $3"
  exit "$1"
}

[ -z "$BAD_LIMIT" ] || verdict 3 ERROR "fv.toml: limits must be positive whole numbers (0 disables a limit): ${BAD_LIMIT% }"

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
cfg=(-S "$cmake_dir" -B "$RUN/build" -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_COMPILER=clang
     -DCMAKE_BUILD_TYPE=RelWithDebInfo
     -DFV_HARNESS_DIR="$FV_HARNESS_DIR" -DLEAN_PROJECT="$RUN/oracle_project" -DLEAN_BIN_DIR="$LEAN_TC/bin")
BIN_CLS=""
case "$lang" in
  cpp)
    [ -n "$impl" ] && cfg+=(-DIMPL_DIR="$(cd "$impl" && pwd)")
    if ! { capped cmake "${cfg[@]}" && capped cmake --build "$RUN/build" --target "$target" -j "$FV_JOBS"; } >> "$LOG" 2>&1; then
      verdict 3 ERROR "fuzzer build failed (see $LOG)"
    fi
    BIN="$RUN/build/$target"
    # The labels-only classify build is optional: without it (e.g. an older vendored
    # LeanOracle.cmake) the run is simply not classified. It never affects the verdict.
    if capped cmake --build "$RUN/build" --target "${target}_classify" -j "$FV_JOBS" >> "$RUN/build-classify.log" 2>&1 \
       && [ -x "$RUN/build/${target}_classify" ]; then
      BIN_CLS="$RUN/build/${target}_classify"
    fi
    ;;
  rust)
    rh="${FV_RUST_HOME:-$FV_ROOT/rust}"
    [ -x "$rh/cargo/bin/cargo-fuzz" ] || verdict 3 ERROR "cargo-fuzz not installed under $rh (docs/LANGUAGES.md)"
    impl_dir="$(cd "${impl:-$cmake_dir/../impl}" && pwd)"
    # The comparison loop is the harness's (fuzz/rust/fv_diff.rs): the target must use it.
    tsrc="$cmake_dir/fuzz_targets/$target.rs"
    [ -f "$tsrc" ] || verdict 3 ERROR "no fuzz target source $tsrc"
    if grep -q 'fuzz_target!' "$tsrc" || ! grep -q 'fv_diff_main!' "$tsrc"; then
      verdict 3 ERROR "the Rust fuzz target must end with fv_diff_main!(...) and define no fuzz_target! of its own (fuzz/rust/fv_diff.rs)"
    fi
    # Overflow checks and debug assertions cannot be switched off by the project.
    off=$( { grep -HnE '^[[:space:]]*(overflow-checks|debug-assertions)[[:space:]]*=[[:space:]]*false' "$cmake_dir/Cargo.toml" 2>/dev/null
             d="$cmake_dir"; while :; do
               for c in "$d/.cargo/config" "$d/.cargo/config.toml"; do
                 [ -f "$c" ] && grep -HnE '(overflow-checks|debug-assertions)[[:space:]]*=[[:space:]]*false|overflow-checks=off|debug-assertions=off' "$c"
               done
               [ "$d" = / ] && break; d=$(dirname "$d")
             done
             for c in "$rh/cargo/config" "$rh/cargo/config.toml"; do
               [ -f "$c" ] && grep -HnE '(overflow-checks|debug-assertions)[[:space:]]*=[[:space:]]*false|overflow-checks=off|debug-assertions=off' "$c"
             done; } | head -3)
    [ -z "$off" ] || verdict 3 ERROR "overflow checks or debug assertions switched off for the Rust build: $(echo "$off" | tr '\n' ' ')"
    while IFS= read -r v; do unset "$v"; done < <(env | sed -n 's/^\(CARGO_PROFILE_[A-Z0-9_]*\)=.*/\1/p')
    if ! { capped cmake "${cfg[@]}" && capped cmake --build "$RUN/build" --target "${target}_oracle" -j "$FV_JOBS" \
           && (cd "$cmake_dir" && RUSTUP_HOME="$rh/rustup" CARGO_HOME="$rh/cargo" PATH="$rh/cargo/bin:$PATH" \
               FV_ORACLE_LIB_DIR="$RUN/build" FV_ORACLE_LIB="${target}_oracle" FV_IMPL_DIR="$impl_dir" \
               FV_DIFF_RS="$HERE/rust/fv_diff.rs" RUSTFLAGS="-C overflow-checks=on -C debug-assertions=on" \
               capped cargo fuzz build -a --fuzz-dir "$cmake_dir" --target-dir "$RUN/cargo-target" "$target"); } >> "$LOG" 2>&1; then
      verdict 3 ERROR "fuzzer build failed (see $LOG)"
    fi
    BIN="$RUN/cargo-target/x86_64-unknown-linux-gnu/release/$target"
    [ -x "$BIN" ] || verdict 3 ERROR "cargo fuzz produced no binary at $BIN"
    impl="$impl_dir"
    ;;
  *) verdict 3 ERROR "unknown --lang $lang (cpp|rust)" ;;
esac
classify_line_in() { # a verdict log must never come from the classify build
  local f; for f in "$@"; do [ -f "$f" ] && grep -q 'diff-oracle: CLASSIFY BUILD' "$f" && return 0; done; return 1
}
mkdir -p "$RUN/artifacts" "$RUN/new_corpus"
export LSAN_OPTIONS="detect_leaks=1"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"
export FV_FUZZ_ARTIFACT_DIR="$RUN/artifacts"

classify() { # classify corpus|findings — labels only; sets CLASSES_JSON, never the verdict
  [ "${FV_NO_CLASSIFY:-0}" = 1 ] && return 0
  [ -n "$BIN_CLS" ] || { CLASSES_JSON='{"labels_only": true, "error": "no classify build (add_diff_fuzzer from an older LeanOracle.cmake?)"}'; return 0; }
  local C="$RUN/classify" hdr=() src=() fnd=()
  mkdir -p "$C"; rm -f "$C/log.jsonl"
  [ -f "$cmake_dir/classes.hpp" ] && hdr=(--classes-header "$cmake_dir/classes.hpp")
  if [ "$1" = corpus ]; then
    src=("$corpus"); [ "$merge" -eq 1 ] || src+=("$RUN/new_corpus")
    FV_CLASSIFY="$C/log.jsonl" FV_CLASSIFY_TIME_IMPL=1 capped "$BIN_CLS" "${LIMITS[@]}" -runs=0 "${src[@]}" > "$C/replay.log" 2>&1
  else
    for f in "$RUN"/artifacts/*; do [ -f "$f" ] && fnd+=("$f"); done
    [ ${#fnd[@]} -gt 0 ] || return 0
    fnd=(--findings "${fnd[@]}")
  fi
  if ! CLASSES_JSON=$(capped python3 -I "$HERE/classify_report.py" --log "$C/log.jsonl" --bin "$BIN_CLS" --out "$C" \
       --corpus "${src[@]}" "${hdr[@]}" "${fnd[@]}" 2>> "$C/report.log") || [ -z "$CLASSES_JSON" ]; then
    CLASSES_JSON='{"labels_only": true, "error": "classification failed (see classify/report.log)"}'
  fi
}

fail_kind() { # fail_kind LOG -> a verdict detail naming what went wrong, or nothing
  local l="$1"
  if grep -q 'diff-oracle: MISMATCH' "$l"; then echo "oracle/implementation mismatch"
  elif grep -q 'ERROR: libFuzzer: timeout' "$l"; then echo "HANG: input exceeded ${T_OUT} s"
  elif grep -q 'ERROR: libFuzzer: out-of-memory' "$l"; then
    echo "OOM: $(grep -m1 -oE 'out-of-memory \([^)]*\)' "$l")"
  elif grep -q 'ERROR: LeakSanitizer' "$l"; then
    echo "LEAK: $(grep -m1 -oE '(Direct|Indirect) leak of [0-9]+ byte\(s\) in [0-9]+ object\(s\)' "$l")"
  elif grep -q "panicked at" "$l"; then  # Rust: overflow checks, explicit panics, unwraps
    echo "panic: $(grep -m1 -A1 'panicked at' "$l" | tr '\n' ' ' | sed -E "s/^thread '[^']*' //" | cut -c1-160)"
  elif grep -qE 'ERROR: (AddressSanitizer|UndefinedBehaviorSanitizer)|runtime error:' "$l"; then
    echo "sanitizer: $(grep -m1 -oE '(AddressSanitizer|UndefinedBehaviorSanitizer): [A-Za-z-]+|runtime error: .{0,80}' "$l")"
  elif grep -q 'ERROR: libFuzzer' "$l"; then echo "fuzzer: $(grep -m1 -oE 'ERROR: libFuzzer: [a-z-]+' "$l")"
  fi
}

keep_reproducers() { # a failing input joins the persisted corpus, so replay fails until it is fixed
  [ "$merge" -eq 1 ] || return 0
  for f in "$RUN"/artifacts/*; do [ -f "$f" ] && cp "$f" "$corpus/"; done
}

# 3. Regression replay of the persisted corpus.
capped "$BIN" "${LIMITS[@]}" -runs=0 -artifact_prefix="$RUN/artifacts/" "$corpus" > "$RUN/replay.log" 2>&1
replay_rc=$?
classify_line_in "$RUN/replay.log" && verdict 3 ERROR "the replay ran a classify build, which never compares"
if [ $replay_rc -ne 0 ]; then
  cp "$RUN/replay.log" "$RUN/campaign.log"
  classify findings
  verdict 1 FAIL "regression replay failed on the persisted corpus: $(fail_kind "$RUN/replay.log")"
fi
rm -f "$RUN"/artifacts/*

# 4. Campaign.
limit=(); [ -n "$secs" ] && limit+=(-max_total_time="$secs"); [ -n "$runs" ] && limit+=(-runs="$runs")
t0=$(date +%s.%N)
capped "$BIN" "${limit[@]}" "${LIMITS[@]}" -print_final_stats=1 -artifact_prefix="$RUN/artifacts/" \
  "$RUN/new_corpus" "$corpus" > "$RUN/campaign.log" 2>&1
rc=$?
elapsed=$(echo "$(date +%s.%N) - $t0" | bc)
classify_line_in "$RUN/campaign.log" && verdict 3 ERROR "the campaign ran a classify build, which never compares"
if [ $rc -ne 0 ]; then
  keep_reproducers
  classify findings
  kind=$(fail_kind "$RUN/campaign.log")
  if [ $rc -eq 86 ] && [ "$kind" = "oracle/implementation mismatch" ]; then
    verdict 1 FAIL "$kind"
  elif [ -n "$kind" ]; then verdict 1 FAIL "$kind"
  else verdict 3 ERROR "fuzzer exited $rc"; fi
fi

# 5. Corpus persistence.
if [ "$merge" -eq 1 ]; then
  capped "$BIN" "${LIMITS[@]}" -merge=1 "$corpus" "$RUN/new_corpus" > "$RUN/merge.log" 2>&1 || verdict 3 ERROR "corpus merge failed"
  classify_line_in "$RUN/merge.log" && verdict 3 ERROR "the merge ran a classify build"
fi
# 6. Edge-case classification (labels only).
classify corpus
verdict 0 PASS "no mismatch"
