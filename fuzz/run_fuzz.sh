#!/usr/bin/env bash
# run_fuzz.sh — differential fuzz campaign (COUPLE stage, Module 5).
#
#   fuzz/run_fuzz.sh --lean-project DIR --lock LOCKFILE --cmake-dir DIR --target NAME [--lang cpp|rust|python|evm]
#                    [--impl-dir DIR] [--runs N | --time SECONDS] [--corpus DIR]
#                    [--no-merge] [--out RUNDIR] [--draft]
#
# --draft: validate a DRAFT specification before its owner signs it. --lock is then an UNSIGNED
#    manifest (scripts/spec_lock.sh lock output) and step 1 is a content check only
#    (spec_lock.sh check-content); the oracle is still built only from the files it lists. Nothing a
#    draft run produces is countable: "DRAFT (unsigned, not countable)" is the first line of fuzz.log
#    and the first key of fuzz.json, the verdict reads "DRAFT PASS" / "DRAFT FAIL" / ... (never
#    "PASS"), the persisted corpus is never merged into (implies --no-merge), and the gate's COUPLE
#    and CLOSE (scripts/formal_task.py, which never passes --draft) refuse a draft fuzz.json.
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
#    .cargo/config cargo would read) is ERROR. Toolchain: $FV_RUST_HOME (default $FV_ROOT/rust). A second
#    build with `--cfg fv_classify` is the labels-only classify binary (the binding's classes()).
#    --lang evm: a Rust target as above whose implementation is a contract. --impl-dir (default
#    CMAKE_DIR/../contract) holds the Solidity sources; [evm] in CMAKE_DIR/fv.toml names the contract,
#    evmVersion and optimizer settings. solc must be the pinned build ($FV_SOLC, default
#    $FV_ROOT/evm/solc-$FV_SOLC_VERSION, sha256 $FV_SOLC_SHA256), else ERROR. fuzz/evm/compile.py
#    compiles it; the bytecode is embedded through FV_EVM_CREATION/FV_EVM_RUNTIME and run by the
#    harness's EVM (fuzz/evm/fv_evm.rs, FV_EVM_RS). fuzz.json "evm" records the compiler sha256 and
#    version, the settings, and the sha256 of the sources and both bytecodes. If fv.toml sets
#    expect_runtime_sha256 (a deployed contract) and the runtime bytecode differs: BLOCKED. Cargo runs
#    offline and Cargo.lock must not change during the build.
#    --lang python: the same oracle library; the harness's driver fuzz/python/fv_diff.py (Atheris,
#    $FV_PY, default $FV_ROOT/py/venv/bin/python) loads CMAKE_DIR/binding.py and the implementation
#    from --impl-dir; implementation values outside [0, 2^64) FAIL as "domain: ...".
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
# Input length, campaign only (libFuzzer's own defaults when absent):
#   max_len = bytes (a positive whole number)  -> -max_len; the longest input the campaign generates
#   len_control = N (0 or a positive number)   -> -len_control; 0 starts at max_len at once instead of
#                                                 growing from short inputs (structured, multi-case targets)
# They are not applied to the replay, the merge or the classification: -max_len would truncate longer
# corpus inputs there. Both are recorded in fuzz.json .limits (null when absent).
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

proj=""; lock=""; cmake_dir=""; target=""; impl=""; runs=""; secs=""; corpus=""; merge=1; out=""; lang=cpp; draft=0
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
    --draft) draft=1; shift ;;
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
MAX_LEN=$(cfg max_len ""); LEN_CTL=$(cfg len_control "")
[ -z "$MAX_LEN" ] || [[ "$MAX_LEN" =~ ^[1-9][0-9]*$ ]] || BAD_LIMIT+="max_len=$MAX_LEN "
[ -z "$LEN_CTL" ] || [[ "$LEN_CTL" =~ ^(0|[1-9][0-9]*)$ ]] || BAD_LIMIT+="len_control=$LEN_CTL "
[ -z "$BAD_LIMIT" ] || { T_OUT=0; RSS_MB=0; MAL_MB=0; SLOW_S=0; MAX_LEN=""; LEN_CTL=""; }
LENS=(); [ -n "$MAX_LEN" ] && LENS+=(-max_len="$MAX_LEN"); [ -n "$LEN_CTL" ] && LENS+=(-len_control="$LEN_CTL")
LIMITS=(-timeout="$T_OUT" -rss_limit_mb="$RSS_MB" -malloc_limit_mb="$MAL_MB" -report_slow_units="$SLOW_S")
RUN="${out:-$FV_ROOT/runs/fuzz-$target-$(date +%Y%m%dT%H%M%S)-$$}"
mkdir -p "$RUN"; RUN="$(cd "$RUN" && pwd)"
LOG="$RUN/fuzz.log"; : > "$LOG"
DRAFT_STAMP="DRAFT (unsigned, not countable)"
if [ "$draft" -eq 1 ]; then
  merge=0
  echo "$DRAFT_STAMP: run_fuzz.sh --draft, lock $lock is an unsigned manifest" | tee -a "$LOG" >&2
fi
verdict() { # verdict EXIT VERDICT DETAIL
  local v="$2"; [ "$draft" -eq 1 ] && v="DRAFT $2"
  jq -n --arg v "$v" --arg draft "$([ "$draft" -eq 1 ] && echo "$DRAFT_STAMP")" --argjson e "$1" --arg d "$3" --arg t "$target" --arg runs "${runs:-}" \
    --arg secs "${secs:-}" --arg corpus "$corpus" --arg impl "${impl:-default}" \
    --arg lock "$(sha256sum "$lock" | cut -d' ' -f1)" --arg el "${elapsed:-}" \
    --arg mm "$(grep -m1 'diff-oracle: MISMATCH' "$RUN/campaign.log" 2>/dev/null)" \
    --arg art "$(ls "$RUN"/artifacts/ 2>/dev/null | head -1)" \
    --arg stats "$(grep -E '^(stat::number_of_executed_units|stat::average_exec_per_sec|stat::new_units_added)' "$RUN/campaign.log" 2>/dev/null | tr '\n' ' ')" \
    --argjson vend "${VENDORED_JSON:-{\}}" --argjson cls "${CLASSES_JSON:-null}" --argjson evm "${EVM_JSON:-null}" \
    --argjson lim "{\"timeout_s\":$T_OUT,\"rss_limit_mb\":$RSS_MB,\"malloc_limit_mb\":$MAL_MB,\"report_slow_units_s\":$SLOW_S,\"max_len\":${MAX_LEN:-null},\"len_control\":${LEN_CTL:-null}}" \
    --arg slow "$(ls "$RUN"/artifacts/ 2>/dev/null | grep '^slow-unit-' | tr '\n' ' ')" \
    '(if $draft != "" then {draft:$draft} else {} end) + {verdict:$v, exit:$e, detail:$d, target:$t, runs:$runs, max_total_time:$secs, impl_dir:$impl,
      corpus:$corpus, lock_digest:$lock, campaign_seconds:$el, mismatch:$mm, artifact:$art, stats:$stats,
      vendored:$vend, classes:$cls, evm:$evm, limits:$lim, slow_units:($slow | split(" ") | map(select(. != "")))}' \
    > "$RUN/fuzz.json"
  note "fuzz verdict $v (exit $1): $3"
  exit "$1"
}

[ -z "$BAD_LIMIT" ] || verdict 3 ERROR "fv.toml: limits must be positive whole numbers (0 disables a limit; len_control may be 0): ${BAD_LIMIT% }"

# 1. Lock and trusted oracle copy.
if [ "$draft" -eq 1 ]; then
  "$HERE/../scripts/spec_lock.sh" check-content "$proj" "$lock" >> "$LOG" 2>&1 \
    || verdict 2 BLOCKED "draft spec project differs from its unsigned manifest; oracle not built"
elif ! "$HERE/../scripts/spec_lock.sh" check "$proj" "$lock" >> "$LOG" 2>&1; then
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
  rust|evm)
    rh="${FV_RUST_HOME:-$FV_ROOT/rust}"
    [ -x "$rh/cargo/bin/cargo-fuzz" ] || verdict 3 ERROR "cargo-fuzz not installed under $rh (docs/LANGUAGES.md)"
    if [ "$lang" = evm ]; then
      impl_dir="$(cd "${impl:-$cmake_dir/../contract}" && pwd)"
    else
      impl_dir="$(cd "${impl:-$cmake_dir/../impl}" && pwd)"
    fi
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
    unset CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS
    xenv=()
    if [ "$lang" = evm ]; then
      solc="${FV_SOLC:-$FV_ROOT/evm/solc-$FV_SOLC_VERSION}"
      [ -x "$solc" ] || verdict 3 ERROR "solc not installed at $solc (docs/LANGUAGES.md)"
      ssha=$(sha256sum < "$solc" | cut -d' ' -f1)
      [ "$ssha" = "$FV_SOLC_SHA256" ] || verdict 3 ERROR "solc at $solc is not the pinned build: sha256 $ssha, pinned $FV_SOLC_SHA256"
      if ! EVM_JSON=$(capped python3 -I "$HERE/evm/compile.py" --solc "$solc" --src-dir "$impl_dir" \
                      --fv-toml "$cmake_dir/fv.toml" --out "$RUN/evm" 2> "$RUN/evm-compile.err"); then
        EVM_JSON=null; verdict 3 ERROR "contract compilation failed: $(tail -1 "$RUN/evm-compile.err" | cut -c1-300)"
      fi
      EVM_JSON=$(jq -c --arg s "$ssha" '. + {solc_sha256: $s}' <<< "$EVM_JSON")
      exp=$(jq -r .expect_runtime_sha256 <<< "$EVM_JSON"); got=$(jq -r .runtime_sha256 <<< "$EVM_JSON")
      [ -z "$exp" ] || [ "$exp" = "$got" ] \
        || verdict 2 BLOCKED "runtime bytecode sha256 $got differs from expect_runtime_sha256 $exp (fv.toml); not coupled"
      xenv=(FV_EVM_RS="$HERE/evm/fv_evm.rs" FV_EVM_CREATION="$RUN/evm/creation.bin" FV_EVM_RUNTIME="$RUN/evm/runtime.bin"
            FV_EVM_SPEC="$(jq -r .settings.evm_version <<< "$EVM_JSON")" CARGO_NET_OFFLINE=true)
    fi
    cargo_build() { # cargo_build TARGET_DIR EXTRA_RUSTFLAGS
      (cd "$cmake_dir" && capped env RUSTUP_HOME="$rh/rustup" CARGO_HOME="$rh/cargo" PATH="$rh/cargo/bin:$PATH" \
         FV_ORACLE_LIB_DIR="$RUN/build" FV_ORACLE_LIB="${target}_oracle" FV_IMPL_DIR="$impl_dir" \
         FV_DIFF_RS="$HERE/rust/fv_diff.rs" "${xenv[@]}" RUSTFLAGS="-C overflow-checks=on -C debug-assertions=on$2" \
         cargo fuzz build -a --fuzz-dir "$cmake_dir" --target-dir "$1" "$target")
    }
    lock0=$(sha256sum < "$cmake_dir/Cargo.lock" 2>/dev/null)
    if ! { capped cmake "${cfg[@]}" && capped cmake --build "$RUN/build" --target "${target}_oracle" -j "$FV_JOBS" \
           && cargo_build "$RUN/cargo-target" ""; } >> "$LOG" 2>&1; then
      verdict 3 ERROR "fuzzer build failed (see $LOG)"
    fi
    if [ "$lang" = evm ] && { [ ! -f "$cmake_dir/Cargo.lock" ] || [ "$(sha256sum < "$cmake_dir/Cargo.lock")" != "$lock0" ]; }; then
      verdict 3 ERROR "Cargo.lock is missing or changed during the build: dependencies must be pinned in the committed Cargo.lock"
    fi
    BIN="$RUN/cargo-target/x86_64-unknown-linux-gnu/release/$target"
    [ -x "$BIN" ] || verdict 3 ERROR "cargo fuzz produced no binary at $BIN"
    # The labels-only classify binary: a separate build with --cfg fv_classify (never compares).
    if [ "${FV_NO_CLASSIFY:-0}" != 1 ] && cargo_build "$RUN/cargo-target-classify" " --cfg fv_classify" >> "$RUN/build-classify.log" 2>&1 \
       && [ -x "$RUN/cargo-target-classify/x86_64-unknown-linux-gnu/release/$target" ]; then
      BIN_CLS="$RUN/cargo-target-classify/x86_64-unknown-linux-gnu/release/$target"
    fi
    impl="$impl_dir"
    ;;
  python)
    py="${FV_PY:-$FV_ROOT/py/venv/bin/python}"
    { [ -x "$py" ] && "$py" -I -c 'import atheris' 2>/dev/null; } || verdict 3 ERROR "atheris not available to $py (docs/LANGUAGES.md)"
    impl_dir="$(cd "${impl:-$cmake_dir/../impl}" && pwd)"
    bnd="$cmake_dir/binding.py"
    [ -f "$bnd" ] || verdict 3 ERROR "no Python binding $bnd"
    # The loop is the harness's (fuzz/python/fv_diff.py): the binding must not drive the fuzzer.
    if grep -qE '^[^#]*(def[[:space:]]+TestOneInput|atheris\.(Setup|Fuzz))' "$bnd"; then
      verdict 3 ERROR "the Python binding must not define TestOneInput or call atheris.Setup/Fuzz (fuzz/python/fv_diff.py drives the fuzzer)"
    fi
    if ! { capped cmake "${cfg[@]}" && capped cmake --build "$RUN/build" --target "${target}_oracle" -j "$FV_JOBS"; } >> "$LOG" 2>&1; then
      verdict 3 ERROR "oracle build failed (see $LOG)"
    fi
    so="$RUN/build/lib${target}_oracle.so"; [ -f "$so" ] || verdict 3 ERROR "no oracle library $so"
    BIN="$RUN/fuzz-$target"
    printf '#!/bin/sh\nexec env FV_BINDING=%q FV_IMPL_DIR=%q FV_ORACLE_SO=%q %q -I %q "$@"\n' \
      "$bnd" "$impl_dir" "$so" "$py" "$HERE/python/fv_diff.py" > "$BIN"
    chmod +x "$BIN"
    impl="$impl_dir"
    ;;
  *) verdict 3 ERROR "unknown --lang $lang (cpp|rust|python|evm)" ;;
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
  if grep -q 'diff-oracle: DOMAIN' "$l"; then  # Python: a value outside the declared integer width
    echo "domain: $(grep -m1 -oE 'diff-oracle: DOMAIN at step [0-9]+ \(.*\)' "$l" | sed 's/^diff-oracle: DOMAIN //' | cut -c1-140)"
  elif grep -q 'diff-oracle: MISMATCH' "$l"; then echo "oracle/implementation mismatch"
  elif grep -q 'ERROR: libFuzzer: timeout' "$l"; then echo "HANG: input exceeded ${T_OUT} s"
  elif grep -q 'ERROR: libFuzzer: out-of-memory' "$l"; then
    echo "OOM: $(grep -m1 -oE 'out-of-memory \([^)]*\)' "$l")"
  elif grep -q 'ERROR: LeakSanitizer' "$l"; then
    echo "LEAK: $(grep -m1 -oE '(Direct|Indirect) leak of [0-9]+ byte\(s\) in [0-9]+ object\(s\)' "$l")"
  elif grep -q 'Uncaught Python exception' "$l"; then
    echo "python exception: $(grep -A40 'Uncaught Python exception' "$l" | grep -m1 -E '^[A-Za-z_.]*(Error|Exception)' | cut -c1-140)"
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
capped "$BIN" "${limit[@]}" "${LIMITS[@]}" "${LENS[@]}" -print_final_stats=1 -artifact_prefix="$RUN/artifacts/" \
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
