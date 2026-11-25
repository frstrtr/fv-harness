#!/usr/bin/env bash
# run_fuzz_controls.sh OUTDIR — the differential-fuzzer legs of the acceptance controls.
#
#   c1_fuzz       correct implementation, 10^6 runs (local budget): PASS, no mismatch
#   c6_cpp_drift  fee rounded half up instead of down: FAIL (the fixture corpus reaches it at replay), reproducer written
#   c7_lsan_leak  production code leaks a buffer per call (results unchanged): LeakSanitizer must
#                 report it with a ledger.hpp frame. Proves the Lean-runtime exemption
#                 (ScopedDisabler in LLVMFuzzerInitialize) does not hide production leaks.
#   c8_vendored_tamper  the fuzz directory vendors the harness's template with its comparison
#                 disabled (one line): COUPLE must FAIL before building, naming the file; an
#                 untampered vendored pair must pass the same check.
#   c9_edge_not_exercised  the fixture binding's generator never produces a fee rate above the cap;
#                 the edge-case classifier must list that domain class as NOT EXERCISED while the
#                 verdict stays PASS (classes are labels only). c1_fuzz, with the normal generator,
#                 must show the same class exercised.
#   c10_leak_class  production code leaks only when the amount exceeds the balance: FAIL as LEAK,
#                 the finding tagged with that domain class.
#   c11_hang      production code loops forever on one fee rate: FAIL as "HANG: input exceeded 2 s"
#                 (fv.toml timeout = 2) well within a 60 s campaign, reproducer kept.
#   c12_growth    production code keeps a reachable cache that grows 1 MiB per call (not a leak):
#                 FAIL as OOM under fv.toml rss_limit_mb = 256.
#   c13_classify_env  c6's drift variant with FV_CLASSIFY, FV_CLASSIFY_RENDER and FV_CLASSIFY_TIME_IMPL
#                 exported by the caller: must still FAIL as a mismatch; the verdict binary must not
#                 contain the classify build (nm: no fv_classify_build_marker), the classify binary must.
#   c14_zero_limits   fv.toml timeout / rss_limit_mb / malloc_limit_mb = 0 (libFuzzer: "no limit"):
#                 each must be refused with ERROR (exit 3) before anything is built.
#   c32_len_limits  fv.toml [fuzz] max_len / len_control: max_len = 0 and len_control = -1 are each
#                 ERROR before any build; max_len = 300 with len_control = 0 reaches the campaign
#                 (libFuzzer status lines show "lim: 300") and is recorded in fuzz.json .limits, while a
#                 run without them (c1) records null.
#   c38_jobs        --jobs 4: (a) the correct implementation, 40,000 executions in total: PASS, fuzz.json
#                 counts the sum of the 4 workers' executed units; (b) an implementation that drifts only
#                 in worker 2 (FV_FUZZ_WORKER=2): FAIL naming worker 2, the other workers passing.
#   c39_remote_bundle  workers from a hash-pinned bundle (--remote local:K): (a) correct implementation,
#                 1 local + 2 bundle workers: PASS, total executions include the bundle workers, fuzz.json
#                 records the bundle sha256 and the worker's glibc / libstdc++; (b) a drift only in bundle
#                 worker 2: FAIL naming it; (c) the worker runner refuses a bundle with a changed file
#                 (BLOCKED, exit 2); (d) a bundle that is not this run's build (changed file, re-made
#                 manifest): the gate refuses it before any worker starts, BLOCKED.
#   c40_guards     the shared-host guards (fuzz/worker/fv_guard.sh), driven by fake readings on this host:
#                 the start gate (NTP, unparsable or stale head); a stale head, failing endpoint, NTP lost,
#                 busy or vanished inference, low memory and high load each END the running batch and,
#                 once cleared, a new batch starts; no RESUME while a reading is still bad; a decoy
#                 "java" is never stopped (tests/harness_fv_controls/c40_guards.sh, on the c39 bundle).
#   c43_merge .. c47_run_name  batch verdicts, bundle strictness, a pause longer than the timeout, the
#                 ssh transport against a test-only localhost sshd, run names
#                 (tests/harness_fv_controls/multihost_controls.sh, on the c39 bundle).
#   c42_cmake_args  extra project CMake definitions: a non -D argument, one with whitespace and one that
#                 names a harness-owned variable (CMAKE_CXX_FLAGS) are each ERROR before any build; a
#                 site default (FV_CMAKE_ARGS) plus a command-line -D reach the build and are recorded in
#                 fuzz.json with their source and the sha256 of the path they name.
#   c48_record_failure  the fuzz.json record is part of the verdict: with the writer's jq failing, a run
#                 that would PASS and one that would FAIL each end ERROR (exit 3), never 0 or 1
#                 (tests/harness_fv_controls/c48_record_failure.sh).
#   c50_bytes_abi  the ByteArray oracle ABI (LeanOracle.cmake BYTES): no memory growth over 2 x 100,000
#                 calls, one reference consumed, a wrong length is ERROR, no change without BYTES; with red
#                 wrappers for a leak and a double release (tests/harness_fv_controls/c50_bytes_abi.sh).
#   c53_merge_failure  an implementation that is wrong only inside libFuzzer's corpus-merge inner
#                 process (-merge_inner=1; fee one unit high on odd amounts): the campaign and replay pass,
#                 the merge meets the mismatch; libFuzzer alone would retry without it and report success.
#                 The run must FAIL (exit 1) naming the merge, with the mismatch recorded in fuzz.json and
#                 the reproducer kept in the corpus. This control runs WITH the merge, into a copy.
#   c54_merge_inner_exit  the inner merge process exits 1 on odd amounts (no finding): ERROR (exit 3),
#                 never PASS.
#   c62_slow_units_jobs  --jobs 2 with an implementation that is correct but slow on its first input in each
#                 process: PASS, the workers' slow units (w<w>-slow-unit-*) recorded in fuzz.json slow_units,
#                 never counted as failing artifacts (the retention replay's own, retain-slow-unit-*, likewise).
#   c63_out_lock   a second run on an --out another run is using is refused at once (ERROR, "another run
#                 holds"), and the first run's verdict and record are intact.
#   c66_chain_unreachable  a chain node that does not answer PAUSEs the campaign and is retried; only past
#                 FV_GUARD_UNREACHABLE_MAX is the worker BLOCKED (tests/harness_fv_controls/c66_chain_unreachable.sh).
#   c67_restart_window  the lease's restart window: a silent node during its scheduled restart resumes after
#                 the short wait, every other pause after the long one (tests/harness_fv_controls/c67_restart_window.sh).
#   c65_bundle_target  the gate checks a worker bundle against the worker's glibc / GLIBCXX target before
#                 shipping: (a) an implementation calling a glibc 2.42 function, built without the sysroot,
#                 for a worker declared 2.39: BLOCKED, no worker started; (b) the fixture built with the
#                 pinned 2.39 sysroot: PASS, its bundle needs glibc <= 2.39 and no GLIBCXX; (c) the 2.42
#                 caller with the sysroot: ERROR (it does not compile); (d) an ssh worker with no declared
#                 target: ERROR before any ssh connection; (e) a target that is not a version
#                 ("latest"), (f) objdump failing on the bundle: ERROR before shipping. SKIPPED without
#                 FV_BUILD_SYSROOT on the host.
#   c89_retain_artifact  an input on which the retention generation stops (a trap in the binding, reached
#                 only there) is replayed by the verdict binary: FAIL with the reproducer kept.
#   c90_retention_recorded  (a) a generation stopped by its time guard is in classes.error; (b) FV_NO_CLASSIFY=1
#                 is recorded (no classification, no retention), never silent.
#   c59_merge_inner_start  the inner merge process exits at start, before any input (no input to blame;
#                 libFuzzer exits 0 having merged nothing): ERROR "did not complete in one attempt".
#   c30_draft_not_countable  a draft (an UNSIGNED spec_lock.sh manifest) can be validated with
#                 run_fuzz.sh --draft but never counts: (a) the --draft run is stamped "DRAFT (unsigned, not
#                 countable)" first in fuzz.log and fuzz.json, its verdict reads "DRAFT PASS", and the
#                 persisted corpus is not merged into; (b) the same manifest without --draft is BLOCKED;
#                 (c) a task with that manifest stops at SPEC_LOCK (BLOCKED); (d) CLOSE given a draft
#                 fuzz.json refuses (ERROR, no closure.json).
#
# Prints one "ID RESULT DETAIL" line per control; exit 0 iff all behave as specified. Controls
# never write to the persisted corpus (--no-merge; the corpus is copied into OUTDIR first).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT/scripts/lib.sh"
OUT="$1"; mkdir -p "$OUT"
FIX="$ROOT/fixtures/conservation"; LOCK="$ROOT/locks/conservation.sha256"
CPP="$ROOT/fixtures/conservation_cpp/fuzz"
fails=0

campaign() { # campaign ID ARGS...  (CMAKE_DIR overrides the fuzz directory)
  local id="$1"; shift
  rm -rf "$OUT/$id"; mkdir -p "$OUT/$id"
  cp -r "$CPP/corpus" "$OUT/$id/corpus"
  "$ROOT/fuzz/run_fuzz.sh" --lean-project "$FIX" --lock "$LOCK" --cmake-dir "${CMAKE_DIR:-$CPP}" \
    --target diff_transfer --corpus "$OUT/$id/corpus" --no-merge --out "$OUT/$id/run" "$@" \
    > "$OUT/$id/run_fuzz.out" 2>&1
}

campaign c1_fuzz --runs 1000000
rc=$?
j="$OUT/c1_fuzz/run/fuzz.json"
lsan=$(cat "$OUT/c1_fuzz/run/replay.log" "$OUT/c1_fuzz/run/campaign.log" 2>/dev/null | grep -c 'LeakSanitizer')
if [ $rc -eq 0 ] && [ "$(jq -r .verdict "$j")" = PASS ] && [ "$lsan" -eq 0 ]; then
  echo "c1_fuzz OK $(jq -r '"runs=\(.runs) seconds=\(.campaign_seconds) \(.stats)"' "$j") leak_reports=0"
else
  echo "c1_fuzz WRONG exit=$rc leak_reports=$lsan $(jq -c '{verdict,detail,mismatch}' "$j" 2>/dev/null)"; fails=1
fi

campaign c6_cpp_drift --time 10 --impl-dir "$ROOT/tests/harness_fv_controls/variants/c6_drift"
rc=$?
j="$OUT/c6_cpp_drift/run/fuzz.json"
mm=$(jq -r .mismatch "$j" 2>/dev/null)
t=$(sed -n 's/.*(\([0-9.]*\) s after start).*/\1/p' <<< "$mm")
repro=$(ls "$OUT/c6_cpp_drift/run/artifacts/" 2>/dev/null | head -1)
if [ $rc -eq 1 ] && [ -n "$t" ] && [ -n "$repro" ]; then
  echo "c6_cpp_drift OK FAIL after ${t}s (found at the corpus replay or the campaign; no time limit asserted); reproducer $repro; $(grep -A4 'diff-oracle: MISMATCH' "$OUT/c6_cpp_drift/run/campaign.log" | grep -E 'oracle|impl' | tr -s ' ' | tr '\n' ';')"
else
  echo "c6_cpp_drift WRONG exit=$rc mismatch=[$mm] reproducer=[$repro]"; fails=1
fi
campaign c7_lsan_leak --time 10 --impl-dir "$ROOT/tests/harness_fv_controls/variants/c7_leak"
rc=$?
j="$OUT/c7_lsan_leak/run/fuzz.json"
log="$OUT/c7_lsan_leak/run/campaign.log"; [ -s "$log" ] || log="$OUT/c7_lsan_leak/run/replay.log"
if [ $rc -eq 1 ] && grep -q 'ERROR: LeakSanitizer: detected memory leaks' "$log" && grep -q 'ledger.hpp' "$log"; then
  echo "c7_lsan_leak OK leak reported: $(grep -m1 -E 'leak of [0-9]+ byte' "$log" | sed 's/^ *//'); $(grep -m1 -oE 'ledger::transfer.*ledger\.hpp:[0-9]+:[0-9]+' "$log" | sed 's|(.*) .*/|() at |')"
else
  echo "c7_lsan_leak WRONG exit=$rc verdict=$(jq -r .verdict "$j" 2>/dev/null): production leak not reported"; fails=1
fi

# Control 8: a tampered vendored copy of the harness template in the fuzz directory.
# The fuzz directory lives outside $OUT/c8_vendored_tamper, which campaign() recreates.
V="$OUT/c8_fuzzdir"; rm -rf "$V"; mkdir -p "$V"
cp -r "$CPP"/. "$V"/
# Each copy cites a pinned id whose body equals the harness's current file (fuzz/VENDORED.sha256).
pin_missing=""
for f in LeanOracle.cmake diff_oracle_template.cpp fv_classify.hpp; do
  case "$f" in *.cmake) c="#" ;; *) c="//" ;; esac
  rel=$(awk -v n="$f" -v h="$(sha256sum < "$ROOT/fuzz/$f" | cut -d' ' -f1)" '!/^#/ && $2 == n && $3 == h { print $1; exit }' "$ROOT/fuzz/VENDORED.sha256")
  [ -n "$rel" ] || pin_missing+="$f "
  { echo "$c Vendored from fv-harness ${rel:-UNPINNED} ($f), unchanged below this header."; echo "$c"; cat "$ROOT/fuzz/$f"; } > "$V/$f"
done
[ -z "$pin_missing" ] || echo "c8 setup: no VENDORED.sha256 pin for the current body of: $pin_missing" >&2
"$ROOT/fuzz/check_vendored.sh" "$V" > "$OUT/c8_untampered.json" 2>/dev/null; rc0=$?
sed -i 's/  if (rc != 0) {/  if (false \&\& rc != 0) {/' "$V/diff_oracle_template.cpp"
grep -q 'if (false && rc != 0)' "$V/diff_oracle_template.cpp" || echo "c8 setup: tamper line not found" >&2
CMAKE_DIR="$V" campaign c8_vendored_tamper --runs 1000
rc=$?
j="$OUT/c8_vendored_tamper/run/fuzz.json"
if [ $rc0 -eq 0 ] && [ $rc -eq 1 ] && [ "$(jq -r .verdict "$j")" = FAIL ] \
   && jq -e '.vendored["diff_oracle_template.cpp"].match == false and .vendored["LeanOracle.cmake"].match == true' "$j" > /dev/null \
   && [ ! -d "$OUT/c8_vendored_tamper/run/build" ]; then
  echo "c8_vendored_tamper OK untampered pair passes; tampered template: FAIL before build: $(jq -r .detail "$j"); body $(jq -r '.vendored["diff_oracle_template.cpp"].body_sha256[0:12]' "$j") != pinned $(jq -r '.vendored["diff_oracle_template.cpp"].pinned_sha256[0:12]' "$j")"
else
  echo "c8_vendored_tamper WRONG untampered_rc=$rc0 exit=$rc $(jq -c '{verdict,detail,vendored}' "$j" 2>/dev/null)"; fails=1
fi

# Control 9: an edge class the generator never reaches must be reported, without touching the verdict.
V9="$OUT/c9_fuzzdir"; rm -rf "$V9"; mkdir -p "$V9"; cp -r "$CPP"/. "$V9"/
sed -i 's|return Op{fvfuzz::pick_u64(in), fvfuzz::pick_u64(in)};|return Op{fvfuzz::pick_u64(in), in.ConsumeIntegralInRange<uint64_t>(0, 10000)};  // c9: never above the cap|' "$V9/binding.hpp"
grep -q 'c9: never above the cap' "$V9/binding.hpp" || echo "c9 setup: generator line not found" >&2
CMAKE_DIR="$V9" campaign c9_edge_not_exercised --runs 20000 --impl-dir "$ROOT/fixtures/conservation_cpp/impl"
rc=$?
j="$OUT/c9_edge_not_exercised/run/fuzz.json"; j1="$OUT/c1_fuzz/run/fuzz.json"
cls="domain: fee rate above the cap (bps > 10000)"
if [ $rc -eq 0 ] && [ "$(jq -r .verdict "$j")" = PASS ] && jq -e --arg c "$cls" '.classes.labels_only and (.classes.not_exercised | index($c)) and ([.classes.classes[] | select(.kind == "generic" and .inputs > 0)] | length > 0)' "$j" > /dev/null \
   && jq -e --arg c "$cls" '[.classes.classes[] | select(.class == $c and .inputs > 0)] | length == 1' "$j1" > /dev/null \
   && [ -s "$OUT/c9_edge_not_exercised/run/classify/review_deck.md" ]; then
  echo "c9_edge_not_exercised OK verdict PASS; NOT EXERCISED: [$cls]; c1 normal generator: $(jq -r --arg c "$cls" '.classes.classes[] | select(.class == $c) | "\(.inputs) inputs"' "$j1"); $(jq -r '.classes | "\(.inputs) inputs, \([.classes[] | select(.inputs > 0)] | length) classes hit, \(.not_exercised | length) not exercised"' "$j")"
else
  echo "c9_edge_not_exercised WRONG exit=$rc $(jq -c '{verdict, ne: .classes.not_exercised, err: .classes.error}' "$j" 2>/dev/null) c1: $(jq -c --arg c "$cls" '[.classes.classes[]? | select(.class == $c)]' "$j1" 2>/dev/null)"; fails=1
fi

# Controls 10-12: leaks on one input class, a hang, unbounded reachable growth.
VAR="$ROOT/tests/harness_fv_controls/variants"
campaign c10_leak_class --time 60 --impl-dir "$VAR/c10_leak_class"
rc=$?; j="$OUT/c10_leak_class/run/fuzz.json"
if [ $rc -eq 1 ] && jq -e '(.detail | contains("LEAK: ")) and ([.classes.finding_classes[]?[] | select(. == "domain: amount exceeds the balance (amt > a)")] | length > 0)' "$j" > /dev/null; then
  echo "c10_leak_class OK $(jq -r .detail "$j"); finding classes: $(jq -r '[.classes.finding_classes[]?[] | select(startswith("domain:"))] | unique | join(", ")' "$j")"
else
  echo "c10_leak_class WRONG exit=$rc $(jq -c '{detail, fc: .classes.finding_classes}' "$j" 2>/dev/null)"; fails=1
fi
for c in c11_hang c12_growth; do
  D="$OUT/${c}_fuzzdir"; rm -rf "$D"; mkdir -p "$D"; cp -r "$CPP"/. "$D"/
  case $c in
    c11_hang)   printf 'timeout = 2\n' >> "$D/fv.toml" ;;          # the fixture's [fuzz] table
    c12_growth) printf 'rss_limit_mb = 256\n' >> "$D/fv.toml" ;;
  esac
  CMAKE_DIR="$D" campaign $c --time 60 --impl-dir "$VAR/$c"
  rc=$?; j="$OUT/$c/run/fuzz.json"
  want="HANG: input exceeded 2 s"; [ $c = c12_growth ] && want="OOM: "
  art=$(ls "$OUT/$c/run/artifacts/" 2>/dev/null | grep -E '^(timeout|oom)-' | head -1)
  logs=("$OUT/$c/run/replay.log" "$OUT/$c/run/campaign.log")
  # c11: libFuzzer itself must have stopped the input at the configured 2 s (not a longer default);
  # c12: the OOM must be against the configured 256 MB, not libFuzzer's 2048 MB default.
  if [ $c = c11_hang ]; then
    n=$(cat "${logs[@]}" 2>/dev/null | grep -m1 -oE 'timeout after [0-9]+ seconds' | grep -oE '[0-9]+')
    bound_ok=$([ -n "$n" ] && [ "$n" -le 3 ] && echo 1)
  else
    bound_ok=$(jq -e '.detail | contains("limit: 256Mb")' "$j" > /dev/null && echo 1)
  fi
  if [ $rc -eq 1 ] && jq -e --arg w "$want" '.detail | contains($w)' "$j" > /dev/null && [ -n "$art" ] && [ "$bound_ok" = 1 ]; then
    echo "$c OK $(jq -r '.detail + (if (.campaign_seconds // "") != "" then " (campaign " + (.campaign_seconds | .[0:5]) + " s)" else "" end)' "$j"); stopped at: $(cat "${logs[@]}" 2>/dev/null | grep -m1 -oE 'timeout after [0-9]+ seconds|out-of-memory \([^)]*\)'); reproducer $art; limits $(jq -c .limits "$j")"
  else
    echo "$c WRONG exit=$rc $(jq -c '{detail, limits}' "$j" 2>/dev/null) artifact=[$art]"; fails=1
  fi
done

# Control 13: classify variables in the caller's environment cannot switch off the comparison.
( export FV_CLASSIFY="$OUT/c13_stray.jsonl" FV_CLASSIFY_RENDER=1 FV_CLASSIFY_TIME_IMPL=1
  campaign c13_classify_env --time 10 --impl-dir "$ROOT/tests/harness_fv_controls/variants/c6_drift" )
rc=$?; j="$OUT/c13_classify_env/run/fuzz.json"; B="$OUT/c13_classify_env/run/build"
nm_v=$(nm -C "$B/diff_transfer" 2>/dev/null | grep -c fv_classify_build_marker)
nm_c=$(nm -C "$B/diff_transfer_classify" 2>/dev/null | grep -c fv_classify_build_marker)
# The drift may be caught in the corpus replay or in the campaign; either is a mismatch FAIL.
if [ $rc -eq 1 ] && jq -e '.detail | contains("oracle/implementation mismatch")' "$j" > /dev/null && [ "$nm_v" = 0 ] && [ "$nm_c" -ge 1 ]; then
  echo "c13_classify_env OK env exported, still FAIL: $(jq -r .detail "$j") ($(jq -r .mismatch "$j" | cut -c1-60)); nm: verdict binary 0 classify markers, classify binary $nm_c"
else
  echo "c13_classify_env WRONG exit=$rc detail=[$(jq -r .detail "$j" 2>/dev/null)] nm verdict=$nm_v classify=$nm_c"; fails=1
fi

# Control 14: a zero limit in fv.toml is refused (it would disable HANG/OOM detection).
bad=""
for k in timeout rss_limit_mb malloc_limit_mb; do
  Z="$OUT/c14_zero_limits/$k"; rm -rf "$Z"; mkdir -p "$Z/fuzz"; printf '[fuzz]\n%s = 0\n' "$k" > "$Z/fuzz/fv.toml"
  "$ROOT/fuzz/run_fuzz.sh" --lean-project "$FIX" --lock "$LOCK" --cmake-dir "$Z/fuzz" --target diff_transfer \
    --no-merge --out "$Z/run" > "$Z/run_fuzz.out" 2>&1
  zrc=$?
  if [ $zrc -ne 3 ] || ! jq -e --arg k "$k" '.verdict == "ERROR" and (.detail | contains("fv.toml") and contains($k + "=0"))' "$Z/run/fuzz.json" > /dev/null \
     || [ -d "$Z/run/build" ]; then bad+="$k(exit=$zrc) "; fi
done
if [ -z "$bad" ]; then
  echo "c14_zero_limits OK timeout=0, rss_limit_mb=0, malloc_limit_mb=0 each refused: ERROR exit 3 before build ($(jq -r .detail "$OUT/c14_zero_limits/timeout/run/fuzz.json"))"
else
  echo "c14_zero_limits WRONG not refused: $bad"; fails=1
fi

D30="$OUT/c30"; rm -rf "$D30"; mkdir -p "$D30"
cp -r "$FIX" "$D30/proj"; rm -rf "$D30/proj/.lake" "$D30/proj/spec/solution"
"$ROOT/scripts/spec_lock.sh" lock "$D30/proj" "$D30/draft.sha256" > "$D30/lock.out" 2>&1
cp -r "$CPP/corpus" "$D30/corpus"; n0=$(ls "$D30/corpus" | wc -l)
"$ROOT/fuzz/run_fuzz.sh" --draft --lean-project "$D30/proj" --lock "$D30/draft.sha256" --cmake-dir "$CPP" \
  --target diff_transfer --runs 20000 --corpus "$D30/corpus" --out "$D30/draft" > "$D30/draft.out" 2>&1; ra=$?
ja="$D30/draft/fuzz.json"; n1=$(ls "$D30/corpus" | wc -l)
"$ROOT/fuzz/run_fuzz.sh" --lean-project "$D30/proj" --lock "$D30/draft.sha256" --cmake-dir "$CPP" \
  --target diff_transfer --runs 20000 --corpus "$D30/corpus" --no-merge --out "$D30/signed-path" > "$D30/signed-path.out" 2>&1; rb=$?
jb="$D30/signed-path/fuzz.json"
FT=(python3 -I "$ROOT/scripts/formal_task.py"); T30="c30-draft-$$"; T30d="c30-close-$$"
"${FT[@]}" init "$T30" --project "$D30/proj" --lock "$D30/draft.sha256" --cmake-dir "$CPP" --target diff_transfer \
  --fuzz-runs 1000 > "$D30/task.out" 2>&1
"${FT[@]}" spec-lock "$T30" >> "$D30/task.out" 2>&1; rc_c=$?
st_c=$(jq -r .state "$FV_ROOT/tasks/$T30/state.json" 2>/dev/null)
mkdir -p "$D30/audit"; echo '{"verdict": "PASS", "stages": {}}' > "$D30/audit/verdict.json"
mkdir -p "$FV_ROOT/tasks/$T30d"
jq --arg a "$D30/audit" --arg c "$D30/draft" --arg t "$T30d" '.task = $t | .state = "CLOSE" | .last_audit = $a | .last_couple = $c' \
  "$FV_ROOT/tasks/$T30/state.json" > "$FV_ROOT/tasks/$T30d/state.json"
"${FT[@]}" close "$T30d" >> "$D30/task.out" 2>&1; rc_d=$?
st_d=$(jq -r .state "$FV_ROOT/tasks/$T30d/state.json" 2>/dev/null); cl_d=$([ -e "$FV_ROOT/tasks/$T30d/closure.json" ] && echo yes || echo no)
cp -r "$FV_ROOT/tasks/$T30" "$FV_ROOT/tasks/$T30d" "$D30/" 2>/dev/null; rm -rf "$FV_ROOT/tasks/$T30" "$FV_ROOT/tasks/$T30d"
if [ ! -e "$D30/draft.sha256.sig" ] && [ $ra -eq 0 ] && [ "$(jq -r 'keys_unsorted[0]' "$ja")" = draft ] \
   && [ "$(jq -r .verdict "$ja")" = "DRAFT PASS" ] && head -1 "$D30/draft/fuzz.log" | grep -q '^DRAFT (unsigned, not countable)' \
   && [ "$n0" = "$n1" ] && [ $rb -eq 2 ] && [ "$(jq -r .verdict "$jb")" = BLOCKED ] \
   && [ $rc_c -ne 0 ] && [ "$st_c" = BLOCKED ] && [ $rc_d -eq 3 ] && [ "$st_d" = ERROR ] && [ "$cl_d" = no ]; then
  echo "c30_draft_not_countable OK --draft: \"$(jq -r .verdict "$ja")\" (first key draft, fuzz.log line 1 DRAFT, corpus $n0 -> $n1 files); same manifest without --draft: BLOCKED; task: SPEC_LOCK -> BLOCKED; CLOSE on a draft fuzz.json: ERROR, no closure"
else
  echo "c30_draft_not_countable WRONG draft exit=$ra verdict=$(jq -r .verdict "$ja" 2>/dev/null) first_key=$(jq -r 'keys_unsorted[0]' "$ja" 2>/dev/null) corpus $n0->$n1; signed-path exit=$rb; task rc=$rc_c state=$st_c; close rc=$rc_d state=$st_d closure=$cl_d"; fails=1
fi

D32="$OUT/c32"; rm -rf "$D32"; mkdir -p "$D32"; bad32=""
for kv in "max_len = 0" "len_control = -1"; do
  k=${kv%% *}; Z="$D32/$k"; mkdir -p "$Z"; cp -r "$ROOT/fixtures/conservation_cpp/." "$Z/ex"
  printf '%s\n' "$kv" >> "$Z/ex/fuzz/fv.toml"   # the fixture's [fuzz] table
  "$ROOT/fuzz/run_fuzz.sh" --lean-project "$FIX" --lock "$LOCK" --cmake-dir "$Z/ex/fuzz" --target diff_transfer \
    --corpus "$Z/corpus" --no-merge --out "$Z/run" > "$Z/run_fuzz.out" 2>&1; zrc=$?
  if [ $zrc -ne 3 ] || ! jq -e --arg k "$k" '.verdict == "ERROR" and (.detail | contains($k))' "$Z/run/fuzz.json" > /dev/null \
     || [ -d "$Z/run/build" ]; then bad32+="$k(exit=$zrc) "; fi
done
Z="$D32/set"; mkdir -p "$Z"; cp -r "$ROOT/fixtures/conservation_cpp/." "$Z/ex"; printf 'max_len = 300\nlen_control = 0\n' >> "$Z/ex/fuzz/fv.toml"
cp -r "$CPP/corpus" "$Z/corpus"
"$ROOT/fuzz/run_fuzz.sh" --lean-project "$FIX" --lock "$LOCK" --cmake-dir "$Z/ex/fuzz" --target diff_transfer \
  --corpus "$Z/corpus" --no-merge --runs 3000 --out "$Z/run" > "$Z/run_fuzz.out" 2>&1; src=$?
j32="$Z/run/fuzz.json"
if [ -z "$bad32" ] && [ $src -eq 0 ] && jq -e '.verdict == "PASS" and .limits.max_len == 300 and .limits.len_control == 0' "$j32" > /dev/null \
   && grep -q 'lim: 300' "$Z/run/campaign.log" && ! grep -q -- '-max_len is not provided' "$Z/run/campaign.log" \
   && jq -e '.limits.max_len == null and .limits.len_control == null' "$OUT/c1_fuzz/run/fuzz.json" > /dev/null; then
  echo "c32_len_limits OK max_len=0, len_control=-1: ERROR before build; max_len=300 len_control=0: campaign at lim 300, recorded $(jq -c '.limits | {max_len, len_control}' "$j32"); c1 records null"
else
  echo "c32_len_limits WRONG refused-bad=[${bad32:-ok}] set: exit=$src $(jq -c '{verdict, limits}' "$j32" 2>/dev/null) c1: $(jq -c '.limits | {max_len, len_control}' "$OUT/c1_fuzz/run/fuzz.json" 2>/dev/null)"; fails=1
fi

campaign c38_jobs_clean --jobs 4 --runs 40000
rca=$?; ja="$OUT/c38_jobs_clean/run/fuzz.json"
campaign c38_jobs_one --jobs 4 --time 30 --impl-dir "$ROOT/tests/harness_fv_controls/variants/c38_one_worker"
rcb=$?; jb="$OUT/c38_jobs_one/run/fuzz.json"
if [ $rca -eq 0 ] && jq -e '.verdict == "PASS" and .jobs == 4 and (.workers | length) == 4 and ([.workers[].executions] | all(. != null))
     and .total_executions == ([.workers[].executions] | add) and .total_executions >= 40000' "$ja" > /dev/null \
   && [ $rcb -eq 1 ] && jq -e '(.detail | contains("oracle/implementation mismatch") and contains("worker 2 of 4"))
     and ([.workers[] | select(any(.batches[]; .exit != 0)) | .worker] == [2])' "$jb" > /dev/null; then
  echo "c38_jobs OK 4 workers, $(jq -r .total_executions "$ja") executions in total ($(jq -r '[.workers[].executions] | map(tostring) | join("+")' "$ja")): PASS; drift only in worker 2: $(jq -r .detail "$jb"), workers 0,1,3 exit 0"
else
  echo "c38_jobs WRONG clean exit=$rca $(jq -c '{verdict, total_executions, workers}' "$ja" 2>/dev/null) one-worker exit=$rcb $(jq -c '{verdict, detail, failed: [.workers[]? | select(any(.batches[]; .exit != 0)) | .worker]}' "$jb" 2>/dev/null)"; fails=1
fi

X39="${OUT:?}/c39"; mkdir -p "$X39"
campaign c39_remote_clean --jobs 1 --remote local:2 --runs 30000 --bundle-out "$X39/bundle.tar"
rca=$?; ja="$OUT/c39_remote_clean/run/fuzz.json"
campaign c39_remote_one --jobs 1 --remote local:2 --time 30 --impl-dir "$ROOT/tests/harness_fv_controls/variants/c39_remote_worker"
rcb=$?; jb="$OUT/c39_remote_one/run/fuzz.json"
T1="$X39/t1"; mkdir -p "$T1"; tar -xf "$X39/bundle.tar" -C "$T1"; printf 'x' >> "$(ls "$T1"/bundle/corpus/* | head -1)"
bash "$T1/bundle/fv_worker.sh" "$T1/bundle" 0 1 100 "" 1 > "$X39/worker-tampered.out" 2>&1; rcc=$?
rm -rf "${T1:?}/bundle/out"  # the refused run's own output is not part of a bundle
(cd "$T1/bundle" && find . -type f ! -name MANIFEST.sha256 -printf '%P\n' | LC_ALL=C sort | xargs sha256sum > MANIFEST.sha256)
tar -cf "$X39/remanifested.tar" -C "$T1" bundle
campaign c39_remote_remanifested --jobs 1 --remote local:2 --runs 3000 --bundle "$X39/remanifested.tar"
rcd=$?; jd="$OUT/c39_remote_remanifested/run/fuzz.json"
if [ $rca -eq 0 ] && jq -e '.verdict == "PASS" and (.workers | length) == 3 and ([.workers[] | select(.remote == true)] | length) == 2
     and .total_executions == ([.workers[].executions] | add) and .total_executions >= 30000
     and (.remote.bundle_sha256 | length) == 64 and .remote.bundle_sha256 == .remote.built_sha256
     and (.remote.worker_env.glibc | length) > 0 and (.remote.worker_env.libstdcxx_sha256 | length) == 64' "$ja" > /dev/null \
   && [ $rcb -eq 1 ] && jq -e '.detail | contains("worker 2 of 3, remote")' "$jb" > /dev/null \
   && [ $rcc -eq 2 ] && grep -q '^BLOCKED: bundle files differ from MANIFEST.sha256' "$X39/worker-tampered.out" \
   && [ ! -s "$T1/bundle/out/pids" ] \
   && [ $rcd -eq 2 ] && jq -e '.verdict == "BLOCKED" and (.detail | contains("not this build"))' "$jd" > /dev/null \
   && [ ! -e "$OUT/c39_remote_remanifested/run/remote-local/bundle/out/pids" ]; then
  echo "c39_remote_bundle OK 1+2 workers: PASS, $(jq -r .total_executions "$ja") executions, bundle $(jq -r '.remote.bundle_sha256[0:12]' "$ja"), worker glibc $(jq -r .remote.worker_env.glibc "$ja") libstdc++ $(jq -r '.remote.worker_env.glibcxx_max' "$ja"); drift in bundle worker 2: FAIL; changed bundle file: the worker refuses it (BLOCKED, nothing started); a bundle not of this build: the gate refuses it before any worker"
else
  echo "c39_remote_bundle WRONG clean=$rca [$(jq -c '{verdict, detail, total_executions, remote: (.remote | {bundle_sha256, built_sha256})}' "$ja" 2>/dev/null)] one=$rcb [$(jq -r .detail "$jb" 2>/dev/null)] tampered=$rcc [$(head -1 "$X39/worker-tampered.out")] remanifested=$rcd [$(jq -r .detail "$jd" 2>/dev/null)]"; fails=1
fi

if [ -f "$X39/bundle.tar" ]; then
  "$ROOT/tests/harness_fv_controls/c40_guards.sh" "$X39/bundle.tar" "${OUT:?}/c40" > "$OUT/c40.out" 2>&1 || fails=1
  grep -E '^c40_guards ' "$OUT/c40.out" || { echo "c40_guards WRONG no verdict line (see $OUT/c40.out)"; fails=1; }
  "$ROOT/tests/harness_fv_controls/c66_chain_unreachable.sh" "$X39/bundle.tar" "${OUT:?}/c66" > "$OUT/c66.out" 2>&1 || fails=1
  grep -E '^c66_chain_unreachable ' "$OUT/c66.out"   # run_controls.sh requires the line
  "$ROOT/tests/harness_fv_controls/c67_restart_window.sh" "$X39/bundle.tar" "${OUT:?}/c67" > "$OUT/c67.out" 2>&1 || fails=1
  grep -E '^c67_restart_window ' "$OUT/c67.out"   # run_controls.sh requires the line
else
  echo "c40_guards WRONG no bundle from c39"; fails=1
fi
if [ -f "$X39/bundle.tar" ]; then
  "$ROOT/tests/harness_fv_controls/multihost_controls.sh" "${OUT:?}/multihost" "$X39/bundle.tar" > "$OUT/multihost.out" 2>&1 || fails=1
  grep -E '^(c4[3-7]|c58|c60|c61)_' "$OUT/multihost.out"   # run_controls.sh requires each id
fi
D42="${OUT:?}/c42"; rm -rf "${D42:?}"; mkdir -p "$D42"; bad42=""
for arg in "--trace" "-DEXTRA=a b" "-DCMAKE_CXX_FLAGS=-O0"; do
  k42=$((${k42:-0} + 1)); Z="$D42/bad$k42"; mkdir -p "$Z"   # its own counter: c32 leaves k = "len_control"
  "$ROOT/fuzz/run_fuzz.sh" --lean-project "$FIX" --lock "$LOCK" --cmake-dir "$CPP" --target diff_transfer --no-merge \
    --runs 1000 --cmake-arg "$arg" --out "$Z/run" > "$Z/out" 2>&1; zrc=$?
  if [ $zrc -ne 3 ] || ! jq -e '.verdict == "ERROR" and (.detail | startswith("cmake args refused"))' "$Z/run/fuzz.json" > /dev/null \
     || [ -d "$Z/run/build" ]; then bad42+="[$arg](exit=$zrc) "; fi
done
cp -r "$CPP/corpus" "$D42/corpus"
FV_CMAKE_ARGS="-DFV_CONTROL_UNUSED_SITE=1" "$ROOT/fuzz/run_fuzz.sh" --lean-project "$FIX" --lock "$LOCK" --cmake-dir "$CPP" \
  --target diff_transfer --no-merge --runs 2000 --corpus "$D42/corpus" --out "$D42/ok" > "$D42/ok.out" 2>&1; rc42=$?
# FV_ names are harness-owned: the site default above must be refused too; then a valid pair must pass.
FV_CMAKE_ARGS="-DSITE_DEPS_DIR=$ROOT/fixtures/conservation_cpp/impl" "$ROOT/fuzz/run_fuzz.sh" --lean-project "$FIX" --lock "$LOCK" \
  --cmake-dir "$CPP" --target diff_transfer --no-merge --runs 2000 --corpus "$D42/corpus" --cmake-arg "-DEXTRA_DEFINITION=1" \
  --out "$D42/ok2" > "$D42/ok2.out" 2>&1; rc42b=$?
want=$( (cd "$ROOT/fixtures/conservation_cpp/impl" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum) | sha256sum | cut -d' ' -f1)
if [ -z "$bad42" ] && [ $rc42 -eq 3 ] && jq -e '.detail | contains("harness-owned name FV_CONTROL_UNUSED_SITE")' "$D42/ok/fuzz.json" > /dev/null \
   && [ $rc42b -eq 0 ] && jq -e --arg w "$want" '.verdict == "PASS" and (.cmake_args | length) == 2
     and .cmake_args[0].source == "site" and .cmake_args[0].paths[0].kind == "dir_manifest" and .cmake_args[0].paths[0].sha256 == $w
     and .cmake_args[1] == {arg: "-DEXTRA_DEFINITION=1", source: "cli", paths: []}' "$D42/ok2/fuzz.json" > /dev/null \
   && grep -q 'EXTRA_DEFINITION' "$D42/ok2/build/CMakeCache.txt" 2>/dev/null; then
  echo "c42_cmake_args OK non -D, whitespace and CMAKE_CXX_FLAGS: ERROR before build; FV_ site name refused; site dir + cli -D: PASS, recorded (dir manifest ${want:0:12}), reached CMakeCache"
else
  echo "c42_cmake_args WRONG refused-bad=[${bad42:-ok}] fv-name exit=$rc42 [$(jq -r .detail "$D42/ok/fuzz.json" 2>/dev/null)] valid exit=$rc42b $(jq -c '{verdict, detail, cmake_args}' "$D42/ok2/fuzz.json" 2>/dev/null)"; fails=1
fi
"$ROOT/tests/harness_fv_controls/c48_record_failure.sh" "$ROOT/fuzz/run_fuzz.sh" "${OUT:?}/c48" > "$OUT/c48.out" 2>&1 || fails=1
grep -E '^c48_record_failure ' "$OUT/c48.out" || { echo "c48_record_failure WRONG no verdict line (see $OUT/c48.out)"; fails=1; }
"$ROOT/tests/harness_fv_controls/c50_bytes_abi.sh" "${OUT:?}/c50" > "$OUT/c50.out" 2>&1 || fails=1
grep -E '^c50_bytes_abi ' "$OUT/c50.out" || { echo "c50_bytes_abi WRONG no verdict line (see $OUT/c50.out)"; fails=1; }

merged() { # merged ID IMPL_DIR  — a campaign WITH the corpus merge, into this control's own corpus copy
  local id="$1" impl="$2"
  rm -rf "$OUT/$id"; mkdir -p "$OUT/$id"
  cp -r "$CPP/corpus" "$OUT/$id/corpus"
  "$ROOT/fuzz/run_fuzz.sh" --lean-project "$FIX" --lock "$LOCK" --cmake-dir "$CPP" --target diff_transfer \
    --corpus "$OUT/$id/corpus" --impl-dir "$impl" --runs 20000 --out "$OUT/$id/run" > "$OUT/$id/run_fuzz.out" 2>&1
}
merged c53_merge_failure "$ROOT/tests/harness_fv_controls/variants/c53_merge_only"
rc=$?; j="$OUT/c53_merge_failure/run/fuzz.json"
cl=$(grep -c 'diff-oracle: MISMATCH' "$OUT/c53_merge_failure/run/campaign.log" 2>/dev/null)
nart=$(ls "$OUT/c53_merge_failure/run/artifacts/" 2>/dev/null | grep -vc '^slow-unit-')
kept=0; for f in "$OUT/c53_merge_failure/run/artifacts/"*; do [ -f "$f" ] && cmp -s "$f" "$OUT/c53_merge_failure/corpus/$(basename "$f")" && kept=1; done
if [ $rc -eq 1 ] && [ "$(jq -r .verdict "$j")" = FAIL ] && jq -r .detail "$j" | grep -q 'during the corpus merge: oracle/implementation mismatch' \
   && [ -n "$(jq -r '.mismatch // empty' "$j")" ] && [ "${cl:-0}" -eq 0 ] && [ "$nart" -ge 1 ] && [ $kept -eq 1 ]; then
  echo "c53_merge_failure OK FAIL during the merge (campaign clean, $(grep -c '^MERGE-OUTER: attempt' "$OUT/c53_merge_failure/run/merge.log") merge attempts), mismatch recorded, reproducer kept: $(jq -r .detail "$j" | cut -c1-110)"
else
  echo "c53_merge_failure WRONG exit=$rc campaign_mismatches=${cl:-?} artifacts=$nart kept=$kept $(jq -c '{verdict,detail,mismatch}' "$j" 2>/dev/null | cut -c1-300)"; fails=1
fi
merged c54_merge_inner_exit "$ROOT/tests/harness_fv_controls/variants/c54_merge_exit"
rc=$?; j="$OUT/c54_merge_inner_exit/run/fuzz.json"
if [ $rc -eq 3 ] && [ "$(jq -r .verdict "$j")" = ERROR ] && jq -r .detail "$j" | grep -q 'inner merge process failed without a finding'; then
  echo "c54_merge_inner_exit OK ERROR: $(jq -r .detail "$j" | cut -c1-120)"
else
  echo "c54_merge_inner_exit WRONG exit=$rc $(jq -c '{verdict,detail}' "$j" 2>/dev/null | cut -c1-300)"; fails=1
fi
merged c59_merge_inner_start "$ROOT/tests/harness_fv_controls/variants/c59_merge_start"
rc=$?; j="$OUT/c59_merge_inner_start/run/fuzz.json"
if [ $rc -eq 3 ] && [ "$(jq -r .verdict "$j")" = ERROR ] && jq -r .detail "$j" | grep -q 'corpus merge did not complete in one attempt'; then
  echo "c59_merge_inner_start OK ERROR: $(jq -r .detail "$j" | cut -c1-120)"
else
  echo "c59_merge_inner_start WRONG exit=$rc $(jq -c '{verdict,detail}' "$j" 2>/dev/null | cut -c1-300)"; fails=1
fi

campaign c62_slow_units_jobs --jobs 2 --runs 4000 --impl-dir "$ROOT/tests/harness_fv_controls/variants/c62_slow_first"
rc=$?; j="$OUT/c62_slow_units_jobs/run/fuzz.json"
if [ $rc -eq 0 ] && jq -e '.verdict == "PASS" and (.slow_units | length) >= 1 and any(.slow_units[]; test("^w[0-9]+-slow-unit-")) and all(.slow_units[]; test("^(w[0-9]+|retain)-slow-unit-"))' "$j" > /dev/null; then
  echo "c62_slow_units_jobs OK --jobs 2, a slow but correct first input per worker: PASS, slow units recorded: $(jq -r '.slow_units | join(" ") | .[0:120]' "$j")"
else
  echo "c62_slow_units_jobs WRONG exit=$rc $(jq -c '{verdict, detail, slow_units}' "$j" 2>/dev/null | cut -c1-300)"; fails=1
fi
D63="$OUT/c63"; rm -rf "${D63:?}"; mkdir -p "$D63"; cp -r "$CPP/corpus" "$D63/corpus-a"; cp -r "$CPP/corpus" "$D63/corpus-b"
"$ROOT/fuzz/run_fuzz.sh" --lean-project "$FIX" --lock "$LOCK" --cmake-dir "$CPP" --target diff_transfer --corpus "$D63/corpus-a" \
  --no-merge --runs 300000 --out "$D63/run" > "$D63/a.out" 2>&1 & pa=$!
for i in $(seq 1 240); do [ -e "$D63/run/build" ] && break; sleep 0.5; done
"$ROOT/fuzz/run_fuzz.sh" --lean-project "$FIX" --lock "$LOCK" --cmake-dir "$CPP" --target diff_transfer --corpus "$D63/corpus-b" \
  --no-merge --runs 1000 --out "$D63/run" > "$D63/b.out" 2>&1; rb=$?
alive=$(kill -0 $pa 2>/dev/null && echo yes || echo no); wait $pa; ra=$?
if [ "$alive" = yes ] && [ $rb -eq 3 ] && grep -q 'another run holds' "$D63/b.out" && [ $ra -eq 0 ] \
   && jq -e '.verdict == "PASS" and (.runs == "300000")' "$D63/run/fuzz.json" > /dev/null; then
  echo "c63_out_lock OK a second run on a busy --out: refused (exit 3, $(grep -m1 -o 'another run holds[^:]*' "$D63/b.out")); the first run: PASS, its record intact"
else
  echo "c63_out_lock WRONG second exit=$rb [$(tail -1 "$D63/b.out" | cut -c1-100)] overlap=$alive first exit=$ra $(jq -c '{verdict, runs}' "$D63/run/fuzz.json" 2>/dev/null)"; fails=1
fi

# Control 89: an input on which the retention generation itself stops is compared by the verdict binary. The
# binding traps on one pair of edge values (amount and fee rate both 10000, in both builds); the campaign's single
# execution and the fixture corpus do not reach it, the retention generation does and stops there: the verdict binary must replay that input, so
# the run FAILs with it kept, not PASS with only a classifier error.
V89="$OUT/c89_fuzzdir"; rm -rf "$V89"; mkdir -p "$V89"; cp -r "$CPP"/. "$V89"/
sed -i 's|  return Op{fvfuzz::pick_u64(in), fvfuzz::pick_u64(in)};|  Op o{fvfuzz::pick_u64(in), fvfuzz::pick_u64(in)}; if (o.amt == 10000 \&\& o.bps == 10000) __builtin_trap();  // c89\n  return o;|' "$V89/binding.hpp"
sed -i 's/^retain_runs = .*/retain_runs = 200000/' "$V89/fv.toml"
grep -q '// c89' "$V89/binding.hpp" || echo "c89 setup: generator line not found" >&2
CMAKE_DIR="$V89" campaign c89_retain_artifact --runs 1 --impl-dir "$ROOT/fixtures/conservation_cpp/impl"
rc=$?; j="$OUT/c89_retain_artifact/run/fuzz.json"
ga=$(jq -r '.classes.retention.generation_artifacts // [] | join(" ")' "$j" 2>/dev/null)
if [ $rc -eq 1 ] && jq -e '(.detail | contains("retention replay")) and ((.classes.retention.generation_artifacts // []) | length) >= 1' "$j" > /dev/null \
   && ls "$OUT/c89_retain_artifact/run/artifacts/" 2>/dev/null | grep -q '^retain-' && ! grep -q 'deadly signal' "$OUT/c89_retain_artifact/run/campaign.log"; then
  echo "c89_retain_artifact OK the generation stopped on [$ga]; the verdict binary replayed it: FAIL ($(jq -r '.detail | .[0:110]' "$j")), reproducer kept"
else
  echo "c89_retain_artifact WRONG exit=$rc $(jq -c '{verdict, detail, ret: (.classes.retention | {error, generation_artifacts}), err: .classes.error}' "$j" 2>/dev/null | cut -c1-400)"; fails=1
fi

# Control 90: a retention pass that did not run in full is never silent. (a) The time guard stops the generation
# (FV_RETAIN_GUARD_S=1, budget 200000): classes.error names it. (b) FV_NO_CLASSIFY=1: the record says that
# neither classification nor retention ran.
V90="$OUT/c90_fuzzdir"; rm -rf "$V90"; mkdir -p "$V90"; cp -r "$CPP"/. "$V90"/; sed -i 's/^retain_runs = .*/retain_runs = 200000/' "$V90/fv.toml"
FV_RETAIN_GUARD_S=1 CMAKE_DIR="$V90" campaign c90a_retain_guard --runs 1000 --impl-dir "$ROOT/fixtures/conservation_cpp/impl"; ra=$?; ja="$OUT/c90a_retain_guard/run/fuzz.json"
FV_NO_CLASSIFY=1 campaign c90b_no_classify --runs 1000; rb=$?; jb="$OUT/c90b_no_classify/run/fuzz.json"
if [ $ra -eq 0 ] && jq -e '.verdict == "PASS" and (.classes.error // "" | contains("retention: the generation stopped after")) and .classes.retention.complete == false' "$ja" > /dev/null \
   && [ $rb -eq 0 ] && jq -e '.verdict == "PASS" and (.classes.skipped // "" | contains("FV_NO_CLASSIFY=1")) and .classes.retention.skipped == "FV_NO_CLASSIFY=1"' "$jb" > /dev/null; then
  echo "c90_retention_recorded OK (a) time guard: PASS, classes.error [$(jq -r '.classes.error | .[0:90]' "$ja")]; (b) FV_NO_CLASSIFY=1: PASS, recorded [$(jq -r '.classes.skipped | .[0:70]' "$jb")]"
else
  echo "c90_retention_recorded WRONG (a) exit=$ra $(jq -c '{verdict, err: .classes.error, ret: .classes.retention.error}' "$ja" 2>/dev/null | cut -c1-200); (b) exit=$rb $(jq -c '{verdict, classes}' "$jb" 2>/dev/null | cut -c1-200)"; fails=1
fi

D65="${OUT:?}/c65"; rm -rf "${D65:?}"; mkdir -p "$D65"
t65() { # t65 NAME IMPL [env...] : one --remote local:1 run of the fixture against IMPL
  local n="$1" impl="$2"; shift 2; mkdir -p "$D65/$n"; cp -r "$CPP/corpus" "$D65/$n/corpus"
  env "$@" "$ROOT/fuzz/run_fuzz.sh" --lean-project "$FIX" --lock "$LOCK" --cmake-dir "$CPP" --target diff_transfer --corpus "$D65/$n/corpus" \
    --no-merge --jobs 1 --remote local:1 --runs 2000 --impl-dir "$impl" --out "$D65/$n/run" > "$D65/$n/out" 2>&1; }
TGT=(FV_WORKER_GLIBC_MAX_LOCAL=2.39 FV_WORKER_GLIBCXX_MAX_LOCAL=3.4.33)
if [ -z "${FV_BUILD_SYSROOT:-}" ] || [ ! -d "${FV_BUILD_SYSROOT:-/nonexistent}" ]; then
  echo "c65_bundle_target SKIPPED no build sysroot on this host (FV_BUILD_SYSROOT): fuzz/sysroot/install_sysroot.sh installs it"
else
  r65=""
  t65 a "$ROOT/tests/harness_fv_controls/variants/c65_new_glibc" FV_BUILD_SYSROOT= "${TGT[@]}"; ra=$?   # empty and exported: overrides hosts.env
  ja="$D65/a/run/fuzz.json"
  [ $ra -eq 2 ] && jq -e '.verdict == "BLOCKED" and (.detail | test("the bundle needs glibc 2\\.(4[0-9])"))' "$ja" > /dev/null \
    && [ ! -e "$D65/a/run/remote-local/bundle/out/worker-env.json" ] || r65+="(a) exit=$ra [$(jq -r .detail "$ja" 2>/dev/null | cut -c1-120)] "
  t65 b "$ROOT/fixtures/conservation_cpp/impl" "${TGT[@]}"; rb=$?
  jb="$D65/b/run/fuzz.json"
  gb=$(jq -r '.remote.requires.glibc // ""' "$jb" 2>/dev/null); xb=$(jq -r '.remote.requires.glibcxx // "?"' "$jb" 2>/dev/null)
  [ $rb -eq 0 ] && [ -n "$gb" ] && [ "$(printf '%s\n2.39\n' "$gb" | sort -V | tail -1)" = 2.39 ] && [ -z "$xb" ] \
    && jq -e --arg s "$FV_BUILD_SYSROOT_SHA256" '.verdict == "PASS" and .remote.build_sysroot_sha256 == $s' "$jb" > /dev/null \
    || r65+="(b) exit=$rb requires=$gb/$xb [$(jq -r .detail "$jb" 2>/dev/null | cut -c1-100)] "
  t65 c "$ROOT/tests/harness_fv_controls/variants/c65_new_glibc" "${TGT[@]}"; rc_=$?
  [ $rc_ -eq 3 ] && jq -e '.detail | test("build failed")' "$D65/c/run/fuzz.json" > /dev/null || r65+="(c) exit=$rc_ [$(jq -r .detail "$D65/c/run/fuzz.json" 2>/dev/null | cut -c1-100)] "
  mkdir -p "$D65/d"; cp -r "$CPP/corpus" "$D65/d/corpus"
  FV_WORKER_SSH_NOTARGET="-o BatchMode=yes -o ConnectTimeout=2 nobody@nonexistent.invalid" "$ROOT/fuzz/run_fuzz.sh" --lean-project "$FIX" --lock "$LOCK" \
    --cmake-dir "$CPP" --target diff_transfer --corpus "$D65/d/corpus" --no-merge --jobs 1 --remote ssh:NOTARGET:1 --runs 2000 --out "$D65/d/run" > "$D65/d/out" 2>&1; rd=$?
  [ $rd -eq 3 ] && jq -e '.detail | test("has no glibc / libstdc\\+\\+ target")' "$D65/d/run/fuzz.json" > /dev/null && [ ! -e "$D65/d/run/ssh-ctl" ] \
    || r65+="(d) exit=$rd [$(jq -r .detail "$D65/d/run/fuzz.json" 2>/dev/null | cut -c1-100)] "
  t65 e "$ROOT/fixtures/conservation_cpp/impl" FV_WORKER_GLIBC_MAX_LOCAL=latest FV_WORKER_GLIBCXX_MAX_LOCAL=3.4.33; re=$?   # not a version
  [ $re -eq 3 ] && jq -e '.detail | test("FV_WORKER_GLIBC_MAX_LOCAL=\"latest\" .* is not a version")' "$D65/e/run/fuzz.json" > /dev/null \
    && [ ! -e "$D65/e/run/remote-local" ] || r65+="(e) exit=$re [$(jq -r .detail "$D65/e/run/fuzz.json" 2>/dev/null | cut -c1-100)] "
  mkdir -p "$D65/f/shim"; printf '#!/bin/sh\necho "objdump: c65 shim: cannot read" >&2\nexit 1\n' > "$D65/f/shim/objdump"; chmod +x "$D65/f/shim/objdump"
  t65 f "$ROOT/fixtures/conservation_cpp/impl" PATH="$D65/f/shim:$PATH" "${TGT[@]}"; rf=$?   # objdump fails: not "needs nothing"
  [ $rf -eq 3 ] && jq -e '.detail | test("objdump -T could not read")' "$D65/f/run/fuzz.json" > /dev/null \
    && [ ! -e "$D65/f/run/remote-local" ] || r65+="(f) exit=$rf [$(jq -r .detail "$D65/f/run/fuzz.json" 2>/dev/null | cut -c1-100)] "
  if [ -z "$r65" ]; then
    echo "c65_bundle_target OK (a) glibc 2.42 caller, host build, 2.39 worker: BLOCKED before shipping [$(jq -r .detail "$ja" | cut -c1-90)]; (b) with the sysroot: PASS, bundle needs glibc $gb and no GLIBCXX; (c) the 2.42 caller with the sysroot: does not build; (d) ssh worker without a target: ERROR before ssh; (e) a target that is not a version, (f) objdump failing: ERROR before shipping"
  else
    echo "c65_bundle_target WRONG $r65"; fails=1
  fi
fi
exit $fails
