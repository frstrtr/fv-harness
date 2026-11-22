#!/usr/bin/env bash
# run_fuzz_controls.sh OUTDIR — the differential-fuzzer legs of the acceptance controls.
#
#   c1_fuzz       correct implementation, 10^6 runs (local budget): PASS, no mismatch
#   c6_cpp_drift  fee rounded half up instead of down: FAIL within 10 seconds, reproducer written
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
#
# Prints one "ID RESULT DETAIL" line per control; exit 0 iff all behave as specified. Controls
# never write to the persisted corpus (--no-merge; the corpus is copied into OUTDIR first).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
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
if [ $rc -eq 1 ] && [ -n "$t" ] && [ "$(echo "$t < 10" | bc)" = 1 ] && [ -n "$repro" ]; then
  echo "c6_cpp_drift OK FAIL after ${t}s (limit 10s); reproducer $repro; $(grep -A4 'diff-oracle: MISMATCH' "$OUT/c6_cpp_drift/run/campaign.log" | grep -E 'oracle|impl' | tr -s ' ' | tr '\n' ';')"
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
rel=$(awk '!/^#/ && $1 ~ /^v/ { t = $1 } END { print t }' "$ROOT/fuzz/VENDORED.sha256")  # newest release
for f in LeanOracle.cmake diff_oracle_template.cpp fv_classify.hpp; do
  case "$f" in *.cmake) c="#" ;; *) c="//" ;; esac
  { echo "$c Vendored from fv-harness $rel ($f), unchanged below this header."; echo "$c"; cat "$ROOT/fuzz/$f"; } > "$V/$f"
done
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
    c11_hang)   printf '[fuzz]\ntimeout = 2\n' > "$D/fv.toml" ;;
    c12_growth) printf '[fuzz]\nrss_limit_mb = 256\n' > "$D/fv.toml" ;;
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
exit $fails
