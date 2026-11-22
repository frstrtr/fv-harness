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
for f in LeanOracle.cmake diff_oracle_template.cpp; do
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
exit $fails
