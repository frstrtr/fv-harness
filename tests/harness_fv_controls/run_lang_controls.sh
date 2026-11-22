#!/usr/bin/env bash
# run_lang_controls.sh OUTDIR — controls for bindings beyond C++ (docs/LANGUAGES.md). Each language
# runs the risk-limit example's signed Lean spec (locks/risk-limit.*) against that language's
# implementation through fuzz/run_fuzz.sh --lang.
#
#   c15_rust_clean     correct Rust implementation, 10^6 runs: PASS, no leak report
#   c16_rust_drift     a reduction one unit short: FAIL "oracle/implementation mismatch" within 10 s
#   c17_rust_overflow  the limit check adds before comparing (pos + open + q): with overflow checks
#                      ON (cargo fuzz build -a) it FAILs as "panic: ... overflow"
#   c18_rust_vendored_tamper  (a) a vendored copy of the harness driver fv_diff.rs passes the vendored
#                      check untampered, and with its comparison disabled FAILs before any build;
#                      (b) a target with its own fuzz_target! (bypassing the driver) is ERROR
#   c19_rust_profile_off  overflow-checks = false in the project's Cargo.toml, or in a
#                      .cargo/config.toml cargo would read, is ERROR before any build
#   c21_py_clean       correct Python implementation (Atheris), 10^6 runs: PASS
#   c22_py_drift       a reduction one unit short: FAIL "oracle/implementation mismatch" within 10 s
#   c23_py_wide        a fill adds 2^64 (a bug that reduction mod 2^64 would hide): FAIL "domain: ..."
#   c24_py_vendored_tamper  (a) a vendored copy of the harness driver fv_diff.py passes untampered and,
#                      with its comparison disabled, FAILs before any build; (b) a binding that
#                      defines its own TestOneInput is ERROR
#
# Prints one "ID RESULT DETAIL" line per control. RESULT is SKIP when the language's toolchain is
# not installed (it is then not tested, and the summary says so) — unless the language is listed in
# FV_REQUIRE_LANGS (config/hosts.env), where a missing toolchain is WRONG. Exit 0 iff none is WRONG.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT/scripts/lib.sh"
OUT="$1"; mkdir -p "$OUT"
LOCK="$ROOT/locks/risk-limit.sha256"; LEAN="$ROOT/examples/risk-limit/lean"
fails=0

lang_campaign() { # lang_campaign ID LANG DIR IMPL ARGS...
  local id="$1" lang="$2" dir="$3" impl="$4"; shift 4
  rm -rf "$OUT/$id"; mkdir -p "$OUT/$id"
  cp -r "$LEAN" "$OUT/$id/lean"; rm -rf "$OUT/$id/lean/.lake"
  cp -r "$dir/fuzz/corpus" "$OUT/$id/corpus"
  "$ROOT/fuzz/run_fuzz.sh" --lang "$lang" --lean-project "$OUT/$id/lean" --lock "$LOCK" --cmake-dir "$dir/fuzz" \
    --target diff_risk --impl-dir "$dir/$impl" --corpus "$OUT/$id/corpus" --no-merge --out "$OUT/$id/run" "$@" \
    > "$OUT/$id/run_fuzz.out" 2>&1
}

pin_id() { # pin_id NAME FILE -> the VENDORED.sha256 id whose pinned body equals FILE, or nothing
  awk -v n="$1" -v h="$(sha256sum < "$2" | cut -d' ' -f1)" '!/^#/ && $2 == n && $3 == h { print $1; exit }' "$ROOT/fuzz/VENDORED.sha256"
}
absent() { # absent LANG WHERE CONTROLS... : SKIP each control, or WRONG if the language is required
  local lang="$1" where="$2"; shift 2
  if [[ " ${FV_REQUIRE_LANGS:-} " == *" $lang "* ]]; then
    for c in "$@"; do echo "$c WRONG required language $lang (FV_REQUIRE_LANGS) but no toolchain at $where"; done
    fails=1
  else
    for c in "$@"; do echo "$c SKIP $lang toolchain not installed ($where; docs/LANGUAGES.md)"; done
  fi
}

R="$ROOT/examples/risk-limit-rust"
if [ ! -x "${FV_RUST_HOME:-$FV_ROOT/rust}/cargo/bin/cargo-fuzz" ]; then
  absent rust "${FV_RUST_HOME:-$FV_ROOT/rust}" c15_rust_clean c16_rust_drift c17_rust_overflow c18_rust_vendored_tamper c19_rust_profile_off
else

lang_campaign c15_rust_clean rust "$R" impl --runs 1000000
rc=$?; j="$OUT/c15_rust_clean/run/fuzz.json"
lsan=$(cat "$OUT/c15_rust_clean/run/replay.log" "$OUT/c15_rust_clean/run/campaign.log" 2>/dev/null | grep -c LeakSanitizer)
if [ $rc -eq 0 ] && [ "$(jq -r .verdict "$j")" = PASS ] && [ "$lsan" -eq 0 ]; then
  echo "c15_rust_clean OK $(jq -r '"runs=\(.runs) seconds=\(.campaign_seconds | .[0:6]) \(.stats)"' "$j") leak_reports=0"
else
  echo "c15_rust_clean WRONG exit=$rc leak_reports=$lsan $(jq -c '{verdict, detail}' "$j" 2>/dev/null)"; fails=1
fi

lang_campaign c16_rust_drift rust "$R" impl-drift --time 10
rc=$?; j="$OUT/c16_rust_drift/run/fuzz.json"
t=$(jq -r '.campaign_seconds // ""' "$j" 2>/dev/null)
if [ $rc -eq 1 ] && jq -e '.detail | contains("oracle/implementation mismatch")' "$j" > /dev/null \
   && { [ -z "$t" ] || [ "$(echo "$t < 10" | bc)" = 1 ]; }; then
  echo "c16_rust_drift OK FAIL after ${t:-replay} s (limit 10 s); $(grep -A4 'diff-oracle: MISMATCH' "$OUT/c16_rust_drift/run/campaign.log" "$OUT/c16_rust_drift/run/replay.log" 2>/dev/null | grep -E 'op |oracle|impl' | sed 's/^[^:]*-//' | tr -s ' ' | tr '\n' ';')"
else
  echo "c16_rust_drift WRONG exit=$rc $(jq -c '{verdict, detail, campaign_seconds}' "$j" 2>/dev/null)"; fails=1
fi

lang_campaign c17_rust_overflow rust "$R" impl-overflow --time 10
rc=$?; j="$OUT/c17_rust_overflow/run/fuzz.json"
if [ $rc -eq 1 ] && jq -e '.detail | startswith("panic:") and contains("overflow")' "$j" > /dev/null; then
  echo "c17_rust_overflow OK $(jq -r '.detail | .[0:150]' "$j") (after $(jq -r '.campaign_seconds // "replay" | .[0:5]' "$j") s)"
else
  echo "c17_rust_overflow WRONG exit=$rc $(jq -c '{verdict, detail}' "$j" 2>/dev/null)"; fails=1
fi

# Control 18: the comparison loop is the harness's, vendored copies are pinned, no own loop.
E18="$OUT/c18_ex"; rm -rf "$E18"; cp -r "$R" "$E18"; rm -rf "$E18/fuzz/target"
rid=$(pin_id fv_diff.rs "$ROOT/fuzz/rust/fv_diff.rs")
{ echo "// Vendored from fv-harness ${rid:-UNPINNED} (fv_diff.rs), unchanged below this header."; echo "//"
  cat "$ROOT/fuzz/rust/fv_diff.rs"; } > "$E18/fuzz/fv_diff.rs"
"$ROOT/fuzz/check_vendored.sh" "$E18/fuzz" > "$OUT/c18_untampered.json" 2>/dev/null; rc0=$?
sed -i 's|        if !B::same(&want, &got) {|        if false \&\& !B::same(\&want, \&got) { // tampered|' "$E18/fuzz/fv_diff.rs"
grep -q '// tampered' "$E18/fuzz/fv_diff.rs" || echo "c18 setup: tamper line not found" >&2
lang_campaign c18_rust_vendored_tamper rust "$E18" impl-drift --time 10
rca=$?; ja="$OUT/c18_rust_vendored_tamper/run/fuzz.json"
E18b="$OUT/c18b_ex"; rm -rf "$E18b"; cp -r "$R" "$E18b"; rm -rf "$E18b/fuzz/target"
sed -i 's|^fv_diff_main!(Risk);|libfuzzer_sys::fuzz_target!(\|data: \&[u8]\| { let _ = data; }); // own loop|' "$E18b/fuzz/fuzz_targets/diff_risk.rs"
lang_campaign c18b_rust_own_loop rust "$E18b" impl-drift --time 10
rcb=$?; jb="$OUT/c18b_rust_own_loop/run/fuzz.json"
if [ $rc0 -eq 0 ] && [ $rca -eq 1 ] && jq -e '.verdict == "FAIL" and (.detail | contains("fv_diff.rs"))' "$ja" > /dev/null \
   && [ ! -d "$OUT/c18_rust_vendored_tamper/run/cargo-target" ] \
   && [ $rcb -eq 3 ] && jq -e '.detail | contains("fv_diff_main!")' "$jb" > /dev/null && [ -n "$rid" ]; then
  echo "c18_rust_vendored_tamper OK untampered vendored driver passes; tampered: FAIL before build ($(jq -r .detail "$ja")); own fuzz_target!: ERROR ($(jq -r '.detail | .[0:90]' "$jb"))"
else
  echo "c18_rust_vendored_tamper WRONG pin=${rid:-none} untampered_rc=$rc0 tampered exit=$rca [$(jq -r .detail "$ja" 2>/dev/null)] own-loop exit=$rcb [$(jq -r .detail "$jb" 2>/dev/null)]"; fails=1
fi

# Control 19: the project cannot switch overflow checks off.
bad=""
for where in Cargo.toml .cargo/config.toml; do
  E19="$OUT/c19_ex_${where//[\/.]/_}"; rm -rf "$E19"; cp -r "$R" "$E19"; rm -rf "$E19/fuzz/target"
  mkdir -p "$(dirname "$E19/fuzz/$where")"; printf '\n[profile.release]\noverflow-checks = false\n' >> "$E19/fuzz/$where"
  id="c19_${where//[\/.]/_}"
  lang_campaign "$id" rust "$E19" impl-overflow --time 10
  rc=$?; j="$OUT/$id/run/fuzz.json"
  if [ $rc -ne 3 ] || ! jq -e '.detail | contains("overflow checks or debug assertions switched off")' "$j" > /dev/null; then
    bad+="$where(exit=$rc: $(jq -r .detail "$j" 2>/dev/null | cut -c1-60)) "
  fi
done
if [ -z "$bad" ]; then
  echo "c19_rust_profile_off OK overflow-checks = false in Cargo.toml and in .cargo/config.toml each refused: ERROR before build"
else
  echo "c19_rust_profile_off WRONG not refused: $bad"; fails=1
fi
fi  # rust

P="$ROOT/examples/risk-limit-py"; PY="${FV_PY:-$FV_ROOT/py/venv/bin/python}"
if ! { [ -x "$PY" ] && "$PY" -I -c 'import atheris' 2>/dev/null; }; then
  absent python "$PY" c21_py_clean c22_py_drift c23_py_wide c24_py_vendored_tamper
else
lang_campaign c21_py_clean python "$P" impl --runs 1000000
rc=$?; j="$OUT/c21_py_clean/run/fuzz.json"
if [ $rc -eq 0 ] && [ "$(jq -r .verdict "$j")" = PASS ]; then
  echo "c21_py_clean OK $(jq -r '"runs=\(.runs) seconds=\(.campaign_seconds | .[0:6]) \(.stats)"' "$j")"
else
  echo "c21_py_clean WRONG exit=$rc $(jq -c '{verdict, detail}' "$j" 2>/dev/null)"; fails=1
fi
lang_campaign c22_py_drift python "$P" impl-drift --time 10
rc=$?; j="$OUT/c22_py_drift/run/fuzz.json"; t=$(jq -r '.campaign_seconds // ""' "$j" 2>/dev/null)
if [ $rc -eq 1 ] && jq -e '.detail | contains("oracle/implementation mismatch")' "$j" > /dev/null \
   && { [ -z "$t" ] || [ "$(echo "$t < 10" | bc)" = 1 ]; }; then
  echo "c22_py_drift OK FAIL after ${t:-replay} s (limit 10 s)"
else
  echo "c22_py_drift WRONG exit=$rc $(jq -c '{verdict, detail, campaign_seconds}' "$j" 2>/dev/null)"; fails=1
fi
lang_campaign c23_py_wide python "$P" impl-wide --time 10
rc=$?; j="$OUT/c23_py_wide/run/fuzz.json"
if [ $rc -eq 1 ] && jq -e '.detail | startswith("domain:") and contains("outside [0, 2^64)")' "$j" > /dev/null; then
  echo "c23_py_wide OK $(jq -r .detail "$j")"
else
  echo "c23_py_wide WRONG exit=$rc $(jq -c '{verdict, detail}' "$j" 2>/dev/null)"; fails=1
fi
E24="$OUT/c24_ex"; rm -rf "$E24"; cp -r "$P" "$E24"
pid=$(pin_id fv_diff.py "$ROOT/fuzz/python/fv_diff.py")
{ echo "# Vendored from fv-harness ${pid:-UNPINNED} (fv_diff.py), unchanged below this header."; echo "#"
  cat "$ROOT/fuzz/python/fv_diff.py"; } > "$E24/fuzz/fv_diff.py"
"$ROOT/fuzz/check_vendored.sh" "$E24/fuzz" > "$OUT/c24_untampered.json" 2>/dev/null; rc0=$?
sed -i 's|        if not B.same(want, got):|        if False and not B.same(want, got):  # tampered|' "$E24/fuzz/fv_diff.py"
grep -q '# tampered' "$E24/fuzz/fv_diff.py" || echo "c24 setup: tamper line not found" >&2
lang_campaign c24_py_vendored_tamper python "$E24" impl-drift --time 10
rca=$?; ja="$OUT/c24_py_vendored_tamper/run/fuzz.json"
E24b="$OUT/c24b_ex"; rm -rf "$E24b"; cp -r "$P" "$E24b"
printf '\n\ndef TestOneInput(data):  # own loop\n    pass\n' >> "$E24b/fuzz/binding.py"
lang_campaign c24b_py_own_loop python "$E24b" impl-drift --time 10
rcb=$?; jb="$OUT/c24b_py_own_loop/run/fuzz.json"
if [ -n "$pid" ] && [ $rc0 -eq 0 ] && [ $rca -eq 1 ] && jq -e '.verdict == "FAIL" and (.detail | contains("fv_diff.py"))' "$ja" > /dev/null \
   && [ ! -d "$OUT/c24_py_vendored_tamper/run/build" ] && [ $rcb -eq 3 ] && jq -e '.detail | contains("TestOneInput")' "$jb" > /dev/null; then
  echo "c24_py_vendored_tamper OK untampered vendored driver passes; tampered: FAIL before build ($(jq -r .detail "$ja")); own TestOneInput: ERROR"
else
  echo "c24_py_vendored_tamper WRONG pin=${pid:-none} untampered_rc=$rc0 tampered exit=$rca [$(jq -r .detail "$ja" 2>/dev/null)] own-loop exit=$rcb [$(jq -r .detail "$jb" 2>/dev/null)]"; fails=1
fi
fi  # python
exit $fails
