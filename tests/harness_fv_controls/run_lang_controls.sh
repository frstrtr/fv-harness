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
#   c52_py_merge       the corpus merge on the Python loop really runs: a campaign that adds units grows the
#                      persisted corpus (copied), and the merge log reports success
#   c22_py_drift       a reduction one unit short: FAIL "oracle/implementation mismatch" within 10 s
#   c23_py_wide        a fill adds 2^64 (a bug that reduction mod 2^64 would hide): FAIL "domain: ..."
#   c24_py_vendored_tamper  (a) a vendored copy of the harness driver fv_diff.py passes untampered and,
#                      with its comparison disabled, FAILs before any build; (b) a binding that
#                      defines its own TestOneInput is ERROR
#   c25_evm_clean      the correct contract (solc 0.8.39, in-process EVM), with fv.toml pinning its
#                      runtime bytecode sha256: PASS; fuzz.json records the pinned solc sha256; the
#                      outcome classes include submit reverting LimitExceeded() and none is NOT EXERCISED
#   c26_evm_drift      a reduction one unit short: FAIL "oracle/implementation mismatch" within 50,000
#                      executions (60 s wall cap; the EVM path is slower than native, see the block)
#   c27_evm_overflow   (a) pos + open + q in checked uint64 arithmetic reverts with Panic(0x11) where
#                      the model rejects: FAIL mismatch showing "panic 0x11"; (b) the same test inside
#                      unchecked {} wraps and accepts: FAIL mismatch
#   c28_evm_vendored_tamper  (a) a vendored copy of the harness EVM fv_evm.rs passes untampered and,
#                      with reverts reported as successes, FAILs before any build; (b) a target with
#                      its own fuzz_target! is ERROR
#   c29_evm_pins       (a) a solc that is not the pinned build is ERROR before compiling; (b) a runtime
#                      bytecode that differs from fv.toml's expect_runtime_sha256 is BLOCKED before any
#                      fuzzer build
#
# Prints one "ID RESULT DETAIL" line per control. RESULT is SKIP when the language's toolchain is
# not installed (it is then not tested, and the summary says so) — unless the language is listed in
# FV_REQUIRE_LANGS (config/hosts.env), where a missing toolchain is WRONG. Exit 0 iff none is WRONG.
# FV_LANG_CONTROLS (default "rust python evm") limits which languages run (for negatives; the full
# suite, run_controls.sh, requires every line).
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
    --target diff_risk --impl-dir "$dir/$impl" --corpus "$OUT/$id/corpus" $([ "${LANG_MERGE:-0}" = 1 ] || echo --no-merge) --out "$OUT/$id/run" "$@" \
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

only() { [[ " ${FV_LANG_CONTROLS:-rust python evm} " == *" $1 "* ]]; }

R="$ROOT/examples/risk-limit-rust"
if ! only rust; then :
elif [ ! -x "${FV_RUST_HOME:-$FV_ROOT/rust}/cargo/bin/cargo-fuzz" ]; then
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
if ! only python; then :
elif ! { [ -x "$PY" ] && "$PY" -I -c 'import atheris' 2>/dev/null; }; then
  absent python "$PY" c21_py_clean c22_py_drift c23_py_wide c24_py_vendored_tamper c52_py_merge
else
LANG_MERGE=1 lang_campaign c52_py_merge python "$P" impl --runs 20000
rc=$?; j="$OUT/c52_py_merge/run/fuzz.json"; m52="$OUT/c52_py_merge/run/merge.log"
n52a=$(ls "$P/fuzz/corpus" | wc -l); n52b=$(ls "$OUT/c52_py_merge/corpus" | wc -l); nu52=$(jq -r .stats "$j" 2>/dev/null | grep -oE 'new_units_added: *[0-9]+' | grep -oE '[0-9]+$')
if [ $rc -eq 0 ] && grep -q '^MERGE-OUTER: successful in' "$m52" && [ "${nu52:-0}" -gt 0 ] && [ "$n52b" -gt "$n52a" ]; then
  echo "c52_py_merge OK merge ran ($(grep -m1 -oE 'successful in [0-9]+ attempt\(s\)' "$m52")): $nu52 new units, corpus $n52a -> $n52b"
else
  echo "c52_py_merge WRONG exit=$rc new_units=${nu52:-?} corpus $n52a -> $n52b merge: $(grep -m1 -E 'successful|Permission denied|did not run' "$m52" 2>/dev/null | cut -c1-100) [$(jq -r .detail "$j" 2>/dev/null)]"; fails=1
fi
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

X="$ROOT/examples/risk-limit-evm"; SOLC="${FV_SOLC:-$FV_ROOT/evm/solc-$FV_SOLC_VERSION}"
if ! only evm; then :
elif [ ! -x "${FV_RUST_HOME:-$FV_ROOT/rust}/cargo/bin/cargo-fuzz" ] || [ ! -x "$SOLC" ]; then
  absent evm "${FV_RUST_HOME:-$FV_ROOT/rust} + $SOLC" c25_evm_clean c26_evm_drift c27_evm_overflow c28_evm_vendored_tamper c29_evm_pins
else
E25="$OUT/c25_ex"; rm -rf "$E25"; cp -r "$X" "$E25"
rt=$(python3 -I "$ROOT/fuzz/evm/compile.py" --solc "$SOLC" --src-dir "$E25/contract" --fv-toml "$E25/fuzz/fv.toml" --out "$OUT/c25_compile" | jq -r .runtime_sha256)
printf 'expect_runtime_sha256 = "%s"\n' "$rt" >> "$E25/fuzz/fv.toml"
lang_campaign c25_evm_clean evm "$E25" contract --runs "${FV_EVM_CLEAN_RUNS:-1000000}"
rc=$?; j="$OUT/c25_evm_clean/run/fuzz.json"
if [ $rc -eq 0 ] && [ "$(jq -r .verdict "$j")" = PASS ] && [ "$(jq -r .evm.solc_sha256 "$j")" = "$FV_SOLC_SHA256" ] \
   && [ "$(jq -r .evm.runtime_sha256 "$j")" = "$rt" ] && [ "$(jq '.classes.not_exercised | length' "$j")" = 0 ] \
   && jq -e '[.classes.classes[] | select(.class == "outcome: submit(uint64) -> revert LimitExceeded()" and .inputs > 0)] | length == 1' "$j" > /dev/null; then
  echo "c25_evm_clean OK $(jq -r '"runs=\(.runs) seconds=\(.campaign_seconds | .[0:6]) runtime=\(.evm.runtime_sha256 | .[0:12]) (pinned) solc=\(.evm.solc_sha256 | .[0:12]) classes=\([.classes.classes[] | select(.kind == "outcome")] | length) not_exercised=0 \(.stats)"' "$j")"
else
  echo "c25_evm_clean WRONG exit=$rc $(jq -c '{verdict, detail, evm: (.evm | {solc_sha256, runtime_sha256}), not_exercised: .classes.not_exercised, cls_error: .classes.error}' "$j" 2>/dev/null)"; fails=1
fi
# The EVM path runs about 10-20x fewer inputs per second than native code under ASan, and that rate
# depends on the host. The criterion is therefore the number of EXECUTIONS before the drift is found
# (<= 50,000; observed 5,000-8,000), with a 60 s wall cap, not the 10 s used for native targets.
FV_NO_CLASSIFY=1 lang_campaign c26_evm_drift evm "$X" contract-drift --time 60
rc=$?; j="$OUT/c26_evm_drift/run/fuzz.json"; t=$(jq -r '.campaign_seconds // ""' "$j" 2>/dev/null)
n=$(grep -m1 -oE 'stat::number_of_executed_units: *[0-9]+' "$OUT/c26_evm_drift/run/campaign.log" 2>/dev/null | grep -oE '[0-9]+$')
if [ $rc -eq 1 ] && jq -e '.detail | contains("oracle/implementation mismatch")' "$j" > /dev/null \
   && { [ -z "$t" ] || { [ -n "$n" ] && [ "$n" -le 50000 ]; }; }; then
  echo "c26_evm_drift OK FAIL after ${n:-replay} executions, ${t:-0} s (limits 50,000 executions, 60 s)"
else
  echo "c26_evm_drift WRONG exit=$rc executions=${n:-?} $(jq -c '{verdict, detail, campaign_seconds}' "$j" 2>/dev/null)"; fails=1
fi
FV_NO_CLASSIFY=1 lang_campaign c27_evm_overflow evm "$X" contract-overflow --time 10
rca=$?; ja="$OUT/c27_evm_overflow/run/fuzz.json"
FV_NO_CLASSIFY=1 lang_campaign c27b_evm_wrap evm "$X" contract-wrap --time 10
rcb=$?; jb="$OUT/c27b_evm_wrap/run/fuzz.json"
if [ $rca -eq 1 ] && jq -e '.detail | contains("oracle/implementation mismatch")' "$ja" > /dev/null \
   && grep -q 'impl .*panic 0x11' "$OUT/c27_evm_overflow/run/campaign.log" \
   && [ $rcb -eq 1 ] && jq -e '.detail | contains("oracle/implementation mismatch")' "$jb" > /dev/null; then
  echo "c27_evm_overflow OK checked: FAIL, the contract $(grep -m1 -oE 'impl .*panic 0x11' "$OUT/c27_evm_overflow/run/campaign.log" | grep -oE 'panic 0x11') where the model rejects; unchecked: FAIL ($(grep -m1 -A3 'diff-oracle: MISMATCH' "$OUT/c27b_evm_wrap/run/campaign.log" | grep -m1 -oE 'op +[a-z]+\(uint64\) q=[0-9]+'))"
else
  echo "c27_evm_overflow WRONG checked exit=$rca [$(jq -r .detail "$ja" 2>/dev/null)] unchecked exit=$rcb [$(jq -r .detail "$jb" 2>/dev/null)]"; fails=1
fi
E28="$OUT/c28_ex"; rm -rf "$E28"; cp -r "$X" "$E28"
eid=$(pin_id fv_evm.rs "$ROOT/fuzz/evm/fv_evm.rs")
{ echo "// Vendored from fv-harness ${eid:-UNPINNED} (fv_evm.rs), unchanged below this header."; echo "//"
  cat "$ROOT/fuzz/evm/fv_evm.rs"; } > "$E28/fuzz/fv_evm.rs"
"$ROOT/fuzz/check_vendored.sh" "$E28/fuzz" > "$OUT/c28_untampered.json" 2>/dev/null; rc0=$?
sed -i 's|ExecutionResult::Revert { output, .. } => Outcome { kind: Kind::Revert,|ExecutionResult::Revert { output, .. } => Outcome { kind: Kind::Success, /* tampered */|' "$E28/fuzz/fv_evm.rs"
grep -q 'tampered' "$E28/fuzz/fv_evm.rs" || echo "c28 setup: tamper line not found" >&2
FV_NO_CLASSIFY=1 lang_campaign c28_evm_vendored_tamper evm "$E28" contract --time 10
rca=$?; ja="$OUT/c28_evm_vendored_tamper/run/fuzz.json"
E28b="$OUT/c28b_ex"; rm -rf "$E28b"; cp -r "$X" "$E28b"
printf '\nlibfuzzer_sys::fuzz_target!(|data: &[u8]| { let _ = data; });\n' >> "$E28b/fuzz/fuzz_targets/diff_risk.rs"
FV_NO_CLASSIFY=1 lang_campaign c28b_evm_own_target evm "$E28b" contract --time 10
rcb=$?; jb="$OUT/c28b_evm_own_target/run/fuzz.json"
if [ -n "$eid" ] && [ $rc0 -eq 0 ] && [ $rca -eq 1 ] && jq -e '.verdict == "FAIL" and (.detail | contains("fv_evm.rs"))' "$ja" > /dev/null \
   && [ ! -d "$OUT/c28_evm_vendored_tamper/run/cargo-target" ] && [ $rcb -eq 3 ] && jq -e '.detail | contains("fv_diff_main!")' "$jb" > /dev/null; then
  echo "c28_evm_vendored_tamper OK untampered vendored EVM passes; tampered: FAIL before build ($(jq -r .detail "$ja")); own fuzz_target!: ERROR"
else
  echo "c28_evm_vendored_tamper WRONG pin=${eid:-none} untampered_rc=$rc0 tampered exit=$rca [$(jq -r .detail "$ja" 2>/dev/null)] own-target exit=$rcb [$(jq -r .detail "$jb" 2>/dev/null)]"; fails=1
fi
B29="$OUT/c29_solc"; mkdir -p "$B29"; rm -f "$B29/solc"; cp "$SOLC" "$B29/solc"; chmod u+w "$B29/solc"; printf '\0' >> "$B29/solc"
c29_setup_ok=1  # the copy must really differ from the pinned build, or this leg proves nothing
[ "$(sha256sum < "$B29/solc" | cut -d' ' -f1)" != "$FV_SOLC_SHA256" ] || { c29_setup_ok=0; echo "c29 setup: the modified solc copy still has the pinned sha256" >&2; }
FV_SOLC="$B29/solc" FV_NO_CLASSIFY=1 lang_campaign c29_evm_solc evm "$X" contract --time 10
rca=$?; ja="$OUT/c29_evm_solc/run/fuzz.json"
E29="$OUT/c29_ex"; rm -rf "$E29"; cp -r "$X" "$E29"
printf 'expect_runtime_sha256 = "%064d"\n' 0 >> "$E29/fuzz/fv.toml"
FV_NO_CLASSIFY=1 lang_campaign c29b_evm_runtime evm "$E29" contract --time 10
rcb=$?; jb="$OUT/c29b_evm_runtime/run/fuzz.json"
if [ "$c29_setup_ok" = 1 ] && [ $rca -eq 3 ] && jq -e '.detail | contains("not the pinned build")' "$ja" > /dev/null && [ ! -d "$OUT/c29_evm_solc/run/evm" ] \
   && [ $rcb -eq 2 ] && jq -e '.verdict == "BLOCKED" and (.detail | contains("expect_runtime_sha256"))' "$jb" > /dev/null \
   && [ ! -d "$OUT/c29b_evm_runtime/run/cargo-target" ]; then
  echo "c29_evm_pins OK other solc: ERROR before compiling; runtime bytecode not the expected one: BLOCKED before any fuzzer build"
else
  echo "c29_evm_pins WRONG solc exit=$rca [$(jq -r .detail "$ja" 2>/dev/null)] runtime exit=$rcb [$(jq -r .detail "$jb" 2>/dev/null)]"; fails=1
fi
fi  # evm
exit $fails
