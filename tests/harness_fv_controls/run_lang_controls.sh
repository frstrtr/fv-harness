#!/usr/bin/env bash
# run_lang_controls.sh OUTDIR — controls for bindings beyond C++ (docs/LANGUAGES.md). Each language
# runs the risk-limit example's signed Lean spec (locks/risk-limit.*) against that language's
# implementation through fuzz/run_fuzz.sh --lang.
#
#   c15_rust_clean     correct Rust implementation, 10^6 runs: PASS, no leak report
#   c16_rust_drift     a reduction one unit short: FAIL "oracle/implementation mismatch" within 32,000 executions
#   c17_rust_overflow  the limit check adds before comparing (pos + open + q): with overflow checks
#                      ON (cargo fuzz build -a) it FAILs as "panic: ... overflow"
#   c18_rust_vendored_tamper  (a) a vendored copy of the harness driver fv_diff.rs passes the vendored
#                      check untampered, and with its comparison disabled FAILs before any build;
#                      (b) a target with its own fuzz_target! (bypassing the driver) is ERROR
#   c19_rust_profile_off  overflow-checks = false in the project's Cargo.toml, or in a
#                      .cargo/config.toml cargo would read, is ERROR before any build
#   c21_py_clean       correct Python implementation (Atheris), 10^6 runs: PASS
#   c52_py_merge       the corpus merge on the Python loop really runs: a campaign that adds units leaves the
#                      persisted corpus (copied) with more files than before (the merge keeps a subset of the
#                      new units, so "more", not "by that many"), and the merge reports success in one attempt
#   c22_py_drift       a reduction one unit short: FAIL "oracle/implementation mismatch" within 26,000 executions
#   c23_py_wide        a fill adds 2^64 (a bug that reduction mod 2^64 would hide): FAIL "domain: ..."
#   c55_py_oracle_error  the Python loop's ByteArray oracle path through run_fuzz.sh: a binding whose
#                      ORACLE_BYTES names a function the oracle does not export, and one declaring 0 bytes,
#                      each end ERROR (exit 3, "oracle: ORACLE_BYTES ..."), never FAIL or PASS.
#   c24_py_vendored_tamper  (a) a vendored copy of the harness driver fv_diff.py passes untampered and,
#                      with its comparison disabled, FAILs before any build; (b) a binding that
#                      defines its own TestOneInput is ERROR
#   c25_evm_clean      the correct contract (solc 0.8.39, in-process EVM), with fv.toml pinning its
#                      runtime bytecode sha256: PASS; fuzz.json records the pinned solc sha256; the
#                      outcome classes include submit reverting LimitExceeded() and none is NOT EXERCISED
#   c26_evm_drift      a reduction one unit short: FAIL "oracle/implementation mismatch" within 37,000
#                      executions
# Every control that must FIND something by search runs on an execution budget of at least 5x the worst
# executions-to-find observed in past runs (--runs), with --time only as a hang guard: a time budget can
# miss under host load (c27 on the v0.2.1 head did, once).
#   c27_evm_overflow   (a) pos + open + q in checked uint64 arithmetic reverts with Panic(0x11) where
#                      the model rejects: FAIL mismatch showing "panic 0x11"; (b) the same test inside
#                      unchecked {} wraps and accepts: FAIL mismatch
#   c28_evm_vendored_tamper  (a) a vendored copy of the harness EVM fv_evm.rs passes untampered and,
#                      with reverts reported as successes, FAILs before any build; (b) a target with
#                      its own fuzz_target! is ERROR
#   c29_evm_pins       (a) a solc that is not the pinned build is ERROR before compiling; (b) a runtime
#                      bytecode that differs from fv.toml's expect_runtime_sha256 is BLOCKED before any
#                      fuzzer build
#   c33_tron_tvm_trc10      TRC-10 opcodes on the TRON-TVM reference (java-tron, mainnet profile) against fixed
#                      answers: CALLTOKENID, CALLTOKENVALUE, TOKENBALANCE, CALLTOKEN (7 checks)
#   c34_tron_tvm_clean      the capped faucet contract on the TRON-TVM reference, signed spec: PASS through the
#                      corpus-merge path (no --no-merge, on a copied corpus: the merge must report success in one
#                      attempt and the corpus end with more files than before); fuzz.json records
#                      the pinned profile, the network as observed (only lo in every fuzz process), the
#                      driver's config as observed (debug=true, energy_limit_hard_fork=true), the classpath
#                      and JDK manifests, and every driver start with at least one transaction
#   c35_tron_tvm_drift      the faucet's cap test off by one when the cap is above 1 (tron-tvm/contract-drift-deep;
#                      the empty input does not reach it): FAIL mismatch found by the campaign, not the
#                      replay, within 5,000 executions
#   c36_tron_tvm_refusals   (a) a driver without --debug: the client aborts; (b) a profile key java-tron cannot
#                      apply and (c) a parameter the profile leaves unset: the driver refuses; (d) a
#                      profile whose sha256 differs from its record and (e) another TRON solc: ERROR; and
#                      through fuzz/run_fuzz.sh on a copy of the harness: (f) a profile the driver refuses
#                      and (g) a driver without --debug: ERROR, nothing kept; (h) deployed code that is not
#                      the compiler's: BLOCKED; (i) a driver that dies mid-run: ERROR, its input NOT kept as
#                      a reproducer (merge path, corpus unchanged); (j) a binding that never calls the TRON-TVM
#                      (its implementation answers from the oracle itself): ERROR, not PASS; (k)
#                      JAVA_TOOL_OPTIONS set: ERROR; (l) a binding that sends one transaction in warm_up and
#                      then answers every step from the oracle: ERROR (every implementation step must send a
#                      transaction), not PASS; (m) a driver that leaves the energy-limit fork inactive: ERROR;
#                      (n) an input over the per-input timeout (the executor's time): ERROR, corpus unchanged,
#                      no timeout-* kept; (o) a driver with the VM trace off: ERROR "coverage empty"; (p) a
#                      binding raising in make_op: ERROR naming the phase, input in artifacts/binding-error-*
#   c56_tron_tvm_roundtrip  the profile's read-back is live: a driver built from the current source with ONE
#                      parameter applied wrong (energy fee + 1 through ProposalService) must refuse to start
#                      ("does not round-trip ... getEnergyFee"); deleting the read-back turns this red
#   c57_tron_tvm_build_pins the executed build is pinned, each ERROR through run_fuzz.sh: (a) a build pin unset;
#                      (b) another classpath manifest sha256; (c) another JDK tree sha256; (d) another node
#                      config sha256 (observed in the drivers); (e) a TRON-TVM home whose classpath points
#                      outside it (stale absolute paths); (f) an old FV_TVM_* variable set
#   c64_tron_tvm_record     a tron-tvm PASS must carry the reference's record: (a) a run whose record says
#                      processes.with_transactions = 0 and (b) one with no tron_tvm record at all each end
#                      ERROR (the record write is refused); CLOSE given (c) c34's PASS record with tron_tvm
#                      null and (d) with with_transactions = 0 each refuses: ERROR "lacks ...", no closure
#   c109_tron_tvm_replay_drivers  the driver checks run again after the retention replay and the merge: with the
#                      test hook FV_TEST_HOOK_REPLAY_STATUS forging, after that replay only, the observation of a
#                      driver that saw another network interface, the run is ERROR; without the hook, and with it
#                      set to a phase that never happens, PASS (the hook is inert), and a set hook is recorded
#   c41_tron_tvm_coverage   contract coverage: the faucet plus a branch the generator cannot reach PASSes, and
#                      the report lists that branch's source line as NOT EXERCISED (labels only)
#   c49_tron_tvm_itx_drop   internal transactions are compared as an ordered list: a faucet whose withdraw(0)
#                      skips its (zero-amount) token transfer — balances, storage and events unchanged —
#                      must FAIL, the mismatch showing the internal transaction
#   c51_tron_tvm_guidance  with no IMPL_MODULE the harness instruments the binding's functions: the faucet
#                      campaign adds new corpus units within 3,000 executions (0 without it)
#   c37_tron_tvm_vendored_tamper  vendored copies of fv_tron_tvm.py and FvTronTvmDriver.java pass untampered; each,
#                      tampered, FAILs before any build
#
# Prints one "ID RESULT DETAIL" line per control. RESULT is SKIP when the language's toolchain is
# not installed (it is then not tested, and the summary says so) — unless the language is listed in
# FV_REQUIRE_LANGS (config/hosts.env), where a missing toolchain is WRONG. Exit 0 iff none is WRONG.
# FV_LANG_CONTROLS (default "rust python evm tron-tvm") limits which languages run (for negatives; the full
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

execs() { # execs ID -> executions to the finding: final stats, else the last status line; "replay" if found there
  local r="$OUT/$1/run" n
  if grep -q 'diff-oracle: MISMATCH\|panicked at\|Uncaught Python exception\|diff-oracle: DOMAIN' "$r/replay.log" 2>/dev/null; then echo replay; return; fi
  n=$(grep -E '^stat::number_of_executed_units' "$r/campaign.log" 2>/dev/null | tail -1 | grep -oE '[0-9]+$')
  [ -n "$n" ] || n=$(grep -oE '^#[0-9]+' "$r/campaign.log" 2>/dev/null | tail -1 | tr -d '#')
  echo "${n:-unknown}"
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

only() { [[ " ${FV_LANG_CONTROLS:-rust python evm tron-tvm} " == *" $1 "* ]]; }

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

lang_campaign c16_rust_drift rust "$R" impl-drift --runs 32000 --time 600
rc=$?; j="$OUT/c16_rust_drift/run/fuzz.json"
n=$(execs c16_rust_drift)
if [ $rc -eq 1 ] && jq -e '.detail | contains("oracle/implementation mismatch")' "$j" > /dev/null; then
  echo "c16_rust_drift OK FAIL after ${n} executions (budget 32,000); $(grep -A4 'diff-oracle: MISMATCH' "$OUT/c16_rust_drift/run/campaign.log" "$OUT/c16_rust_drift/run/replay.log" 2>/dev/null | grep -E 'op |oracle|impl' | sed 's/^[^:]*-//' | tr -s ' ' | tr '\n' ';')"
else
  echo "c16_rust_drift WRONG exit=$rc $(jq -c '{verdict, detail, campaign_seconds}' "$j" 2>/dev/null)"; fails=1
fi

lang_campaign c17_rust_overflow rust "$R" impl-overflow --runs 37000 --time 600
rc=$?; j="$OUT/c17_rust_overflow/run/fuzz.json"
if [ $rc -eq 1 ] && jq -e '.detail | startswith("panic:") and contains("overflow")' "$j" > /dev/null; then
  echo "c17_rust_overflow OK $(jq -r '.detail | .[0:150]' "$j") (after $(execs c17_rust_overflow) executions, budget 37,000)"
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
  absent python "$PY" c21_py_clean c22_py_drift c23_py_wide c24_py_vendored_tamper c52_py_merge c55_py_oracle_error
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
lang_campaign c22_py_drift python "$P" impl-drift --runs 26000 --time 600
rc=$?; j="$OUT/c22_py_drift/run/fuzz.json"; n=$(execs c22_py_drift)
if [ $rc -eq 1 ] && jq -e '.detail | contains("oracle/implementation mismatch")' "$j" > /dev/null; then
  echo "c22_py_drift OK FAIL after ${n} executions (budget 26,000)"
else
  echo "c22_py_drift WRONG exit=$rc $(jq -c '{verdict, detail, campaign_seconds}' "$j" 2>/dev/null)"; fails=1
fi
lang_campaign c23_py_wide python "$P" impl-wide --runs 16000 --time 600
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
E55="$OUT/c55_ex"; r55=""
for v in nofn zero; do
  rm -rf "$E55-$v"; cp -r "$P" "$E55-$v"
  [ $v = nofn ] && printf '\nORACLE_BYTES = {"fv_no_such_export": 4}\n' >> "$E55-$v/fuzz/binding.py"
  [ $v = zero ] && printf '\nORACLE_BYTES = {"fv_no_such_export": 0}\n' >> "$E55-$v/fuzz/binding.py"
  lang_campaign c55_py_oracle_error_$v python "$E55-$v" impl --time 10
  rc=$?; j="$OUT/c55_py_oracle_error_$v/run/fuzz.json"
  [ $rc -eq 3 ] && jq -e '.verdict == "ERROR" and (.detail | startswith("oracle: ORACLE_BYTES"))' "$j" > /dev/null \
    || r55+="$v exit=$rc [$(jq -r .detail "$j" 2>/dev/null | cut -c1-100)] "
done
if [ -z "$r55" ]; then
  echo "c55_py_oracle_error OK unknown ByteArray export and 0-byte declaration each ERROR: $(jq -r .detail "$OUT/c55_py_oracle_error_zero/run/fuzz.json" | cut -c1-100)"
else
  echo "c55_py_oracle_error WRONG $r55"; fails=1
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
# (budget 37,000 = 5x the worst observed 7,350; 900 s only as a hang guard).
FV_NO_CLASSIFY=1 lang_campaign c26_evm_drift evm "$X" contract-drift --runs 37000 --time 900
rc=$?; j="$OUT/c26_evm_drift/run/fuzz.json"; t=$(jq -r '.campaign_seconds // ""' "$j" 2>/dev/null)
n=$(grep -m1 -oE 'stat::number_of_executed_units: *[0-9]+' "$OUT/c26_evm_drift/run/campaign.log" 2>/dev/null | grep -oE '[0-9]+$')
if [ $rc -eq 1 ] && jq -e '.detail | contains("oracle/implementation mismatch")' "$j" > /dev/null \
   && { [ -z "$t" ] || { [ -n "$n" ] && [ "$n" -le 37000 ]; }; }; then
  echo "c26_evm_drift OK FAIL after ${n:-replay} executions, ${t:-0} s (budget 37,000 executions; 900 s only as a hang guard)"
else
  echo "c26_evm_drift WRONG exit=$rc executions=${n:-?} $(jq -c '{verdict, detail, campaign_seconds}' "$j" 2>/dev/null)"; fails=1
fi
FV_NO_CLASSIFY=1 lang_campaign c27_evm_overflow evm "$X" contract-overflow --runs 48000 --time 900
rca=$?; ja="$OUT/c27_evm_overflow/run/fuzz.json"
FV_NO_CLASSIFY=1 lang_campaign c27b_evm_wrap evm "$X" contract-wrap --runs 48000 --time 900
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
TH="${FV_TRON_TVM_HOME:-$FV_ROOT/tron-tvm}"; F="$ROOT/examples/token-faucet-tron-tvm"; TRON_TVM_ALL="c33_tron_tvm_trc10 c34_tron_tvm_clean c35_tron_tvm_drift c36_tron_tvm_refusals c37_tron_tvm_vendored_tamper c41_tron_tvm_coverage c49_tron_tvm_itx_drop c51_tron_tvm_guidance c56_tron_tvm_roundtrip c57_tron_tvm_build_pins c64_tron_tvm_record c109_tron_tvm_replay_drivers"
fresh() { rm -rf "${1:?}"; mkdir -p "$1"; }  # fresh DIR: an empty directory (refuses an empty argument)
tron_tvm_campaign() { # tron_tvm_campaign ID DIR IMPL ARGS...  (signed faucet spec)
  local id="$1" dir="$2" impl="$3"; shift 3
  fresh "${OUT:?}/${id:?}"
  cp -r "$F/lean" "$OUT/$id/lean"; rm -rf "${OUT:?}/${id:?}/lean/.lake"; cp -r "$dir/fuzz/corpus" "$OUT/$id/corpus"
  "$ROOT/fuzz/run_fuzz.sh" --lang tron-tvm --lean-project "$OUT/$id/lean" --lock "$ROOT/locks/token-faucet.sha256" \
    --cmake-dir "$dir/fuzz" --target diff_faucet --impl-dir "$dir/$impl" --corpus "$OUT/$id/corpus" $([ "${TRON_TVM_MERGE:-0}" = 1 ] || echo --no-merge) \
    --out "$OUT/$id/run" "$@" > "$OUT/$id/run_fuzz.out" 2>&1
}
tron_tvm_driver() { # tron_tvm_driver DIR [DRIVER_SRC] : compiles the driver into DIR/drv, writes DIR/driver.sh [PROFILE]
  local d="$1" src="${2:-$ROOT/fuzz/tron-tvm/FvTronTvmDriver.java}"; mkdir -p "$d/drv"
  "$TH/$FV_TRON_TVM_JDK/bin/javac" -nowarn -cp "$(cat "$TH/framework-test-classpath.txt")" -d "$d/drv" "$src" > "$d/javac.log" 2>&1
  printf '#!/bin/sh\nexec %q -Xmx2g -cp %q FvTronTvmDriver "$1" "${FV_TEST_PROFILE:-%s}" 2>> %q\n' "$TH/$FV_TRON_TVM_JDK/bin/java" \
    "$d/drv:$(cat "$TH/framework-test-classpath.txt")" "$ROOT/fuzz/tron-tvm/profiles/mainnet-20261122.json" "$d/driver.log" > "$d/driver.sh"
  chmod +x "$d/driver.sh"
}
if ! only tron-tvm; then :
elif [ ! -x "$TH/$FV_TRON_TVM_JDK/bin/java" ] || [ ! -f "$TH/framework-test-classpath.txt" ] || [ ! -x "$TH/tron-solc-$FV_TRON_SOLC_VERSION" ] \
     || ! { [ -x "$PY" ] && "$PY" -I -c 'import atheris' 2>/dev/null; }; then
  absent tron-tvm "$TH (java-tron, JDK, TRON solc) + $PY" $TRON_TVM_ALL
else
# c33: known answers through the harness client, offline.
D="${OUT:?}/c33"; fresh "$D"; mkdir -p "$D/src"; cp "$ROOT/tests/harness_fv_controls/tron-tvm/Trc10Probe.sol" "$D/src/"
printf '[tron-tvm]\ncontract = "Trc10Probe"\nsource = "Trc10Probe.sol"\nevm_version = "petersburg"\noptimizer = true\noptimizer_runs = 200\n' > "$D/fv.toml"
python3 -I "$ROOT/fuzz/evm/compile.py" --section tron-tvm --solc "$TH/tron-solc-$FV_TRON_SOLC_VERSION" --src-dir "$D/src" --fv-toml "$D/fv.toml" --out "$D" > "$D/compile.json"
od -An -v -tx1 "$D/creation.bin" | tr -d ' \n' > "$D/creation.hex"; od -An -v -tx1 "$D/runtime.bin" | tr -d ' \n' > "$D/runtime.hex"
tron_tvm_driver "$D"
tron_tvm_client() { # tron_tvm_client DIR DRIVER_DIR SCRIPT : runs SCRIPT with fv_tron_tvm against DRIVER_DIR's driver, offline
  local d="$1" dd="$2"; fresh "$d/db"
  capped bwrap --dev-bind / / --unshare-net -- env FV_TRON_TVM_CMD="$dd/driver.sh" FV_TRON_TVM_CREATION="$D/creation.hex" \
    FV_TRON_TVM_RUNTIME="$D/runtime.hex" FV_TRON_TVM_DB="$d/db" FV_TEST_PROFILE="${FV_TEST_PROFILE:-}" \
    python3 -I -c 'import sys; sys.path.insert(0, sys.argv[1]); exec(open(sys.argv[2]).read())' "$ROOT/fuzz/tron-tvm" "$3"
}
MAINNET="$ROOT/fuzz/tron-tvm/profiles/mainnet-20261122.json"
FV_TEST_PROFILE="$MAINNET" tron_tvm_client "$D" "$D" "$ROOT/tests/harness_fv_controls/tron-tvm/known_answers.py" > "$D/answers.txt" 2> "$D/answers.err"; rc=$?
if [ $rc -eq 0 ] && grep -q '^c33 PASS 9/9' "$D/answers.txt"; then
  echo "c33_tron_tvm_trc10 OK 9/9 known answers on java-tron $FV_JAVA_TRON_COMMIT (mainnet profile): CALLTOKENID, CALLTOKENVALUE, TOKENBALANCE, CALLTOKEN; reads create no account"
else
  echo "c33_tron_tvm_trc10 WRONG exit=$rc $(grep -E '^BAD|^c33' "$D/answers.txt" | head -3 | tr '\n' ' ') $(tail -1 "$D/answers.err")"; fails=1
fi
TRON_TVM_MERGE=1 tron_tvm_campaign c34_tron_tvm_clean "$F" contract --runs "${FV_TRON_TVM_CLEAN_RUNS:-12000}" --time 1800
rc=$?; j="$OUT/c34_tron_tvm_clean/run/fuzz.json"
n34a=$(ls "$F/fuzz/corpus" | wc -l); n34b=$(ls "$OUT/c34_tron_tvm_clean/corpus" | wc -l)
nu34=$(jq -r .stats "$j" 2>/dev/null | grep -oE 'new_units_added: *[0-9]+' | grep -oE '[0-9]+$')
if [ $rc -eq 0 ] && grep -q '^MERGE-OUTER: successful in' "$OUT/c34_tron_tvm_clean/run/merge.log" && [ "${nu34:-0}" -gt 0 ] && [ "$n34b" -gt "$n34a" ] && jq -e --arg c "$FV_JAVA_TRON_COMMIT" '.verdict == "PASS" and .tron_tvm.java_tron_commit == $c
     and .tron_tvm.chain_profile.sha256 == "9012d4a9211268c1861a8c052ab26b82e4feab3cf96d33c643fdbf378b9b0c8f"
     and (.tron_tvm.network | startswith("none (observed: only lo")) and (.tron_tvm.cpu_time_limit | startswith("disabled (--debug, observed"))
     and (.tron_tvm.driver_config | contains("energy_limit_hard_fork=true")) and (.tron_tvm.classpath_manifest_sha256 | length) == 64
     and (.tron_tvm.jdk_tree_sha256 | length) == 64 and .tron_tvm.processes.with_transactions >= 1' "$j" > /dev/null; then
  echo "c34_tron_tvm_clean OK $(jq -r '"seconds=\(.campaign_seconds | .[0:6]) runtime=\(.tron_tvm.runtime_sha256 | .[0:12]) stripped=\(.tron_tvm.runtime_stripped_sha256 | .[0:12]) profile=\(.tron_tvm.chain_profile.name) drivers=\(.tron_tvm.processes.driver_starts) \(.stats)"' "$j"); merge ran, $nu34 new units, corpus $n34a -> $n34b"
else
  echo "c34_tron_tvm_clean WRONG exit=$rc $(jq -c '{verdict, detail, tron_tvm: (.tron_tvm | {java_tron_commit, chain_profile, network})}' "$j" 2>/dev/null) merge.log=$([ -s "$OUT/c34_tron_tvm_clean/run/merge.log" ] && echo yes || echo no) corpus $n34a -> $n34b"; fails=1
fi
tron_tvm_campaign c35_tron_tvm_drift "$F" contract --runs 5000 --time 1800 --impl-dir "$ROOT/tests/harness_fv_controls/tron-tvm/contract-drift-deep"
rc=$?; j="$OUT/c35_tron_tvm_drift/run/fuzz.json"
n=$(grep -oE '^#[0-9]+' "$OUT/c35_tron_tvm_drift/run/campaign.log" 2>/dev/null | tail -1 | tr -d '#')
if [ $rc -eq 1 ] && jq -e '(.detail | contains("oracle/implementation mismatch")) and (.detail | startswith("regression replay") | not)' "$j" > /dev/null \
   && [ -n "$n" ] && [ "$n" -ge 2 ] && [ "$n" -le 5000 ]; then
  echo "c35_tron_tvm_drift OK FAIL in the campaign (not the replay) at execution ~$n (limit 5,000): $(jq -r .detail "$j" | cut -c1-80)"
else
  echo "c35_tron_tvm_drift WRONG exit=$rc executions=${n:-?} $(jq -c '{verdict, detail}' "$j" 2>/dev/null)"; fails=1
fi
# c36: refusals.
R="${OUT:?}/c36"; fresh "$R"; mkdir -p "$R/nodebug"
sed 's|new String\[\]{"--output-directory", argv\[0\], "--debug"}|new String[]{"--output-directory", argv[0]}|' "$ROOT/fuzz/tron-tvm/FvTronTvmDriver.java" > "$R/nodebug/FvTronTvmDriver.java"
grep -q '"--debug"' "$R/nodebug/FvTronTvmDriver.java" && echo "c36 setup: --debug still present" >&2
tron_tvm_driver "$R/nodebug" "$R/nodebug/FvTronTvmDriver.java"
FV_TEST_PROFILE="$MAINNET" tron_tvm_client "$R/nodebug" "$R/nodebug" "$ROOT/tests/harness_fv_controls/tron-tvm/known_answers.py" > "$R/a.out" 2> "$R/a.err"; ra=$?
python3 -I - "$MAINNET" "$R" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
u = {"chainParameter": d["chainParameter"] + [{"key": "getAllowSomethingNew", "value": 1}]}
m = {"chainParameter": [p for p in d["chainParameter"] if p["key"] != "getAllowMultiSign"]}
json.dump(u, open(sys.argv[2] + "/unknown.json", "w")); json.dump(m, open(sys.argv[2] + "/unset.json", "w"))
PY
mkdir -p "$R/db-unknown" "$R/db-unset"
rb=$(echo quit | FV_TEST_PROFILE="$R/unknown.json" capped bwrap --dev-bind / / --unshare-net -- "$D/driver.sh" "$R/db-unknown" 2>/dev/null | head -1)
rcx=$(echo quit | FV_TEST_PROFILE="$R/unset.json" capped bwrap --dev-bind / / --unshare-net -- "$D/driver.sh" "$R/db-unset" 2>/dev/null | head -1)
FX="$R/harness"; mkdir -p "$FX"; cp -r "$ROOT/fuzz" "$ROOT/scripts" "$ROOT/config" "$FX/"
printf ' ' >> "$FX/fuzz/tron-tvm/profiles/mainnet-20261122.json"
"$FX/fuzz/run_fuzz.sh" --lang tron-tvm --lean-project "$F/lean" --lock "$ROOT/locks/token-faucet.sha256" --cmake-dir "$F/fuzz" \
  --target diff_faucet --impl-dir "$F/contract" --no-merge --time 10 --out "$R/prof" > /dev/null 2>&1; rd=$?
cp "$TH/tron-solc-$FV_TRON_SOLC_VERSION" "$R/solc"; chmod u+w "$R/solc"; printf '\0' >> "$R/solc"
FV_TRON_SOLC="$R/solc" "$ROOT/fuzz/run_fuzz.sh" --lang tron-tvm --lean-project "$F/lean" --lock "$ROOT/locks/token-faucet.sha256" \
  --cmake-dir "$F/fuzz" --target diff_faucet --impl-dir "$F/contract" --no-merge --time 10 --out "$R/solcrun" > /dev/null 2>&1; re=$?
# (f)-(k): through run_fuzz.sh. hx NAME: a copy of the harness to change; rf HARNESS NAME ARGS: one faucet run.
hx() { local h="$R/hx-$1"; fresh "$h"; cp -r "$ROOT/fuzz" "$ROOT/scripts" "$ROOT/config" "$h/"; echo "$h"; }
rf() { local h="$1" n="$2"; shift 2; fresh "$R/$n"; cp -r "$F/fuzz/corpus" "$R/$n/corpus"
  "$h/fuzz/run_fuzz.sh" --lang tron-tvm --lean-project "$F/lean" --lock "$ROOT/locks/token-faucet.sha256" --target diff_faucet \
    --impl-dir "$F/contract" --corpus "$R/$n/corpus" --out "$R/$n/run" "$@" > "$R/$n/out" 2>&1; }
H=$(hx refuse); cp "$R/unknown.json" "$H/fuzz/tron-tvm/profiles/mainnet-20261122.json"
jq --arg s "$(sha256sum < "$R/unknown.json" | cut -d' ' -f1)" '.sha256 = $s' "$ROOT/fuzz/tron-tvm/profiles/mainnet-20261122.meta.json" > "$H/fuzz/tron-tvm/profiles/mainnet-20261122.meta.json"
rf "$H" f --cmake-dir "$F/fuzz" --no-merge --time 10; rf_f=$?
H=$(hx nodebug); cp "$R/nodebug/FvTronTvmDriver.java" "$H/fuzz/tron-tvm/FvTronTvmDriver.java"
rf "$H" g --cmake-dir "$F/fuzz" --no-merge --time 10; rf_g=$?
H=$(hx deploy); python3 -I - "$H/fuzz/run_fuzz.sh" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
a = 'od -An -v -tx1 "$RUN/tron-tvm/runtime.bin" | tr -d \' \\n\' > "$RUN/tron-tvm/runtime.hex"'
assert a in s, "c36 setup: runtime.hex line not found"
s = s.replace(a, a + '; sed -i "s/..$/ff/" "$RUN/tron-tvm/runtime.hex"', 1)
open(p, "w").write(s)
PY
rf "$H" h --cmake-dir "$F/fuzz" --no-merge --time 10; rf_h=$?
for v in dies nocall warmonly; do fresh "$R/fz-$v"; cp -r "$F/fuzz/." "$R/fz-$v/"; done
python3 -I "$ROOT/tests/harness_fv_controls/tron-tvm/make_variants.py" "$R/fz-dies/binding.py" "$R/fz-nocall/binding.py" "$R/fz-warmonly/binding.py"
rf "$ROOT" i --cmake-dir "$R/fz-dies" --time 60; rf_i=$?
ni_a=$(ls "$F/fuzz/corpus" | wc -l); ni_b=$(ls "$R/i/corpus" | wc -l)
rf "$ROOT" j --cmake-dir "$R/fz-nocall" --no-merge --time 15; rf_j=$?
JAVA_TOOL_OPTIONS=-Xint rf "$ROOT" k --cmake-dir "$F/fuzz" --no-merge --time 10; rf_k=$?
rf "$ROOT" l --cmake-dir "$R/fz-warmonly" --no-merge --time 15; rf_l=$?
H=$(hx nofork); python3 -I - "$H/fuzz/tron-tvm/FvTronTvmDriver.java" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
a = "    org.tron.common.parameter.CommonParameter.getInstance().blockNumForEnergyLimit = 0L;"
assert s.count(a) == 1, "c36 setup: fork line not found"
open(p, "w").write(s.replace(a, "    // (c36 m: the energy-limit fork left at java-tron's default, inactive on a fresh node)"))
PY
rf "$H" m --cmake-dir "$F/fuzz" --no-merge --time 10; rf_m=$?
# (n) an input over the per-input timeout (the binding sleeps after its transaction): ERROR, nothing kept
fresh "$R/fz-slow"; cp -r "$F/fuzz/." "$R/fz-slow/"
python3 -I - "$R/fz-slow" <<'PY'
import sys, re
d = sys.argv[1]
b = open(d + "/binding.py").read()
a = "def impl_step(impl, s, op):\n"
assert b.count(a) == 1, "c36 n: impl_step not found"
b = b.replace(a, a + "    global SLOW_N\n    SLOW_N = globals().get('SLOW_N', 0) + 1\n", 1)
a = "    w = T.sload(2)\n"
assert b.count(a) == 1, "c36 n: sload line not found"
b = b.replace(a, "    if SLOW_N == 30:\n        import time\n        time.sleep(8)  # the executor's time, after its transaction\n" + a, 1)
open(d + "/binding.py", "w").write(b)
t = open(d + "/fv.toml").read()
t2 = re.sub(r"(?m)^timeout = [0-9]+.*$", "timeout = 3", t)
assert t2 != t, "c36 n: timeout line not found"
open(d + "/fv.toml", "w").write(t2)
PY
rf "$ROOT" n --cmake-dir "$R/fz-slow" --runs 2000 --time 600; rf_n=$?
nn_a=$(ls "$F/fuzz/corpus" | wc -l); nn_b=$(ls "$R/n/corpus" | wc -l)
# (o) a driver with the VM trace off: no coverage, so the reference did not demonstrably run
H=$(hx notrace); python3 -I - "$H/fuzz/tron-tvm/FvTronTvmDriver.java" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
a = "org.tron.common.parameter.CommonParameter.getInstance().vmTrace = true;"
assert s.count(a) == 1, "c36 o: vmTrace line not found"
open(p, "w").write(s.replace(a, "org.tron.common.parameter.CommonParameter.getInstance().vmTrace = false;  // c36 o"))
PY
rf "$H" o --cmake-dir "$F/fuzz" --no-merge --runs 200 --time 600; rf_o=$?
# (p) a binding that raises in make_op on its 20th call: ERROR naming the phase, the input kept as
#     artifacts/binding-error-*, never in the corpus
fresh "$R/fz-raise"; cp -r "$F/fuzz/." "$R/fz-raise/"
python3 -I - "$R/fz-raise/binding.py" <<'PY'
import sys
p = sys.argv[1]; b = open(p).read()
a = "def make_op(inp, s):\n"
assert b.count(a) == 1, "c36 p: make_op not found"
b = b.replace(a, a + "    global RAISE_N\n    RAISE_N = globals().get('RAISE_N', 0) + 1\n    if RAISE_N == 20:\n        raise ValueError('c36 p: binding bug')\n", 1)
open(p, "w").write(b)
PY
rf "$ROOT" p --cmake-dir "$R/fz-raise" --runs 2000 --time 600; rf_p=$?
np_a=$(ls "$F/fuzz/corpus" | wc -l); np_b=$(ls "$R/p/corpus" | wc -l); pe=$(ls "$R/p/run/artifacts/" 2>/dev/null | grep -c '^binding-error-')
dj() { jq -r .detail "$R/$1/run/fuzz.json" 2>/dev/null | cut -c1-110; }
c36b=""
[ $rf_f -eq 3 ] && [[ "$(dj f)" == "TRON-TVM reference executor: driver did not start"* ]] || c36b+="(f) exit=$rf_f [$(dj f)] "
[ $rf_g -eq 3 ] && [[ "$(dj g)" == *"cpu-time limit is not disabled"* ]] || c36b+="(g) exit=$rf_g [$(dj g)] "
[ $rf_h -eq 2 ] && [[ "$(dj h)" == "DEPLOYED CODE MISMATCH"* ]] || c36b+="(h) exit=$rf_h [$(dj h)] "
[ $rf_i -eq 3 ] && [[ "$(dj i)" == "TRON-TVM reference executor: driver gone"* ]] && [ "$ni_a" -eq "$ni_b" ] || c36b+="(i) exit=$rf_i corpus $ni_a->$ni_b [$(dj i)] "
[ $rf_j -eq 3 ] && [[ "$(dj j)" == "TRON-TVM reference executor: step 0: impl_step sent no transaction"* ]] || c36b+="(j) exit=$rf_j [$(dj j)] "
[ $rf_k -eq 3 ] && [[ "$(dj k)" == "JAVA_TOOL_OPTIONS is set"* ]] || c36b+="(k) exit=$rf_k [$(dj k)] "
[ $rf_l -eq 3 ] && [[ "$(dj l)" == "TRON-TVM reference executor: step 0: impl_step sent no transaction"* ]] || c36b+="(l) exit=$rf_l [$(dj l)] "
[ $rf_m -eq 3 ] && [[ "$(dj m)" == "the energy-limit fork was not active"* ]] || c36b+="(m) exit=$rf_m [$(dj m)] "
[ $rf_n -eq 3 ] && [[ "$(dj n)" == "TRON-TVM reference executor: an input exceeded the per-input timeout"* ]] && [ "$nn_a" -eq "$nn_b" ] \
  && [ -z "$(ls "$R/n/corpus" | grep '^timeout-')" ] || c36b+="(n) exit=$rf_n corpus $nn_a->$nn_b [$(dj n)] "
[ $rf_o -eq 3 ] && [[ "$(jq -r .detail "$R/o/run/fuzz.json" 2>/dev/null)" == "the TRON-TVM reference did not demonstrably run"*"coverage empty"* ]] || c36b+="(o) exit=$rf_o [$(jq -r .detail "$R/o/run/fuzz.json" 2>/dev/null | cut -c1-200)] "
[ $rf_p -eq 3 ] && [[ "$(jq -r .detail "$R/p/run/fuzz.json" 2>/dev/null)" == *"raised ValueError in make_op"* ]] && [ "$np_a" -eq "$np_b" ] && [ "${pe:-0}" -ge 1 ] \
  || c36b+="(p) exit=$rf_p corpus $np_a->$np_b kept=${pe:-0} [$(dj p)] "
if [ -z "$c36b" ] && [ $ra -ne 0 ] && grep -q "cpu-time limit is not disabled" "$R/a.err" \
   && [[ "$rb" == "error "*"keys it cannot apply [getAllowSomethingNew]"* ]] && [[ "$rcx" == "error "*"leaves unset [saveAllowMultiSign]"* ]] \
   && [ $rd -eq 3 ] && jq -e '.detail | contains("not the recorded one")' "$R/prof/fuzz.json" > /dev/null \
   && [ $re -eq 3 ] && jq -e '.detail | contains("not the pinned build")' "$R/solcrun/fuzz.json" > /dev/null; then
  echo "c36_tron_tvm_refusals OK no --debug: client aborts; unknown profile key: refused; unset parameter (allowMultiSign): refused; profile sha mismatch: ERROR; other TRON solc: ERROR; through run_fuzz.sh: refused profile ERROR, no --debug ERROR, deployed code differs BLOCKED, driver killed mid-run ERROR with the corpus unchanged ($ni_a files), a binding that never calls the TRON-TVM ERROR, JAVA_TOOL_OPTIONS ERROR, a binding calling the TRON-TVM only in warm_up ERROR (every step must send a transaction), the energy-limit fork off ERROR, an input over the per-input timeout ERROR with nothing kept, the VM trace off ERROR (coverage empty), a binding raising in make_op ERROR naming the phase with the input in artifacts/binding-error-*"
else
  echo "c36_tron_tvm_refusals WRONG nodebug=$ra [$(tail -1 "$R/a.err" | cut -c1-80)] unknown=[${rb:0:120}] unset=[${rcx:0:120}] prof=$rd solc=$re run_fuzz: ${c36b:-ok}"; fails=1
fi
# c37: vendored copies of the TRON-TVM client and driver.
V="${OUT:?}/c37"; fresh "$V"; cp -r "$F" "$V/a"
tid=$(pin_id fv_tron_tvm.py "$ROOT/fuzz/tron-tvm/fv_tron_tvm.py"); did=$(pin_id FvTronTvmDriver.java "$ROOT/fuzz/tron-tvm/FvTronTvmDriver.java")
{ echo "# Vendored from fv-harness ${tid:-UNPINNED} (fv_tron_tvm.py), unchanged below this header."; echo "#"; cat "$ROOT/fuzz/tron-tvm/fv_tron_tvm.py"; } > "$V/a/fuzz/fv_tron_tvm.py"
{ echo "// Vendored from fv-harness ${did:-UNPINNED} (FvTronTvmDriver.java), unchanged below this header."; echo "//"; cat "$ROOT/fuzz/tron-tvm/FvTronTvmDriver.java"; } > "$V/a/fuzz/FvTronTvmDriver.java"
"$ROOT/fuzz/check_vendored.sh" "$V/a/fuzz" > "$V/untampered.json" 2>/dev/null; rc0=$?
cp -r "$V/a" "$V/b"; cp -r "$F" "$V/c"; cp "$ROOT/fuzz/tron-tvm/fv_tron_tvm.py" "$V/c/fuzz/fv_tvm.py"
"$ROOT/fuzz/check_vendored.sh" "$V/c/fuzz" > "$V/oldname.json" 2>/dev/null; rcc=$?
sed -i 's|        kind = {"SUCCESS": "success", "REVERT": "revert"}.get(code, "halt " + code)|        kind = "success"  # tampered|' "$V/a/fuzz/fv_tron_tvm.py"
sed -i 's|      if (relevant \&\& mt.getParameterCount() == 1|      if (false \&\& relevant \&\& mt.getParameterCount() == 1|' "$V/b/fuzz/FvTronTvmDriver.java"
{ grep -q tampered "$V/a/fuzz/fv_tron_tvm.py" && grep -q 'if (false' "$V/b/fuzz/FvTronTvmDriver.java"; } || echo "c37 setup: tamper lines not found" >&2
for x in a b; do
  "$ROOT/fuzz/run_fuzz.sh" --lang tron-tvm --lean-project "$F/lean" --lock "$ROOT/locks/token-faucet.sha256" --cmake-dir "$V/$x/fuzz" \
    --target diff_faucet --impl-dir "$F/contract" --no-merge --time 10 --out "$V/run-$x" > /dev/null 2>&1; echo $? > "$V/rc-$x"
done
if [ -n "$tid" ] && [ -n "$did" ] && [ $rc0 -eq 0 ] && [ "$(cat "$V/rc-a")" = 1 ] && jq -e '.detail | contains("fv_tron_tvm.py")' "$V/run-a/fuzz.json" > /dev/null \
   && [ "$(cat "$V/rc-b")" = 1 ] && jq -e '.detail | contains("FvTronTvmDriver.java")' "$V/run-b/fuzz.json" > /dev/null \
   && [ ! -d "$V/run-a/tron-tvm/drv" ] && [ ! -d "$V/run-b/tron-tvm/drv" ] \
   && [ $rcc -eq 1 ] && jq -e '."fv_tvm.py".match == false' "$V/oldname.json" > /dev/null; then
  echo "c37_tron_tvm_vendored_tamper OK untampered vendored client and driver pass; tampered client (outcomes as success): FAIL before build; tampered driver (profile check off): FAIL before build; a copy under the old name fv_tvm.py: refused"
else
  echo "c37_tron_tvm_vendored_tamper WRONG oldname=$rcc pins=${tid:-none}/${did:-none} untampered=$rc0 client=$(cat "$V/rc-a") [$(jq -r .detail "$V/run-a/fuzz.json" 2>/dev/null)] driver=$(cat "$V/rc-b") [$(jq -r .detail "$V/run-b/fuzz.json" 2>/dev/null)]"; fails=1
fi
# c56: the profile read-back, on a driver with one parameter applied wrong.
R56="${OUT:?}/c56"; fresh "$R56"; cp "$ROOT/fuzz/tron-tvm/FvTronTvmDriver.java" "$R56/FvTronTvmDriver.java"
python3 -I - "$R56/FvTronTvmDriver.java" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
a = "        one.put(codes.get(pname), v);"
assert s.count(a) == 1, "c56 setup: proposal value line not found"
open(p, "w").write(s.replace(a, '        one.put(codes.get(pname), "getEnergyFee".equals(key) ? v + 1 : v);  // c56: applied wrong'))
PY
tron_tvm_driver "$R56" "$R56/FvTronTvmDriver.java"; mkdir -p "$R56/db"
r56=$(echo quit | FV_TEST_PROFILE="$MAINNET" capped bwrap --dev-bind / / --unshare-net -- "$R56/driver.sh" "$R56/db" 2>/dev/null | head -1)
if [[ "$r56" == "error "*"does not round-trip"*"getEnergyFee = "* ]]; then
  echo "c56_tron_tvm_roundtrip OK energy fee applied +1: driver refuses: $(grep -oE 'getEnergyFee = [0-9]+, profile [0-9]+' <<< "$r56")"
else
  echo "c56_tron_tvm_roundtrip WRONG driver answered [${r56:0:160}] (javac: $(tail -1 "$R56/javac.log" 2>/dev/null | cut -c1-80))"; fails=1
fi
# c57: the executed build's pins, through run_fuzz.sh on copies of the harness.
R="${OUT:?}/c57"; fresh "$R"; r57=""
djf() { jq -r .detail "$R/$1/run/fuzz.json" 2>/dev/null; }  # the whole detail (sha256 values make it long)
Z=0000000000000000000000000000000000000000000000000000000000000000
H=$(hx unset); sed -i '/^FV_TRON_TVM_CLASSPATH_SHA256=/d' "$H/config/pins.env"; rf "$H" a --cmake-dir "$F/fuzz" --no-merge --time 10; ra=$?
H=$(hx cp); sed -i "s/^FV_TRON_TVM_CLASSPATH_SHA256=.*/FV_TRON_TVM_CLASSPATH_SHA256=\"$Z\"/" "$H/config/pins.env"; rf "$H" b --cmake-dir "$F/fuzz" --no-merge --time 10; rb=$?
H=$(hx jdk); sed -i "s/^FV_TRON_TVM_JDK_TREE_SHA256=.*/FV_TRON_TVM_JDK_TREE_SHA256=\"$Z\"/" "$H/config/pins.env"; rf "$H" c --cmake-dir "$F/fuzz" --no-merge --time 10; rc_=$?
H=$(hx node); sed -i "s/^FV_TRON_TVM_NODE_CONFIG_SHA256=.*/FV_TRON_TVM_NODE_CONFIG_SHA256=\"$Z\"/" "$H/config/pins.env"; rf "$H" d --cmake-dir "$F/fuzz" --no-merge --time 10; rd=$?
TH57="$R/th"; mkdir -p "$TH57"; for e in "$TH"/*; do [ "$(basename "$e")" = framework-test-classpath.txt ] || ln -s "$e" "$TH57/"; done
cp "$TH/framework-test-classpath.txt" "$TH57/"
FV_TRON_TVM_HOME="$TH57" rf "$ROOT" e --cmake-dir "$F/fuzz" --no-merge --time 10; re_=$?
FV_TVM_HOME=/nonexistent rf "$ROOT" f --cmake-dir "$F/fuzz" --no-merge --time 10; rf_=$?
[ $ra -eq 3 ] && [[ "$(djf a)" == "FV_TRON_TVM_CLASSPATH_SHA256 is not set"* ]] || r57+="(a) exit=$ra [$(djf a)] "
[ $rb -eq 3 ] && [[ "$(djf b)" == "the TRON-TVM executor's classpath"*"is not the pinned build"* ]] || r57+="(b) exit=$rb [$(djf b)] "
[ $rc_ -eq 3 ] && [[ "$(djf c)" == "the JDK tree at"*"is not the pinned one"* ]] || r57+="(c) exit=$rc_ [$(djf c)] "
[ $rd -eq 3 ] && [[ "$(djf d)" == "the node config (config-test.conf) differs"* ]] || r57+="(d) exit=$rd [$(djf d)] "
[ $re_ -eq 3 ] && [[ "$(djf e)" == "TRON-TVM classpath entries outside"* ]] || r57+="(e) exit=$re_ [$(djf e)] "
[ $rf_ -eq 3 ] && [[ "$(djf f)" == "old variable name(s) set: FV_TVM_HOME"* ]] || r57+="(f) exit=$rf_ [$(djf f)] "
if [ -z "$r57" ]; then
  echo "c57_tron_tvm_build_pins OK each ERROR: pin unset, classpath manifest, JDK tree, node config (observed), classpath outside the home, old FV_TVM_HOME"
else
  echo "c57_tron_tvm_build_pins WRONG $r57"; fails=1
fi
# c64: the tron-tvm record and CLOSE checks.
R="${OUT:?}/c64"; fresh "$R"; r64=""
inject() { # inject NAME JQ-OR-NULL: a harness copy whose run replaces the observed record before the verdict
  local h; h=$(hx "$1"); python3 -I - "$h/fuzz/run_fuzz.sh" "$2" <<'PY'
import sys
p, what = sys.argv[1], sys.argv[2]; s = open(p).read()
a = "processes: {driver_starts: $n, with_transactions: $k}}' <<< \"$EVM_JSON\")\n"
assert s.count(a) == 1, "c64 setup: record line not found"
new = "EVM_JSON=null\n" if what == "null" else "EVM_JSON=$(jq -c '" + what + "' <<< \"$EVM_JSON\")\n"
open(p, "w").write(s.replace(a, a + new))
PY
  echo "$h"; }
H=$(inject zero '.processes.with_transactions = 0'); rf "$H" a --cmake-dir "$F/fuzz" --no-merge --runs 200 --time 600; ra=$?
H=$(inject null null); rf "$H" b --cmake-dir "$F/fuzz" --no-merge --runs 200 --time 600; rb=$?
for x in a b; do
  [ "$(eval echo \$r$x)" -eq 3 ] && [ "$(jq -r .verdict "$R/$x/run/fuzz.json" 2>/dev/null)" = ERROR ] \
    && grep -q 'intended verdict was PASS' "$R/$x/out" || r64+="($x) exit=$(eval echo \$r$x) [$(jq -r .detail "$R/$x/run/fuzz.json" 2>/dev/null | cut -c1-80)] "
done
J34="$OUT/c34_tron_tvm_clean/run/fuzz.json"
FT=(python3 -I "$ROOT/scripts/formal_task.py"); T64="c64-$$"
cp -r "$F/lean" "$R/lean"; rm -rf "${R:?}/lean/.lake"
"${FT[@]}" init "$T64" --project "$R/lean" --lock "$ROOT/locks/token-faucet.sha256" --cmake-dir "$F/fuzz" --target diff_faucet \
  --lang tron-tvm --fuzz-runs 1000 > "$R/task.out" 2>&1
mkdir -p "$R/audit"; echo '{"verdict": "PASS", "stages": {}}' > "$R/audit/verdict.json"
for x in c d; do
  mkdir -p "$R/couple-$x"
  if [ $x = c ]; then jq '.tron_tvm = null' "$J34" > "$R/couple-$x/fuzz.json"; else jq '.tron_tvm.processes.with_transactions = 0' "$J34" > "$R/couple-$x/fuzz.json"; fi
  mkdir -p "$FV_ROOT/tasks/$T64-$x"
  jq --arg a "$R/audit" --arg c "$R/couple-$x" --arg t "$T64-$x" '.task = $t | .state = "CLOSE" | .last_audit = $a | .last_couple = $c' \
    "$FV_ROOT/tasks/$T64/state.json" > "$FV_ROOT/tasks/$T64-$x/state.json"
  "${FT[@]}" close "$T64-$x" >> "$R/task.out" 2>&1; rc=$?
  st=$(jq -r .state "$FV_ROOT/tasks/$T64-$x/state.json"); why=$(jq -r '.history[-1].reason // .history[-1].note // ""' "$FV_ROOT/tasks/$T64-$x/state.json")
  cl=$([ -e "$FV_ROOT/tasks/$T64-$x/closure.json" ] && echo yes || echo no)
  [ $rc -eq 3 ] && [ "$st" = ERROR ] && [ "$cl" = no ] && grep -q "TRON-TVM fuzz record lacks" "$FV_ROOT/tasks/$T64-$x/state.json" \
    || r64+="($x) close rc=$rc state=$st closure=$cl [${why:0:80}] "
  cp -r "$FV_ROOT/tasks/$T64-$x" "$R/" 2>/dev/null
done
cp -r "$FV_ROOT/tasks/$T64" "$R/" 2>/dev/null; rm -rf "${FV_ROOT:?}/tasks/$T64" "${FV_ROOT:?}/tasks/$T64-c" "${FV_ROOT:?}/tasks/$T64-d"
if [ -z "$r64" ] && [ -f "$J34" ]; then
  echo "c64_tron_tvm_record OK record with_transactions 0: ERROR; no tron_tvm record: ERROR; CLOSE on c34's record with tron_tvm null and with with_transactions 0: ERROR \"lacks ...\", no closure"
else
  echo "c64_tron_tvm_record WRONG ${r64:-c34 record missing ($J34)}"; fails=1
fi
tron_tvm_campaign c49_tron_tvm_itx_drop "$F" contract --runs 24000 --time 1800 --impl-dir "$ROOT/tests/harness_fv_controls/tron-tvm/contract-itx-drop"
rc=$?; j="$OUT/c49_tron_tvm_itx_drop/run/fuzz.json"
if [ $rc -eq 1 ] && jq -e '.verdict == "FAIL" and (.detail | contains("oracle/implementation mismatch"))' "$j" > /dev/null \
   && grep -A8 'diff-oracle: MISMATCH' "$OUT/c49_tron_tvm_itx_drop/run/campaign.log" | grep -q 'itx\[call'; then
  echo "c49_tron_tvm_itx_drop OK FAIL: withdraw(0) without its internal transfer is a mismatch ($(grep -m1 -A8 'diff-oracle: MISMATCH' "$OUT/c49_tron_tvm_itx_drop/run/campaign.log" | grep -m1 -oE 'withdraw[^|]{0,60}'))"
else
  echo "c49_tron_tvm_itx_drop WRONG exit=$rc $(jq -c '{verdict, detail}' "$j" 2>/dev/null)"; fails=1
fi
tron_tvm_campaign c51_tron_tvm_guidance "$F" contract --runs 3000
rc=$?; j="$OUT/c51_tron_tvm_guidance/run/fuzz.json"; nu=$(jq -r '.stats' "$j" 2>/dev/null | grep -oE 'new_units_added: *[0-9]+' | grep -oE '[0-9]+$')
if [ $rc -eq 0 ] && [ "${nu:-0}" -gt 0 ] && grep -q 'binding function(s) instrumented for coverage guidance' "$OUT/c51_tron_tvm_guidance/run/campaign.log"; then
  echo "c51_tron_tvm_guidance OK the binding is instrumented ($(grep -m1 -oE '[0-9]+ binding function\(s\) instrumented' "$OUT/c51_tron_tvm_guidance/run/campaign.log")): $nu new corpus units within 3,000 executions"
else
  echo "c51_tron_tvm_guidance WRONG exit=$rc new_units_added=${nu:-?} $(jq -c '{verdict, detail}' "$j" 2>/dev/null)"; fails=1
fi
tron_tvm_campaign c41_tron_tvm_coverage "$F" contract --time 120 --impl-dir "$ROOT/tests/harness_fv_controls/tron-tvm/contract-unreachable"
rc=$?; j="$OUT/c41_tron_tvm_coverage/run/fuzz.json"
ln=$(grep -n 'note = amount' "$ROOT/tests/harness_fv_controls/tron-tvm/contract-unreachable/CappedFaucet.sol" | cut -d: -f1)
if [ $rc -eq 0 ] && jq -e --arg w "CappedFaucet.sol:$ln " '.verdict == "PASS" and .tron_tvm.contract_coverage.blocks_hit > 0
     and ([.tron_tvm.contract_coverage.not_exercised[].at | select(. != null and startswith($w))] | length) >= 1' "$j" > /dev/null; then
  echo "c41_tron_tvm_coverage OK PASS; $(jq -r '.tron_tvm.contract_coverage | "\(.blocks_hit)/\(.blocks_total) blocks"' "$j"); NOT EXERCISED includes the unreachable branch at line $ln: $(jq -r --arg w "CappedFaucet.sol:$ln " '[.tron_tvm.contract_coverage.not_exercised[] | select(.at != null and (.at | startswith($w)))][0].at' "$j")"
else
  echo "c41_tron_tvm_coverage WRONG exit=$rc $(jq -c '{verdict, detail, cov: (.tron_tvm.contract_coverage | {blocks_hit, blocks_total, error})}' "$j" 2>/dev/null)"; fails=1
fi

# Control 109: the driver checks run again after the retention replay and after the merge. The test hook
# FV_TEST_HOOK_REPLAY_STATUS forges, after that replay only, the observation a driver seeing another network
# interface would write. (a) no hook: PASS (the hook is inert when unset); (b) after the retention replay and
# (c) after the merge: ERROR, a run seen as having had a network; (d) a phase that never happens: PASS, and
# the hook is recorded (test_hooks), so CLOSE refuses the run.
r109=""
tron_tvm_campaign c109a_no_hook "$F" contract --runs 2000 --time 1800; ra=$?
jq -e '.verdict == "PASS" and .test_hooks == []' "$OUT/c109a_no_hook/run/fuzz.json" > /dev/null && [ $ra -eq 0 ] \
  || r109+="(a) exit=$ra [$(jq -c '{verdict, detail, test_hooks}' "$OUT/c109a_no_hook/run/fuzz.json" 2>/dev/null | cut -c1-120)]; "
for k in "b retention 0" "c merge 1"; do
  set -- $k
  FV_TEST_HOOK_REPLAY_STATUS="$2" TRON_TVM_MERGE="$3" tron_tvm_campaign "c109${1}_$2" "$F" contract --runs 2000 --time 1800; rc=$?
  jq -e '.verdict == "ERROR" and (.detail | contains("network interfaces other than lo")) and .test_hooks == ["FV_TEST_HOOK_REPLAY_STATUS"]' \
    "$OUT/c109${1}_$2/run/fuzz.json" > /dev/null && [ $rc -eq 3 ] \
    || r109+="($1) exit=$rc [$(jq -c '{verdict, detail, test_hooks}' "$OUT/c109${1}_$2/run/fuzz.json" 2>/dev/null | cut -c1-160)]; "
done
FV_TEST_HOOK_REPLAY_STATUS=never tron_tvm_campaign c109d_inert "$F" contract --runs 2000 --time 1800; rd=$?
jq -e '.verdict == "PASS" and .test_hooks == ["FV_TEST_HOOK_REPLAY_STATUS"]' "$OUT/c109d_inert/run/fuzz.json" > /dev/null && [ $rd -eq 0 ] \
  && ! grep -q '"test_hook"' "$OUT/c109d_inert/run/tron-tvm/status.jsonl" || r109+="(d) exit=$rd [$(jq -c '{verdict, test_hooks}' "$OUT/c109d_inert/run/fuzz.json" 2>/dev/null)]; "
if [ -z "$r109" ]; then
  echo "c109_tron_tvm_replay_drivers OK (a) no hook: PASS; (b) a forged observation after the retention replay, (c) after the merge: ERROR [$(jq -r '.detail | .[0:70]' "$OUT/c109b_retention/run/fuzz.json")]; (d) hook set to a phase that never happens: PASS, nothing forged, recorded in test_hooks"
else
  echo "c109_tron_tvm_replay_drivers WRONG $r109"; fails=1
fi
fi  # tron-tvm
exit $fails
