#!/usr/bin/env bash
# run_classify_controls.sh OUTDIR — controls for the edge-case classifier beyond C++ (labels only;
# fuzz/python/fv_classify.py, fuzz/python/fv_sink.py, fuzz/rust/fv_diff.rs Sink / fv_class!,
# fuzz/classify_report.py). Each runs the risk-limit (or faucet) example's signed spec through
# fuzz/run_fuzz.sh --lang.
#
#   c68_gap_rust, c69_gap_py, c70_gap_evm, c71_gap_tron_tvm
#                      the example with its generator restricted to quantities below 2^32 and the correct
#                      implementation: verdict PASS; the classifier reports the gap: NOT EXERCISED lists
#                      "domain: q at or above 2^32" and "generic: q = max", while at least one domain class is
#                      exercised (the report is not vacuous); fuzz.json records the classes file, its sha256
#                      (equal to the file's), the sha256 of the predicate sources, and each domain class's
#                      source; no classification error
#   c72_class_source_mismatch  the class predicates shown must be the ones that ran (classify_report.py on
#                      the c68/c69 replay logs): (a) Rust and (b) Python, a predicate edited after the run:
#                      error naming that class; (c) Rust and (d) Python, the file changed elsewhere (a
#                      comment): error naming the sha256; (e) a classes.py with classes built in a loop (no
#                      literal name and lambda, so no source to show): classes.error, verdict PASS; (f) on a FAIL
#                      run the reproducers are classified against the same checked sources, with no
#                      classification error (Rust drift)
#   c75_py_classify_isolation  the labels-only replay can neither weaken nor reach the verdict: (a) FV_CLASSIFY,
#                      FV_CLASSIFY_RENDER and FV_CLASSIFY_TIME_IMPL exported, the drift implementation still
#                      FAILs as a mismatch, and its reproducer is classified against the same sources with no
#                      classification error; (b) a classes.py that raises at import: the clean run PASSes with
#                      classes.error naming it, the drift run still FAILs; (c) the verdict wrapper and
#                      fv_diff.py name neither fv_classify.py, fv_sink nor FV_CLASSIFY; (d) the replay never
#                      imports the implementation (an implementation that records each import: none from
#                      fv_classify.py); (e) TRON-TVM: a describe() that sends a transaction: classes.error
#                      "sent ... transaction", verdict PASS, and the run's TRON-TVM record counts only the
#                      verdict processes; (f) a describe() that raises mid-replay: PASS, and classes.error
#                      says the classification replay stopped (never a silent partial classification)
#   c73_retention_keeps  the class-guided retention pass (fuzz/run_fuzz.sh 4b) on the clean C++ fixture and
#                      the clean Python example: PASS; the record says seed 1, 200000 executions budgeted and
#                      done, complete; the retained files are exactly the recorded hashes, each replayed by the
#                      verdict binary (retain-replay.log, no classify line); at least one class is hit only by a
#                      retained input and is therefore not NOT EXERCISED; the deck's heading names the retention
#   c74_retention_replay_fails  a Python implementation wrong exactly on "reduce more than the position", seeded
#                      only with the empty input and a 1-execution campaign (which never reaches that class):
#                      the retention pass keeps an input of the class and the verdict binary's replay FAILs
#                      ("retention replay ... oracle/implementation mismatch"), reproducer kept. Run three times:
#                      the same retained set and the same reproducer each time (the pass is deterministic)
#
# Prints one "ID RESULT DETAIL" line per control; SKIP when a toolchain is missing (WRONG when the language
# is in FV_REQUIRE_LANGS). Exit 0 iff none is WRONG.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT/scripts/lib.sh"
OUT="$1"; mkdir -p "$OUT"
LOCK="$ROOT/locks/risk-limit.sha256"; LEAN="$ROOT/examples/risk-limit/lean"
fails=0
GAP_D="domain: q at or above 2^32"; GAP_G="generic: q = max"

fresh() { rm -rf "${1:?}"; mkdir -p "$1"; }
campaign() { # campaign ID LANG EXAMPLE_COPY IMPL TARGET LOCK LEAN ARGS...
  local id="$1" lang="$2" dir="$3" impl="$4" target="$5" lock="$6" lean="$7"; shift 7
  fresh "$OUT/$id"
  cp -r "$lean" "$OUT/$id/lean"; rm -rf "${OUT:?}/${id:?}/lean/.lake"; cp -r "$dir/fuzz/corpus" "$OUT/$id/corpus"
  "$ROOT/fuzz/run_fuzz.sh" --lang "$lang" --lean-project "$OUT/$id/lean" --lock "$lock" --cmake-dir "$dir/fuzz" \
    --target "$target" --impl-dir "$dir/$impl" --corpus "$OUT/$id/corpus" --no-merge --out "$OUT/$id/run" "$@" \
    > "$OUT/$id/run_fuzz.out" 2>&1
}
copy_example() { fresh "$2"; cp -r "$1/." "$2/"; rm -rf "$2/fuzz/target"; }  # copy_example SRC DST
absent() { # absent LANG WHERE CONTROLS...
  local lang="$1" where="$2"; shift 2
  if [[ " ${FV_REQUIRE_LANGS:-} " == *" $lang "* ]]; then
    for c in "$@"; do echo "$c WRONG required language $lang (FV_REQUIRE_LANGS) but no toolchain at $where"; done; fails=1
  else
    for c in "$@"; do echo "$c SKIP $lang toolchain not installed ($where; docs/LANGUAGES.md)"; done
  fi
}
gap_check() { # gap_check ID CLASSES_FILE EXIT
  local id="$1" cf="$2" j="$OUT/$1/run/fuzz.json" rc="$3"
  local sha; sha=$(sha256sum < "$cf" | cut -d' ' -f1)
  if [ "$rc" -eq 0 ] && jq -e --arg d "$GAP_D" --arg g "$GAP_G" --arg s "$sha" '
       .verdict == "PASS" and .classes.labels_only and (.classes.error == null)
       and (.classes.not_exercised | index($d) and index($g))
       and ([.classes.classes[] | select(.kind == "domain" and .inputs > 0)] | length >= 1)
       and .classes.classes_file_sha256 == $s and (.classes.classes_source_sha256 | test("^[0-9a-f]{64}$"))
       and ([.classes.classes[] | select(.kind == "domain" and ((.source // "") == ""))] | length == 0)' "$j" > /dev/null; then
    echo "$id OK PASS; NOT EXERCISED includes [$GAP_D] and [$GAP_G]; exercised: $(jq -r '[.classes.classes[] | select(.kind == "domain" and .inputs > 0) | "[\(.class)] \(.inputs)"] | join(", ")' "$j"); $(jq -r '"\(.classes.classes_file | split("/") | last) sha256 \(.classes.classes_file_sha256[0:12]) (= file), sources sha256 \(.classes.classes_source_sha256[0:12]), \(.classes.inputs) inputs"' "$j")"
  else
    echo "$id WRONG exit=$rc $(jq -c '{verdict, detail, err: .classes.error, ne: .classes.not_exercised, f: .classes.classes_file_sha256, s: .classes.classes_source_sha256}' "$j" 2>/dev/null | cut -c1-600) file_sha=${sha:0:12}"; fails=1
  fi
}
report_err() { # report_err ID_DIR CLASSES_FILE [SHA_AT_BUILD] -> classes.error from classify_report.py on that run's log
  local r="$1/run" b; b=$(ls "$r"/classify-* "$r"/cargo-target-classify/x86_64-unknown-linux-gnu/release/diff_risk 2>/dev/null | head -1)
  python3 -I "$ROOT/fuzz/classify_report.py" --log "$r/classify/log.jsonl" --bin "$b" --out "$(mktemp -d "$OUT/rep.XXXX")" \
    --classes-file "$2" ${3:+--classes-file-sha256 "$3"} 2>/dev/null | jq -r '.error // "none"'
}

R="$ROOT/examples/risk-limit-rust"; P="$ROOT/examples/risk-limit-py"; E="$ROOT/examples/risk-limit-evm"
F="$ROOT/examples/token-faucet-tron-tvm"
have_rust=0; [ -x "${FV_RUST_HOME:-$FV_ROOT/rust}/cargo/bin/cargo-fuzz" ] && have_rust=1
PY="${FV_PY:-$FV_ROOT/py/venv/bin/python}"; have_py=0; { [ -x "$PY" ] && "$PY" -I -c 'import atheris' 2>/dev/null; } && have_py=1
have_evm=0; [ "$have_rust" = 1 ] && [ -x "${FV_SOLC:-$FV_ROOT/evm/solc-$FV_SOLC_VERSION}" ] && have_evm=1
TH="${FV_TRON_TVM_HOME:-$FV_ROOT/tron-tvm}"; have_tron=0
[ "$have_py" = 1 ] && [ -x "$TH/$FV_TRON_TVM_JDK/bin/java" ] && [ -f "$TH/framework-test-classpath.txt" ] && have_tron=1

# --- c68: Rust ---
if [ "$have_rust" = 1 ]; then
  X="$OUT/ex68"; copy_example "$R" "$X"
  sed -i 's|((inp.byte() % 4) as u64, inp.pick_u64())|((inp.byte() % 4) as u64, inp.pick_u64() \& 0xFFFF_FFFF) // c68: q < 2^32|' "$X/fuzz/fuzz_targets/diff_risk.rs"
  grep -q 'c68: q < 2^32' "$X/fuzz/fuzz_targets/diff_risk.rs" || echo "c68 setup: generator line not found" >&2
  campaign c68_gap_rust rust "$X" impl diff_risk "$LOCK" "$LEAN" --runs 20000
  gap_check c68_gap_rust "$X/fuzz/fuzz_targets/diff_risk.rs" $?
else absent rust "${FV_RUST_HOME:-$FV_ROOT/rust}" c68_gap_rust; fi

# --- c69: Python ---
if [ "$have_py" = 1 ]; then
  X="$OUT/ex69"; copy_example "$P" "$X"
  sed -i 's|    return (inp.byte() % 4, inp.pick_u64())|    return (inp.byte() % 4, inp.pick_u64() \& 0xFFFFFFFF)  # c69: q < 2^32|' "$X/fuzz/binding.py"
  grep -q 'c69: q < 2^32' "$X/fuzz/binding.py" || echo "c69 setup: generator line not found" >&2
  campaign c69_gap_py python "$X" impl diff_risk "$LOCK" "$LEAN" --runs 20000
  gap_check c69_gap_py "$X/fuzz/classes.py" $?
else absent python "$PY" c69_gap_py; fi

# --- c70: EVM ---
if [ "$have_evm" = 1 ]; then
  X="$OUT/ex70"; copy_example "$E" "$X"
  cp "$ROOT/tests/harness_fv_controls/variants/c70_evm_gap/diff_risk.rs" "$X/fuzz/fuzz_targets/diff_risk.rs"
  campaign c70_gap_evm evm "$X" contract diff_risk "$LOCK" "$LEAN" --runs 20000
  gap_check c70_gap_evm "$X/fuzz/fuzz_targets/diff_risk.rs" $?
else absent evm "${FV_SOLC:-$FV_ROOT/evm/solc-$FV_SOLC_VERSION}" c70_gap_evm; fi

# --- c71: TRON-TVM ---
if [ "$have_tron" = 1 ]; then
  X="$OUT/ex71"; copy_example "$F" "$X"
  sed -i 's|    return (inp.byte() % 4, inp.pick_u64())|    return (inp.byte() % 4, inp.pick_u64() \& 0xFFFFFFFF)  # c71: q < 2^32|' "$X/fuzz/binding.py"
  grep -q 'c71: q < 2^32' "$X/fuzz/binding.py" || echo "c71 setup: generator line not found" >&2
  campaign c71_gap_tron_tvm tron-tvm "$X" contract diff_faucet "$ROOT/locks/token-faucet.sha256" "$F/lean" --runs 3000 --time 1800
  gap_check c71_gap_tron_tvm "$X/fuzz/classes.py" $?
else absent tron-tvm "$TH" c71_gap_tron_tvm; fi

# --- c72: class sources must be the ones that ran ---
if [ "$have_rust" = 1 ] && [ "$have_py" = 1 ] && [ -s "$OUT/c68_gap_rust/run/classify/log.jsonl" ] && [ -s "$OUT/c69_gap_py/run/classify/log.jsonl" ]; then
  T="$OUT/c72"; fresh "$T"
  rs="$OUT/ex68/fuzz/fuzz_targets/diff_risk.rs"; rs_sha=$(sha256sum < "$rs" | cut -d' ' -f1)
  cp "$rs" "$T/a.rs"; sed -i 's|op.1 >= 1 << 32)|op.1 >= 1 << 33)|' "$T/a.rs"
  cp "$rs" "$T/c.rs"; echo "// c72: a comment, nothing else" >> "$T/c.rs"
  cp "$OUT/ex69/fuzz/classes.py" "$T/b.py"; sed -i 's|op\[1\] >= 1 << 32)|op[1] >= 1 << 33)|' "$T/b.py"
  cp "$OUT/ex69/fuzz/classes.py" "$T/d.py"; echo "# c72: a comment, nothing else" >> "$T/d.py"
  ea=$(report_err "$OUT/c68_gap_rust" "$T/a.rs" "$rs_sha"); eb=$(report_err "$OUT/c69_gap_py" "$T/b.py")
  ec=$(report_err "$OUT/c68_gap_rust" "$T/c.rs" "$rs_sha"); ed=$(report_err "$OUT/c69_gap_py" "$T/d.py")
  e0=$(report_err "$OUT/c68_gap_rust" "$rs" "$rs_sha"); e1=$(report_err "$OUT/c69_gap_py" "$OUT/ex69/fuzz/classes.py")
  campaign c72f_rust_fail rust "$OUT/ex68" impl-drift diff_risk "$LOCK" "$LEAN" --runs 32000 --time 900; rcf72=$?
  jf72="$OUT/c72f_rust_fail/run/fuzz.json"
  X="$OUT/ex72"; copy_example "$P" "$X"
  cat >> "$X/fuzz/classes.py" <<'PYEOF'

# c72 (e): classes built in a loop have no literal source
CLASSES = CLASSES + [fv_class(f"q = {v}", (lambda v: lambda before, op, after: op[1] == v)(v)) for v in (7, 8)]
PYEOF
  campaign c72e_loop_classes python "$X" impl diff_risk "$LOCK" "$LEAN" --runs 2000
  rce=$?; je="$OUT/c72e_loop_classes/run/fuzz.json"
  if [[ "$ea" == *"differ from what ran"*"q at or above 2^32"* ]] && [[ "$eb" == *"differ from what ran"*"q at or above 2^32"* ]] \
     && [[ "$ec" == *"sha256"* ]] && [[ "$ed" == *"sha256"* ]] && [ "$e0" = none ] && [ "$e1" = none ] \
     && [ $rce -eq 0 ] && jq -e '.verdict == "PASS" and (.classes.error // "" | contains("a string name and a lambda"))' "$je" > /dev/null \
     && [ $rcf72 -eq 1 ] && jq -e '.classes.error == null and (.classes.finding_classes | length) >= 1' "$jf72" > /dev/null; then
    echo "c72_class_source_mismatch OK unchanged files: no error; (a) rust: ${ea:0:150}; (b) py: ${eb:0:110}; (c) ${ec:0:120}; (d) ${ed:0:100}; (e) PASS, $(jq -r '.classes.error | .[0:110]' "$je"); (f) a Rust FAIL: its reproducers classified, no error"
  else
    echo "c72_class_source_mismatch WRONG unchanged=[$e0|$e1] a=[$ea] b=[$eb] c=[$ec] d=[$ed] e: exit=$rce $(jq -c '{verdict, err: .classes.error}' "$je" 2>/dev/null) f: exit=$rcf72 [$(jq -r '.classes.error // "none"' "$jf72" 2>/dev/null | cut -c1-80)]"; fails=1
  fi
else
  echo "c72_class_source_mismatch $([ "$have_rust$have_py" = 11 ] && echo "WRONG c68/c69 left no classify log" || echo "SKIP needs the rust and python toolchains")"
  [ "$have_rust$have_py" = 11 ] && fails=1
fi

# --- c75: the labels-only replay cannot weaken or reach the verdict ---
if [ "$have_py" = 1 ]; then
  ( export FV_CLASSIFY="$OUT/c75-inherited.jsonl" FV_CLASSIFY_RENDER=1 FV_CLASSIFY_TIME_IMPL=1
    campaign c75a_env python "$P" impl-drift diff_risk "$LOCK" "$LEAN" --runs 130000 --time 1200 )
  rca=$?; ja="$OUT/c75a_env/run/fuzz.json"
  X="$OUT/ex75b"; copy_example "$P" "$X"; printf 'raise RuntimeError("c75: classes.py raises at import")\n' > "$X/fuzz/classes.py"
  cp -r "$P/impl-drift" "$X/impl-drift"
  campaign c75b_raise python "$X" impl diff_risk "$LOCK" "$LEAN" --runs 2000; rcb=$?; jb="$OUT/c75b_raise/run/fuzz.json"
  campaign c75b_raise_drift python "$X" impl-drift diff_risk "$LOCK" "$LEAN" --runs 130000 --time 1200; rcb2=$?; jb2="$OUT/c75b_raise_drift/run/fuzz.json"
  W="$OUT/c75b_raise/run/fuzz-diff_risk"
  leak=$(grep -lE 'fv_classify|fv_sink|FV_CLASSIFY|classes\.py' "$W" "$ROOT/fuzz/python/fv_diff.py" 2>/dev/null | tr '\n' ' ')
  X="$OUT/ex75d"; copy_example "$P" "$X"; M="$OUT/c75d-imports.log"; : > "$M"
  { printf 'import sys as _s\nopen(%s, "a").write(_s.argv[0] + "\\n")\n' "'$M'"; cat "$P/impl/risk.py"; } > "$X/impl/risk.py"
  campaign c75d_imports python "$X" impl diff_risk "$LOCK" "$LEAN" --runs 2000; rcd=$?; jd="$OUT/c75d_imports/run/fuzz.json"
  n_v=$(grep -c 'fv_diff.py\|fuzz-diff_risk' "$M"); n_c=$(grep -c 'fv_classify' "$M")
  X="$OUT/ex75f"; copy_example "$P" "$X"
  cat >> "$X/fuzz/classes.py" <<'PYEOF'

_describe = describe


def describe(k, before, op, after):  # c75 (f): raises on some steps, mid-replay
    if op[0] % 4 == 3:
        raise ZeroDivisionError("c75: describe raises on reduce")
    _describe(k, before, op, after)
PYEOF
  # a seed with one reduce step (limit 0, pos 0, open 0; one step, the operation repeated: reduce q=0), so the
  # corpus replay itself reaches the raise, not only the retention generation
  printf '\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1\3\0\0' > "$X/fuzz/corpus/c75f-reduce"
  campaign c75f_describe_raises python "$X" impl diff_risk "$LOCK" "$LEAN" --runs 2000; rcf=$?; jf="$OUT/c75f_describe_raises/run/fuzz.json"
  te="SKIP"
  if [ "$have_tron" = 1 ]; then
    X="$OUT/ex75e"; copy_example "$F" "$X"
    cat >> "$X/fuzz/classes.py" <<'PYEOF'

import fv_tron_tvm as _t
_describe = describe
_USER = bytes.fromhex("41" + "bb" * 19 + "02")  # the binding's recipient account


def describe(k, before, op, after):  # c75 (e): sends a transaction from the labels-only replay
    _t.get().call(_USER, _t.calldata("dispense(address)", [_t.addr_word(_USER)]))
    _describe(k, before, op, after)
PYEOF
    campaign c75e_tron_tx tron-tvm "$X" contract diff_faucet "$ROOT/locks/token-faucet.sha256" "$F/lean" --runs 300 --time 900
    rce=$?; je="$OUT/c75e_tron_tx/run/fuzz.json"
    if [ $rce -eq 0 ] && jq -e '.verdict == "PASS" and (.classes.error // "" | contains("transaction")) and .tron_tvm.processes.with_transactions >= 1' "$je" > /dev/null; then
      te="ok: PASS, $(jq -r '.classes.error | .[0:100]' "$je"); driver_starts $(jq -r .tron_tvm.processes.driver_starts "$je")"
    else te="WRONG exit=$rce $(jq -c '{verdict, err: .classes.error, p: .tron_tvm.processes}' "$je" 2>/dev/null)"; fi
  fi
  if [ $rca -eq 1 ] && jq -e '(.detail | contains("oracle/implementation mismatch")) and .classes.error == null
       and (.classes.finding_classes | length) >= 1 and (.classes.classes_source_sha256 | test("^[0-9a-f]{64}$"))' "$ja" > /dev/null \
     && [ $rcb -eq 0 ] && jq -e '.verdict == "PASS" and (.classes.error // "" | contains("c75: classes.py raises"))' "$jb" > /dev/null \
     && [ $rcb2 -eq 1 ] && jq -e '.detail | contains("oracle/implementation mismatch")' "$jb2" > /dev/null \
     && [ $rcf -eq 0 ] && jq -e '.verdict == "PASS" and (.classes.error // "" | contains("classification replay exited") and contains("retention: the generation exited"))' "$jf" > /dev/null \
     && [ -z "$leak" ] && [ $rcd -eq 0 ] && [ "$n_v" -gt 0 ] && [ "$n_c" -eq 0 ] && [[ "$te" != WRONG* ]] \
     && { [ "$te" != SKIP ] || [[ " ${FV_REQUIRE_LANGS:-} " != *" tron-tvm "* ]]; }; then
    echo "c75_py_classify_isolation OK (a) env exported, drift still FAIL ($(jq -r .detail "$ja")), its reproducer classified with no error ($(jq -c '.classes.finding_classes | to_entries[0].value' "$ja" | cut -c1-60)); (b) raising classes.py: PASS with error [$(jq -r '.classes.error | .[0:70]' "$jb")], drift FAIL; (c) verdict wrapper/driver name no classify path; (d) implementation imported $n_v time(s) by the verdict path, 0 by the replay; (e) tron-tvm $te; (f) a describe() raising mid-replay: PASS, [$(jq -r '.classes.error | .[0:90]' "$jf")]"
  else
    echo "c75_py_classify_isolation WRONG a: exit=$rca [$(jq -r .detail "$ja" 2>/dev/null)] a-cls=[$(jq -r '.classes.error // "none"' "$ja" 2>/dev/null | cut -c1-80)] b: exit=$rcb [$(jq -c '{verdict, err: .classes.error}' "$jb" 2>/dev/null)] b2: exit=$rcb2 c: [$leak] d: exit=$rcd verdict=$n_v classify=$n_c e: $te f: exit=$rcf $(jq -c '{verdict, err: .classes.error}' "$jf" 2>/dev/null | cut -c1-200)"; fails=1
  fi
else absent python "$PY" c75_py_classify_isolation; fi

# --- c73: retention keeps a class the coverage corpus did not ---
retain_check() { # retain_check RUN_DIR -> "" if the retention record holds, else why not; prints the only-retained classes to fd 3
  local r="$1" j="$1/fuzz.json"
  jq -e '.classes.retention | .seed == 1 and .runs == 200000 and .executions == 200000 and .complete == true and .error == null
           and (.retained | length) > 0 and .replayed == (.retained | length)' "$j" > /dev/null || { echo "record: $(jq -c '.classes.retention | del(.retained)' "$j" 2>/dev/null)"; return; }
  [ "$(jq -r '.classes.retention.retained | join(" ")' "$j")" = "$(ls "$r/classify/retained" | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')" ] || { echo "retained files differ from the record"; return; }
  grep -q 'INITED' "$r/retain-replay.log" && ! grep -q 'CLASSIFY BUILD' "$r/retain-replay.log" || { echo "no verdict-binary replay of the retained inputs"; return; }
  grep -q 'corpus and class-guided retention' "$r/classify/review_deck.md" || { echo "deck heading"; return; }
  python3 -I - "$r/classify/log.jsonl" "$j" >&3 <<'PYEOF' || echo "no class hit only by a retained input, or one still NOT EXERCISED"
import json, sys
recs, j = {}, json.load(open(sys.argv[2]))
for line in open(sys.argv[1]):
    r = json.loads(line)
    if "h" in r:
        recs.setdefault(r["h"], r)
kept = set(j["classes"]["retention"]["retained"])
by_corpus = {c for h, r in recs.items() if h not in kept for c in r["hits"]}
only = sorted({c for h, r in recs.items() if h in kept for c in r["hits"]} - by_corpus)
ne = set(j["classes"]["not_exercised"])
print("; ".join(only[:4]) + (f" (+{len(only) - 4})" if len(only) > 4 else ""))
sys.exit(0 if only and not (set(only) & ne) else 1)
PYEOF
}
if [ "$have_py" = 1 ]; then
  fresh "$OUT/c73_cpp"; cp -r "$ROOT/fixtures/conservation_cpp/fuzz/corpus" "$OUT/c73_cpp/corpus"
  "$ROOT/fuzz/run_fuzz.sh" --lean-project "$ROOT/fixtures/conservation" --lock "$ROOT/locks/conservation.sha256" \
    --cmake-dir "$ROOT/fixtures/conservation_cpp/fuzz" --target diff_transfer --corpus "$OUT/c73_cpp/corpus" --no-merge \
    --out "$OUT/c73_cpp/run" --runs 20000 > "$OUT/c73_cpp/run_fuzz.out" 2>&1; rc1=$?
  w1=$(retain_check "$OUT/c73_cpp/run" 3> "$OUT/c73_cpp/only.txt")
  campaign c73_py python "$P" impl diff_risk "$LOCK" "$LEAN" --runs 20000; rc2=$?
  w2=$(retain_check "$OUT/c73_py/run" 3> "$OUT/c73_py/only.txt")
  if [ $rc1 -eq 0 ] && [ $rc2 -eq 0 ] && [ -z "$w1" ] && [ -z "$w2" ]; then
    echo "c73_retention_keeps OK C++: PASS, $(jq -r '.classes.retention | "\(.retained | length) kept, \(.replayed) replayed, seed \(.seed), \(.executions) executions"' "$OUT/c73_cpp/run/fuzz.json"); only via retention: $(cat "$OUT/c73_cpp/only.txt"). Python: PASS, $(jq -r '.classes.retention | "\(.retained | length) kept, \(.replayed) replayed"' "$OUT/c73_py/run/fuzz.json"); only via retention: $(cat "$OUT/c73_py/only.txt")"
  else
    echo "c73_retention_keeps WRONG C++ exit=$rc1 [$w1] $(jq -c '{verdict, detail}' "$OUT/c73_cpp/run/fuzz.json" 2>/dev/null); Python exit=$rc2 [$w2] $(jq -c '{verdict, detail}' "$OUT/c73_py/run/fuzz.json" 2>/dev/null)"; fails=1
  fi
else absent python "$PY" c73_retention_keeps; fi

# --- c74: a finding only the retention pass reaches; three runs, the same result ---
if [ "$have_py" = 1 ]; then
  X="$OUT/ex74"; copy_example "$P" "$X"; rm -rf "$X/fuzz/corpus"; mkdir -p "$X/fuzz/corpus" "$X/impl-c74"; : > "$X/fuzz/corpus/empty"
  cp "$ROOT/tests/harness_fv_controls/variants/c74_reduce_over/risk.py" "$X/impl-c74/risk.py"
  bad=""; sig=()
  for k in 1 2 3; do
    campaign "c74_$k" python "$X" impl-c74 diff_risk "$LOCK" "$LEAN" --runs 1; rc=$?; j="$OUT/c74_$k/run/fuzz.json"
    a=$(ls "$OUT/c74_$k/run/artifacts/" 2>/dev/null | grep '^mismatch-' | head -1)
    if [ $rc -ne 1 ] || ! jq -e '.detail | contains("retention replay") and contains("oracle/implementation mismatch")' "$j" > /dev/null || [ -z "$a" ]; then
      bad+="run $k: exit=$rc [$(jq -r .detail "$j" 2>/dev/null | cut -c1-120)] artifact=[$a]; "
    fi
    sig+=("$a $(jq -r '.classes.retention | "\(.seed) \(.executions) \(.retained | join(","))"' "$j" 2>/dev/null | sha256sum | cut -c1-16)")
  done
  if [ -z "$bad" ] && [ "${sig[0]}" = "${sig[1]}" ] && [ "${sig[1]}" = "${sig[2]}" ]; then
    echo "c74_retention_replay_fails OK 3/3 FAIL: $(jq -r '.detail | .[0:150]' "$OUT/c74_1/run/fuzz.json"); reproducer ${sig[0]%% *} each time; retained set identical (digest ${sig[0]##* }, $(jq -r '.classes.retention.retained | length' "$OUT/c74_1/run/fuzz.json") inputs); campaign: 1 execution"
  else
    echo "c74_retention_replay_fails WRONG $bad signatures: ${sig[*]}"; fails=1
  fi
else absent python "$PY" c74_retention_replay_fails; fi

exit $fails
