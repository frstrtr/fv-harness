#!/usr/bin/env bash
# lang_rehearsal.sh [LANG...] — scripts/formal_task.py end to end for each implementation language:
# SPEC_LOCK -> DECOMPOSE -> DISCHARGE -> AUDIT -> COUPLE (10 s) -> CLOSE on the harness's examples, then
# the same task with the example's drift implementation (--impl-dir), which must reach CPP_BUGFIX.
#   cpp     examples/risk-limit        (impl, impl-buggy)
#   rust    examples/risk-limit-rust   (impl, impl-drift)
#   python  examples/risk-limit-py     (impl, impl-drift)
#   evm     examples/risk-limit-evm    (contract, contract-drift)
#   tron-tvm examples/token-faucet-tron-tvm (contract, contract-drift)
# Checks per language: the closure's fuzz.lang is the task's, the implementation digests list the
# example's own files (not a C++ default), the evm / tron-tvm pins are recorded for those languages, and the
# drift task's bugfix record names the language. Every example is copied first: the COUPLE corpus
# merge writes only to the copy. Exit 0 iff every language behaves as expected.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib.sh"
FT="python3 -I $ROOT/scripts/formal_task.py"
W="$FV_ROOT/work/lang-rehearsal"; TASKS="$FV_ROOT/tasks"
langs=("$@"); [ ${#langs[@]} -gt 0 ] || langs=(cpp rust python evm tron-tvm)
fails=0; rm -rf "${W:?}"; mkdir -p "$W" "$TASKS"
for lang in "${langs[@]}"; do
  case "$lang" in
    cpp) ex=risk-limit; lean=risk-limit/lean; lock=risk-limit; fz=cpp/fuzz; good=cpp/impl; bad=cpp/impl-buggy; tgt=diff_risk; given=1 ;;
    rust) ex=risk-limit-rust; lean=risk-limit/lean; lock=risk-limit; fz=fuzz; good=impl; bad=impl-drift; tgt=diff_risk; given=0 ;;
    python) ex=risk-limit-py; lean=risk-limit/lean; lock=risk-limit; fz=fuzz; good=impl; bad=impl-drift; tgt=diff_risk; given=0 ;;
    evm) ex=risk-limit-evm; lean=risk-limit/lean; lock=risk-limit; fz=fuzz; good=contract; bad=contract-drift; tgt=diff_risk; given=0 ;;
    tron-tvm) ex=token-faucet-tron-tvm; lean=token-faucet-tron-tvm/lean; lock=token-faucet; fz=fuzz; good=contract; bad=contract-drift; tgt=diff_faucet; given=0 ;;
    *) echo "WRONG unknown language $lang"; fails=1; continue ;;
  esac
  for kind in good bad; do
    T="lang-$lang-$kind"; D="$W/$T"; rm -rf "$TASKS/$T"; mkdir -p "$D"
    cp -r "$ROOT/examples/$lean" "$D/lean"; rm -rf "$D/lean/.lake"; cp -r "$ROOT/examples/$ex" "$D/ex"
    impl_args=(); [ "$kind" = bad ] && impl_args=(--impl-dir "$D/ex/$bad")
    [ "$kind" = good ] && [ "$given" = 1 ] && impl_args=(--impl-dir "$D/ex/$good")
    $FT init "$T" --project "$D/lean" --lock "$ROOT/locks/$lock.sha256" --cmake-dir "$D/ex/$fz" --target "$tgt" \
      --lang "$lang" "${impl_args[@]}" --fuzz-time 10 > "$D/init.out" 2>&1 || { echo "WRONG $T: init failed: $(tail -2 "$D/init.out")"; fails=1; continue; }
    for step in spec-lock "decompose --by rehearsal" discharge audit couple close; do
      $FT $step "$T" >> "$D/steps.out" 2>&1; rc=$?
      st=$(jq -r .state "$TASKS/$T/state.json")
      [ "$st" = CPP_BUGFIX ] || [ "$st" = CLOSED ] || [ $rc -eq 0 ] || break
      [ "$st" = CPP_BUGFIX ] && break
    done
    st=$(jq -r .state "$TASKS/$T/state.json"); C="$TASKS/$T/closure.json"
    if [ "$kind" = good ]; then
      want_dir="$D/ex/$good"
      if [ "$st" = CLOSED ] && jq -e --arg l "$lang" --arg d "$(cd "$want_dir" && pwd)" '.fuzz.lang == $l and .fuzz.verdict == "PASS"
           and .source_digests.impl.lang == $l and .source_digests.impl.dir == $d and (.source_digests.impl.files | length) > 0
           and (if ($l == "evm") then (.fuzz.evm | type) == "object" elif ($l == "tron-tvm") then (.fuzz.tron_tvm | type) == "object"
                else .fuzz.evm == null and .fuzz.tron_tvm == null end)' "$C" > /dev/null \
         && grep -q "language: \`$lang\`" "$TASKS/$T/closure.md"; then
        echo "OK    $lang: CLOSED, closure fuzz.lang $lang, impl $(jq -r '.source_digests.impl.files | length' "$C") file(s) from $good$([ "$lang" = evm ] || [ "$lang" = tron-tvm ] && echo ", $lang pins recorded")"
      else
        echo "WRONG $lang: state $st $(jq -c '{lang: .fuzz.lang, verdict: .fuzz.verdict, impl: .source_digests.impl.dir}' "$C" 2>/dev/null) $(tail -3 "$D/steps.out" | tr '\n' ' ' | cut -c1-300)"; fails=1
      fi
    else
      B=$(ls "$TASKS/$T"/cpp-bugfix-*.json 2>/dev/null | head -1)
      if [ "$st" = CPP_BUGFIX ] && [ -n "$B" ] && jq -e --arg l "$lang" '.lang == $l' "$B" > /dev/null \
         && jq -e --arg l "$lang" '.lang == $l and .verdict == "FAIL"' "$(jq -r .last_couple "$TASKS/$T/state.json")/fuzz.json" > /dev/null; then
        echo "OK    $lang: drift ($bad) -> CPP_BUGFIX: $(jq -r .detail "$B" | cut -c1-120)"
      else
        echo "WRONG $lang: drift task state $st (want CPP_BUGFIX) $(tail -3 "$D/steps.out" | tr '\n' ' ' | cut -c1-300)"; fails=1
      fi
    fi
  done
done
exit $fails
