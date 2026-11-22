#!/usr/bin/env bash
# run_controls.sh — acceptance controls for the verification gate (HARNESS-UPGRADE-FV-01 §4).
#
#   tests/harness_fv_controls/run_controls.sh [OUTDIR]
#
# Each control copies the fixture, swaps in a solution variant (or tampers with the challenge),
# runs scripts/verify_proof.sh and checks the overall exit code plus the stages that must catch
# it. Exit 0 iff every control behaves as specified. Summary: OUTDIR/summary.txt.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT/scripts/lib.sh"
FIX="$ROOT/fixtures/conservation"
LOCK="$ROOT/locks/conservation.sha256"
# The fixture signer's fingerprint as recorded out-of-band (what the orchestrator records for a real key).
# CI compares against this constant, so a swapped key or pin file shows up as a failing control.
RECORDED_FIXTURE_FP="SHA256:R6l4wkshUPWT3e1nrbQysrKihLdvMoY9Sh+q9EfNtMw"
VAR="$ROOT/tests/harness_fv_controls/variants"
OUT="${1:-$FV_ROOT/runs/controls-$(date +%Y%m%dT%H%M%S)}"
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
SUM="$OUT/summary.txt"; : > "$SUM"
fails=0

skipped=0
report() { # report ID RESULT DETAIL   (SKIP: toolchain absent, listed and counted, not a failure)
  printf '%-22s %-6s %s\n' "$1" "$2" "$3" | tee -a "$SUM"
  case "$2" in OK) ;; SKIP) skipped=$((skipped + 1)) ;; *) fails=$((fails + 1)) ;; esac
}

new_project() { # new_project ID [VARIANT] -> path
  local p="$OUT/$1/project"
  rm -rf "$OUT/$1"; mkdir -p "$OUT/$1"
  cp -r "$FIX" "$p"; rm -rf "$p/.lake"
  if [ -n "${2:-}" ]; then rm -rf "$p/$FV_SOLUTION_REL"; cp -r "$VAR/$2" "$p/$FV_SOLUTION_REL"; fi
  echo "$p"
}

# gate_control ID VARIANT EXPECTED_EXIT "stage=STATUS ..."
gate_control() {
  local id="$1" variant="$2" want="$3" expects="$4" p rc got bad=""
  p=$(new_project "$id" "$variant")
  "$ROOT/scripts/verify_proof.sh" --project "$p" --lock "$LOCK" --out "$OUT/$id/run" > "$OUT/$id/gate.out" 2>&1
  rc=$?
  [ "$rc" -eq "$want" ] || bad="exit $rc (want $want);"
  for e in $expects; do
    got=$(cat "$OUT/$id/run/stages/${e%%=*}.status" 2>/dev/null || echo MISSING)
    [ "$got" = "${e#*=}" ] || bad="$bad ${e%%=*}=$got (want ${e#*=});"
  done
  local stages; stages=$(jq -r '.stages | to_entries | map("\(.key)=\(.value)") | join(" ")' "$OUT/$id/run/verdict.json" 2>/dev/null)
  if [ -z "$bad" ]; then report "$id" OK "exit=$rc | $stages"; else report "$id" WRONG "$bad | $stages"; fi
}

ALL_PASS="lock=PASS lint=PASS netns=PASS config=PASS comparator_native=PASS export=PASS comparator_export=PASS con_leche=PASS con_ron=PASS con_leche_compare=PASS"
CAUGHT="comparator_native=FAIL comparator_export=FAIL"

note "controls -> $OUT"
# Control 1 (positive): the gate leg here; its differential-fuzzer leg (c1_fuzz) runs below.
gate_control c1_clean "" 0 "$ALL_PASS"
# Control 2: sorry in an auxiliary lemma the theorem rests on.
gate_control c2_sorry c2_sorry 1 "lint=FAIL $CAUGHT con_leche=FAIL con_ron=FAIL con_leche_compare=FAIL"
# Control 3: custom axiom; the compiler-trust axiom; native_decide.
gate_control c3a_axiom c3a_axiom 1 "lint=FAIL $CAUGHT con_leche=FAIL con_ron=FAIL con_leche_compare=FAIL"
# Lean 4.36 removed Lean.trustCompiler/ofReduceBool/ofReduceNat; the variant re-declares
# `axiom Lean.trustCompiler : True`. con-leche/con-ron install that name as sound by design
# (ConLeche/Kernel/TrustAxioms.lean), so only comparator's axiom whitelist catches it.
gate_control c3b_trustcompiler c3b_trustcompiler 1 "lint=FAIL $CAUGHT con_leche=PASS con_ron=PASS"
# In 4.36 native_decide emits an auxiliary axiom (<decl>._native.native_decide.ax_N_M): every
# checker refuses it (comparator: illegal axiom; con-*: declined, non-standard axiom).
gate_control c3c_native_decide c3c_native_decide 1 "lint=FAIL $CAUGHT con_leche=FAIL con_ron=FAIL"
# Control 4: weakened statement; shadowed definitions.
gate_control c4a_weakened c4a_weakened 1 "lint=PASS $CAUGHT con_leche_compare=FAIL"
gate_control c4b_shadow_def c4b_shadow_def 1 "lint=PASS $CAUGHT con_leche_compare=FAIL"

# Control 5a: a synthesis-side process tries to edit spec/challenge/ inside the synthesis sandbox.
p=$(new_project c5a_sandbox_write)
before=$(sha256sum "$p/spec/challenge/Challenge.lean")
"$ROOT/scripts/synth_sandbox.sh" --project "$p" -- /bin/sh -c \
  'printf "\naxiom cheat : False\n" >> spec/challenge/Challenge.lean' > "$OUT/c5a_sandbox_write/attempt.out" 2>&1
rc_bad=$?
"$ROOT/scripts/synth_sandbox.sh" --project "$p" -- /bin/sh -c \
  'printf "\n" >> spec/solution/Solution.lean' > "$OUT/c5a_sandbox_write/control.out" 2>&1
rc_ok=$?
after=$(sha256sum "$p/spec/challenge/Challenge.lean")
if [ "$rc_bad" -ne 0 ] && [ "$before" = "$after" ] && [ "$rc_ok" -eq 0 ]; then
  report c5a_sandbox_write OK "challenge write blocked (exit $rc_bad: $(head -c 120 "$OUT/c5a_sandbox_write/attempt.out" | tr '\n' ' ')); solution write allowed"
else
  report c5a_sandbox_write WRONG "challenge write exit $rc_bad, changed=$([ "$before" = "$after" ] && echo no || echo YES), solution write exit $rc_ok"
fi

# Control 5b: the challenge is edited by a route outside the sandbox (statement weakened to match
# a weakened proof). The gate must BLOCK at the lock stage and audit nothing.
p=$(new_project c5b_tamper c4a_weakened)
sed -i 's/(transfer l amt bps).total = l.total := by/(transfer l amt bps).total ≤ l.total + amt := by/' "$p/spec/challenge/Challenge.lean"
"$ROOT/scripts/verify_proof.sh" --project "$p" --lock "$LOCK" --out "$OUT/c5b_tamper/run" > "$OUT/c5b_tamper/gate.out" 2>&1
rc=$?
audited=$(cd "$OUT/c5b_tamper/run/stages" && ls ./*.status | grep -v '/lock.status' | tr '\n' ' ')
if [ "$rc" -eq 2 ] && [ "$(cat "$OUT/c5b_tamper/run/stages/lock.status")" = BLOCKED ] && [ -z "$audited" ]; then
  report c5b_tamper OK "exit=2 BLOCKED before audit: $(grep -m1 -E '^[-+][^-+]' "$OUT/c5b_tamper/run/stages/lock.log")"
else
  report c5b_tamper WRONG "exit=$rc lock=$(cat "$OUT/c5b_tamper/run/stages/lock.status" 2>/dev/null) other stages run: [$audited]"
fi

# Controls 5c/5d: the agent edits the challenge AND rewrites the lock. Each run starts from a
# private copy of the lock files (the agent can write the harness repo too: same OS user).
tampered_lock() { # tampered_lock ID -> project path; LOCKDIR=$OUT/ID/locks holds a re-made manifest
  local id="$1" p
  p=$(new_project "$id" c4a_weakened)
  sed -i 's/(transfer l amt bps).total = l.total := by/(transfer l amt bps).total ≤ l.total + amt := by/' "$p/spec/challenge/Challenge.lean"
  mkdir -p "$OUT/$id/locks"
  cp "$LOCK" "$LOCK.sig" "${LOCK%.sha256}.allowed_signers" "$OUT/$id/locks/"
  "$ROOT/scripts/spec_lock.sh" lock "$p" "$OUT/$id/locks/conservation.sha256" > /dev/null
  echo "$p"
}
first_line_signer() { head -1 "$1" | grep -E '^SPEC-LOCK SIGNER principal=' ; }

# Control 5c: the lock digest is rewritten, the old signature kept: the signature no longer verifies.
p=$(tampered_lock c5c_unsigned_relock)
cp "$LOCK.sig" "$OUT/c5c_unsigned_relock/locks/conservation.sha256.sig"
"$ROOT/scripts/verify_proof.sh" --project "$p" --lock "$OUT/c5c_unsigned_relock/locks/conservation.sha256" \
  --out "$OUT/c5c_unsigned_relock/run" > "$OUT/c5c_unsigned_relock/gate.out" 2>&1
rc=$?
audited=$(cd "$OUT/c5c_unsigned_relock/run/stages" && ls ./*.status | grep -v '/lock.status' | tr '\n' ' ')
if [ "$rc" -eq 2 ] && [ -z "$audited" ] && grep -q 'SPEC-LOCK SIGNATURE INVALID' "$OUT/c5c_unsigned_relock/gate.out" \
   && first_line_signer "$OUT/c5c_unsigned_relock/gate.out" > /dev/null; then
  report c5c_unsigned_relock OK "exit=2 BLOCKED before audit: $(grep -m1 '^BLOCKED' "$OUT/c5c_unsigned_relock/run/stages/lock.log" | cut -c1-110)"
else
  report c5c_unsigned_relock WRONG "exit=$rc other stages run: [$audited]"
fi

# Control 5d: lock, signature AND allowed_signers replaced with the agent's own key (same principal
# name). (i) Against the pinned fingerprint: BLOCKED with a loud mismatch banner. (ii) With the pin
# file swapped too, nothing in-band can stop it: the gate passes, and the check is that the
# signer fingerprint printed first differs from the recorded operator fingerprint, and that the
# pin swap is a visible diff.
p=$(tampered_lock c5d_key_swap)
D="$OUT/c5d_key_swap"
ssh-keygen -q -t ed25519 -N "" -C "attacker key (control c5d)" -f "$D/attacker_ed25519"
ATTACKER_FP=$(ssh-keygen -lf "$D/attacker_ed25519.pub" | awk '{print $2}')
"$ROOT/scripts/spec_lock.sh" sign "$D/locks/conservation.sha256" "$D/attacker_ed25519" > /dev/null
echo "fixture-only@fv-harness namespaces=\"fv-spec-lock\" $(cat "$D/attacker_ed25519.pub")" > "$D/locks/conservation.allowed_signers"
"$ROOT/scripts/verify_proof.sh" --project "$p" --lock "$D/locks/conservation.sha256" --out "$D/run-pinned" > "$D/gate-pinned.out" 2>&1
rc1=$?
sed "s|$RECORDED_FIXTURE_FP|$ATTACKER_FP|" "$ROOT/config/signer_pins.txt" > "$D/signer_pins.swapped.txt"
FV_SIGNER_PINS="$D/signer_pins.swapped.txt" "$ROOT/scripts/verify_proof.sh" --project "$p" \
  --lock "$D/locks/conservation.sha256" --out "$D/run-swapped" > "$D/gate-swapped.out" 2>&1
rc2=$?
fp2=$(jq -r '.spec_lock_signer.fingerprint' "$D/run-swapped/verdict.json" 2>/dev/null)
first2=$(first_line_signer "$D/gate-swapped.out")
pin_diff=$(diff "$ROOT/config/signer_pins.txt" "$D/signer_pins.swapped.txt" | grep -c '^[<>]')
if [ "$rc1" -eq 2 ] && grep -q "SPEC-LOCK SIGNER FINGERPRINT MISMATCH: signed by $ATTACKER_FP, pinned $RECORDED_FIXTURE_FP" "$D/gate-pinned.out" \
   && first_line_signer "$D/gate-pinned.out" | grep -q "fingerprint=$ATTACKER_FP .*match=no" \
   && [ "$fp2" = "$ATTACKER_FP" ] && [ "$fp2" != "$RECORDED_FIXTURE_FP" ] && grep -q "fingerprint=$ATTACKER_FP" <<< "$first2" \
   && [ "$pin_diff" -gt 0 ]; then
  report c5d_key_swap OK "pinned: exit=2 BLOCKED, mismatch banner; pins swapped too: gate exit=$rc2 (not stoppable in-band) but first output line and verdict.json name signer $ATTACKER_FP != recorded $RECORDED_FIXTURE_FP; pin swap = $pin_diff-line diff"
else
  report c5d_key_swap WRONG "pinned exit=$rc1; swapped exit=$rc2 fp=$fp2 first-line=[$first2] pin-diff=$pin_diff"
fi

# Control 1 (fuzz leg) and Control 6 (C++ drift): the differential fuzzer (Module 5).
"$ROOT/tests/harness_fv_controls/run_fuzz_controls.sh" "$OUT/fuzz" > "$OUT/fuzz.out" 2>&1
while read -r id res detail; do
  [ -n "$id" ] && report "$id" "$res" "$detail"
done < "$OUT/fuzz.out"
grep -qE "^c1_fuzz " "$OUT/fuzz.out" && grep -qE "^c6_cpp_drift " "$OUT/fuzz.out" && grep -qE "^c7_lsan_leak " "$OUT/fuzz.out" && grep -qE "^c8_vendored_tamper " "$OUT/fuzz.out" && grep -qE "^c9_edge_not_exercised " "$OUT/fuzz.out" \
   && grep -qE "^c10_leak_class " "$OUT/fuzz.out" && grep -qE "^c11_hang " "$OUT/fuzz.out" && grep -qE "^c12_growth " "$OUT/fuzz.out" \
   && grep -qE "^c13_classify_env " "$OUT/fuzz.out" && grep -qE "^c14_zero_limits " "$OUT/fuzz.out" ||
  report fuzz_controls WRONG "runner produced no verdict lines (see $OUT/fuzz.out)"

# Languages beyond C++ (docs/LANGUAGES.md): SKIP when a toolchain is absent.
"$ROOT/tests/harness_fv_controls/run_lang_controls.sh" "$OUT/lang" > "$OUT/lang.out" 2>&1
while read -r id res detail; do
  [ -n "$id" ] && report "$id" "$res" "$detail"
done < "$OUT/lang.out"
grep -qE "^c15_rust_clean " "$OUT/lang.out" && grep -qE "^c16_rust_drift " "$OUT/lang.out" && grep -qE "^c17_rust_overflow " "$OUT/lang.out" ||
  report lang_controls WRONG "runner produced no verdict lines (see $OUT/lang.out)"

# Control 20: a language the gate host requires (FV_REQUIRE_LANGS) may not be skipped.
D20="$OUT/c20_required_lang"; mkdir -p "$D20"
FV_REQUIRE_LANGS=rust FV_RUST_HOME="$D20/no-toolchain" "$ROOT/tests/harness_fv_controls/run_lang_controls.sh" "$D20/req" > "$D20/req.out" 2>&1; r1=$?
FV_REQUIRE_LANGS= FV_RUST_HOME="$D20/no-toolchain" "$ROOT/tests/harness_fv_controls/run_lang_controls.sh" "$D20/opt" > "$D20/opt.out" 2>&1; r2=$?
if [ $r1 -ne 0 ] && [ "$(grep -c ' WRONG required language rust' "$D20/req.out")" = 3 ] && [ $r2 -eq 0 ] && [ "$(grep -c ' SKIP ' "$D20/opt.out")" = 3 ]; then
  report c20_required_lang OK "required + no toolchain: 3 WRONG (exit $r1); not required: 3 SKIP (exit 0)"
else
  report c20_required_lang WRONG "required exit=$r1 [$(head -1 "$D20/req.out")]; optional exit=$r2 [$(head -1 "$D20/opt.out")]"
fi

note "$fails control(s) misbehaved, $skipped skipped (toolchain absent); summary $SUM"
exit $((fails > 0))
