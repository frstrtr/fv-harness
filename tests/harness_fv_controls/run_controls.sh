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
# For c114: what the harness root and the caller's directory hold before any control runs.
PRE_ROOT=$(ls -A "$ROOT" | LC_ALL=C sort); PRE_CWD=$(ls -A . | LC_ALL=C sort)
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

# Control 115: the gate audits the locked files, not whatever the working tree holds after the check. A test
# hook appends a line to the trusted Challenge.lean right after the lock check (a writer racing the gate):
# (a) with an empty held-out store: BLOCKED (the copy differs from the lock), nothing audited;
# (b) with the store c1 already filled: the audit runs on the locked content (the hook's line is in the working
#     tree, not in any staged tree); (c) a hook that edits the staged trusted tree after staging: BLOCKED before
#     any build; (d) the gate copies a forged lock F, then the genuine G is put in its place: the check reads the
#     copy F, BLOCKED; (e) a run directory planted beforehand: BLOCKED; (f) CLOSE on a gate run with a hook: refused;
#     (g) the gate's copy of the lock edited after the check: BLOCKED before the held-out copy is used; (h) the
#     signature replaced by a link between the gate's test and its copy: BLOCKED at the copy.
r115=""
p=$(new_project c115a)
FV_LOCK_STORE="$OUT/c115a/store" FV_TEST_HOOK_GATE_EDIT=spec/challenge/Challenge.lean \
  "$ROOT/scripts/verify_proof.sh" --project "$p" --lock "$LOCK" --out "$OUT/c115a/run" > "$OUT/c115a/gate.out" 2>&1; ra=$?
ja="$OUT/c115a/run/verdict.json"
{ [ $ra -eq 2 ] && [ "$(cat "$OUT/c115a/run/stages/held_out.status" 2>/dev/null)" = BLOCKED ] && [ ! -e "$OUT/c115a/run/trusted" ] \
  && jq -e '.test_hooks == ["FV_TEST_HOOK_GATE_EDIT"]' "$ja" > /dev/null && [ -z "$(ls -A "$OUT/c115a/store" 2>/dev/null)" ]; } \
  || r115+="(a) exit=$ra held_out=$(cat "$OUT/c115a/run/stages/held_out.status" 2>/dev/null) trusted=$([ -e "$OUT/c115a/run/trusted" ] && echo staged || echo none); "
p=$(new_project c115b); FV_TEST_HOOK_GATE_EDIT=spec/challenge/Challenge.lean \
  "$ROOT/scripts/verify_proof.sh" --project "$p" --lock "$LOCK" --out "$OUT/c115b/run" > "$OUT/c115b/gate.out" 2>&1; rb=$?
{ [ $rb -eq 0 ] && grep -q 'FV_TEST_HOOK_GATE_EDIT' "$p/spec/challenge/Challenge.lean" \
  && ! grep -rq 'FV_TEST_HOOK_GATE_EDIT' "$OUT/c115b/run/trusted/spec" "$OUT/c115b/run/full/spec" "$OUT/c115b/run/native/spec" \
  && [ "$(cat "$OUT/c115b/run/stages/staged.status" 2>/dev/null)" = PASS ]; } \
  || r115+="(b) exit=$rb staged=$(cat "$OUT/c115b/run/stages/staged.status" 2>/dev/null) hook-line-in-staged=$(grep -rl 'FV_TEST_HOOK_GATE_EDIT' "$OUT/c115b/run/trusted/spec" 2>/dev/null | head -1); "
p=$(new_project c115c); FV_TEST_HOOK_GATE_EDIT_STAGED=spec/challenge/Challenge.lean \
  "$ROOT/scripts/verify_proof.sh" --project "$p" --lock "$LOCK" --out "$OUT/c115c/run" > "$OUT/c115c/gate.out" 2>&1; rc=$?
built=$(cd "$OUT/c115c/run/stages" && ls ./*.status | grep -vE '/(lock|lint|held_out|staged)\.status' | tr '\n' ' ')
{ [ $rc -eq 2 ] && [ "$(cat "$OUT/c115c/run/stages/staged.status" 2>/dev/null)" = BLOCKED ] && [ -z "$built" ] \
  && jq -e '.test_hooks == ["FV_TEST_HOOK_GATE_EDIT_STAGED"]' "$OUT/c115c/run/verdict.json" > /dev/null; } \
  || r115+="(c) exit=$rc staged=$(cat "$OUT/c115c/run/stages/staged.status" 2>/dev/null) later stages: [$built]; "
# (d) The lock swapped for the check: the lock file is a forged manifest F (made for the trusted tree plus the edit the
# GATE_EDIT hook appends) with the genuine signature; a hook puts the genuine manifest back right after the gate's
# copy, and the edit lands after the check. The check reads the copy (F): BLOCKED, nothing staged.
p=$(new_project c115d); L="$OUT/c115d/locks"; mkdir -p "$L"; cp "$LOCK" "$LOCK.sig" "${LOCK%.sha256}.allowed_signers" "$L/"
F="$OUT/c115d/forged"; cp -r "$p" "$F"; printf '\n-- FV_TEST_HOOK_GATE_EDIT\n' >> "$F/spec/challenge/Challenge.lean"
"$ROOT/scripts/spec_lock.sh" lock "$F" "$OUT/c115d/F.sha256" > /dev/null; cp "$OUT/c115d/F.sha256" "$L/conservation.sha256"
FV_LOCK_STORE="$OUT/c115d/store" FV_TEST_HOOK_LOCK_SWAP="$LOCK" FV_TEST_HOOK_GATE_EDIT=spec/challenge/Challenge.lean \
  "$ROOT/scripts/verify_proof.sh" --project "$p" --lock "$L/conservation.sha256" --out "$OUT/c115d/run" > "$OUT/c115d/gate.out" 2>&1; rd=$?
{ [ $rd -eq 2 ] && [ "$(cat "$OUT/c115d/run/stages/lock.status" 2>/dev/null)" = BLOCKED ] && [ ! -e "$OUT/c115d/run/trusted" ]; } \
  || r115+="(d) exit=$rd lock=$(cat "$OUT/c115d/run/stages/lock.status" 2>/dev/null) trusted=$([ -e "$OUT/c115d/run/trusted" ] && echo staged || echo none); "
# (e) A run directory planted beforehand (a lock.manifest symlink to a file the planter controls): BLOCKED, the
# planted file untouched.
mkdir -p "$OUT/c115e/run"; echo planted > "$OUT/c115e/target"; ln -s "$OUT/c115e/target" "$OUT/c115e/run/lock.manifest"
p=$(new_project c115e_p); "$ROOT/scripts/verify_proof.sh" --project "$p" --lock "$LOCK" --out "$OUT/c115e/run" > "$OUT/c115e/gate.out" 2>&1; re=$?
{ [ $re -eq 2 ] && grep -q 'already exists' "$OUT/c115e/gate.out" && [ "$(cat "$OUT/c115e/target")" = planted ]; } \
  || r115+="(e) exit=$re target=[$(head -c 40 "$OUT/c115e/target")]; "
# (f) CLOSE of a task whose gate run had a hook (b's PASS): refused. The fuzz record is complete (classification and
# a full retention pass), so the gate's hook is the only reason to refuse: without that check CLOSE goes on.
T115="c115f-$$"; mkdir -p "$FV_ROOT/tasks/$T115" "$OUT/c115f/couple"
echo '{"lang": "cpp", "verdict": "PASS", "classes": {"inputs": 10, "retention": {"complete": true, "runs": 200000, "retained": []}}}' > "$OUT/c115f/couple/fuzz.json"
jq -n --arg t "$T115" --arg a "$OUT/c115b/run" --arg c "$OUT/c115f/couple" '{task: $t, state: "CLOSE", project: "", lock: "", lang: "cpp",
  cpp: {lang: "cpp"}, last_audit: $a, last_couple: $c, history: [], stubs: {}, rounds: 0}' > "$FV_ROOT/tasks/$T115/state.json"
python3 -I "$ROOT/scripts/formal_task.py" close "$T115" > "$OUT/c115f/close.out" 2>&1; rf=$?
cp -r "$FV_ROOT/tasks/$T115" "$OUT/c115f/"; rm -rf "${FV_ROOT:?}/tasks/${T115:?}"
{ [ $rf -eq 3 ] && grep -q 'CLOSE refused: the gate ran with test hooks FV_TEST_HOOK_GATE_EDIT' "$OUT/c115f/close.out" "$OUT/c115f/$T115/state.json"; } \
  || r115+="(f) close exit=$rf [$(tail -1 "$OUT/c115f/close.out" | cut -c1-120)]; "
# (g) The gate's copy of the lock edited after the check (a writer in the run directory): BLOCKED at the held-out step.
p=$(new_project c115g); FV_TEST_HOOK_LOCK_COPY_EDIT=1 \
  "$ROOT/scripts/verify_proof.sh" --project "$p" --lock "$LOCK" --out "$OUT/c115g/run" > "$OUT/c115g/gate.out" 2>&1; rg=$?
{ [ $rg -eq 2 ] && grep -q "the gate's copy of the lock changed after the check" "$OUT/c115g/run/stages/held_out.log" 2>/dev/null \
  && [ ! -e "$OUT/c115g/run/trusted" ]; } \
  || r115+="(g) exit=$rg held_out=[$(head -1 "$OUT/c115g/run/stages/held_out.log" 2>/dev/null | cut -c1-80)]; "
# (h) The signature replaced by a link (to a genuine signature) between the gate's link test and its copy: the copy is
# tested again, BLOCKED.
p=$(new_project c115h); L="$OUT/c115h/locks"; mkdir -p "$L"; cp "$LOCK" "$LOCK.sig" "${LOCK%.sha256}.allowed_signers" "$L/"
cp "$LOCK.sig" "$OUT/c115h/genuine.sig"
FV_TEST_HOOK_LOCK_LINK="$OUT/c115h/genuine.sig" \
  "$ROOT/scripts/verify_proof.sh" --project "$p" --lock "$L/conservation.sha256" --out "$OUT/c115h/run" > "$OUT/c115h/gate.out" 2>&1; rh=$?
{ [ $rh -eq 2 ] && grep -q 'was replaced by a link or a non-file while it was copied' "$OUT/c115h/run/stages/lock.log" 2>/dev/null; } \
  || r115+="(h) exit=$rh lock=$(cat "$OUT/c115h/run/stages/lock.status" 2>/dev/null) [$(head -1 "$OUT/c115h/run/stages/lock.log" 2>/dev/null | cut -c1-80)]; "
if [ -z "$r115" ]; then
  report c115_gate_held_out OK "(a) a trusted file edited after the check, empty store: BLOCKED, nothing staged; (b) the same with c1's store: audited the locked content (PASS), the edit only in the working tree; (c) the staged tree edited: BLOCKED before any build; (d) the gate copied a forged lock, then the genuine one was put in place: the copy was checked, BLOCKED; (e) a planted run directory: BLOCKED, the planted file untouched; (f) CLOSE on a hooked gate PASS: refused; (g) the lock copy edited after the check: BLOCKED; (h) the signature swapped for a link while copied: BLOCKED"
else
  report c115_gate_held_out WRONG "$r115"
fi

# Control 117: the lint and the builds read one copy of the solution. A hook puts a Solution.lean with #eval (which the
# lint refuses) in place right after the lint: (a) in the project and the gate's copy: BLOCKED before any build, the
# lint having passed the clean copy; (b) in the project only: the gate builds the clean copy it linted (PASS), no
# staged tree holds the #eval.
r117=""; E117="$OUT/c117_eval.lean"; { cat "$FIX/$FV_SOLUTION_REL/Solution.lean"; printf '\n#eval (1 : Nat)\n'; } > "$E117"
p=$(new_project c117a); FV_TEST_HOOK_LINT_SWAP="$E117" \
  "$ROOT/scripts/verify_proof.sh" --project "$p" --lock "$LOCK" --out "$OUT/c117a/run" > "$OUT/c117a/gate.out" 2>&1; r1=$?
built=$(cd "$OUT/c117a/run/stages" 2>/dev/null && ls ./*.status | grep -vE '/(lock|lint|held_out|staged)\.status' | tr '\n' ' ')
{ [ $r1 -eq 2 ] && [ "$(cat "$OUT/c117a/run/stages/lint.status" 2>/dev/null)" = PASS ] \
  && [ "$(cat "$OUT/c117a/run/stages/staged.status" 2>/dev/null)" = BLOCKED ] && [ -z "$built" ] \
  && grep -q 'changed after the lint' "$OUT/c117a/run/stages/staged.log"; } \
  || r117+="(a) exit=$r1 lint=$(cat "$OUT/c117a/run/stages/lint.status" 2>/dev/null) staged=$(cat "$OUT/c117a/run/stages/staged.status" 2>/dev/null) later=[$built]; "
p=$(new_project c117b); FV_TEST_HOOK_LINT_SWAP="$E117:project" \
  "$ROOT/scripts/verify_proof.sh" --project "$p" --lock "$LOCK" --out "$OUT/c117b/run" > "$OUT/c117b/gate.out" 2>&1; r2=$?
{ [ $r2 -eq 0 ] && grep -q '#eval' "$p/$FV_SOLUTION_REL/Solution.lean" \
  && ! grep -rq '#eval' "$OUT/c117b/run/full/$FV_SOLUTION_REL" "$OUT/c117b/run/native/$FV_SOLUTION_REL"; } \
  || r117+="(b) exit=$r2 #eval-in-staged=$(grep -rl '#eval' "$OUT/c117b/run/full/$FV_SOLUTION_REL" 2>/dev/null | head -1); "
if [ -z "$r117" ]; then
  report c117_lint_staged_copy OK "(a) the gate's copy swapped after the lint: BLOCKED before any build (lint PASS on the clean copy); (b) the project's file swapped after the lint: the clean copy it linted was built (PASS), no #eval staged"
else
  report c117_lint_staged_copy WRONG "$r117"
fi

# Control 118: gate_inner.sh checks every staged tree again right before each step that reads it. A hook acts as a
# writer in the run directory after verify_proof.sh's own checks; each refusal is BLOCKED at its step:
# (a) a locked file edited before the audit; (b) a file planted before the audit; (c) .lake made before the first build;
# (d) a file planted in the native tree before comparator_native; (e) the staged solution edited before the export;
# (f) a locked file of the built trusted tree edited before comparator_export.
r118=""
inner_case() { # inner_case KEY HOOK MESSAGE [STAGE-THAT-MUST-HAVE-RUN]
  local k="$1" h="$2" msg="$3" ran="${4:-}" p rk
  p=$(new_project "c118$k"); FV_TEST_HOOK_INNER="$h" \
    "$ROOT/scripts/verify_proof.sh" --project "$p" --lock "$LOCK" --out "$OUT/c118$k/run" > "$OUT/c118$k/gate.out" 2>&1; rk=$?
  { [ $rk -eq 2 ] && [ "$(cat "$OUT/c118$k/run/stages/staged.status" 2>/dev/null)" = BLOCKED ] \
    && grep -q -- "$msg" "$OUT/c118$k/run/stages/staged.log" \
    && { [ -z "$ran" ] || [ -e "$OUT/c118$k/run/stages/$ran.status" ]; } \
    && jq -e '.test_hooks == ["FV_TEST_HOOK_INNER"]' "$OUT/c118$k/run/verdict.json" > /dev/null; } \
    || r118+="($k) exit=$rk staged=$(cat "$OUT/c118$k/run/stages/staged.status" 2>/dev/null) [$(head -1 "$OUT/c118$k/run/stages/staged.log" 2>/dev/null | cut -c1-90)]; "
}
inner_case a audit:edit:trusted:spec/challenge/Challenge.lean "differs from the lock or its staging before audit"
inner_case b audit:plant:full:spec/solution/Planted.lean "files the staging did not put there before audit"
inner_case c audit:lake:native "has a .lake before its first build (audit)"
inner_case d comparator_native:plant:native:spec/solution/Planted.lean "files the staging did not put there before comparator_native"
inner_case e export:edit:full:spec/solution/Solution.lean "differs from the lock or its staging before export" comparator_native
inner_case f comparator_export:edit:trusted:spec/challenge/Challenge.lean "differs from the lock or its staging before comparator_export" export
if [ -z "$r118" ]; then
  report c118_inner_rechecks OK "a writer in the run after the gate's checks is BLOCKED at the next step: (a) a locked file edited, (b) a file planted, (c) an early .lake, all before the audit; (d) a file planted before comparator_native; (e) the staged solution edited before the export; (f) the built trusted tree edited before comparator_export"
else
  report c118_inner_rechecks WRONG "$r118"
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
# Every expected control must report a line (OK, WRONG, or SKIPPED with its reason), and a runner that
# exits non-zero without a WRONG line of its own (it crashed, or a control script stopped early) is a
# failure too.
collect() { # collect RUNNER_NAME OUT_FILE EXIT EXPECTED_IDS...
  local name="$1" f="$2" rc="$3" c id res detail; shift 3
  while read -r id res detail; do
    [[ "$id" =~ ^c[0-9]+[a-z]?_[a-z0-9_]+$ ]] || continue
    [ "$res" = SKIPPED ] && res=SKIP
    report "$id" "$res" "$detail"
  done < "$f"
  for c in "$@"; do
    grep -qE "^$c +(OK|WRONG|SKIP|SKIPPED) " "$f" || report "$c" WRONG "no verdict line from the $name runner (see $f)"
  done
  if [ "$rc" -ne 0 ] && ! grep -qE '^c[0-9]+[a-z]?_[a-z0-9_]+ +WRONG ' "$f"; then
    report "${name}_runner" WRONG "exited $rc without a WRONG line: $(grep -vE '^c[0-9]' "$f" | tail -1 | cut -c1-160)"
  fi
}
FUZZ_IDS="c1_fuzz c6_cpp_drift c7_lsan_leak c8_vendored_tamper c9_edge_not_exercised c10_leak_class c11_hang c12_growth
  c13_classify_env c14_zero_limits c30_draft_not_countable c32_len_limits c38_jobs c39_remote_bundle c40_guards c42_cmake_args
  c43_merge c44_bundle_strict c45_pause_no_hang c46_ssh_localhost c58_remote_same_name c47_run_name c60_runs_time c61_out_unpack
  c48_record_failure c50_bytes_abi c53_merge_failure c54_merge_inner_exit c59_merge_inner_start c62_slow_units_jobs c63_out_lock
  c65_bundle_target c66_chain_unreachable c67_restart_window c89_retain_artifact c112_retain_paths c116_retain_uncaptured c90_retention_recorded c113_hook_hosts_env c108_no_classify_close"
LANG_IDS="c15_rust_clean c16_rust_drift c17_rust_overflow c18_rust_vendored_tamper c19_rust_profile_off
  c52_py_merge c21_py_clean c22_py_drift c23_py_wide c24_py_vendored_tamper c55_py_oracle_error
  c25_evm_clean c26_evm_drift c27_evm_overflow c28_evm_vendored_tamper c29_evm_pins
  c33_tron_tvm_trc10 c34_tron_tvm_clean c35_tron_tvm_drift c36_tron_tvm_refusals c37_tron_tvm_vendored_tamper
  c56_tron_tvm_roundtrip c57_tron_tvm_build_pins c64_tron_tvm_record c49_tron_tvm_itx_drop c51_tron_tvm_guidance c41_tron_tvm_coverage c109_tron_tvm_replay_drivers"

# Control 1 (fuzz leg) and Control 6 (C++ drift): the differential fuzzer (Module 5), and the multi-worker
# controls.
"$ROOT/tests/harness_fv_controls/run_fuzz_controls.sh" "$OUT/fuzz" > "$OUT/fuzz.out" 2>&1; rcf=$?
# shellcheck disable=SC2086
collect fuzz "$OUT/fuzz.out" $rcf $FUZZ_IDS

# Languages beyond C++ (docs/LANGUAGES.md): SKIP when a toolchain is absent.
FV_LANG_CONTROLS="rust python evm tron-tvm" "$ROOT/tests/harness_fv_controls/run_lang_controls.sh" "$OUT/lang" > "$OUT/lang.out" 2>&1; rcl=$?
# shellcheck disable=SC2086
collect lang "$OUT/lang.out" $rcl $LANG_IDS

# The edge-case classifier beyond C++ and the class-guided retention pass (labels; retention replays are verdicts).
CLS_IDS="c68_gap_rust c69_gap_py c70_gap_evm c71_gap_tron_tvm c72_class_source_mismatch c75_py_classify_isolation
  c73_retention_keeps c73_py_retention_keeps c74_retention_replay_fails"
"$ROOT/tests/harness_fv_controls/run_classify_controls.sh" "$OUT/classify" > "$OUT/classify.out" 2>&1; rcc=$?
# shellcheck disable=SC2086
collect classify "$OUT/classify.out" $rcc $CLS_IDS

# Control 20: a language the gate host requires (FV_REQUIRE_LANGS) may not be skipped.
D20="$OUT/c20_required_lang"; mkdir -p "$D20"
FV_LANG_CONTROLS="rust python evm tron-tvm" FV_REQUIRE_LANGS="rust python evm tron-tvm" FV_RUST_HOME="$D20/no-toolchain" FV_PY="$D20/no-python" FV_SOLC="$D20/no-solc" FV_TRON_TVM_HOME="$D20/no-tvm" "$ROOT/tests/harness_fv_controls/run_lang_controls.sh" "$D20/req" > "$D20/req.out" 2>&1; r1=$?
FV_LANG_CONTROLS="rust python evm tron-tvm" FV_REQUIRE_LANGS= FV_RUST_HOME="$D20/no-toolchain" FV_PY="$D20/no-python" FV_SOLC="$D20/no-solc" FV_TRON_TVM_HOME="$D20/no-tvm" "$ROOT/tests/harness_fv_controls/run_lang_controls.sh" "$D20/opt" > "$D20/opt.out" 2>&1; r2=$?
n20w=$(grep -c ' WRONG required language' "$D20/req.out"); n20s=$(grep -c ' SKIP ' "$D20/opt.out")
if [ $r1 -ne 0 ] && [ "$n20w" -ge 20 ] && [ "$n20w" = "$n20s" ] && [ $r2 -eq 0 ]; then
  report c20_required_lang OK "required (rust, python, evm, tron-tvm) + no toolchains: $n20w WRONG (exit $r1); not required: $n20s SKIP (exit 0), one per language control"
else
  report c20_required_lang WRONG "required exit=$r1 [$(head -1 "$D20/req.out")]; optional exit=$r2 [$(head -1 "$D20/opt.out")]"
fi

# c31: one rule for site settings: an EXPORTED variable overrides config/hosts.env, which only supplies
# defaults; a plain shell assignment that is not exported never reaches a child process.
D31="$OUT/c31_hosts_env"; rm -rf "$D31"; mkdir -p "$D31/h/config" "$D31/h/scripts"
cp "$ROOT/scripts/lib.sh" "$D31/h/scripts/"; cp "$ROOT/config/pins.env" "$D31/h/config/"
printf 'FV_CPUSET=0-1\nFV_JOBS=3\n' > "$D31/h/config/hosts.env"
q() { bash -c ". '$D31/h/scripts/lib.sh'; echo \"\$FV_CPUSET \$FV_JOBS\""; }
e1=$(env -u FV_CPUSET -u FV_JOBS bash -c "$(declare -f q); D31='$D31'; q")
e2=$(env -u FV_JOBS FV_CPUSET=0 bash -c "$(declare -f q); D31='$D31'; q")
e3=$(env -u FV_CPUSET -u FV_JOBS bash -c "FV_CPUSET=0; $(declare -f q); D31='$D31'; q")
if [ "$e1" = "0-1 3" ] && [ "$e2" = "0 3" ] && [ "$e3" = "0-1 3" ]; then
  report c31_hosts_env OK "file only: [$e1]; exported FV_CPUSET=0: [$e2] (environment wins); unexported assignment: [$e3] (not seen)"
else
  report c31_hosts_env WRONG "file only: [$e1] (want 0-1 3); exported: [$e2] (want 0 3); unexported: [$e3] (want 0-1 3)"
fi

# Control 88: the sysroot lock tool reads only the text gpgv verified (fuzz/sysroot/make_lock.py).
"$ROOT/tests/harness_fv_controls/c88_sysroot_lock.sh" "$OUT/c88" > "$OUT/c88.out" 2>&1; rc88=$?
collect c88 "$OUT/c88.out" $rc88 c88_sysroot_lock

# Control 114: no control and no run left files in the harness root or in the caller's directory (a fuzzer without
# an artifact prefix writes crash-*/slow-unit-* to its working directory; a TRON-TVM driver started outside its node
# store writes vm_trace/ there).
new_root=$(comm -13 <(printf '%s\n' "$PRE_ROOT") <(ls -A "$ROOT" | LC_ALL=C sort) | tr '\n' ' ')
new_cwd=$(comm -13 <(printf '%s\n' "$PRE_CWD") <(ls -A . | LC_ALL=C sort) | tr '\n' ' ')
if [ -z "${new_root// /}" ] && [ -z "${new_cwd// /}" ]; then
  report c114_no_stray_files OK "nothing new in the harness root or the caller's directory after the suite"
else
  report c114_no_stray_files WRONG "new in the harness root: [${new_root% }]; in the caller's directory: [${new_cwd% }]"
fi

note "$fails control(s) misbehaved, $skipped skipped (toolchain absent); summary $SUM"
exit $((fails > 0))
