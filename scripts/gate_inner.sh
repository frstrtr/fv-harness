#!/usr/bin/env bash
# gate_inner.sh — audit stages of verify_proof.sh. Runs inside a fresh network namespace as the
# invoking user, with RUN pointing at the prepared run directory. Not meant to be run by hand.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"
[ -n "${RUN:-}" ] && [ -d "$RUN/full" ] || die "RUN not prepared"

LAKE="$LEAN_TC/bin/lake"
export PATH="$LEAN_TC/bin:/usr/bin:/bin"
cfg="$RUN/trusted/comparator.json"

# ---- netns: prove there is no network but loopback ------------------------------------------
ifaces=$(tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d ' ' | sort | tr '\n' ' ')
echo "interfaces: $ifaces" > "$RUN/stages/netns.log"
if [ "$ifaces" = "lo " ]; then stage_set netns PASS; else stage_set netns ERROR; exit 0; fi

# ---- the staged trees, checked again right before every step that reads them ---------------------
# Every locked file with its locked hash, every staged solution file with its staged hash, and nothing else: a
# file the staging did not put there fails, and so does .lake in a tree that has not been built yet.
check_tree() { # check_tree TREE BUILT(0|1) STEP
  local d="$RUN/$1" extra
  (cd "$d" && sha256sum --check --quiet --strict "$RUN/lock.manifest" \
     && { [ ! -s "$RUN/staged-$1.manifest" ] || sha256sum --check --quiet --strict "$RUN/staged-$1.manifest"; }) \
    > /dev/null 2>&1 || { echo "BLOCKED: staged tree $1 differs from the lock or its staging before $3"; return 1; }
  extra=$(cd "$d" && find . -type f ! -path "./.lake/*" -printf '%P\n' | LC_ALL=C sort \
          | comm -23 - <( { cut -d' ' -f3- "$RUN/lock.manifest"; cut -d' ' -f3- "$RUN/staged-$1.manifest"; } | LC_ALL=C sort))
  [ -z "$extra" ] || { echo "BLOCKED: staged tree $1 has files the staging did not put there before $3: $(echo $extra | cut -c1-200)"; return 1; }
  [ "$2" = 1 ] || [ ! -e "$d/.lake" ] || { echo "BLOCKED: staged tree $1 has a .lake before its first build ($3)"; return 1; }
}
inner_hook() { # FV_TEST_HOOK_INNER=STEP:ACTION:TREE[:REL] (controls only; verify_proof.sh records it): a writer in the run
  local step act tree rel
  [ -n "${FV_TEST_HOOK_INNER:-}" ] || return 0
  IFS=: read -r step act tree rel <<< "$FV_TEST_HOOK_INNER"
  [ "$step" = "$1" ] || return 0
  case "$act" in
    edit) chmod u+w "$RUN/$tree/$rel"; printf '\n-- FV_TEST_HOOK_INNER\n' >> "$RUN/$tree/$rel" ;;
    plant) mkdir -p "$(dirname "$RUN/$tree/$rel")"; echo "-- FV_TEST_HOOK_INNER" > "$RUN/$tree/$rel" ;;
    lake) mkdir -p "$RUN/$tree/.lake/build" ;;
  esac
}
check_trees() { # check_trees STEP TREE:BUILT ...
  local step="$1" tb; shift
  inner_hook "$step"
  for tb in "$@"; do
    if ! check_tree "${tb%%:*}" "${tb#*:}" "$step" > "$RUN/stages/staged.log" 2>&1; then stage_set staged BLOCKED; exit 0; fi
  done
  echo "every staged tree matches the lock and its staging (last check: before $step)" > "$RUN/stages/staged.log"
}
check_trees audit trusted:0 full:0 native:0

# ---- provenance ------------------------------------------------------------------------------
{
  echo "lean: $("$LEAN_TC/bin/lean" --version)"
  echo "expected lean commit: $LEAN_COMMIT"
  for b in lake lean leanexport leanchecker leanchecker-paranoid lean4lean nanoda_bin con-leche con-ron; do
    printf '%s  %s\n' "$(sha256sum < "$LEAN_TC/bin/$b" | cut -d' ' -f1)" "bundled/$b"
  done
  if [ -x "$CON_LECHE_MASTER_BIN" ]; then
    printf '%s  %s\n' "$(sha256sum < "$CON_LECHE_MASTER_BIN" | cut -d' ' -f1)" "con-leche-master@$CON_LECHE_MASTER_SHA"
  fi
  echo "bwrap: $(bwrap --version)"
} > "$RUN/provenance.txt" 2>&1

# Config sanity: the axiom whitelist must be exactly the harness policy.
got=$(jq -r '.permitted_axioms | sort | join(" ")' "$cfg")
want=$(tr ' ' '\n' < "$RUN/permitted_axioms.expected" | sort | tr '\n' ' ' | sed 's/ $//')
if [ "$got" != "$want" ]; then
  echo "comparator.json permitted_axioms [$got] != policy [$want]" > "$RUN/stages/config.log"
  stage_set config ERROR
  for s in comparator_native export comparator_export con_leche con_ron con_leche_compare; do stage_set "$s" SKIP; done
  exit 0
fi
stage_set config PASS

chal_mod=$(jq -r .challenge_module "$cfg")
sol_mod=$(jq -r .solution_module "$cfg")
# Export targets, mirroring Lake's own comparator (Lake/CLI/Check.lean @ v4.36.0: builtinTargets,
# theorem names, permitted axioms, primitiveTargets, definition names) so that
# `lake comparator --*-from-export` sees the same environment Lake's own export would produce.
LAKE_PRIMITIVES="Nat.add Nat.sub Nat.mul Nat.pow Nat.gcd Nat.div Nat.mod Nat.beq Nat.ble Nat.land
  Nat.lor Nat.xor Nat.shiftLeft Nat.shiftRight String.ofList Char.ofNat List eagerReduce Nat String
  String.mk Char optParam autoParam semiOutParam outParam"
mapfile -t names < <(
  jq -e '.permitted_axioms | index("Quot.sound")' "$cfg" > /dev/null && printf '%s\n' Quot Quot.mk Quot.lift Quot.ind
  json_names "$cfg" theorem_names
  json_names "$cfg" permitted_axioms
  printf '%s\n' $LAKE_PRIMITIVES
  json_names "$cfg" definition_names)

# ---- comparator_native ------------------------------------------------------------------------
check_trees comparator_native native:0
( cd "$RUN/native" && capped "$LAKE" comparator --paranoid --config comparator.json ) \
  > "$RUN/stages/comparator_native.log" 2>&1
rc=$?
echo "exit=$rc" >> "$RUN/stages/comparator_native.log"
comparator_status() { # Lake: 0 judged okay, 1 judged not okay, 2 could not run
  if [ "$1" -eq 0 ] && grep -q '^Your solution is okay!$' "$2"; then echo PASS
  elif [ "$1" -eq 1 ]; then echo FAIL
  else echo ERROR; fi
}
stage_set comparator_native "$(comparator_status $rc "$RUN/stages/comparator_native.log")"

# ---- export: sandboxed builds and inert exports ---------------------------------------------
build_export() { # build_export TREE MODULE OUT.ndjson
  local tree="$1" mod="$2" outf="$3" lp
  mkdir -p "$tree/.lake"
  sbx --ro "$tree" --rw "$tree/.lake" --chdir "$tree" -- "$LAKE" build "$mod" || return 1
  lp=$(sbx --ro "$tree" --chdir "$tree" -- "$LAKE" env printenv LEAN_PATH) || return 1
  sbx --ro "$tree" --chdir "$tree" --env LEAN_PATH "$lp" -- \
    "$LEAN_TC/bin/leanexport" "$mod" -- "${names[@]}" > "$outf" || return 1
  [ -s "$outf" ]
}
check_trees export trusted:0 full:0
{
  echo "== challenge ($chal_mod) from the solution-free tree"
  build_export "$RUN/trusted" "$chal_mod" "$RUN/exports/challenge.ndjson" && c_ok=1 || c_ok=0
  echo "== solution ($sol_mod)"
  build_export "$RUN/full" "$sol_mod" "$RUN/exports/solution.ndjson" && s_ok=1 || s_ok=0
  (cd "$RUN/exports" && sha256sum ./*.ndjson && wc -l ./*.ndjson) || true
  echo "challenge_ok=$c_ok solution_ok=$s_ok"
} > "$RUN/stages/export.log" 2>&1
if [ "$c_ok" = 1 ] && [ "$s_ok" = 1 ]; then stage_set export PASS
elif [ "$c_ok" = 1 ]; then stage_set export FAIL   # the solution does not build: a verdict
else stage_set export ERROR; fi                     # the trusted challenge does not build

if [ "$(stage_get export)" != PASS ]; then
  for s in comparator_export con_leche con_ron con_leche_compare; do stage_set "$s" SKIP; done
  [ "$(stage_get export)" = FAIL ] && for s in comparator_export con_leche con_ron con_leche_compare; do stage_set "$s" FAIL; done
  exit 0
fi
C="$RUN/exports/challenge.ndjson"; S="$RUN/exports/solution.ndjson"

# ---- comparator_export ------------------------------------------------------------------------
check_trees comparator_export trusted:1
( cd "$RUN/trusted" && capped "$LAKE" comparator --config comparator.json \
    --challenge-from-export="$C" --solution-from-export="$S" ) > "$RUN/stages/comparator_export.log" 2>&1
rc=$?
echo "exit=$rc" >> "$RUN/stages/comparator_export.log"
stage_set comparator_export "$(comparator_status $rc "$RUN/stages/comparator_export.log")"

# ---- independent kernels ----------------------------------------------------------------------
kernel() { # kernel STAGE PREFIX BIN ARGS...
  local stage="$1" prefix="$2"; shift 2
  sbx --ro "$RUN/exports" --ro "$1" -- "$@" > "$RUN/stages/$stage.log" 2>&1
  local rc=$?
  echo "exit=$rc" >> "$RUN/stages/$stage.log"
  if [ $rc -eq 0 ] && grep -qE "^$prefix: accepted [0-9]+ declarations" "$RUN/stages/$stage.log"; then
    stage_set "$stage" PASS
  elif [ $rc -le 2 ]; then stage_set "$stage" FAIL   # 1 rejected, 2 declined
  else stage_set "$stage" ERROR; fi                  # 3 usage/malformed/internal, or a crash
}
kernel con_leche con-leche "$LEAN_TC/bin/con-leche" --jobs="$FV_JOBS" "$S"
kernel con_ron con-ron "$LEAN_TC/bin/con-ron" --jobs="$FV_JOBS" "$S"
if [ -x "$CON_LECHE_MASTER_BIN" ]; then
  kernel con_leche_compare con-leche "$CON_LECHE_MASTER_BIN" --jobs="$FV_JOBS" --compare -- "$C" "$S"
else
  echo "con-leche master binary missing: $CON_LECHE_MASTER_BIN" > "$RUN/stages/con_leche_compare.log"
  stage_set con_leche_compare ERROR
fi
exit 0
