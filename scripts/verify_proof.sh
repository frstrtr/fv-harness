#!/usr/bin/env bash
# verify_proof.sh — the isolated verification gate (Module 4).
#
#   verify_proof.sh --project DIR --lock LOCKFILE [--expect-fingerprint SHA256:...] [--out RUNDIR] [--git-base REV]
#
# Exit: 0 PASS, 1 FAIL (audit rejected), 2 BLOCKED (trusted files changed; nothing audited),
#       3 ERROR (the harness could not reach a verdict).
#
# Stages (logs and statuses under RUNDIR/stages/, summary in RUNDIR/verdict.json):
#   lock              LOCKFILE.sig verifies, its signer equals the pinned fingerprint, and the
#                     trusted files equal the manifest (+ optional git diff gate) -> BLOCKED otherwise.
#                     The first output line is the signer: "SPEC-LOCK SIGNER principal=... fingerprint=..."
#   held_out          the locked files, copied once into a content-addressed read-only store
#                     ($FV_LOCK_STORE or $FV_ROOT/lock-store/<manifest sha256>) and verified -> BLOCKED otherwise;
#                     every staged tree comes from there, never again from the working tree
#   staged            each staged tree (trusted, full, native) re-hashed against the lock right before the
#                     builds, and again at the start of the audit -> BLOCKED otherwise
#   lint              policy lint over spec/solution/
#   ---- everything below runs in a fresh network namespace (only lo), as the invoking user ----
#   comparator_native lake comparator --paranoid: Lake builds and exports challenge and solution in
#                     its own bwrap sandbox, compares statements, checks axioms, runs leanchecker,
#                     leanchecker-paranoid, lean4lean, nanoda, con-leche, con-ron
#   export            the gate's own sandboxed builds; inert NDJSON exports of challenge (from a
#                     solution-free tree) and solution
#   comparator_export lake comparator on those exports (structure + axioms + leanchecker)
#   con_leche         bundled con-leche on the solution export   (exit 0 and "accepted N" required)
#   con_ron           bundled con-ron on the solution export     (exit 0 and "accepted N" required)
#   con_leche_compare con-leche master --compare challenge solution
#
# The project is never built in place: the gate copies the locked files plus spec/solution's
# regular .lean files into RUNDIR and builds only there.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

proj=""; lock=""; out=""; git_base=""; expect_fp=""
while [ $# -gt 0 ]; do
  case "$1" in
    --project) proj="$2"; shift 2 ;;
    --lock) lock="$2"; shift 2 ;;
    --expect-fingerprint) expect_fp="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    --git-base) git_base="$2"; shift 2 ;;
    *) die "unknown argument $1" ;;
  esac
done
[ -d "$proj" ] && [ -f "$lock" ] || die "usage: $0 --project DIR --lock LOCKFILE [--out RUNDIR] [--git-base REV]"
proj="$(cd "$proj" && pwd)"; lock="$(cd "$(dirname "$lock")" && pwd)/$(basename "$lock")"

RUN="${out:-$FV_ROOT/runs/$(basename "$proj")-$(date +%Y%m%dT%H%M%S)-$$}"
mkdir -p "$RUN/stages"
RUN="$(cd "$RUN" && pwd)"; export RUN

finish() { # finish EXITCODE VERDICT
  python3 -I "$HERE/verdict.py" "$RUN" "$2" "$1" "$proj" "$lock" > "$RUN/verdict.json"
  note "verdict $2 (exit $1) — $RUN/verdict.json"
  [ -s "$RUN/signer.txt" ] && echo "SPEC-LOCK $(cat "$RUN/signer.txt")"
  exit "$1"
}

# Test hooks (FV_TEST_HOOK_*): for controls only. Each one set (exported or not) is recorded in verdict.json
# (test_hooks), and CLOSE refuses such a run.
#   FV_TEST_HOOK_GATE_EDIT=REL         after the lock check, append a line to the project's trusted file REL
#                                      (a writer racing the gate)
#   FV_TEST_HOOK_GATE_EDIT_STAGED=REL  after staging, append a line to RUN/trusted/REL (a writer in the run)
compgen -v | grep -E '^FV_TEST_HOOK_[A-Z0-9_]*$' | LC_ALL=C sort > "$RUN/test_hooks.txt" || true

# The manifest as it is now: every later step reads this copy, never the lock file again (a lock replaced
# during the check is BLOCKED below).
cp -- "$lock" "$RUN/lock.manifest"
verify_tree() { # verify_tree DIR: DIR holds every locked file with its locked sha256
  (cd "$1" && sha256sum --check --quiet --strict "$RUN/lock.manifest") > /dev/null 2>&1
}

# ---- stage: lock (signature, pinned signer, content) -----------------------------------------
expect=(); [ -n "$expect_fp" ] && expect=(--expect-fingerprint "$expect_fp")
(
  rc=0
  "$HERE/spec_lock.sh" check "$proj" "$lock" "${expect[@]}" || rc=$?
  if [ "$rc" -eq 0 ] && [ -n "$git_base" ]; then
    changed=$(git -C "$proj" diff --name-only "$git_base" -- . ":(exclude)$FV_SOLUTION_REL" ; \
              git -C "$proj" ls-files --others --exclude-standard -- . ":(exclude)$FV_SOLUTION_REL")
    if [ -n "$changed" ]; then echo "BLOCKED: git diff gate vs $git_base:"; echo "$changed"; rc=2
    else echo "OK: git diff gate vs $git_base clean outside $FV_SOLUTION_REL"; fi
  fi
  exit "$rc"
) > "$RUN/stages/lock.log" 2>&1 && lock_rc=0 || lock_rc=$?
# The signer comes first in everything the gate prints: the operator checks this fingerprint.
grep -m1 '^SIGNER ' "$RUN/stages/lock.log" > "$RUN/signer.txt" || echo "SIGNER principal=- fingerprint=- pinned=- match=no" > "$RUN/signer.txt"
echo "SPEC-LOCK $(cat "$RUN/signer.txt")"
grep -q 'match=yes' "$RUN/signer.txt" || grep -E '^!!!' "$RUN/stages/lock.log" || true
note "run dir $RUN"
[ "$lock_rc" -eq 0 ] && ! cmp -s "$lock" "$RUN/lock.manifest" && { echo "BLOCKED: the lock file changed during the check" >> "$RUN/stages/lock.log"; lock_rc=2; }
[ "$lock_rc" -eq 0 ] && stage_set lock PASS || {
  rc=$lock_rc
  cat "$RUN/stages/lock.log"
  if [ "$rc" -eq 2 ]; then stage_set lock BLOCKED; finish 2 BLOCKED; fi
  stage_set lock ERROR; finish 3 ERROR
}

# ---- stage: lint ----------------------------------------------------------------------------
if "$HERE/solution_lint.sh" "$proj" > "$RUN/stages/lint.log" 2>&1; then stage_set lint PASS
else stage_set lint FAIL; fi

# ---- the held-out copy -----------------------------------------------------------------------
# The locked files are copied once, right after the check, into a content-addressed store named by the
# manifest's digest, made read-only, and verified against the manifest; the gate stages only from there,
# never again from the working tree (a writer between the check and the copy is caught here, BLOCKED).
if [ -n "${FV_TEST_HOOK_GATE_EDIT:-}" ]; then printf '\n-- FV_TEST_HOOK_GATE_EDIT\n' >> "$proj/$FV_TEST_HOOK_GATE_EDIT"; fi
STORE_DIR="${FV_LOCK_STORE:-$FV_ROOT/lock-store}"   # FV_LOCK_STORE: another store (controls)
STORE="$STORE_DIR/$(sha256sum < "$RUN/lock.manifest" | cut -d' ' -f1)"
{
  if [ ! -d "$STORE" ]; then
    mkdir -p "$STORE_DIR"; tmp=$(mktemp -d "$STORE_DIR/.new.XXXXXX")
    (cd "$proj" && cut -d' ' -f3- "$RUN/lock.manifest" | tr '\n' '\0' | xargs -0 cp --parents -t "$tmp")
    # The files read-only (their content is verified at every use anyway); the directories stay as created.
    if verify_tree "$tmp"; then find "$tmp" -type f -exec chmod a-w {} +; mv -T "$tmp" "$STORE" 2>/dev/null || rm -rf "$tmp"
    else echo "the working tree's trusted files differ from the lock after the check (a writer raced the gate)"; rm -rf "$tmp"; fi
  fi
  if [ -d "$STORE" ] && verify_tree "$STORE"; then echo "held-out copy $STORE: $(wc -l < "$RUN/lock.manifest") files match the lock"
  else echo "BLOCKED: no held-out copy matches the lock"; false; fi
} > "$RUN/stages/held_out.log" 2>&1 && stage_set held_out PASS || { stage_set held_out BLOCKED; cat "$RUN/stages/held_out.log"; finish 2 BLOCKED; }

# ---- staging: clean copies ------------------------------------------------------------------
stage_tree() { # stage_tree DEST WITH_SOLUTION
  local dest="$1"
  mkdir -p "$dest"
  # Trusted files from the held-out copy (read-only), never from the working tree.
  (cd "$STORE" && cut -d' ' -f3- "$RUN/lock.manifest" | tr '\n' '\0' | xargs -0 cp --parents --no-preserve=mode -t "$dest")
  (cd "$dest" && cut -d' ' -f3- "$RUN/lock.manifest" | tr '\n' '\0' | xargs -0 chmod a-w)
  if [ "$2" = yes ]; then
    mkdir -p "$dest/$FV_SOLUTION_REL"
    (cd "$proj" && find "$FV_SOLUTION_REL" -type f -name '*.lean' -print0 | xargs -0 -r cp --parents -t "$dest")
  fi
}
stage_tree "$RUN/trusted" no
stage_tree "$RUN/full" yes
stage_tree "$RUN/native" yes
if [ -n "${FV_TEST_HOOK_GATE_EDIT_STAGED:-}" ]; then
  chmod u+w "$RUN/trusted/$FV_TEST_HOOK_GATE_EDIT_STAGED"; printf '\n-- FV_TEST_HOOK_GATE_EDIT_STAGED\n' >> "$RUN/trusted/$FV_TEST_HOOK_GATE_EDIT_STAGED"
fi
# Every staged tree is re-hashed against the lock immediately before the builds (and again by gate_inner.sh).
bad_trees=""; for t in trusted full native; do verify_tree "$RUN/$t" || bad_trees+="$t "; done
if [ -n "$bad_trees" ]; then
  echo "BLOCKED: staged tree(s) differ from the lock: $bad_trees" > "$RUN/stages/staged.log"; stage_set staged BLOCKED
  cat "$RUN/stages/staged.log"; finish 2 BLOCKED
fi
echo "trusted, full, native: every locked file matches the lock" > "$RUN/stages/staged.log"; stage_set staged PASS
mkdir -p "$RUN/exports"
echo "$FV_PERMITTED_AXIOMS" > "$RUN/permitted_axioms.expected"

# ---- audit stages in a fresh network namespace ----------------------------------------------
if sudo -n true 2>/dev/null; then
  sudo -n unshare --net -- setpriv --reuid="$(id -u)" --regid="$(id -g)" --init-groups -- \
    env -i HOME="$HOME" USER="$USER" PATH="/usr/bin:/bin" FV_ROOT="$FV_ROOT" RUN="$RUN" \
    FV_CPUSET="$FV_CPUSET" FV_NICE="$FV_NICE" FV_JOBS="$FV_JOBS" \
    bash "$HERE/gate_inner.sh" > "$RUN/inner.log" 2>&1 || true
else
  echo "cannot create a network namespace (sudo -n unavailable)" > "$RUN/inner.log"
  stage_set netns ERROR
fi

# ---- verdict --------------------------------------------------------------------------------
any() { local want="$1"; shift; for s in "$@"; do [ "$(stage_get "$s")" = "$want" ] && return 0; done; return 1; }
AUDIT=(lint comparator_native export comparator_export con_leche con_ron con_leche_compare)
[ "$(stage_get staged)" = PASS ] || { cat "$RUN/stages/staged.log" 2>/dev/null; finish 2 BLOCKED; }
if [ "$(stage_get netns)" != PASS ]; then finish 3 ERROR; fi
if any FAIL "${AUDIT[@]}"; then finish 1 FAIL; fi
for s in "${AUDIT[@]}"; do [ "$(stage_get "$s")" = PASS ] || finish 3 ERROR; done
finish 0 PASS
