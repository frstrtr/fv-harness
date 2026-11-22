#!/usr/bin/env bash
# spec_lock.sh — record, sign or verify the SPEC_LOCK of a project's trusted files.
#
#   spec_lock.sh lock  PROJECT LOCKFILE   write the manifest (LOCKFILE = locks/<name>.sha256)
#   spec_lock.sh sign  LOCKFILE KEY       sign it: ssh-keygen -Y sign -n fv-spec-lock -> LOCKFILE.sig
#                                         (real projects: the operator, on their own terminal, with a
#                                         key that never leaves it)
#   spec_lock.sh check PROJECT LOCKFILE [--expect-fingerprint SHA256:...]
#                                         exit 0 if signed, pinned and unchanged; 2 (BLOCKED) otherwise
#
# Trusted = every file in PROJECT except .lake/, .git/ and spec/solution/. That covers
# spec/challenge/, the lakefile, lean-toolchain, lake-manifest.json and comparator.json. The
# content check is set equality: a changed, added or removed trusted file is BLOCKED.
#
# check, in order. Any failure is BLOCKED, before anything is audited:
#   1. LOCKFILE.sig verifies (namespace fv-spec-lock) against <name>.allowed_signers next to the lock.
#   2. The signer's key fingerprint equals the pin for <name> in config/signer_pins.txt (or
#      FV_SIGNER_PINS, or --expect-fingerprint). Missing pin = BLOCKED.
#   3. The project's trusted files equal the manifest.
# The first output line is always "SIGNER principal=... fingerprint=... pinned=... match=...".
#
# Residual risk: every agent runs as the same OS user under one GitHub identity, so an agent that
# replaces the challenge, lock, signature, allowed_signers AND the pin file passes this check. The
# printed fingerprint then differs from the one the operator stated out-of-band; checking it on
# every CLOSE report is the final assurance (see README).
set -euo pipefail
. "$(dirname "$0")/lib.sh"
NS="fv-spec-lock"

manifest() { # manifest PROJECT -> "sha256  relpath" lines, sorted
  local p="$1"
  [ -d "$p/spec/challenge" ] && [ ! -L "$p/spec/challenge" ] || { echo "spec/challenge missing or a symlink" >&2; return 2; }
  if [ -e "$p/$FV_SOLUTION_REL" ] && { [ -L "$p/$FV_SOLUTION_REL" ] || [ ! -d "$p/$FV_SOLUTION_REL" ]; }; then
    echo "$FV_SOLUTION_REL is not a plain directory" >&2; return 2
  fi
  local odd
  odd=$(cd "$p" && find . \( -path ./.lake -o -path ./.git -o -path "./$FV_SOLUTION_REL" \) -prune \
          -o ! -type f ! -type d -print)
  [ -z "$odd" ] || { echo "non-regular trusted entries (symlinks, devices):" >&2; echo "$odd" >&2; return 2; }
  (cd "$p" && find . \( -path ./.lake -o -path ./.git -o -path "./$FV_SOLUTION_REL" \) -prune \
      -o -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum) | sed 's#  \./#  #'
}

banner() { printf '%s\n' "==================================================================" "!!! $* !!!" \
  "=================================================================="; }

verify_signature() { # verify_signature LOCK -> sets PRINCIPAL and FINGERPRINT; returns 2 on failure
  local lock="$1" sig="$1.sig" signers="${1%.sha256}.allowed_signers" out
  PRINCIPAL="-"; FINGERPRINT="-"
  [ -f "$sig" ] || { MSG="unsigned lock: $sig not found"; return 2; }
  [ -f "$signers" ] || { MSG="no allowed-signers file: $signers"; return 2; }
  PRINCIPAL=$(ssh-keygen -Y find-principals -s "$sig" -f "$signers" 2>/dev/null | head -1) || true
  [ -n "$PRINCIPAL" ] || { PRINCIPAL="-"; MSG="signature is not by any key in $signers"; return 2; }
  if ! out=$(ssh-keygen -Y verify -f "$signers" -I "$PRINCIPAL" -n "$NS" -s "$sig" < "$lock" 2>&1); then
    MSG="bad signature: $out"; return 2
  fi
  FINGERPRINT=$(sed -n 's/.* key \(SHA256:[A-Za-z0-9+/=]*\).*/\1/p' <<< "$out" | head -1)
  [ -n "$FINGERPRINT" ] || { FINGERPRINT="-"; MSG="could not read the signer fingerprint: $out"; return 2; }
}

pinned_fingerprint() { # pinned_fingerprint NAME -> the pinned fingerprint or nothing
  local pins="${FV_SIGNER_PINS:-$FV_HARNESS_DIR/config/signer_pins.txt}"
  [ -f "$pins" ] && awk -v n="$1" '$1 == n { print $2; exit }' "$pins"
}

cmd="${1:-}"
case "$cmd" in
  lock)
    proj="${2:-}"; lock="${3:-}"
    [ -d "$proj" ] && [ -n "$lock" ] || { echo "usage: $0 lock PROJECT LOCKFILE" >&2; exit 3; }
    manifest "$proj" > "$lock.tmp" || { rm -f "$lock.tmp"; exit 3; }
    mv "$lock.tmp" "$lock"; rm -f "$lock.sig"   # a new manifest needs a new signature
    echo "locked $(wc -l < "$lock") trusted files; manifest digest $(sha256sum "$lock" | cut -d' ' -f1)"
    echo "now sign it: ssh-keygen -Y sign -f <key> -n $NS $lock"
    ;;
  sign)
    lock="${2:-}"; key="${3:-}"
    [ -f "$lock" ] && [ -f "$key" ] || { echo "usage: $0 sign LOCKFILE KEY" >&2; exit 3; }
    rm -f "$lock.sig"
    ssh-keygen -q -Y sign -f "$key" -n "$NS" "$lock"
    echo "signed $lock -> $lock.sig ($(ssh-keygen -lf "$key" | awk '{print $2}'))"
    ;;
  check)
    proj="${2:-}"; lock="${3:-}"; expect=""
    [ "${4:-}" = "--expect-fingerprint" ] && expect="${5:-}"
    [ -d "$proj" ] && [ -f "$lock" ] || { echo "usage: $0 check PROJECT LOCKFILE [--expect-fingerprint FP]" >&2; exit 3; }
    name="$(basename "${lock%.sha256}")"
    pin="${expect:-$(pinned_fingerprint "$name")}"
    MSG=""
    if ! verify_signature "$lock"; then
      echo "SIGNER principal=$PRINCIPAL fingerprint=$FINGERPRINT pinned=${pin:-none} match=no"
      banner "SPEC-LOCK SIGNATURE INVALID"; echo "BLOCKED: $MSG"; exit 2
    fi
    if [ -z "$pin" ]; then
      echo "SIGNER principal=$PRINCIPAL fingerprint=$FINGERPRINT pinned=none match=unpinned"
      banner "SPEC-LOCK SIGNER NOT PINNED"; echo "BLOCKED: no pinned fingerprint for '$name'"; exit 2
    fi
    if [ "$FINGERPRINT" != "$pin" ]; then
      echo "SIGNER principal=$PRINCIPAL fingerprint=$FINGERPRINT pinned=$pin match=no"
      banner "SPEC-LOCK SIGNER FINGERPRINT MISMATCH: signed by $FINGERPRINT, pinned $pin"
      echo "BLOCKED: the lock is not signed by the pinned key"; exit 2
    fi
    echo "SIGNER principal=$PRINCIPAL fingerprint=$FINGERPRINT pinned=$pin match=yes"
    now=$(mktemp); trap 'rm -f "$now"' EXIT
    if ! manifest "$proj" > "$now"; then echo "BLOCKED: trusted tree is malformed"; exit 2; fi
    if diff -u "$lock" "$now" > /dev/null; then
      echo "OK: $(wc -l < "$lock") trusted files match signed lock $(sha256sum "$lock" | cut -d' ' -f1)"
    else
      echo "BLOCKED: trusted files differ from the signed lock"
      diff -u --label lock --label now "$lock" "$now" | grep -E '^[-+][^-+]' || true
      exit 2
    fi
    ;;
  *) echo "usage: $0 lock|sign|check ..." >&2; exit 3 ;;
esac
