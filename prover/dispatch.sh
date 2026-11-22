#!/usr/bin/env bash
# dispatch.sh — the harness tool dispatch_local_prover(file, lemma_name, budget).
#
#   prover/dispatch.sh --project DIR --file spec/solution/X.lean --lemma NAME --budget K [--apply]
#
# Runs prover/dispatch_local_prover.py inside the synthesis sandbox with network (to reach the
# Tier-2 endpoint): it can write only spec/solution/ and .lake/ of the project. From the agent
# host: ssh $FV_GATE_HOST '~/fv-harness/harness/prover/dispatch.sh --project ... --lemma ...'.
# Exit 0 closed, 1 not closed within budget (escalate to Tier 1), 3 error.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/../scripts/lib.sh"

proj=""; out=""
args=("$@")
while [ $# -gt 0 ]; do
  case "$1" in --project) proj="$2"; shift 2 ;; --out) out="$2"; shift 2 ;; *) shift ;; esac
done
[ -d "$proj/$FV_SOLUTION_REL" ] || die "usage: $0 --project DIR --file F --lemma NAME --budget K [--apply] [--out DIR]"
proj="$(cd "$proj" && pwd)"
mkdir -p "$proj/.lake"
# An --out outside the project must be bound writable, or the attempt logs land in the sandbox's
# private tmpfs and disappear when it exits.
outbind=()
if [ -n "$out" ]; then mkdir -p "$out"; outbind=(--rw "$(cd "$out" && pwd)"); fi
# The sandbox starts from an empty environment; carry TIER2_* overrides (endpoint moves) across.
fwd=()
while IFS='=' read -r k v; do fwd+=(--env "$k" "$v"); done < <(env | grep -E '^TIER2_[A-Z_]+=' || true)
sbx --ro "$proj" --rw "$proj/$FV_SOLUTION_REL" --rw "$proj/.lake" --ro "$FV_HARNESS_DIR" "${outbind[@]}" \
  --share-net --chdir "$proj" --env FV_ROOT "$FV_ROOT" "${fwd[@]}" -- \
  /usr/bin/python3 -I "$HERE/dispatch_local_prover.py" "${args[@]}"
