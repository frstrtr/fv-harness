#!/usr/bin/env bash
# synth_sandbox.sh — run a synthesis-side command (lake build, prover client, LSP server) with
# spec/challenge and every other trusted file read-only. Only spec/solution/ and .lake/ are
# writable. No network unless --net (needed only to reach the Tier-2 prover endpoint).
#
#   synth_sandbox.sh --project DIR [--net] -- CMD ARGS...
#
# This is one layer of the trust boundary. The authoritative one is the gate's lock stage:
# anything that reaches spec/challenge/ by another route is BLOCKED by verify_proof.sh.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

proj=""; net=()
while [ $# -gt 0 ] && [ "$1" != "--" ]; do
  case "$1" in
    --project) proj="$2"; shift 2 ;;
    --net) net=(--share-net); shift ;;
    *) die "unknown argument $1" ;;
  esac
done
[ "${1:-}" = "--" ] && [ -d "$proj/$FV_SOLUTION_REL" ] || die "usage: $0 --project DIR [--net] -- CMD ARGS..."
shift
proj="$(cd "$proj" && pwd)"
mkdir -p "$proj/.lake"
sbx --ro "$proj" --rw "$proj/$FV_SOLUTION_REL" --rw "$proj/.lake" --chdir "$proj" "${net[@]}" -- "$@"
