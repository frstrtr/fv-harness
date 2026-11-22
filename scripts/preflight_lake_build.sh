#!/usr/bin/env bash
# preflight_lake_build.sh PROJECT — build a verified project once, inside the synthesis sandbox,
# before Lean subagents start, so lean-lsp-mcp's `lake serve` does not time out during MCP
# initialisation. Builds the trusted libraries first (they must succeed), then the solution
# (sorry stubs are expected during DECOMPOSE/DISCHARGE; its errors are reported, not fatal).
#
# Exit 0 when the trusted part builds; 3 otherwise. Prints a one-line summary last.
set -uo pipefail
. "$(dirname "$0")/lib.sh"

proj="${1:-}"
[ -d "$proj/$FV_SOLUTION_REL" ] || die "usage: $0 PROJECT"
proj="$(cd "$proj" && pwd)"
cfg="$proj/comparator.json"
chal=$(jq -r .challenge_module "$cfg"); sol=$(jq -r .solution_module "$cfg")
SB="$(dirname "$0")/synth_sandbox.sh"
LAKE="$LEAN_TC/bin/lake"

t0=$(date +%s)
if ! "$SB" --project "$proj" -- "$LAKE" build "$chal"; then
  echo "preflight: challenge '$chal' does not build"; exit 3
fi
"$SB" --project "$proj" -- "$LAKE" build "$sol" > "$proj/.lake/preflight-solution.log" 2>&1
rc=$?
sorries=$(grep -c "declaration uses 'sorry'\|declaration uses \`sorry\`" "$proj/.lake/preflight-solution.log")
errors=$(grep -c '^error:' "$proj/.lake/preflight-solution.log")
echo "preflight: $chal built; $sol build exit=$rc, $sorries sorry warning(s), $errors error line(s); $(( $(date +%s) - t0 ))s"
exit 0
