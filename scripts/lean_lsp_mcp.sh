#!/usr/bin/env bash
# lean_lsp_mcp.sh PROJECT — start lean-lsp-mcp (stdio MCP server) for a verified project, inside
# the synthesis sandbox: spec/challenge and all trusted files read-only, only spec/solution/ and
# .lake/ writable, no network. The remote search tools are removed from the tool list as well
# (LEAN_MCP_DISABLED_TOOLS), so project text never leaves the host.
#
# Registered at project scope on the agent host as (see agent-config/README.md):
#   $AGENT_CLI mcp add lean-lsp -s project -- ssh -T -o BatchMode=yes $FV_GATE_HOST \
#     '~/fv-harness/harness/scripts/lean_lsp_mcp.sh <project path on the gate host>'
#
# Run scripts/preflight_lake_build.sh PROJECT first so that `lake serve` starts warm.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

proj="${1:-}"
[ -d "$proj/$FV_SOLUTION_REL" ] || die "usage: $0 PROJECT (with spec/solution/)"
proj="$(cd "$proj" && pwd)"
TOOL="$FV_ROOT/uv/tools/lean-lsp-mcp"
[ -x "$TOOL/bin/lean-lsp-mcp" ] || die "lean-lsp-mcp not installed under $TOOL"

REMOTE_TOOLS="lean_leansearch,lean_loogle,lean_leanfinder,lean_hammer_premise"
mkdir -p "$proj/.lake"
sbx --ro "$proj" --rw "$proj/$FV_SOLUTION_REL" --rw "$proj/.lake" --ro "$TOOL" \
  --chdir "$proj" \
  --env LEAN_PROJECT_PATH "$proj" \
  --env LEAN_MCP_DISABLED_TOOLS "$REMOTE_TOOLS" \
  --env LEAN_LOG_LEVEL WARNING \
  -- "$TOOL/bin/lean-lsp-mcp"
