# Agent routing configuration (Modules 1 and 3)

Synthesis agents run on the agent host. Lean, the gate and the Tier-2 prover run on the gate
host (`FV_GATE_HOST` in `config/hosts.env`). Everything below crosses over `ssh $FV_GATE_HOST`.

## 1. lean-lsp MCP server (project scope only)

From the verification project's directory on the agent host (only directories the orchestrator names):

```sh
$AGENT_CLI mcp add lean-lsp -s project -- ssh -T -o BatchMode=yes $FV_GATE_HOST \
  '~/fv-harness/harness/scripts/lean_lsp_mcp.sh <project path on the gate host>'
```

This writes `.mcp.json` with the server name `lean-lsp`, so its tools appear as `mcp__lean-lsp__*`.
This replaces the spec's `$AGENT_CLI mcp add lean-lsp -s project uvx lean-lsp-mcp`, because Lean is
not on the agent host. The server is `lean-lsp-mcp==0.33.0`:
- PyPI, from github.com/oOo0oOo/lean-lsp-mcp, commit 7932203d;
- installed with uv 0.13.9 under `~/fv-harness/uv`; dependency freeze in `config/lean-lsp-mcp.freeze.txt`.

`scripts/lean_lsp_mcp.sh` runs it inside the synthesis sandbox:
- only `spec/solution/` and `.lake/` are writable;
- there is no network;
- the remote search tools (`lean_leansearch`, `lean_loogle`, `lean_leanfinder`, `lean_hammer_premise`) are removed via `LEAN_MCP_DISABLED_TOOLS`.

Smoke test: `python3 -I tests/mcp_smoke.py 8 -- ssh -T -o BatchMode=yes $FV_GATE_HOST '~/fv-harness/harness/scripts/lean_lsp_mcp.sh <project>'`.

## 2. Pre-flight build hook

`settings.synthesis.json` runs `scripts/preflight_lake_build.sh <project>` at session start and
before each subagent spawn (`PreToolUse` on `Agent|Task`), so `lake serve` starts warm.
- Replace `__PROJECT__` with the project path on the gate host.
- Merge the result into the agent's project settings file.
- The same file allows the `mcp__lean-lsp__*` tools.
- It also denies edits to `spec/challenge/**` and the build config, plus `git commit` and `git push`.

These permission rules cover local paths only. When the project lives on the gate host, the barriers
are the synthesis sandbox (read-only challenge) and the gate's lock stage (BLOCKED).

## 3. Policies

`synthesis-policy.md` goes into the system prompt of the Tier-1 planner and every prover or coder
subagent.

## 4. Tier-2 tool

`dispatch_local_prover(file, lemma_name, budget)` is:

```sh
ssh $FV_GATE_HOST '~/fv-harness/harness/prover/dispatch.sh --project <P> --file <F> --lemma <name> --budget <K> [--apply]'
```

Exit codes:
- 0: closed, and applied with `--apply`.
- 1: not closed within K samples × `TIER2_ROUNDS` repair rounds. This is a wall event: escalate to Tier 1.
- 3: error.

### Planning baseline (measured in dry run 02, Goedel-Prover-V2-8B IQ4_XS, a laptop RTX 3060 6 GB)

Use these figures to size budgets and to decide when to hand a stub to Tier 2 rather than spend
frontier tokens on it:

| Measure | Value |
|---|---|
| Throughput | 61 tok/s decode, 1,280 tok/s prompt, **1 slot** (K samples run sequentially) |
| Success per sample | **10.5 %** (2 of 19 samples), 2.9 % per model round (2 of 68) |
| Easy leaf (linear Nat arithmetic, one core lemma) | closed in 1–2 samples; **about 1.4 k tokens, 23 s** (`mul_min_le`); 5.5 k tokens, 97 s (`transfer_source_le`) |
| Hard leaf (nonlinear Nat bound) | **wall at 2 attempts × K = 8** (16 samples × 4 rounds, 155 k tokens, 48 min); split out the nonlinear fact as its own leaf |
| Mathlib reflex | all 63 compiled failures on the hard leaf used Mathlib-only tactics; the pre-compile filter now rejects these without compiling (`rounds_rejected_mathlib` in the result) |

Rules of thumb:
- Dispatch leaves that are linear arithmetic, or a single core lemma away from it.
- Decompose nonlinear goals in Tier 1 first, so that each leaf is one product or monotonicity fact.
- At 1 slot, K = 8 with 3 repair rounds costs up to about 25 minutes per attempt. The default is
  now 1 attempt × K = 4 per stub, with an immediate wall when every sample fails the same way
  (`docs/DESIGN-NOTES.md` §1); raise it per task with `formal_task.py set` only for leaves that are
  worth it. A leased 12 GB card with 4 slots cuts the time per attempt roughly 3×.

The endpoint is `config/tier2.env` (`TIER2_BASE_URL`, `TIER2_MODEL`, `TIER2_SLOTS`); moving it to
a leased card changes only that file. Start or stop the local endpoint with
`prover/tier2_server.sh start|stop|status`.
