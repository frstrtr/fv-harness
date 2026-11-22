# HARNESS-UPGRADE-FV-01: dry-run report

**Result: the full pipeline closed on the minimal arithmetic invariant fixture.** It went
SPEC_LOCK → DECOMPOSE → DISCHARGE → wall event → Tier-1 re-decomposition → DISCHARGE → AUDIT
(all 10 gate stages PASS) → COUPLE (10^6 differential fuzz runs PASS) → CLOSED.
- Task: `dryrun-conservation-02`, harness commit `90c4966` (re-decomposition script added in `7ec21d8`).
- Host: the gate host, 2026-11-22 00:29:32 → 01:22:42 +04 (53 min 10 s).
- `closure.json` sha256: **`ca77883a39528bccd0dcd2ba1290e5b219769a0bab60456d373322ecc71ffddc`**
  (the original bundle; `tests/dry_run/evidence/closure.json` is a copy with local paths replaced by
  `$FV_ROOT`, so its hash differs).

> **Correction to the spec's threat model (Lean 4.36).** Lean v4.36.0 no longer has
> `Lean.trustCompiler`, `Lean.reduceBool`, `Lean.ofReduceBool` or `Lean.ofReduceNat`. `#check`
> reports unknown identifiers, so the hard-fails the spec names cannot even be written.
> `native_decide` now emits a per-use auxiliary axiom (`<decl>._native.native_decide.ax_N_M`).
> comparator rejects it ("Illegal axiom") and con-leche and con-ron decline it ("non-standard axiom").
> A solution that *re-declares* `axiom Lean.trustCompiler : True` is installed as sound by
> con-leche and con-ron by design (`ConLeche/Kernel/TrustAxioms.lean`). Only comparator's axiom
> whitelist rejects it. The gate's FAIL verdict therefore rests on comparator for that case
> (Control `c3b_trustcompiler`).

## 1. Fixture

`fixtures/conservation`, lock manifest digest `64e0f8f79ee7b9abab6b94b3add35c36602463db041cb5c7fb626cf0bb6173e2`.

The model is a ledger transfer: move `min amt a` out of `a`, pay a fee of
`x · min(bps, 10000) / 10000` (rounded down) into a pool, and credit the rest to `b`.

Challenge theorems:
- `FV.transfer_conserves`: `(transfer l amt bps).total = l.total`
- `FV.transfer_source_le`

The oracle `FVSpec.Oracle` exports the transfer with C linkage, and the production C++ is
`fixtures/conservation_cpp/impl/ledger.hpp`.

The fixture was re-locked once by the gate operator as its spec author, approved by the orchestrator for the
fixture only. The old digest was `56f9dad1…`; the reason is the fee model needed for Control 6
(`locks/conservation.history`). Real projects are locked only by their human owner.

## 2. State machine timeline (`scripts/formal_task.py`)

| Time (+04) | Transition | Note |
|---|---|---|
| 00:29:32 | SPEC_LOCK → DECOMPOSE | lock verified, digest recorded |
| 00:29:32 | DECOMPOSE → DISCHARGE | skeleton by Tier 1 (`tests/dry_run/skeleton`): 2 stubs, `feeOf_le` and `transfer_source_le` |
| 01:18:55 | DISCHARGE → DECOMPOSE | **wall event**: `feeOf_le` not closed after 2 attempts × budget 8 |
| 01:19:40 | DECOMPOSE → DISCHARGE | Tier-1 re-decomposition (`tests/dry_run/redecompose_feeOf_le.py`) |
| 01:20:09 | DISCHARGE → AUDIT | all stubs closed by Tier 2 |
| 01:20:40 | AUDIT → COUPLE | gate PASS (31 s) |
| 01:22:42 | COUPLE → CLOSE → CLOSED | fuzz PASS (campaign 118.9 s); closure bundle written |

The Tier-1 re-decomposition split the nonlinear product bound `x * min bps 10000 ≤ x * 10000`
out as a new leaf `mul_min_le` and proved `feeOf_le` from it with `unfold feeOf; omega`. Every
failed candidate either used Mathlib-only tactics or never stated that bound.

## 3. Tier 2 (Goedel-Prover-V2-8B IQ4_XS, llama.cpp b12387, RTX 3060 Laptop 6 GB)

Settings: one slot, 8,192-token context with q8_0 KV cache, VRAM 4.95 of 6.14 GB.
Measured throughput: 61 tok/s decode, 1,280 tok/s prompt. Budget K = 8 samples per attempt;
each sample gets up to 3 compiler-feedback repair rounds (4 rounds total).

### Per-stub results, dry run 02

| Stub | Attempt | Samples run | Rounds | Closed | Winning sample | Completion tokens | Wall time |
|---|---|---|---|---|---|---|---|
| `transfer_source_le` | 1 | 2 | 3 | **yes** | 1 (repair round 1) | 5,485 | 96.5 s |
| `feeOf_le` | 1 | 8 | 32 | no | — | 80,160 | 1,489.9 s |
| `feeOf_le` | 2 | 8 | 32 | no → **wall event** | — | 74,631 | 1,374.7 s |
| `mul_min_le` (after re-decomposition) | 1 | 1 | 1 | **yes** | 0 (first round) | 1,359 | 23.2 s |

- Totals: Tier 2 ran 19 samples (68 model rounds) and produced 161,635 tokens in 2,984 s (49.7 min).
- Success rate: 2/19 samples (10.5%) and 2/68 rounds (2.9%). By stub, 2 of 3 dispatched leaves closed on their first attempt; 1 walled and went back to Tier 1, as designed.
- `feeOf_le` failure breakdown (64 rounds): 89 "unsolved goals" and 63 "unknown tactic" errors (Mathlib tactics such as `nlinarith`, despite the core-only note). There were also unknown names: `Nat.min_lt_iff`, `mul_comm`, `min_le_right`.

### Planning baseline for Tier-2 routing

Also recorded in `agent-config/README.md`.
- 61 tok/s on 1 slot, with K samples sequential.
- **10.5 % success per sample** (2/19).
- An easy leaf costs **about 1.4 k tokens** (`mul_min_le`: 1,359 tokens, 23 s).
- A nonlinear Nat bound **walls at 2 × 8** (154,791 tokens, 48 min). Tier 1 must split such goals before dispatch.

Follow-up after the orchestrator's review: a pre-compile filter rejects candidates that use Mathlib-only
tactics in a core-only project and sends them straight to repair. It counts them separately
(`rounds_rejected_mathlib`). Back-tested on run 02, it would have rejected all 63 compiled
`feeOf_le` failures: the same 63 the compiler reported as "unknown tactic".

### Dry run 01 (06b6d2d)

The same skeleton reached the same wall event on `feeOf_le`:
- 16 samples, 70,521 tokens, 1,360 s;
- `transfer_source_le` closed at sample 5 (6 samples, 19,820 tokens, 363 s).

It exposed two dispatcher defects, fixed in `90c4966` before dry run 02:
1. Repair rounds resent the previous reply, including thousands of tokens of reasoning, and overflowed the 8,192-token context. The result was 8 × HTTP 400: "request (8373 tokens) exceeds the available context size". Repairs are now single-turn (problem + previous code + errors); dry run 02 had 0 endpoint errors.
2. 43 "unknown tactic" errors: the prompt never said the project is core Lean. Projects without Mathlib now get a core-only note. The model still mostly ignores it (point 7 in §6).

The rehearsal (`tests/state_machine_rehearsal.sh`, mock endpoint, every transition) had caught
an earlier gap. A fresh working copy has no built imports, so every candidate failed on
`unknown module prefix`. DISCHARGE now runs the pre-flight build, and the dispatcher stops with a
setup error (exit 3) instead of spending its budget.

## 4. AUDIT: gate verdict (`scripts/verify_proof.sh`; verdict `PASS`, exit 0)

| Stage | Verdict | Evidence |
|---|---|---|
| lock | PASS | 9 trusted files match lock `64e0f8f7…` |
| lint | PASS | no forbidden constructs; files ≤ 1000 lines |
| netns | PASS | audit ran in a fresh network namespace (only `lo`) |
| config | PASS | `permitted_axioms` = {propext, Quot.sound, Classical.choice} |
| comparator_native | PASS | `lake comparator --paranoid`: Lean, Lean-paranoid, lean4lean, nanoda, con-leche, con-ron kernels accept; "Your solution is okay!" |
| export | PASS | challenge export (solution-free tree) `96c6c5e6…`, solution export `5f9f938a…` |
| comparator_export | PASS | `lake comparator --*-from-export` on the gate's own exports |
| con_leche | PASS | `con-leche: accepted 1426 declarations (--verified)` (bundled b46cb0e6) |
| con_ron | PASS | `con-ron: accepted 1426 declarations (--verified)` (bundled cb54c9a4) |
| con_leche_compare | PASS | con-leche master 5ea446d5 `--compare`: accepted 484 declarations, 2 axioms justified by the solution; `FV.transfer_conserves` and `FV.transfer_source_le` justified |

## 5. COUPLE: differential fuzz (`fuzz/run_fuzz.sh`; verdict `PASS`)

- 1,000,000 executed inputs in 118.9 s (8,474 exec/s), 45 new units.
- The corpus replay passed first.
- The oracle was built from the locked challenge only and linked against the production `ledger.hpp` (sha256 `49d98716…`) under libFuzzer + ASan + UBSan.
- LeakSanitizer had no suppression file. The Lean runtime initialisation is exempted by `__lsan::ScopedDisabler`; the positive leak control `c7_lsan_leak` proves production leaks are still reported.
- Note: COUPLE merged the 45 new units into the deployed corpus on the gate host. They are not committed to the repo.

Acceptance controls (spec §4): suite `tests/harness_fv_controls/run_controls.sh` on commit
`9479b34`, exit 0. All 12 controls behave as specified: C1 (gate + 10^6 fuzz), C2, C3a/b/c,
C4a/b, C5a/b, C6 (drift caught in 0.022 s), and C7 (leak reported at `ledger.hpp:25:23`).
The latest suite summary is in `tests/harness_fv_controls/evidence/summary.txt`.

## 6. Where the build differs from the operator's spec

1. **The trust axioms are gone in Lean 4.36** (see the box at the top). `native_decide` is rejected by every checker. A re-declared `axiom Lean.trustCompiler : True` is caught only by comparator.
2. **con-leche and con-ron do not check statement equality.** They check consistency, so a weakened or shadowed statement passes them (`c4a`, `c4b`). Statement equality is carried by comparator, run both natively and on the gate's own exports, and by **con-leche `--compare`**. `--compare` exists only on con-leche master (≥ 4480384d; built at 5ea446d5), not in the con-leche bundled with Lean 4.36 (b46cb0e6). **con-ron has no `--compare`** at its pin or on master.
3. **comparator**: the standalone `leanprover/comparator` is archived. The gate uses `lake comparator` (core Lake since 4.35, sandboxed with bwrap). It checks structural identity of the statements' dependency closures, which is stricter than the spec's "definitional equality".
4. **lean4export**: the standalone tool has no v4.36.0 tag. The gate uses the `leanexport` bundled with Lean, which `lake comparator` also uses.
5. **lean-lsp-mcp**: the spec names `project-numina/lean-lsp-mcp`, an untagged copy that is not on PyPI. `uvx lean-lsp-mcp` installs `oOo0oOo/lean-lsp-mcp`, pinned here at 0.33.0. It is registered as `lean-lsp` over `ssh $FV_GATE_HOST` inside the synthesis sandbox, with the remote search tools removed, rather than as a bare `uvx` on the agent host. It is registered only in the gate operator's project directory.
6. **Tier-2 model provenance**: Goedel-Prover-V2-8B in a **community** GGUF quantization (mradermacher, revision 43fab68e, sha256 `e948e3a8…2602`). It is not first-party; the base weights are Goedel-LM revision dfd02e62, Apache-2.0.
7. **Tier-2 capacity**: the spec's parallel best-of-K with K = 16..64 does not fit the 6 GB laptop card. It runs one slot, so K samples run sequentially, and the dry run used K = 8. The model was trained on Lean 4.9-era Mathlib: it keeps using Mathlib tactics and names, and it walled on a nonlinear Nat bound. Production K would need a leased 12 GB card; that is the operator's call.
8. **Tier-2 server lifetime**: it runs detached with a pidfile, not as a systemd user unit, because the gate user has no lingering session. Consequences: no cgroup RAM cap (measured peak 4.5 GB on a 57 GB host), and the server stops at reboot. **Proposal**, if it must survive logouts long-term: the operator enables linger for the gate user, and the server becomes a user unit with `MemoryMax` and `CPUAffinity`.
9. **Control 6** needed rounding in the model, hence the fee model and the fixture re-lock (§1).
10. **COUPLE in CI**: `run_fuzz.sh --time 60` is the CI form, but no CI workflow is wired into any repository. The target repository's CI belongs to its maintainers.
11. **Trust anchor of SPEC_LOCK**: at the time of the dry run the lock was an unsigned SHA-256 manifest in `locks/`. Every agent ran as the same OS user and the same repository identity, so an agent could have replaced a challenge and its lock together. The operator-signed lock (ssh-keygen `-Y` signatures, signer fingerprint as the first line of every closure report, controls C5c and C5d) was added right after; README "Signed SPEC_LOCK and the residual risk" states what remains.
12. **Synthesis-side sandboxing** covers tools the harness launches: the LSP server, the dispatcher, and builds via `synth_sandbox.sh`. An agent's own file edits on the agent host are limited only by the agent's own permission rules and, decisively, by the gate's lock stage (BLOCKED).

## 7. Artifacts

The raw run directories (every prompt reply, candidate, compiler log, stage log and export) stay
with the reference deployment. This repository ships neutral summaries:

| What | Where |
|---|---|
| Dry run 02 closure bundle | `tests/dry_run/evidence/closure.json`, `closure.md` |
| Control suite and state-machine rehearsal | `tests/harness_fv_controls/evidence/summary.txt`, `rehearsal.log` |
| Host prerequisites and versions | `README.md` § Host prerequisites |
