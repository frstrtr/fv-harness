# Design notes after the dry run

These notes record four changes and decisions that followed the review of the dry-run report
(`docs/DRY-RUN-REPORT-FV-01.md`).

## 1. Early wall: the Tier-2 escalation budget

**The problem.** Dry run 02 spent 48 of its 53 minutes on one nonlinear leaf (`feeOf_le`):
2 attempts × K = 8 samples × 4 rounds, then a wall. Tier 1 split that leaf in seconds.

**The rule now.**
- **Per task.** The budget is a setting of each [FORMAL] task, kept in its `state.json`:
  - `budget`: K samples per attempt;
  - `max_attempts`: attempts per stub;
  - `same_failure_wall`: on or off.
- **Setting it.** Give it at `formal_task.py init --budget K --max-attempts N --same-failure-wall on|off`.
  Change it at any time before CLOSED with `formal_task.py set TASK ...`. Each change is logged in the task history.
- **Defaults.** They come from `config/tier2.env`:
  - `TIER2_BUDGET=4`;
  - `TIER2_MAX_ATTEMPTS=1`;
  - `TIER2_SAME_FAILURE_WALL=1`.

  With these defaults a stub walls after **1 attempt × K = 4** (previously 2 × 8).
- **Same-failure wall.** If every sample of an attempt failed the same way, the stub walls **at
  once**, even when attempts remain. The dispatcher's `same_failure` (in
  `prover/dispatch_local_prover.py`) decides this from how each sample's final round failed:
  - **Same signature.** Every sample ended with the same failure signature:
    - all Mathlib-rejected;
    - all the same policy violation;
    - all without usable code;
    - the same set of compiler errors;
    - the same set of unsolved goals.
  - **Common unsolved goal.** Every sample left one common unsolved goal (whitespace
    ignored) that is not the lemma's own statement.

  The rule needs at least 2 samples that ran. It does not apply if a sample closed, was cancelled, or hit an endpoint error.

**Counters.**
- Each dispatch report has `failure_signatures` (how many samples ended which way) and `same_failure`.
- Each stub keeps its dispatch summaries and a `wall_reason`, either
  `budget spent: N x K=…` or `same failure in every sample: …`.
- The task keeps `tier2_stats`:
  - `dispatches`, `samples`, `rounds`, `completion_tokens`, `seconds`, `closed`;
  - `walls_budget`, `walls_same_failure`;
  - `attempts_saved`: attempts not spent because of the same-failure wall.
- `closure.json` carries the stats under `tier2`; `closure.md` has a "Tier 2" section.

**Back-test on the dry-run logs** (the raw attempt logs are not shipped). It applies the Mathlib
pre-compile filter, which arrived after dry run 02, to the logged candidates:

| Dispatch | Samples | How they ended | Same failure? |
|---|---|---|---|
| run 02 `feeOf_le` attempt 1 | 8 | 8 Mathlib-rejected | **yes**, also on the first 4: the wall comes after 4 samples, and attempt 2 (1,375 s) is never spent |
| run 02 `feeOf_le` attempt 2 | 8 | 7 Mathlib-rejected, 1 no code | no |
| run 02 `transfer_source_le` | 2 | closed at sample 1 | n/a |
| run 01 `feeOf_le` attempts 1, 2 | 8, 8 | mixed, with endpoint errors (the defect fixed before run 02) | no |

On run 02 the new default walls `feeOf_le` after 4 samples instead of 16. That is roughly 12
minutes at the measured rate, against 48.

The rehearsal (`tests/state_machine_rehearsal.sh`) checks both wall paths with the mock endpoint:
- every sample without code: a same-failure wall after 1 of 3 attempts;
- every sample failing differently: a budget wall after 2 of 2 attempts.

## 2. CI design note: the signer fingerprint as a literal in the workflow

This is for when the CI job is wired; the workflows belong to the target repository's maintainers. The job's check must be
exactly `scripts/spec_lock.sh` plus the pin. The expected signer fingerprint goes into the
workflow file **as a literal**, passed with `--expect-fingerprint`, instead of being read only from
`config/signer_pins.txt`:

```yaml
- name: Spec lock (operator-signed)
  run: >
    scripts/spec_lock.sh check <project dir> locks/<name>.sha256
    --expect-fingerprint SHA256:<the fingerprint the operator stated>
```

**Why.** If the operator removes the `workflow` scope from the agents' token, an agent can no
longer push a change to a workflow file. A pin swap would then need exactly such a change: editing
`config/signer_pins.txt` alone no longer moves what CI expects. The swap of control C5d(ii) (lock,
signature, allowed signers and pin all replaced) then fails in CI unless someone with workflow
rights also edits the literal.

**What it does not close.** The `repo` scope still lets its holder change branch protection on
repositories the identity administers. Such a holder can drop the required check or merge around
it. So this hardens C5d(ii) but does not close it. The final assurance stays the operator's
fingerprint check on the first line of every CLOSE report (README, "Residual risk").

## 3. Fixture corpus: the dry-run units

COUPLE in dry run 02 reported `new_units_added: 45`. In libFuzzer's log these are 1 NEW and 44
REDUCE events (smaller inputs that replace existing ones with the same features).
- **What was kept.** 39 distinct files survive in that run's `new_corpus`; later reductions
  superseded 6. The corpus merge added 1 of them to the deployed corpus, but a redeploy has since
  reset it to the repository's 67 files.
- **What is committed.** All 39 surviving files go into the **fixture** corpus
  (`fixtures/conservation_cpp/fuzz/corpus`, 67 → 106 files) for their regression value. Each file
  name equals the SHA-1 of its content.
- Nothing from the fixture goes to a product repository.

## 4. Mathlib: deferred

Projects stay core-only (Lean 4.36 core library plus `omega`) for now. Adding Mathlib would:
- change the locked `lakefile.toml` and `lake-manifest.json`, which are the operator's side and
  need a new signature;
- grow the inert exports that con-leche and con-ron check by orders of magnitude.

**Revisit only if** Phase 1 leaves stall with core tactics, `omega` and Tier-1 splits. Before
adding it, estimate the export size and the con-* check time on a trial build.

Until then the core-only prompt note and the pre-compile Mathlib filter in the dispatcher stay in
force.
