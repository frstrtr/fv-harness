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

## 5. Edge-case classification: what a reviewer sees, and what it is not

**What it is for.** A PASS over 10^6 runs says nothing about inputs the generator never made. The
classifier tells a reviewer which behaviours the campaign actually exercised. It also tells them
which it did not.

**Where it runs.** In a separate replay after the campaign (`fuzz/run_fuzz.sh` step 6). It uses a
**separate executable**: `add_diff_fuzzer(<name>)` builds two from the same sources.
- `<name>` is the verdict binary. It is compiled **without** any classify code and without
  `classes.hpp`.
- `<name>_classify` is compiled with `-DFV_CLASSIFY_BUILD`. It decodes each corpus input exactly
  as the campaign did, walks it through the Lean oracle only, records classes and never compares.

So nothing at run time (an exported variable, a static constructor in the binding or in linked
code) can switch the verdict binary into a no-compare mode: that code is not in it.
- `run_fuzz.sh` also clears the classify variables.
- It refuses, with ERROR, any replay, campaign or merge log carrying the classify build's
  start-up line.
- Control `c13_classify_env` runs a drifting implementation with those variables exported and
  must still FAIL. It also checks with `nm` that the verdict binary lacks the classify marker.

Consequently a class is computed from the input and the oracle's output, never from the
implementation.

**Labels only.** Classification never decides PASS/FAIL:
- the verdict is fixed before it runs;
- a failure inside it is recorded as an error string;
- the verdict code is unchanged.

The class predicates in `classes.hpp` live outside the signed lock. They are recorded by sha256 in
`fuzz.json` and the closure, and printed with their source in `closure.md` and the review deck,
so the reviewer reads what each class checks.

**Classes.**
- **Generic** (from the binding's `describe()`):
  - field values 0, 1, max, max−1, 2^k or 2^k±1 (signed: −1, 0, 1, min, max);
  - collections empty, single, with equal elements;
  - divisions exact vs remainder = divisor−1, and divisor 0.
- **Outcome labels:** informational.
- **Domain classes:** the spec author's `FV_CLASS` predicates.
- A step with no generic or domain class is **regular**.

**Outputs.**
- the class × inputs × steps × % table in `fuzz.json` (`classes`) and `closure.json`
  (`edge_cases`);
- a **NOT EXERCISED** list, first in `closure.md` and in the deck;
- `classify/review_deck.md`: the smallest input per class, decoded step by step with the oracle's
  output;
- on FAIL, every reproducer's classes (`finding_classes`).

**First result.** On the risk-limit example the classifier showed straight away what the PASS
hid. The generator starts with `limit = 0` in about 70 % of inputs. It never produces a position
or open quantity near 2^64. Its own first domain class also had a bug: `headroom + 1` wrapped in
64-bit C++ and matched `q = 0`. Predicates now use `fvfuzz::u128` where sums can pass 2^64.

**What "NOT EXERCISED" means today.** The replay classifies the persisted corpus. libFuzzer keeps
only inputs that add code coverage. An edge case the campaign generated many times can still be
absent, because no input carrying it added coverage. On the fixture, "fee rate exactly at the
cap" is listed although 10,000 is one of the generator's favoured values. Read each entry as "not
shown to be covered". Add a seed for it, or widen the generator. A class-guided retention pass is
a proposed follow-up: a separate process that keeps one input per class, so absence would mean
"never generated".

**Control.** `c9_edge_not_exercised` caps the fixture generator's fee rate at 10,000 basis
points. The class "fee rate above the cap" must be NOT EXERCISED while the verdict stays PASS.
With the normal generator (c1) the same class must be hit.

## 6. Leaks, hangs, unbounded memory and slow loops

COUPLE checks more than equal outputs. Each failure has its own verdict detail and keeps a
reproducer. Limits are per project, under `[fuzz]` in `fv.toml` in the fuzz directory. They must be positive
whole numbers. libFuzzer reads 0 as "no limit", so `fv.toml` (which lies outside the lock) could
otherwise switch HANG or OOM detection off. A 0 is refused with ERROR, before anything is built
(control `c14_zero_limits`).

| Failure | How it is caught | Verdict detail | Control |
|---|---|---|---|
| Memory leak (unreachable memory) | LeakSanitizer, per input and at exit | `LEAK: Direct leak of N byte(s) in M object(s)` | c7 (every call), c10 (one input class; the finding carries that class) |
| Infinite or runaway loop | libFuzzer `-timeout` (`timeout`, default 10 s per input) | `HANG: input exceeded N s` | c11 (an endless loop on one fee rate, `timeout = 2`) |
| Unbounded growth of reachable memory | libFuzzer `-rss_limit_mb` / `-malloc_limit_mb` (default 2048) | `OOM: out-of-memory (...)` | c12 (a cache that grows 1 MiB per call, `rss_limit_mb = 256`) |
| Memory errors, undefined behaviour | ASan, UBSan | `sanitizer: ...` | — |
| Wrong result | the oracle comparison | `oracle/implementation mismatch` | c6 |

**What LeakSanitizer cannot see.** A leak is memory that nothing points to any more. A map or
cache that keeps growing while still reachable is not a leak; only the RSS limit stops it (c12).
Size `rss_limit_mb` for the largest legitimate state, so that growth beyond it is a finding. An OOM from growth across many inputs is reported against whichever input was running when the limit was crossed, so its reproducer alone may not reproduce it; the verdict and the growth are the finding.

**Slow inputs and bad loops.** Slow inputs are reported but are not a failure. There are two
reports:
- the campaign lists inputs slower than `report_slow_units` seconds in `fuzz.json`
  (`slow_units`);
- the classification replay times each input's C++ steps, with outputs discarded, and the review
  deck shows the 5 slowest by time per step. The slowest 1 % form an informational
  `timing` class.

A short input that is far slower per step than the median points at an accidental quadratic or a
loop over a growing structure.

**Coupling a cost bound (optional, per project).** Termination of the C++ cannot be proved here.
A cost bound can be coupled, though:
- Let the model and the implementation both return an iteration or step counter as part of the
  compared state.
- State the bound on the model, e.g. `iterations ≤ number of entries`. The Lean model always
  terminates, because `partial` and `unsafe` are rejected by the lint.
- The fuzzer then fails any input where the C++ count differs from the model's.

This couples a *cost bound* to the real code on every input the campaign reaches. It is not a
termination proof for the C++.

**For contracts (EVM and EVM-like chains), gas or energy is the natural measure.** An infinite loop is
out-of-gas. A "bad loop" is a loop over storage that users can grow: once it passes the block
limit it is a denial-of-service and stuck-funds risk. The EVM pack (design pending) plans a
gas-vs-input-size report, and optional statements such as "gas ≤ G for any state with ≤ N
entries".

