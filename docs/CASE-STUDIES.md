# What the harness found on first use

These are anonymised findings from the harness's first runs: on its own fixture, on the tools it
builds on, and on its first production specification. They contain no project, product, file,
function or repository names. Every number comes from a logged run.

## 1. A one-unit rounding drift, caught in 22 ms

**Setting.** The fixture is a ledger transfer with a fee. The fee is rounded down in basis points.
Control 6 swaps the production C++ for a variant that rounds the fee half up. In the C++ it is a
one-character change, and the variant compiles and runs normally.

**What happened.** The differential fuzzer compares the C++ bit for bit against the Lean oracle
after every transition. The oracle is exported from the locked specification. The fuzzer reported
the mismatch **0.022 s** after the campaign started. The limit set for this control is 10 s. The
reproducer showed it in one line:
- oracle: `b = 250, fee = 6`;
- implementation: `b = 249, fee = 7`.

The account involved held `2^64 − 259`. That is a boundary value the structure-aware input
generator favours, and not one a hand-written unit test is likely to choose.

**Lesson.** Off-by-one rounding is the cheapest error to make and the hardest to spot in review.
A proof about the model says nothing about the C++. The coupled fuzzer is what turns the proof
into a statement about the shipped code.

## 2. Facts about the tools, found at the source

Before designing the gate, every tool the original specification named was checked at its source
against the pinned Lean release. Three findings changed the design.

- **The named trust axioms no longer exist.** Lean 4.36 has no `Lean.trustCompiler`,
  `Lean.reduceBool`, `Lean.ofReduceBool` or `Lean.ofReduceNat`, so a check list built on those
  names is stale. `native_decide` now emits an auxiliary axiom per use, and all checkers reject
  that axiom.
- **A re-declared trust axiom is installed as sound by the independent kernels.** A solution that
  declares `axiom Lean.trustCompiler : True` is accepted by both external kernels, by design. Only
  the comparator's axiom whitelist rejects it. The gate's FAIL verdict for that case therefore
  rests on the comparator (control C3b).
- **The independent kernels check consistency, not statement equality.** A weakened theorem
  statement (C4a) or a shadowed definition (C4b) passes both external kernels. Statement equality
  comes only from the comparator, which is run twice: natively and on the gate's own inert exports.
  It also comes from the `--compare` mode of one kernel's development branch, which is not in the
  release bundled with the toolchain.

**Lesson.** "Checked by two independent kernels" sounds stronger than it is. Know what each checker
actually decides, and give every attack class a control that proves which stage catches it.

## 3. The harness's own defects, found by its first dry run

The first end-to-end dry run on the fixture failed in useful ways. Each failure became a fix and a
regression check.

1. **Repair rounds overflowed the context.** Each repair request resent the previous reply,
   including thousands of tokens of reasoning. By the second repair round it overflowed the
   8,192-token context: 8 × HTTP 400. Repairs are now single-turn: the problem, the previous code
   and the compiler's messages. The next run had 0 endpoint errors.
2. **A fresh working copy had no built imports.** Every candidate then failed with
   `unknown module prefix`, which looks like a model failure but is an environment failure. The
   discharge stage now runs a pre-flight build first. The dispatcher stops with a setup error
   instead of spending its budget.
3. **The model kept using a library the project does not have.** The local prover models were
   trained against a large mathematics library, and the project is core-only. Telling them so in
   the prompt did not help: 63 of 64 rounds on the hard leaf used tactics from that library. A
   pre-compile filter now rejects such candidates without compiling them and counts them.
4. **One hard leaf took 48 of 53 minutes.** A nonlinear bound walled after 2 attempts × 8 samples.
   The Tier-1 planner then split it into a one-line product fact in seconds. The escalation budget
   is now a per-task setting, with default 1 attempt × 4 samples. A leaf walls at once when every
   sample fails the same way. On the logged attempts, that rule walls the same leaf after 4 samples
   instead of 16.

**Lesson.** Run the whole loop on a toy before the real target. Each of these would have cost
hours on a production specification, and none shows up in unit tests of the parts.

## 4. A leak control that proves the exemption is narrow

The Lean runtime allocates a few constants at start-up and keeps them for the life of the process.
LeakSanitizer reports them as 128 bytes in 12 objects. The easy fix is a suppression file, but a
suppression pattern can also hide a leak in production code.

The harness instead exempts only the runtime start, the module initialisers and one warm-up oracle
call. It uses a scoped disabler in the fuzzer's initialisation hook, with no suppression file and
no pattern. Control 7 then proves the exemption is narrow: a production variant leaks 32 bytes per
call while computing correct results, and LeakSanitizer must report it with the production frame.
It does.

**Lesson.** Every exemption from a safety check needs its own negative control. Otherwise it
quietly widens.

## 5. The trust anchor: when everyone shares an identity

A SHA-256 manifest of the locked specification protects nothing if the agent whose proofs are
judged can rewrite the specification and the manifest together. In the reference deployment, all
agents ran under one OS user and one repository identity, so they could.

The fix moves the anchor out of band:
- The specification owner signs the lock manifest on their own terminal (`ssh-keygen -Y sign`,
  dedicated namespace), with a key that never reaches an agent host.
- The gate verifies the signature against a pinned fingerprint before anything else.
- The signer's fingerprint is the first line of every verdict and closure report.

Controls C5c and C5d cover the two attacks:
- **C5c**, a re-locked manifest without a valid signature: BLOCKED.
- **C5d**, a full swap of lock, signature, allowed signers and pin to the agent's own key: this
  cannot be stopped in band, so the control asserts that the mismatching fingerprint is printed
  first and loudly.

**Lesson.** State the residual risk plainly. The last line of defence is a ten-second human check:
the fingerprint on the report must be the one the owner stated.

## 6. First production use: a signed 19-statement specification, end to end

**Setting.** The target was a production payout routine, which splits a reward among many payees
with integer arithmetic. Its specification was drafted by an agent, reviewed by the owner and
signed by the owner. It holds a reference model of the routine and 19 theorem statements:
- conservation per block;
- rounding bounds;
- integer-width safety at the routine's real widths, up to 320 bits;
- no division by zero;
- monotonicity within the window;
- order independence.

A synthesis agent proved all 19 in the solution tree. It never touched the signed files.

**Gate run**, from the signed lock to the closure report: 2 h 27 min, almost all of it fuzzing.
- **SPEC_LOCK:** 10 locked files. The owner's signature and pinned fingerprint matched. The
  fingerprint is the first line of the gate verdict and of the closure report.
- **AUDIT:** all 10 gate stages PASS, in 44 s.
  - Proofs rest on the three permitted axioms only.
  - Six kernels accepted: the Lean kernel, its paranoid mode, two re-implementations and the two
    external checkers. Each external checker accepted 2,608 declarations.
  - Statement equality was checked by the comparator, natively and from the gate's own inert
    exports. It was also checked by `--compare`, which accepted 1,878 declarations and found
    all 19 statements justified by the solution.
- **COUPLE:** the production C++ against the oracle exported from the signed model, under
  libFuzzer, ASan and UBSan.
  - It first replayed 12,834 inputs from an earlier campaign's corpus.
  - Then it ran **1,000,000 differential runs** in 2 h 25 min, with **0 mismatches and 0
    sanitizer or leak reports**.
  - Those runs drove 4,576,314 whole-block transitions:
    - 1,206,528 paid by the split, with up to 34 outputs;
    - 1,683,667 paid to a single recipient;
    - 848,232 where the rules pay nothing;
    - 529,983 deferred;
    - 307,904 rejected as inconsistent input (from deliberately malformed inputs).
  - They also exercised 3.6 million split cases and 6.6 million window selections directly.
  - The campaign added 336 inputs to the corpus, covering 21 new edges.

**Lesson.**
- The gate is cheap: under a minute for 19 statements. The differential campaign is the
  expensive part, and it is also the only part that speaks about the shipped code.
- The two need different owners. The statements are the owner's, so they are signed. The proofs
  are the agents', so they are audited. The C++ answers to the model, so it is fuzzed against it.

## 7. Synthetic: an overflow bypass of a risk limit, caught in 63 ms

This one is a demonstration on the shipped example (`examples/risk-limit/`), not a production
finding. It shows the classic bug the coupling exists for.

**Setting.** A pre-trade risk check accepts a buy order only if
`position + open buys + order ≤ limit`. The Lean model states and proves five properties,
including the main one: no sequence of events, of any length, breaches the limit. The correct C++
checks the headroom, `q <= limit - pos - open`. The buggy variant writes the check the way most
people would: `pos + open + q <= limit`.

**What happened.** The proofs hold for both, because they are about the model. The gate passed.
The fuzzer then compared the C++ to the model and stopped after **0.063 s**, on the first input:
- the position was already at the limit (3 of 3);
- an order of `2^64 − 1` units arrived;
- the model rejected it;
- the buggy C++ computed `3 + 0 + (2^64 − 1)`, which wraps to 2 (mod 2^64), and accepted it.

The open quantity became `2^64 − 1`. The correct C++ survived 10^6 runs.

**Lesson.** An overflow in a limit check turns the limit into its opposite, and it hides on the
inputs no one writes a test for. A proof about exact arithmetic does not see it. A width statement
says which C++ computation is safe, and boundary-favouring differential fuzzing checks that the
code actually computes it that way.
