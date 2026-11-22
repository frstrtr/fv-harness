# Where the harness fits

The harness proves properties of a **pure reference model** written in Lean, then ties the
production code to that model by differential fuzzing. It therefore fits code whose correctness is
**deterministic arithmetic or state-transition logic over bounded integers**. In those domains a
one-unit error is a real loss, and the rules can be written down exactly.

Each section lists:
- example statements in plain words, and the shape of the Lean statement where it helps;
- the **oracle boundary**: the pure C/C++ function the fuzzer calls on both sides;
- the typical hypotheses;
- a rough size;
- what does not fit.

Shapes are sketches, not the API of any real project.

General pattern:

```text
spec/challenge/Model.lean      -- reference model: plain functions on Nat / Int / structures
spec/challenge/Challenge.lean  -- theorem statements, proofs = sorry          (signed lock)
spec/challenge/Oracle.lean     -- @[export] byte codec + one C entry point    (signed lock)
spec/solution/**               -- proofs (agent-writable, audited)
fuzz/binding.hpp               -- decode the same bytes, call the production C++, compare
```

Write the model in unbounded `Nat`/`Int` and state the width facts separately: "every
intermediate fits 64/128/256 bits under these hypotheses". The fuzzer then checks that the C++,
which uses fixed widths, agrees with the exact model on every input it reaches.

---

## 1. Blockchain and mining pools

**Fits:** reward splitting, coinbase/payout construction, share accounting, difficulty and
work arithmetic, best-chain selection rules, state that must survive restarts.

Example statements:
- A payout split conserves value: the outputs sum to exactly the reward `R`.
- Rounding is bounded: every payee gets its floor share or one unit more, and the leftover units
  are fewer than the payees.
- No intermediate overflows its C++ type, and no division has a zero divisor.
- Monotonicity within a window: raising one payee's weight, with all others unchanged, never lowers
  that payee's output.
- Order independence: permuting the input rows does not change the outputs.
- Consensus-mandated payments in the generated coinbase equal the reference rules.
- Header chain: the selected tip descends from the checkpoint and has more cumulative work than
  it; and `is_synced` implies that.
- Difficulty retarget equals the reference implementation for all inputs in range.
- Restart equivalence: the state resumed from disk equals the state re-folded from the events.

Shapes:

```lean
theorem split_sum_eq (R : Nat) (ws : List Nat) (h : 0 < ws.sum) :
    (split R ws).sum = R
theorem split_bounds (R : Nat) (ws : List Nat) (h : 0 < ws.sum) :
    ∀ i < ws.length, R * ws[i]! / ws.sum ≤ (split R ws)[i]! ∧
                      (split R ws)[i]! ≤ R * ws[i]! / ws.sum + 1
theorem split_widths (R : Nat) (ws : List Nat) (hR : R < 2^64) (hW : ws.sum < 2^256) :
    ∀ i < ws.length, R * ws[i]! < 2^320
theorem split_perm (R : Nat) (rows rows' : List (Payee × Nat)) (h : rows.Perm rows') :
    (splitRows R rows).Perm (splitRows R rows')   -- outputs as (payee, amount) pairs
theorem resume_eq (s : State) (evs : List Event) :
    load (save (evs.foldl step s)) = evs.foldl step s
```

- **Oracle boundary:** one C function `oracle(op, request bytes) -> reply bytes` covering the split,
  the window selection, the fee and the whole per-block step. The binding decodes the same request,
  calls the production routine, encodes its result, and compares bytes.
- **Typical hypotheses:** inputs admitted by the node's validation (widths, rate limits, owner
  fields consistent); totals below a stated bound; "entries with equal sort keys are the same
  entry" when the C++ sort is unstable.
- **Rough size:** a 300–800 line model and 10–25 statements per routine. The first production use
  was 19 statements (case study 6).
- **Does not fit:** networking and peer behaviour, mempool policy, timing and propagation, anything
  whose truth depends on adversarial scheduling. Use model checking or simulation for those.

## 2. HFT and trading systems

**Fits:** pre-trade risk checks, order and position bookkeeping, fee and P&L arithmetic in fixed
point, tick and lot normalisation, recovery logic.

Example statements:
- Risk limits cannot be bypassed by any event sequence: after every event,
  `position + open buy quantity ≤ limit` (and the sell-side mirror).
- Order lifecycle: the sum of fills never exceeds the order quantity; the sum of child-order
  quantities never exceeds the parent's.
- Positions, P&L and fees in fixed point: value is conserved across a fill, and the rounding
  direction is the declared one, always toward the venue or always toward the client.
- Tick and lot normalisation is idempotent and never moves a price across the limit.
- Recovery: replaying the journal from the last snapshot reproduces the live state.

Shapes:

```lean
def Inv (s : RiskState) : Prop :=
  ∀ sym, s.pos sym + s.openBuy sym ≤ s.limit sym ∧ s.openSell sym ≤ s.pos sym + s.limit sym
theorem step_preserves (s : RiskState) (e : Event) (h : Inv s) : Inv (step s e).1
theorem accepted_only_if_safe (s : RiskState) (o : Order) :
    (step s (.submit o)).2 = .accepted → Inv (step s (.submit o)).1
theorem fills_le_qty (s : OrderState) (evs : List Event) :
    ∀ id, (evs.foldl apply s).filled id ≤ (evs.foldl apply s).qty id
```

- **Oracle boundary:** `risk_step(state bytes, event bytes) -> (state bytes, decision)`. The fuzzer
  drives long event sequences: saturation, cancel/replace storms, zero and maximum quantities.
- **Typical hypotheses:** quantities and prices within the instrument's declared ranges; the
  limit table is constant during a sequence (or changes are themselves events).
- **Rough size:** a 150–400 line model and 5–12 statements per component.
- **Does not fit:** alpha and signal logic, latency, lock-free data structures, kernel bypass,
  FPGA pipelines, anything judged by timing or market outcome.
- **Worked example:** `examples/risk-limit/` is a pre-trade risk check with 5 signed statements,
  including "no event sequence breaches the limit". Its correct C++ passes the gate and the fuzzer.
  A deliberately buggy variant checks `pos + open + q <= limit`, which wraps at 2^64, and the fuzzer
  rejects it within seconds (`examples/risk-limit/run.sh`).

## 3. Exchanges and matching engines

Example statements:
- The book is never crossed after a match step: best bid < best ask.
- Price-time priority: an order is filled only after every better-priced order and every
  earlier order at the same price.
- Quantity is conserved: incoming quantity = filled + resting + cancelled.
- Balances reconcile: across a trade, the change in all account balances (fees included) is zero.

- **Oracle boundary:** `match(book bytes, order bytes) -> (book bytes, fills bytes)`.
- **Hypotheses:** valid tick and lot sizes; unique order ids.
- **Size:** a 300–600 line model and 6–15 statements.
- **Does not fit:** gateway concurrency, fairness under network jitter, market-data fan-out.

## 4. Settlement and payments

Example statements:
- Escrow and HTLC-style flows: value is neither created nor lost. For every path (claim, refund,
  timeout), the sum of outputs plus fees equals the locked amount.
- Fee splits sum to the fee, with a declared rounding direction.
- Netting: settling the net positions gives the same balances as settling every gross transfer.

- **Oracle boundary:** `settle(ledger bytes, instruction bytes) -> ledger bytes`.
- **Hypotheses:** amounts in range; time-locks totally ordered.
- **Size:** a 100–300 line model and 4–10 statements.

## 5. Codecs and protocols

**Fits:** FIX/ITCH/SBE-style messages, binary wire formats, serialisers of consensus objects.

Example statements:
- Round trip: `decode (encode m) = some m` for every well-formed message.
- The decoder is total on its domain: it returns a value or a typed error, never reads past the
  buffer, and never loops.
- Canonical form: two encodings that decode to the same message are byte-identical (no
  malleability).

```lean
theorem roundtrip (m : Msg) (h : m.WellFormed) : decode (encode m) = .ok (m, [])
theorem decode_consumes_le (b : ByteArray) :
    ∀ m rest, decode b.toList = .ok (m, rest) → rest.length ≤ b.size
```

- **Oracle boundary:** the codec itself. The fuzzer feeds raw bytes to both decoders and compares
  the results, including the error kind.
- **Size:** small models; most of the work is in stating well-formedness.

## 6. Where it does not fit

- **Concurrency, timing and liveness under scheduling:** use model checking (TLA+, SPIN) or
  deterministic simulation.
- **Networking and distributed protocols as a whole:** model-check the protocol, then use this
  harness for its pure state-transition core.
- **Floating point:** possible in principle, but the model must then fix the rounding mode and
  every operation's order. Prefer fixed point.
- **UI, ML models, fuzzy or judgement-based rules:** there is no exact statement to prove.
- **Performance:** load tests and benchmarks.

A good first target is a function that:
- has fewer than about 1,000 lines;
- has a one-sentence invariant someone would lose money over;
- already has a hand-written test suite that people worry is incomplete.
