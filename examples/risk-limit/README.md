# Example: a pre-trade risk check

A second end-to-end example. It shows the harness on a trading-style component, and it shows why
the proof alone is not enough.

## The component

One instrument, with a limit, a position, and the open (unfilled) buy quantity. There are four
events:

| `op % 4` | Event | Effect |
|---|---|---|
| 0 | submit a buy of `q` | accepted iff position + open + `q` ≤ limit; then open += `q` |
| 1 | cancel `q` | open −= min(`q`, open) |
| 2 | fill `q` | f = min(`q`, open); open −= f; position += f |
| 3 | reduce by `q` (sell) | position −= min(`q`, position) |

- `lean/`: the Lean project.
  - `spec/challenge/RiskSpec/Model.lean`: the model.
  - `spec/challenge/RiskSpec/Oracle.lean`: the `@[export]` oracle.
  - `spec/challenge/Challenge.lean`: the statements, signed with the FIXTURE-ONLY key
    (`locks/risk-limit.*`).
  - `spec/solution/Solution.lean`: the proofs.
- `cpp/impl/risk.hpp`: the production check. It uses the headroom form `q <= limit - pos - open`.
- `cpp/impl-buggy/risk.hpp`: the same check written `pos + open + q <= limit`. That is the natural
  way to write it, and it is wrong: for `q` near 2^64 the sum wraps below the limit, and the order
  is accepted.
- `cpp/fuzz/`: the binding and CMake for the harness's differential fuzzer. It starts only from
  admissible states (position + open ≤ limit), the hypothesis the statements assume.

## The statements (5, all proved with the three permitted axioms only)

1. `step_limit`: no event changes the limit.
2. `accept_iff`: a buy is accepted exactly when it keeps position + open within the limit.
3. `step_preserves`: every event preserves the invariant position + open ≤ limit.
4. `run_preserves`: **no sequence of events, of any length, breaches the limit.**
5. `step_fits`: under the invariant with a 64-bit limit, every field fits 64 bits after any
   event. So the C++ never needs a wider type, provided it computes the check without overflow.

Statement 5 is where the buggy variant goes wrong. The model compares exact sums. The buggy C++
computes a sum that the invariant does not bound, because it adds the new order before comparing.
The proof is about the model; the fuzzer is what catches the C++.

## Run it

```sh
examples/risk-limit/run.sh
```

Reference run:

| Step | Result |
|---|---|
| Gate on `lean/` | **PASS**, all 10 stages (lock, lint, netns, config, comparator native and from export, inert export, two kernels, `--compare`) |
| Fuzz, correct C++, 10^6 runs | **PASS**, 31.6 s (32,258 exec/s), 0 mismatches |
| Fuzz, buggy C++, 10 s budget | **FAIL** after 0.063 s, at the first step of the first sequence |

The buggy run's reproducer:

```text
diff-oracle: MISMATCH at step 0 (0.063 s after start)
  before limit=3 pos=3 open=0 last=0
  op     submit q=18446744073709551615
  oracle limit=3 pos=3 open=0 last=0
  impl   limit=3 pos=3 open=18446744073709551615 last=1
```

The position is already at the limit. The model rejects the order. The buggy C++ computes
`3 + 0 + (2^64 − 1) = 2` (mod 2^64), which is ≤ 3, so it accepts an order of 2^64 − 1 units.
The fuzzer's boundary values (2^64 − 1 is one of them) find this on the first input. A unit test
written by the author of the bug would probably not.
