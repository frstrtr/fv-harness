# Example: a capped TRC-10 token faucet on the TRON Virtual Machine (TVM)

A small contract written for this repository: it hands out one unit of one TRC-10 token per
request, up to a cap, never to itself, and only its owner can withdraw from the pool. It is
checked against a signed Lean specification on the **reference TRON-TVM**: java-tron's own virtual
machine, built from source at a pinned release and run offline (`fuzz/run_fuzz.sh --lang tron-tvm`).

**This spec is signed with the FIXTURE-ONLY key** (`locks/token-faucet.*`, pinned in
`config/signer_pins.txt` as a harness example), exactly like `examples/risk-limit`. That is
acceptable only because this is a harness example. A real project's lock is signed by its
specification owner with their own key, and the fixture key is never pinned for it.

| Path | What |
|---|---|
| `lean/spec/challenge/` | the model (`FaucetSpec/Model.lean`), the C oracle (`Oracle.lean`) and 7 statements (`Challenge.lean`) |
| `lean/spec/solution/` | a reference solution of the statements |
| `contract/CappedFaucet.sol` | the contract under test (TRON solc 0.5.18) |
| `contract-drift/` | drift control: the cap test is off by one (`given <= cap`) |
| `fuzz/binding.py` | the binding only; the loop is `fuzz/python/fv_diff.py`, the TRON-TVM client `fuzz/tron-tvm/fv_tron_tvm.py` |
| `fuzz/fv.toml` | `[tron-tvm]`: contract, compiler settings and the chain-parameter profile (`mainnet-20261122`) |

**What the binding compares after every transaction:**
- `cap` and `given` from storage slot 2; the slot's bits above 128 must stay 0;
- the token balances of the faucet, the recipient and the owner;
- the outcome: success, or the exact `Error(string)` reason, or a halt;
- the return data;
- the logs;
- the internal transactions, as an ordered list: each token transfer the contract makes (kind, from,
  to, TRX value, token amounts, rejected or not), including a transfer of 0.

Energy and TRX balances are not compared; both callers' TRX is reset every step, so energy fees never
run it down over a long campaign.

**Semantics to state in a review note:**
- **Chain parameters.** The reference node runs with the TRON mainnet chain parameters as published
  on 2026-11-22 (`fuzz/tron-tvm/profiles/`, applied completely). Without them, java-tron runs older rules.
  For example, without the multi-sign proposal, `address(this)` keeps the 0x41 prefix, and a
  comparison with an ABI-decoded address fails.
- **Timing.** The per-transaction CPU-time limit is off, as in java-tron's own VM tests, so results do
  not depend on timing. OUT_OF_TIME behaviour is therefore **not covered**. Energy limits are covered
  only where a statement names them.
- **Balances.** TRC-10 balances are 64-bit signed in the TRON-TVM. Admissible states keep their total
  below 2^63.
- **Coverage.** The contract runs inside the JVM, so libFuzzer's coverage guidance sees the binding,
  not the contract. Campaigns are sized in time, and the generator favours the boundaries
  (`given = cap`, an almost empty pool).
