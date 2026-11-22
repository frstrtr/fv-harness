# Example: the pre-trade risk check as a contract (EVM)

The same signed Lean specification as `examples/risk-limit` (`locks/risk-limit.*`), coupled to a
**Solidity contract** compiled with the pinned solc and executed in an in-process EVM. One spec;
C++, Rust, Python and EVM implementations; one gate.

| Path | What |
|---|---|
| `contract/RiskLimit.sol` | the production contract: state in one packed slot, `submit` reverts with `LimitExceeded()` when the model rejects |
| `contract-drift/` | drift control: `reduce` removes one unit less than it should |
| `contract-overflow/` | the limit test written as `pos + open + q` in checked `uint64`: Panic(0x11) where the model rejects |
| `contract-wrap/` | the same test inside `unchecked {}`: it wraps and accepts a far-too-large order |
| `fuzz/fuzz_targets/diff_risk.rs` | the binding only; the loop is `fuzz/rust/fv_diff.rs`, the EVM `fuzz/evm/fv_evm.rs` |
| `fuzz/fv.toml` | `[evm]`: contract, evmVersion, optimizer; optionally the deployed runtime bytecode's sha256 |
| `fuzz/Cargo.toml`, `Cargo.lock` | revm 43.0.3 and its dependency tree, pinned; builds run offline |

```sh
W=$FV_ROOT/work/rl-evm; rm -rf "$W"; cp -r examples/risk-limit/lean "$W"
fuzz/run_fuzz.sh --lang evm --lean-project "$W" --lock locks/risk-limit.sha256 \
  --cmake-dir examples/risk-limit-evm/fuzz --target diff_risk --runs 1000000            # PASS
fuzz/run_fuzz.sh --lang evm --lean-project "$W" --lock locks/risk-limit.sha256 \
  --cmake-dir examples/risk-limit-evm/fuzz --target diff_risk \
  --impl-dir examples/risk-limit-evm/contract-overflow --time 10                        # FAIL
```

**What the binding compares after every call:**
- `limit`, `pos` and `open`, unpacked from storage slot 0; the slot's unused high bits must stay 0;
- the outcome: success, or the exact revert data, or a halt;
- the return data;
- the logs.

Gas is not compared. The model's `last` (order accepted) corresponds to the outcome of `submit`:
- accepted: success, returning `true`, with one `Accepted(q)` event;
- rejected: a revert with `LimitExceeded()`.

**Semantics to state in a review note:**
- The model's integers are unbounded. The contract's fields are `uint64`, which is enough because
  `pos + open <= limit < 2^64` holds in every admissible state.
- Solidity 0.8 reverts on overflow outside `unchecked {}`. The overflow control shows the outcome
  comparison catching it: Panic(0x11) where the model rejects.
- A single caller, no value, no external calls. Reentrancy is out of scope for this model.
- The state is written into storage before each call, the way the other languages start from a
  given state. The constructor runs once, at deployment. Contracts with immutables are not
  supported: their runtime code is only known after deployment.

`fuzz.json` → `evm` records:
- the solc version and sha256;
- the settings;
- the sha256 of each source;
- the sha256 of the creation and runtime bytecode.

When the contract is deployed somewhere, put the deployed runtime bytecode's sha256 in
`fv.toml` as `expect_runtime_sha256`. A different compiler output is then BLOCKED instead of
coupled.
