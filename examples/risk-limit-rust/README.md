# Example: the pre-trade risk check in Rust

The same signed Lean specification as `examples/risk-limit` (`locks/risk-limit.*`, 5 statements),
coupled to a **Rust** implementation instead of C++. One spec, two implementations, the same gate.

| Path | What |
|---|---|
| `impl/lib.rs` | the production check (headroom form `q <= limit - pos - open`) |
| `impl-drift/lib.rs` | drift control: a reduction removes one unit less than it should |
| `impl-overflow/lib.rs` | overflow control: the check adds before comparing (`pos + open + q <= limit`) |
| `fuzz/CMakeLists.txt` | builds only the oracle, as a shared library, from the locked spec |
| `fuzz/build.rs` | links the oracle; includes the implementation from `FV_IMPL_DIR` |
| `fuzz/fuzz_targets/diff_risk.rs` | the binding only (`impl fv_diff::Binding` + `fv_diff_main!`); the decode/compare loop is the harness's `fuzz/rust/fv_diff.rs` |

Run it, with the Rust toolchain installed as in `docs/LANGUAGES.md`:

```sh
W=$FV_ROOT/work/rl-rust; rm -rf "$W"; cp -r examples/risk-limit/lean "$W"
fuzz/run_fuzz.sh --lang rust --lean-project "$W" --lock locks/risk-limit.sha256 \
  --cmake-dir examples/risk-limit-rust/fuzz --target diff_risk --runs 1000000          # PASS
fuzz/run_fuzz.sh --lang rust --lean-project "$W" --lock locks/risk-limit.sha256 \
  --cmake-dir examples/risk-limit-rust/fuzz --target diff_risk \
  --impl-dir examples/risk-limit-rust/impl-drift --time 10                             # FAIL: mismatch
```

The fuzz build has **overflow checks on** (`cargo fuzz build -a`). The overflow variant therefore
FAILs as `panic: … attempt to add with overflow`. In a release build the same code would wrap
silently and accept an order of 2^64 − 3 units. The C++ variant in `examples/risk-limit` shows
that case as a mismatch. Controls c15–c17 in `tests/harness_fv_controls` run all three.
