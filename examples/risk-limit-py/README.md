# Example: the pre-trade risk check in Python

The same signed Lean specification as `examples/risk-limit` (`locks/risk-limit.*`), coupled to a
**Python** implementation through Atheris. One spec, three implementations (C++, Rust, Python),
one gate.

| Path | What |
|---|---|
| `impl/risk.py` | the production check (exact integer arithmetic) |
| `impl-drift/risk.py` | drift control: a reduction removes one unit less than it should |
| `impl-wide/risk.py` | domain control: a fill adds 2^64; reduced mod 2^64 it would look correct |
| `fuzz/binding.py` | the binding only; the loop is the harness's `fuzz/python/fv_diff.py` |
| `fuzz/CMakeLists.txt` | builds only the oracle, as a shared library, from the locked spec |

```sh
W=$FV_ROOT/work/rl-py; rm -rf "$W"; cp -r examples/risk-limit/lean "$W"
fuzz/run_fuzz.sh --lang python --lean-project "$W" --lock locks/risk-limit.sha256 \
  --cmake-dir examples/risk-limit-py/fuzz --target diff_risk --runs 1000000          # PASS
fuzz/run_fuzz.sh --lang python --lean-project "$W" --lock locks/risk-limit.sha256 \
  --cmake-dir examples/risk-limit-py/fuzz --target diff_risk \
  --impl-dir examples/risk-limit-py/impl-wide --time 10                              # FAIL: domain
```

**Modelling assumption.** The oracle's boundary is unsigned 64-bit, and Python integers are
unbounded. The harness requires every value the implementation returns to lie in [0, 2^64)
instead of reducing it, so a result that is wrong only above 2^64 still FAILs.

Note that this implementation's limit check `pos + open + q <= limit` is **correct** in Python. It
is the same expression that overflows in C++ and in Rust: language semantics matter, and each
implementation is checked against the same model.
