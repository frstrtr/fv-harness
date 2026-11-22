# Languages beyond C++

The Lean oracle is exported from the signed specification as **C ABI functions** (`@[export]`). It
is built from the locked files only, as a static library (`lean_oracle_library`, plus a shared
library `oracle_shared` for FFI users). Any language with a C FFI and a coverage-guided fuzzer can
therefore be the side under test. The gate (AUDIT) is the same for every language. What changes
is only the COUPLE step: how the oracle is linked, which fuzzer drives inputs, and which sanitizers
watch the implementation.

`fuzz/run_fuzz.sh --lang cpp|rust` selects the build. The replay, campaign, merge, reproducers,
verdict codes and the edge-case classification replay stay the same wherever the fuzzer speaks
libFuzzer's command line.

## Support matrix

Checked at source on 2026-11-22.

| Language | Fuzzer (licence) | How the oracle binds | Sanitizers | Status | What is lost compared with C++ |
|---|---|---|---|---|---|
| C++ | libFuzzer (LLVM, Apache-2.0 with LLVM exception) | static library, `diff_oracle_template.cpp` | ASan, UBSan, LeakSanitizer | **shipped** (fixture, `examples/risk-limit`) | — |
| C | libFuzzer | the same template (C headers included from C++) | ASan, UBSan, LeakSanitizer | trivial: use the C++ template | — |
| Rust | cargo-fuzz 0.13.2 + libfuzzer-sys 0.4.13 ((MIT OR Apache-2.0) AND NCSA); a pinned **nightly** toolchain | `oracle_shared` linked by `build.rs` | ASan (via cargo-fuzz), LeakSanitizer | **shipped** (`examples/risk-limit-rust`) | UBSan has no Rust equivalent. The fuzz build runs with **overflow checks on**, so an arithmetic overflow panics and FAILs. Release builds wrap silently unless the code uses `checked_*`, `wrapping_*` or `saturating_*`, so write the intended behaviour explicitly. |
| Python | Atheris 3.1.0 (Apache-2.0); wheels for CPython 3.12–3.14 | `ctypes` on `oracle_shared` | none for pure Python (memory-safe); C extensions can be built with ASan | **Pack 3** (`examples/risk-limit-py`) | Python integers are unbounded, so the binding must reduce to the model's widths (e.g. mod 2^64). That is a **modelling assumption**, listed in the review note, and its drift control includes a difference only above 2^64. |
| Go | native fuzzing (`go test -fuzz`, Go 1.27, BSD-3-Clause) | cgo to the static library | `-asan` with clang | planned | A different engine and command line: it needs its own runner, and its corpus format differs. |
| Java / Kotlin | Jazzer (Apache-2.0) | JNA or the Panama FFI on `oracle_shared` | none for JVM code; native parts can use ASan | planned | needs a JVM; GC timing makes per-input timeouts noisier |
| TypeScript / JavaScript | Jazzer.js (Apache-2.0) | N-API or an FFI module on `oracle_shared` | none for JS | planned | Number vs BigInt: 64-bit values must be BigInt end to end |
| Solidity / EVM | the harness's own runner around an in-process EVM; design in progress | the contract runs in the EVM; the oracle is called natively beside it | none; gas and energy are the cost measure | **Pack 4** (design) | A different shape (see below) |

## Rust: setup, pins and measured results

User-local, nothing outside `$FV_ROOT/rust`, no shell-profile changes:

```sh
R=$FV_ROOT/rust; mkdir -p "$R/dl"; export RUSTUP_HOME="$R/rustup" CARGO_HOME="$R/cargo"
curl -sSfL -o "$R/dl/rustup-init" https://static.rust-lang.org/rustup/archive/1.29.3/x86_64-unknown-linux-gnu/rustup-init
echo "b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55  $R/dl/rustup-init" | sha256sum -c
chmod +x "$R/dl/rustup-init"
"$R/dl/rustup-init" -y --no-modify-path --profile minimal --default-toolchain nightly-2026-11-10
"$CARGO_HOME/bin/cargo" install cargo-fuzz --version 0.13.2 --locked
```

| Component | Pin |
|---|---|
| rustup-init | 1.29.3, sha256 `b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55` |
| toolchain | `nightly-2026-11-10`: rustc 1.102.0-nightly (ac8310ba6 2026-11-09), cargo 1.102.0-nightly (c07ac2c4d 2026-11-06) |
| cargo-fuzz | 0.13.2 (`--locked`); the built binary's sha256 on the reference host: `13d67a7f1a998391820774b893d57da99add4951e3ed5b14b46528848ccb426c` |
| libfuzzer-sys | 0.4.13, pinned in `examples/risk-limit-rust/fuzz/Cargo.lock` (checksum `a9fd2f41a1cba099f79a0b6b6c35656cf7c03351a7bae8ff0f28f25270f929d2`) |

How a Rust project plugs in. The split is the same as in C++: the harness owns the comparison
loop, and the project owns only the binding.
- **`fuzz/rust/fv_diff.rs` (harness):**
  - the decode helpers (`Input`, `pick_u64`), the step loop and the bit-exact comparison after
    every step;
  - the mismatch report and exit 86;
  - the oracle start-up with LeakSanitizer disabled for that block only;
  - `fv_diff_main!`, the target's only fuzz entry point.

  `run_fuzz.sh` points `FV_DIFF_RS` at the harness copy. A copy vendored into a project's fuzz
  directory (with a "Vendored from fv-harness <release>" header) is pinned by
  `fuzz/check_vendored.sh` like the C++ files.
- **`fuzz/fuzz_targets/<target>.rs` (project):** `impl fv_diff::Binding` (`initial_state`,
  `make_op`, `oracle_step`, `impl_step`, `same`, `show_*`, `warm_up`) plus one line,
  `fv_diff_main!(MyBinding);`. `run_fuzz.sh` refuses a target that defines its own
  `fuzz_target!`.
- **`fuzz/CMakeLists.txt`** builds only `<target>_oracle` with `lean_oracle_shared()`, from the
  trusted copy of the locked spec.
- **`fuzz/build.rs`** links that library (`FV_ORACLE_LIB_DIR`), includes the implementation from
  `FV_IMPL_DIR` (`--impl-dir`), and selects the driver (`FV_DIFF_RS`).
- **The build** is `cargo fuzz build -a`: ASan, plus **debug assertions and overflow checks ON**.
  cargo-fuzz makes that the default unless `-O` is given. `run_fuzz.sh` passes `-a` explicitly
  and never `-O`, because `-O` builds without overflow checks (see c17's negative). It also forces
  `RUSTFLAGS="-C overflow-checks=on -C debug-assertions=on"` and clears `CARGO_PROFILE_*`. A
  project that switches either off is refused with ERROR (control c19); the switch can be in its
  `Cargo.toml` or in any `.cargo/config*` cargo would read.

Measured on the risk-limit example:
- the correct implementation PASSes about 21,000 runs/s, with no leak report;
- a reduction one unit short FAILs as a mismatch in about 0.3 s;
- the overflowing limit sum `pos + open + q` FAILs as `panic: … attempt to add with overflow` in
  about 0.3 s.

The suite covers these as controls c15–c17. c18 covers the driver: a vendored copy is pinned,
and a target with its own loop is refused. c19 covers overflow checks that a project switches
off. On the gate host, list the languages whose controls must run in `FV_REQUIRE_LANGS`
(`config/hosts.env`). A missing toolchain is then a failure instead of a SKIP (control c20). A copy without the features (comparison disabled,
or no `-a`) turns c16 and c17 red.

**Overflow checks: a fuzz build is not a release build.** In a release build, Rust integer
arithmetic **wraps silently** unless the code uses `checked_*`, `wrapping_*` or `saturating_*`.
The fuzz build turns an overflow into a FAIL, even where production would wrap. That is usually
what you want. If wrapping is intended, write `wrapping_*` explicitly so that both builds agree.

**Not yet:** Rust runs are not classified (the edge-case classifier needs a Rust `describe()`).
The verdict is unaffected.

## Recommended order

1. **C++ / C**: shipped.
2. **Rust**: it links the static oracle directly, speaks libFuzzer's command line, and is in
   demand in trading and crypto.
3. **Python**: Atheris is libFuzzer underneath, so `run_fuzz.sh` reuses everything. Quant and
   risk prototypes often live in Python.
4. **Solidity/EVM**: high value, but a different execution model (next section).
5. **Go**, then **Java/Kotlin**, then **TypeScript/JS**. Each needs a runner for a different engine
   or a managed runtime.

## The shape of a binding in any language

Each language needs the same five pieces as `binding.hpp`:
- decode the fuzzer's bytes into an initial state and an operation sequence (generate only
  admissible states);
- call the oracle's exported functions for each step;
- call the implementation under test for the same step;
- compare **bit for bit** after every step;
- on a difference, write the input to `$FV_FUZZ_ARTIFACT_DIR/mismatch-<hash>`, print both states,
  and exit with status **86**.

A per-language drift control (a 1-unit error in that language's implementation) must FAIL within
10 seconds before the binding is trusted.

## Solidity / EVM: a different shape

- **What runs.** The implementation under test is a compiled contract. Each fuzz input becomes a
  sequence of transactions: ABI-encoded calldata, plus `msg.sender`, `msg.value` and block fields
  as declared inputs. They are executed in an **in-process EVM**, for speed and determinism. The
  oracle runs natively beside it.
- **What is compared.** After every transaction:
  - the return data;
  - success vs revert (with the panic code);
  - the events the specification covers;
  - the storage slots that hold the modelled state.

  Gas is excluded, unless a statement is about it.
- **Semantics to state.**
  - `uint256` against the model's integer widths;
  - Solidity ≥ 0.8 reverts on overflow, except in `unchecked` blocks; 0.5.x does not, unless
    SafeMath is used;
  - reentrancy and external calls are out of scope for a single-contract model unless they are
    modelled.
- **Cost.** Gas (or energy) is the natural measure. An infinite loop shows as out-of-gas. A
  "bad loop" is one over storage that users can grow: past the block gas limit, it is a
  denial-of-service and stuck-funds risk. The plan includes a gas-vs-input-size report and
  statements such as "gas ≤ G for any state with ≤ N entries".
- **Classifier.** The EVM outcomes (success, revert, the panic code) feed the outcome classes
  automatically.
