# Languages beyond C++

The Lean oracle is exported from the signed specification as **C ABI functions** (`@[export]`). It
is built from the locked files only, as a static library (`lean_oracle_library`, plus a shared
library `oracle_shared` for FFI users). Any language with a C FFI and a coverage-guided fuzzer can
therefore be the side under test. The gate (AUDIT) is the same for every language. What changes
is only the COUPLE step: how the oracle is linked, which fuzzer drives inputs, and which sanitizers
watch the implementation.

**What hosted CI covers.** The repository's workflow (`.github/workflows/controls.yml`) installs
only the C++ toolchain. It runs the gate controls and the C++ fuzz controls (c1–c14, c20, c30).
The language controls c15–c29 (Rust, Python, EVM) report **SKIP** there, because their toolchains
are not installed. Their evidence is a run on a gate host that has all three toolchains
(`tests/harness_fv_controls/evidence/`). They are not CI-verified.

`fuzz/run_fuzz.sh --lang cpp|rust|python|evm` selects the build. The replay, campaign, merge, reproducers,
verdict codes and the edge-case classification replay stay the same wherever the fuzzer speaks
libFuzzer's command line.

## The shipped languages at a glance

Each binds the implementation to the same Lean oracle and compares them after every step. Each has
an example whose drift variant (a one-unit error) must FAIL.

- **C++ (and C):** the fuzz target links the oracle's static library; the binding is a C++ header
  (`binding.hpp`) built into `diff_oracle_template.cpp`. Under ASan, UBSan and LeakSanitizer. Example:
  `examples/risk-limit`, and the fixture.
- **Rust:** `cargo-fuzz` with a harness-owned driver (`fuzz/rust/fv_diff.rs`); the oracle comes in as
  `oracle_shared`. Overflow checks stay on in the fuzz build, so a wrapping overflow is a finding.
  Example: `examples/risk-limit-rust`.
- **Python:** Atheris drives a harness-owned loop (`fuzz/python/fv_diff.py`); the binding calls the
  oracle through `ctypes`. Every value is checked to stay within its declared 64-bit width. Example:
  `examples/risk-limit-py`.
- **Solidity / EVM:** the contract, compiled by a pinned solc, runs in revm inside the fuzz process,
  next to the natively linked oracle; outcomes, return data and logs are compared. Example:
  `examples/risk-limit-evm`.

Planned: contracts on the TRON Virtual Machine (TVM), in the next release; then Go, Java/Kotlin and
TypeScript/JavaScript (see the matrix and the recommended order below).

## Support matrix

Checked at source on 2026-11-22.

| Language | Fuzzer (licence) | How the oracle binds | Sanitizers | Status | What is lost compared with C++ |
|---|---|---|---|---|---|
| C++ | libFuzzer (LLVM, Apache-2.0 with LLVM exception) | static library, `diff_oracle_template.cpp` | ASan, UBSan, LeakSanitizer | **shipped** (fixture, `examples/risk-limit`) | — |
| C | libFuzzer | the same template (C headers included from C++) | ASan, UBSan, LeakSanitizer | trivial: use the C++ template | — |
| Rust | cargo-fuzz 0.13.2 + libfuzzer-sys 0.4.13 ((MIT OR Apache-2.0) AND NCSA); a pinned **nightly** toolchain | `oracle_shared` linked by `build.rs` | ASan (via cargo-fuzz), LeakSanitizer | **shipped** (`examples/risk-limit-rust`) | UBSan has no Rust equivalent. The fuzz build runs with **overflow checks on**, so an arithmetic overflow panics and FAILs. Release builds wrap silently unless the code uses `checked_*`, `wrapping_*` or `saturating_*`, so write the intended behaviour explicitly. |
| Python | Atheris 3.1.0 (Apache-2.0); wheels for CPython 3.12–3.14 | `ctypes` on `oracle_shared` | none for pure Python (memory-safe); C extensions can be built with ASan | **shipped** (`examples/risk-limit-py`) | Python integers are unbounded, so the binding must reduce to the model's widths (e.g. mod 2^64). That is a **modelling assumption**, listed in the review note, and its drift control includes a difference only above 2^64. |
| Go | native fuzzing (`go test -fuzz`, Go 1.27, BSD-3-Clause) | cgo to the static library | `-asan` with clang | planned | A different engine and command line: it needs its own runner, and its corpus format differs. |
| Java / Kotlin | Jazzer (Apache-2.0) | JNA or the Panama FFI on `oracle_shared` | none for JVM code; native parts can use ASan | planned | needs a JVM; GC timing makes per-input timeouts noisier |
| TypeScript / JavaScript | Jazzer.js (Apache-2.0) | N-API or an FFI module on `oracle_shared` | none for JS | planned | Number vs BigInt: 64-bit values must be BigInt end to end |
| TRON-TVM contracts | the Python loop (Atheris); the contract runs on java-tron's own TRON-TVM, built from source at a pinned release and run offline | `ctypes` on `oracle_shared`, as for Python | none for the contract (energy is its cost measure) | planned, next release | a JVM reference executor: slower per call than an in-process EVM |
| Solidity / EVM | libFuzzer through cargo-fuzz; the contract runs in revm 43.0.3 (MIT), in process; solc 0.8.39 (GPL-3.0, used as a compiler) | the oracle is linked natively into the same process | ASan over the EVM and the binding; the contract itself has none (gas and energy are its cost measure) | **shipped** (`examples/risk-limit-evm`) | A different shape (see below) |

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

**Classification.** A Rust binding can implement `classes()` and `class_universe()`, which return
labels computed from the step and the oracle's result. `run_fuzz.sh` then builds a second,
labels-only binary with `--cfg fv_classify`. It replays the corpus through the oracle and never
compares; the classifier report and review deck follow, as for C++. The generic boundary classes
of the C++ `describe()` (field = 0, max, 2^k ...) have no Rust counterpart yet. Without
`classes()`, a Rust run is classified with no labels. The verdict is unaffected either way.

## Python: setup, pins and measured results

Atheris runs libFuzzer underneath, so the replay, campaign, merge, reproducers and verdicts are the
same as for C++. User-local, in a uv virtual environment:

```sh
P=$FV_ROOT/py; mkdir -p "$P/dl"; cd "$P/dl"
W=atheris-3.1.0-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.whl
curl -sSfL -o "$W" "$(curl -s https://pypi.org/pypi/atheris/3.1.0/json | python3 -I -c \
  "import json,sys; print([u['url'] for u in json.load(sys.stdin)['urls'] if u['filename'] == '$W'][0])")"
echo "315a0b5c819852b1ffe1ca72efc389c7724881f2c33e4aacb8c6bcec49bd5011  $W" | sha256sum -c
uv venv --python /usr/bin/python3 "$P/venv"
uv pip install --python "$P/venv/bin/python" --no-index "./$W"
```

This is the cp314 wheel. For Python 3.12 or 3.13, pick the matching wheel from the same PyPI JSON
and check its sha256.

The split is the same as for C++ and Rust:
- **`fuzz/python/fv_diff.py` (harness)** loads the oracle `.so` through ctypes and does the
  decoding and the step loop. It compares after every step, checks the **integer domain**, and
  writes the mismatch report with exit 86.
- **`fuzz/binding.py` (project)** declares the oracle functions and the implementation module, and
  implements `initial_state`, `make_op`, `oracle_step`, `impl_step`, `u64_values`, `same` and
  `show_*`. It must not define `TestOneInput` or call `atheris.Setup/Fuzz`; `run_fuzz.sh` refuses
  a binding that does.
- A vendored copy of the driver is pinned like the other harness files (with `fv_oracle_bytes.py`,
  which it imports for the ByteArray oracle ABI).

**Wide values: the ByteArray oracle ABI.** For states that do not fit 64-bit fields (160-bit
addresses, 256-bit words, mappings), the spec exports `@[export fv_x] def f (input : ByteArray) :
ByteArray` and the fuzz CMakeLists lists it: `lean_oracle_shared(<target>_oracle ORACLE … BYTES fv_x)`.
The binding declares `ORACLE_BYTES = {"fv_x": <exact output length in bytes>}` and calls
`lib.bytes_oracle.call("fv_x", data)`. Ownership is Lean's own convention for exports (Lean 4.36 allows
no borrow annotation on `@[export]`): the generated wrapper hands its freshly built input to the
function, which consumes it, and releases the result after copying it out. A result of any other
length than declared is ERROR (`diff-oracle: ORACLE ERROR`, exit 87, nothing kept), never truncated.
Control c50 checks the wrapper: no memory growth over 2 × 100,000 calls of 8 KiB, exactly one
reference consumed, the length check, and an unchanged library when no BYTES are listed.

**Memory checking and Lean's heap.** The sanitizers (ASan, UBSan, LSan) cover the implementation under
test and the harness's own buffers. Lean's runtime allocates its objects with its bundled mimalloc,
which the sanitizers do not see: a memory error on the Lean side is caught only by checks of the c50
kind (memory growth, reference counts) and by the gate's kernel and comparator checks of the spec,
not by a sanitizer report.

**Integer domain: a modelling assumption, made explicit.** Python integers are unbounded, while
the oracle's C boundary is unsigned 64-bit. The driver therefore does **not** reduce the
implementation's results mod 2^64. Every value the binding lists in `u64_values` must lie in
[0, 2^64), or the input FAILs as `domain: …`. A result that differs from the oracle only above
2^64, which a reduction would hide, is caught. Control c23 is such a result: a fill that adds
2^64. State the assumption in the project's review note.

Measured on the risk-limit example:
- the correct implementation PASSes at about 13,000 runs/s;
- a reduction one unit short FAILs as a mismatch in about 0.2 s;
- the 2^64 units bug FAILs as `domain: … pos = 18446744073709551616 is outside [0, 2^64)` in
  about 0.1 s.

Controls c21–c24 cover these and the driver. A copy with the domain check replaced by a
reduction mod 2^64 lets c23 PASS, which is exactly the masking the check exists to prevent.

## Threat model of the coupling: the binding is trusted

In every language the **binding is trusted and must be human-reviewed**. It implements
`oracle_step` and `impl_step`, so it can always defeat the comparison: by calling the wrong
function, by comparing the wrong fields, or, in Python, by monkeypatching the driver at run time.

The harness-owned driver (`diff_oracle_template.cpp`, `fuzz/rust/fv_diff.rs`,
`fuzz/python/fv_diff.py`), the vendored-file pins and the run-time guards protect the **loop and
the verdict mechanics** against:
- accidental weakening;
- the environment (`FV_CLASSIFY*`, `CARGO_PROFILE_*`);
- project configuration (`fv.toml` limits, Cargo profiles);
- a project shipping its own loop.

They do **not** protect against a hostile binding. Therefore every project's REVIEW-NOTE must show
its binding: the binding header or module, its `initial_state` (which inputs count as
admissible), and the exact fields compared.

## TRON Virtual Machine (TVM): a reference executor

TRON-TVM contracts use opcodes that revm does not have: CALLTOKEN, TOKENBALANCE, CALLTOKENVALUE,
CALLTOKENID, and TRON's energy rules. `fuzz/run_fuzz.sh --lang tron-tvm` runs them on **java-tron's own
TRON-TVM**, built from source at a pinned release and run offline, with a pinned chain-parameter
profile. Inputs come from the same Python loop as `--lang python`. Every implementation step must send at least one transaction, and only an oracle/contract difference is a finding (executor failures, timeouts and binding exceptions are ERROR): see "Rules for a binding" in `docs/TRON-TVM-REFERENCE.md`. See `docs/TRON-TVM-REFERENCE.md` for
the pins, the reproducible build, and what is and is not covered (no `OUT_OF_TIME`; contract
coverage is measured but does not guide the fuzzer). Each outcome carries the VM's **internal
transactions** as an ordered list (`Outcome.internal`: note, sender, recipient, TRX value, TRC-10
tokens, rejected), compared as a whole: a missing, extra or reordered transfer is a mismatch (control
c49). The example is `examples/token-faucet-tron-tvm`, a capped TRC-10 faucet. A fast in-process TRON-TVM is planned, differential-tested against this
reference.

## Recommended order

1. **C++ / C**: shipped.
2. **Rust**: it links the static oracle directly, speaks libFuzzer's command line, and is in
   demand in trading and crypto.
3. **Python**: Atheris is libFuzzer underneath, so `run_fuzz.sh` reuses everything. Quant and
   risk prototypes often live in Python.
4. **Solidity/EVM**: high value, but a different execution model (next section).
5. **TRON-TVM contracts**: TRC-10 opcodes and TRON's energy rules, which an EVM does not have; a
   reference executor in the next release.
6. **Go**, then **Java/Kotlin**, then **TypeScript/JS**. Each needs a runner for a different engine
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

A per-language drift control (a 1-unit error in that language's implementation) must FAIL within its
execution budget before the binding is trusted.

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

## EVM: setup, pins and what runs

User-local, offline at run time.
- **solc 0.8.39**: the official static Linux build, at `$FV_ROOT/evm/solc-0.8.39`, sha256
  `b8b0642d46838575d3177628b685564b52f51f2aee546cb4dce781951d23c666`. The sha256 is pinned in
  `config/pins.env` as `FV_SOLC_SHA256`, and any other binary is ERROR.
- **revm 43.0.3**: crate checksum `62b2fbb3…c524c`. It is built with `default-features = false,
  features = ["std"]`, so there are no C crypto libraries. Its tree is pinned in the example's
  `Cargo.lock`: 130 packages for linux x86_64, all under permissive licences (MIT, Apache-2.0,
  BSD, CC0, Zlib).
- **cargo**: it runs offline. A `Cargo.lock` that changes during the build is ERROR.

```sh
mkdir -p "$FV_ROOT/evm/dl" && cd "$FV_ROOT/evm/dl"
curl -sSfL -o solc-static-linux https://github.com/ethereum/solidity/releases/download/v0.8.39/solc-static-linux
echo "b8b0642d46838575d3177628b685564b52f51f2aee546cb4dce781951d23c666  solc-static-linux" | sha256sum -c
install -m 555 solc-static-linux "$FV_ROOT/evm/solc-0.8.39"
# revm and its dependencies: fetched once into the cargo registry (Rust toolchain above)
(cd examples/risk-limit-evm/fuzz && cargo +nightly-2026-11-10 fetch --locked)
```

**The split.**
- **The harness owns three things:**
  - the loop, `fuzz/rust/fv_diff.rs`, the same as for Rust;
  - the EVM, `fuzz/evm/fv_evm.rs`. It deploys the creation code once, aborts unless the deployed
    code equals the compiler's runtime bytecode byte for byte, makes committed calls with a fixed
    gas limit, and reports each call as success, revert (with its data) or halt, together with the
    return data and logs. Gas is kept outside the compared outcome.
  - the compile step, `fuzz/evm/compile.py`. It runs solc's standard JSON, with no import callback
    and nothing fetched.
- **The project owns:**
  - the contract;
  - `fv.toml [evm]`: contract, evmVersion, optimizer and, optionally, `expect_runtime_sha256`;
  - the binding. The binding maps the model's state to storage and an operation to a call. It says
    which outcome the model implies, for example "rejected" = revert `LimitExceeded()`. It declares
    the outcome classes it expects (`class_universe`).

**Recorded and enforced.** `fuzz.json` → `evm` records:
- the solc version and sha256;
- the settings;
- each source's sha256;
- the sha256 of the creation and runtime bytecode.

So a closure names exact bytecode. For a deployed contract, set `expect_runtime_sha256` to the
deployed code's sha256. Different compiler output is then BLOCKED before any fuzzer build.

**Outcome classes.** The labels-only classify binary (a separate `--cfg fv_classify` build of the
same target) replays the corpus through the oracle. It records the outcome the model implies for
each step, for example `outcome: submit(uint64) -> revert LimitExceeded()`. Any declared outcome
with no hit in the retained corpus is listed as NOT EXERCISED. The same mechanism serves Rust
targets that implement `classes()`.

**What this covers, and what it does not.**
- One contract and the callers the binding chooses. A model with external calls needs stubs with
  declared behaviour. Reentrancy is out of scope unless modelled.
- Contracts with immutables are refused, because their runtime code is known only after
  deployment.
- Opcodes outside the Ethereum instruction set (chain-specific extensions) are not in revm. A target
  that uses them needs an executor for that chain.
