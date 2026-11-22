# Using the harness

Two parts:
- **Adopt it in your project**: install from a clean machine, prove the install, start your own
  project from the example, sign it with your own key, gate and fuzz your C++, and wire up CI.
- **The walk-through**: every state of the pipeline on the shipped fixture.

Tested in two places:
- **Ubuntu 26.04:** the reference gate host.
- **Ubuntu 24.04:** a clean GitHub-hosted runner, by this repository's CI workflow
  (`.github/workflows/controls.yml`). It runs A1 and A2 with exactly these commands, including the
  bwrap AppArmor step, which that runner needs. A cold install plus the full suite takes about
  18 minutes there.

## Adopt it in your project

### A1. Prerequisites (one gate machine, x86-64 Linux)

| Component | Version | Why |
|---|---|---|
| Ubuntu | 24.04 or 26.04 | reference OS |
| git, curl, jq, bc, python3 | distribution | scripts |
| bubblewrap | distribution (0.9+) | build and audit sandbox |
| clang with libFuzzer, ASan, UBSan; cmake ≥ 3.20 | distribution (clang 18 on 24.04, 21 on 26.04) | differential fuzzer |
| elan 4.4.0 → Lean 4.36.0 | pinned | toolchain, kernel, comparator, the bundled checkers |
| con-leche at 5ea446d5c79d23ef1f954215d094db2162f1ab6f | built from source | `--compare` stage |
| passwordless `sudo` for the gate account | — | a fresh network namespace for the audit |
| a GPU and llama.cpp | optional | the Tier-2 prover; proofs can also come from people or any other tool |

```sh
sudo apt-get update
sudo apt-get install -y git curl jq bc python3 bubblewrap cmake clang
CLANG_MAJOR=$(clang --version | sed -n 's/.*clang version \([0-9]*\).*/\1/p' | head -1)
sudo apt-get install -y "libclang-rt-$CLANG_MAJOR-dev"      # libFuzzer and sanitizer runtimes

# libFuzzer + sanitizers work:
printf 'extern "C" int LLVMFuzzerTestOneInput(const unsigned char*, unsigned long) { return 0; }\n' > /tmp/fz.cc
clang++ -fsanitize=fuzzer,address,undefined /tmp/fz.cc -o /tmp/fz && /tmp/fz -runs=10 2>&1 | tail -1

# Unprivileged bubblewrap works:
bwrap --unshare-all --ro-bind / / --dev /dev --proc /proc true && echo bwrap-ok
```

**If `bwrap` fails**, for example with `setting up uid map: Permission denied` or
`loopback: Failed RTM_NEWADDR: Operation not permitted`, Ubuntu is restricting
unprivileged user namespaces (`kernel.apparmor_restrict_unprivileged_userns = 1`). Ubuntu 26.04
ships an AppArmor profile for bwrap (`bwrap-userns-restrict`); 24.04 does not. Add a profile for
`/usr/bin/bwrap` only, rather than turning the restriction off globally:

```sh
sudo tee /etc/apparmor.d/bwrap > /dev/null <<'EOF'
abi <abi/4.0>,
include <tunables/global>
profile bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,
  include if exists <local/bwrap>
}
EOF
sudo apparmor_parser -r /etc/apparmor.d/bwrap
```

**Lean 4.36.0 and the `--compare` checker**, under `$FV_ROOT`. The default is `~/fv-harness`; set
it in `config/hosts.env` to move it.

```sh
export FV_ROOT=~/fv-harness; mkdir -p "$FV_ROOT/dl" "$FV_ROOT/src"
curl -sSfL -o "$FV_ROOT/dl/elan-init.sh" https://raw.githubusercontent.com/leanprover/elan/v4.4.0/elan-init.sh
echo "a620ff1641616222c8d37c54845492004bb84d6877cdbc944dd65c1aa685bf53  $FV_ROOT/dl/elan-init.sh" | sha256sum -c
ELAN_HOME="$FV_ROOT/elan" sh "$FV_ROOT/dl/elan-init.sh" -y --no-modify-path --default-toolchain none
export ELAN_HOME="$FV_ROOT/elan" PATH="$FV_ROOT/elan/bin:$PATH"
elan toolchain install leanprover/lean4:v4.36.0
"$FV_ROOT/elan/toolchains/leanprover--lean4---v4.36.0/bin/lean" --version
# Lean (version 4.36.0, x86_64-unknown-linux-gnu, commit 611c117bfaf7b7ae1cfcf246ce6fba31e8f509e9, Release)

git clone https://github.com/leanprover/con-leche "$FV_ROOT/src/con-leche-master"
git -C "$FV_ROOT/src/con-leche-master" checkout 5ea446d5c79d23ef1f954215d094db2162f1ab6f
(cd "$FV_ROOT/src/con-leche-master" && lake build con-leche)     # uses its lean-toolchain: v4.36.0
```

**Network namespace.** The gate runs every audit stage in a fresh network namespace:
`sudo -n unshare --net`, then `setpriv` back to the invoking user. Without passwordless sudo, the
`netns` stage is ERROR and no verdict is PASS.

Be aware that a sudoers rule allowing `unshare`/`setpriv` with arbitrary arguments is equivalent
to root. Give it to a **dedicated gate account**, not to the accounts your agents or developers
use; CI runners usually have it already. The gate's guarantees assume the code it audits cannot
write to the gate's own checkout. Keep that checkout owned by the gate account.

On a shared workstation, reserve cores in `config/hosts.env`, e.g. `FV_CPUSET=4-15` and
`FV_JOBS=8` (default: all CPUs).

### A2. Clone and prove the install

```sh
git clone <this repository> fv-harness && cd fv-harness
tests/harness_fv_controls/run_controls.sh            # about 5–10 minutes on 8 cores
```

Expected: 15 controls, each `OK`, then `0 control(s) misbehaved`, exit 0:
- **c1** (clean proof: every stage PASS, 10^6 fuzz runs);
- **c2–c4** (`sorry`, a custom axiom, `trustCompiler`, `native_decide`, a weakened statement, a
  shadowed definition: FAIL, each at the stages listed in its line);
- **c5a–c5d** (a sandbox write, a tampered challenge, an unsigned re-lock, a key swap: BLOCKED, or
  a loud fingerprint mismatch);
- **c6** (one-unit C++ drift: fuzz FAIL in well under 10 s);
- **c7** (a production leak reported);
- **c8** (a tampered vendored fuzz template: FAIL before the build).

The reference output is in `tests/harness_fv_controls/evidence/summary.txt`. Then run the second
example end to end:

```sh
examples/risk-limit/run.sh     # gate PASS; correct C++ 10^6 runs PASS; buggy C++ FAIL in < 1 s
```

### A3. Start your project from `examples/risk-limit`

Keep the Lean project and the C++ side in **separate** directories. The lock covers every file of
the Lean project except `.lake/` and `spec/solution/`.

```sh
P=formal/my-check                                 # anywhere, e.g. inside your own repository
mkdir -p "$P" && cp -r examples/risk-limit/lean examples/risk-limit/cpp "$P"/
rm -rf "$P/cpp/impl-buggy" "$P/cpp/impl"          # your production code is used in place
```

Then rename and fill in:

| File | Change |
|---|---|
| `lean/lakefile.toml` | `name` (the Lake package, e.g. `my_check`); the library `RiskSpec` → `MyCheckSpec`, with the directory and the imports renamed to match |
| `lean/spec/challenge/<Spec>/Model.lean` | **your reference model**: plain functions over `Nat`/`Int`/structures, no proofs. Mirror the C++ function by function |
| `lean/spec/challenge/Challenge.lean` | **your statements**, each proved by `sorry`: conservation, bounds, widths, invariants under any event sequence |
| `lean/comparator.json` | `theorem_names` = every statement, fully qualified; `permitted_axioms` stays exactly the three |
| `lean/spec/challenge/<Spec>/Oracle.lean` | `@[export your_c_name]` wrappers taking and returning `UInt64` (or a byte codec for structured data), reducing outputs mod 2^64 the way the C++ does |
| `lean/spec/solution/Solution.lean` | the proofs (or a `sorry` skeleton for the provers to fill) |
| `cpp/fuzz/binding.hpp` | `State`, `Op`, `initial_state` (generate **admissible** states only: the ones your hypotheses assume), `make_op`, `oracle_step` (call your exported functions), `impl_step` (call **your production function**), `same`, `print_*`, `warm_up` |
| `cpp/fuzz/CMakeLists.txt` | `lean_oracle_library(... PACKAGE <lake package> LEAN_LIB <Spec> INIT_MODULES <Spec>.Oracle)`; `add_diff_fuzzer(<target> ...)` as below |

Point the fuzzer at your production code:

```cmake
add_diff_fuzzer(diff_my_check
  BINDING "${CMAKE_CURRENT_SOURCE_DIR}/binding.hpp"
  ORACLE my_check_oracle
  INCLUDE_DIRS "${IMPL_DIR}"                          # your headers
  SOURCES "${IMPL_DIR}/../src/risk_check.cpp"         # your translation units, if any
  LINK_LIBRARIES my_trading_core)                     # or your libraries
```

Check the draft before anyone signs it:

```sh
scripts/preflight_lake_build.sh "$P/lean"                                # trusted part builds
scripts/synth_sandbox.sh --project "$P/lean" -- lake build Solution    # skeleton type-checks
```

### A4. Your own signing key, lock and pin

The specification owner, a person and not an agent, does this on their own machine, with a key
that never reaches the gate host or any agent host. **Never reuse the FIXTURE-ONLY key.** Its
fingerprint `SHA256:R6l4…` must never be pinned for a real project.

```sh
ssh-keygen -t ed25519 -C spec-owner -f ~/.ssh/spec_owner_ed25519          # owner's machine; use a passphrase
ssh-keygen -lf ~/.ssh/spec_owner_ed25519.pub                                 # the fingerprint you will state
```

On the gate checkout, write the manifest, have the owner sign it, and record the owner's key and
fingerprint:

```sh
N=my-check
scripts/spec_lock.sh lock "$P/lean" locks/$N.sha256
# owner, on their machine, on a copy of locks/$N.sha256:
#   ssh-keygen -Y sign -f ~/.ssh/spec_owner_ed25519 -n fv-spec-lock $N.sha256   -> $N.sha256.sig
cp <the owner's $N.sha256.sig> locks/
echo "owner@$N namespaces=\"fv-spec-lock\" <contents of spec_owner_ed25519.pub>" > locks/$N.allowed_signers
echo "$N SHA256:<fingerprint as the owner stated it> owner key" >> config/signer_pins.txt
scripts/spec_lock.sh check "$P/lean" locks/$N.sha256                     # match=yes, exit 0
```

Any later change to a locked file is BLOCKED until the owner signs a new manifest. Read
"Signed SPEC_LOCK and the residual risk" in the README.

### A5. Gate your proofs and fuzz your C++

```sh
scripts/verify_proof.sh --project "$P/lean" --lock locks/$N.sha256 --out runs/gate
#   first line: SPEC-LOCK SIGNER ... match=yes ; exit 0 PASS / 1 FAIL / 2 BLOCKED / 3 ERROR
fuzz/run_fuzz.sh --lean-project "$P/lean" --lock locks/$N.sha256 --cmake-dir "$P/cpp/fuzz" \
  --target diff_my_check --impl-dir <your include dir> --runs 1000000 --corpus "$P/cpp/fuzz/corpus"
#   exit 0 PASS / 1 FAIL (mismatch or sanitizer report; reproducer in the run's artifacts/) / 2 BLOCKED
```

Seed `corpus/` with realistic inputs if you have them. Then plant one deliberate bug in a copy of
your C++ and check that the fuzzer finds it, as `cpp/impl-buggy` does in the example.
`scripts/formal_task.py` drives the same steps as a state machine, with a closure report
(walk-through below).

### A6. CI

This repository's own workflow, `.github/workflows/controls.yml`, runs A1 and A2 with these exact
commands on a clean GitHub-hosted Ubuntu 24.04 runner. Use it as a template for the install part.

For your project, run the same two checks on every change to the locked files or to the
production code. Put the owner's fingerprint in the workflow as a **literal**:

```yaml
jobs:
  formal:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      # cache $FV_ROOT (elan, Lean, con-leche) keyed on config/pins.env; install as in A1 on a miss
      - run: scripts/spec_lock.sh check formal/my-check/lean locks/my-check.sha256 --expect-fingerprint SHA256:<owner's>
      - run: scripts/verify_proof.sh --project formal/my-check/lean --lock locks/my-check.sha256 --expect-fingerprint SHA256:<owner's>
      - run: fuzz/run_fuzz.sh --lean-project formal/my-check/lean --lock locks/my-check.sha256 --cmake-dir formal/my-check/cpp/fuzz --target diff_my_check --time 60
```

Hosted runners have passwordless sudo, which the audit's network namespace needs. Run the A1 `bwrap`
check as a step: if the runner restricts user namespaces, add the AppArmor profile there as well.
Why the fingerprint literal matters, and what it does not close: `docs/DESIGN-NOTES.md` §2.

---

# The walk-through

This walk-through takes the shipped fixture through every state, from mapping the code to CI. The
fixture is a ledger transfer with a rounded-down fee: `fixtures/conservation` (Lean) and
`fixtures/conservation_cpp` (the "production" C++ and its fuzz binding). Every command runs on the
gate host from the repository root, after the prerequisites in A1.

```sh
export FV_ROOT=~/fv-harness            # work, task and run directories (config/pins.env)
H=$PWD                                 # this repository
```

## 0. Map the code

Pick a function whose correctness is exact arithmetic or state-transition logic
(`docs/APPLICATIONS.md`). For the fixture:
- **Production code:** `fixtures/conservation_cpp/impl/ledger.hpp`. Its ledger has accounts `a`, `b`
  and a `fee` pool. A transfer moves `x = min(amt, a)` out of `a`, takes a fee of
  `x · min(bps, 10000) / 10000` (rounded down) into the pool, and credits the rest to `b`.
- **The one-sentence invariant:** the total `a + b + fee` is unchanged.

Write down the C++ types (here `uint64_t`, wrapping) and every input range the caller guarantees.

## 1. Write the challenge (`spec/challenge/`)

A Lake project with this layout (see README, "Project contract"):

```text
fixtures/conservation/
  lakefile.toml, lean-toolchain, lake-manifest.json   -- core Lean only
  comparator.json                                     -- theorem names + the three permitted axioms
  spec/challenge/FVSpec/Ledger.lean                   -- the model: plain functions, no proofs
  spec/challenge/FVSpec/Oracle.lean                   -- @[export] wrappers for the fuzzer
  spec/challenge/Challenge.lean                       -- the statements, each proved by `sorry`
  spec/solution/Solution.lean                         -- where proofs go (agent-writable)
```

The statements of the fixture:

```lean
theorem transfer_conserves (l : Ledger) (amt bps : Nat) :
    (transfer l amt bps).total = l.total := by sorry
theorem transfer_source_le (l : Ledger) (amt bps : Nat) :
    (transfer l amt bps).a ≤ l.a := by sorry
```

Rules:
- The challenge imports only Lean core (or a pinned Mathlib).
- The oracle's `@[export]` functions live in `spec/challenge/`, so the oracle is locked with the
  statements.
- `comparator.json` must name exactly `propext`, `Quot.sound` and `Classical.choice` as permitted
  axioms.

## 2. Validate the draft before anyone signs it

```sh
W=$FV_ROOT/work/walkthrough; rm -rf "$W"; cp -r fixtures/conservation "$W"; rm -rf "$W/.lake"
scripts/preflight_lake_build.sh "$W"           # the trusted part builds on its own
scripts/synth_sandbox.sh --project "$W" -- lake build Solution   # a sorry skeleton type-checks
```

Then fuzz the C++ against the **challenge-only** oracle before any proof exists. This finds model
and C++ disagreements early, when they are cheap to fix:

```sh
fuzz/run_fuzz.sh --lean-project "$W" --lock locks/conservation.sha256 \
  --cmake-dir fixtures/conservation_cpp/fuzz --target diff_transfer --time 60 --no-merge
```

(The lock must exist for `run_fuzz.sh`; for a brand-new project, create it with step 3 first, or
build the fuzz directory by hand with `cmake -S <fuzz dir>`.)

## 3. Lock and sign (`SPEC_LOCK`)

Anyone can write the manifest. Only the specification owner signs it, on their own terminal, with
a key that never reaches an agent host:

```sh
scripts/spec_lock.sh lock fixtures/conservation locks/conservation.sha256
ssh-keygen -Y sign -f ~/.ssh/<owner key> -n fv-spec-lock locks/conservation.sha256   # owner only
ssh-keygen -lf ~/.ssh/<owner key>.pub                                               # owner states this
```

Then record the owner's key and fingerprint:
- `locks/<name>.allowed_signers`: one line, `<principal> namespaces="fv-spec-lock" ssh-ed25519 AAAA…`;
- `config/signer_pins.txt`: `<name> SHA256:<fingerprint as the owner stated it>`.

The shipped fixture is already signed with a labelled FIXTURE-ONLY key, so you can check it as is:

```sh
scripts/spec_lock.sh check fixtures/conservation locks/conservation.sha256
# SIGNER principal=fixture-only@fv-harness fingerprint=SHA256:R6l4… pinned=SHA256:R6l4… match=yes
# OK: 9 trusted files match signed lock 64e0f8f7…
```

If you re-lock the fixture you must re-sign it with your own key, replace its `allowed_signers`,
and pin your key's fingerprint.

## 4. Create the task and decompose (`DECOMPOSE`)

```sh
FT="python3 -I $H/scripts/formal_task.py"
$FT init walk --project "$W" --lock locks/conservation.sha256 \
  --cmake-dir fixtures/conservation_cpp/fuzz --target diff_transfer --fuzz-runs 1000000
$FT spec-lock walk                    # SPEC_LOCK -> DECOMPOSE; records the signer
```

The Tier-1 planner, an agent with the lean-lsp MCP server (`agent-config/`), writes a skeleton into
`spec/solution/`. The skeleton is the main theorems proved from small lemmas, each still `sorry`.
The dry run's skeleton is `tests/dry_run/skeleton/Solution.lean`:

```sh
cp tests/dry_run/skeleton/Solution.lean "$W/spec/solution/"
$FT decompose walk --by "Tier-1 planner"   # -> DISCHARGE; lists the open stubs
```

## 5. Discharge (`DISCHARGE`): Tier 2, with the early wall

Start the Tier-2 endpoints from `config/tier2.env`. The `fast` stage runs on the gate host's GPU;
the `main` stage runs on a remote GPU host, through the relay if needed:

```sh
prover/tier2_server.sh start fast
$FT discharge walk
```

For each open stub, the cascade asks K samples: the `fast` model first, then the `main` model.
Each candidate is spliced under the original statement, linted, compiled, and its axioms checked.
A stub **walls** (back to DECOMPOSE for Tier 1) in two cases:
- after `max_attempts` attempts (default 1 × K = 4);
- at once, when every sample of an attempt failed the same way.

Change the budget per task:

```sh
$FT set walk --budget 8 --max-attempts 2 --same-failure-wall on
```

On a wall, the planner splits the leaf. In the dry run that split was the nonlinear product bound
`x * min bps 10000 ≤ x * 10000`. Then run `decompose` again. The counters are in
`$FV_ROOT/tasks/walk/state.json` (`tier2_stats`).

## 6. Audit (`AUDIT`)

```sh
$FT audit walk          # or: scripts/verify_proof.sh --project "$W" --lock locks/conservation.sha256
```

Ten stages run, in a fresh network namespace, on a copy of the project:
- `lock`, `lint`, `netns`, `config`;
- `comparator_native` (six kernels);
- `export`, `comparator_export`;
- `con_leche`, `con_ron`, `con_leche_compare`.

The first line of the output and of `verdict.json` is the signer. A FAIL goes back to DECOMPOSE
with the checker diagnostics, and the synthesis side fixes only `spec/solution/`.

## 7. Couple (`COUPLE`)

```sh
$FT couple walk
```

The oracle is built from the locked files only and linked against the production C++ under
libFuzzer, ASan and UBSan. The persisted corpus is replayed, then a 10^6-run campaign runs. Any
mismatch is a FAIL and opens a C++ bugfix task; the specification is never changed to make the
code pass.

Harness files vendored into the fuzz directory must match the harness at the commit they cite
(`fuzz/check_vendored.sh`).

## 8. Close (`CLOSE`)

```sh
$FT close walk
head -1 $FV_ROOT/tasks/walk/closure.md
# SPEC-LOCK SIGNER: SHA256:R6l4… (fixture-only@fv-harness; pinned SHA256:R6l4…, match=yes). …
```

`closure.json` bundles:
- the source digests;
- the gate stages and kernel verdicts;
- the fuzz statistics;
- the Tier-2 counters;
- the full timeline.

**The owner's ten-second check:** the fingerprint on the first line must be the one they stated.
`$FT run walk` drives DISCHARGE → CLOSE in one go. `tests/dry_run/run_dry_run.sh` runs the whole
walk-through unattended.

## 9. CI

The CI job runs the lock check with the expected fingerprint as a **literal in the workflow**, then
a short fuzz campaign:

```yaml
- run: scripts/spec_lock.sh check <project> locks/<name>.sha256 --expect-fingerprint SHA256:<owner's>
- run: fuzz/run_fuzz.sh --lean-project <project> --lock locks/<name>.sha256 --cmake-dir <fuzz dir> --target <t> --time 60
```

`docs/DESIGN-NOTES.md` §2 explains why the literal matters and what it does not close.

## Acceptance controls

```sh
tests/harness_fv_controls/run_controls.sh      # 15 controls; exit 0 iff all behave as specified
tests/state_machine_rehearsal.sh               # every state transition, mock Tier-2 endpoint
```
