# Formal-verification harness

The trusted side of the Specification → Proof → Independent Audit pipeline: the verification gate,
the challenge/solution trust boundary, and the acceptance controls. Synthesis agents never edit this
repository.

The pipeline:
- A human owner **signs** a Lean specification of a production routine: a reference model plus
  theorem statements.
- AI provers write the proofs in a separate, agent-writable tree.
- An isolated **gate** re-checks them with the Lean kernel, four independent checkers and a
  statement comparator.
- A **differential fuzzer** ties the shipped C/C++ to the proved model bit for bit.

## Changes in v0.2.1

- **COUPLE runs the task's language.** `formal_task.py init --lang cpp|rust|python|evm` (default
  `cpp`) is passed to `fuzz/run_fuzz.sh --lang`, with `--impl-dir` only when it was given. In v0.2.0,
  COUPLE always ran the C++ path, so a Rust, Python or EVM task could not be closed through the state
  machine.
- `fuzz.json` records `lang`; COUPLE and CLOSE refuse a fuzz record of another language.
- **Closure format change.** `closure.json` → `source_digests.cpp_impl` (v0.2.0: a map of file →
  sha256) is replaced by `source_digests.impl`: `{lang, dir, files}`, where `dir` is the
  implementation directory the campaign actually used and `files` the same file → sha256 map
  (generated `__pycache__` left out). The closure's `fuzz` section also records `lang`, `impl_dir`,
  `limits` and, for EVM, `evm`. Readers of v0.2.0 closures: `cpp_impl` there means what
  `impl.files` means here.
- `tests/lang_rehearsal.sh` runs every language through the whole state machine on the examples.
- **Known issue in v0.2.0, fixed in v0.2.1:** with `--lang python` the corpus merge did not run
  (libFuzzer re-executes `argv[0]` for the merge, and the Python driver is not executable on its own);
  verdicts were unaffected (the campaign decides in-process, before the merge), but the persisted corpus
  did not grow. The merge now re-executes the run's wrapper, and a merge that did not run is ERROR, for
  every language (control c52).
- **Known issue in v0.2.0, fixed in v0.2.1:** a failure *during* the corpus merge could end as PASS.
  The merge re-runs every input in a fresh process; when one failed there (an implementation whose
  behaviour depends on process state or order), libFuzzer retried without that input and reported
  success. Now a finding during the merge is FAIL with its reproducer kept, an inner merge process that
  died without a finding is ERROR, and a merge must complete in one attempt (controls c53, c54, c59).
  The input libFuzzer skipped was not added to the corpus either, so later replays did not see it.

## Start here

- **Adopting it for your own C/C++ code?** Read `docs/USAGE.md`, "Adopt it in your project". It
  covers prerequisites and install, proving the install with the control suite, starting from
  `examples/risk-limit`, signing with your own key, gating and fuzzing your code, and CI.
- `docs/USAGE.md`, "The walk-through": every pipeline state on the shipped fixture.
- `docs/APPLICATIONS.md`: where it fits (blockchain and pools, trading, matching, settlement,
  codecs) and where it does not.
- `docs/CASE-STUDIES.md`: what it found on first use.
- `examples/risk-limit/`: a pre-trade risk check, with a correct and an overflow-buggy C++ variant.
- `docs/HARDWARE.md`: machine profiles (minimum and recommended) and the prover models by GPU class. No GPU is needed for the gate.
- `docs/LANGUAGES.md`: languages beyond C++. Rust, Python and Solidity/EVM are shipped
  (`examples/risk-limit-rust`, `examples/risk-limit-py`, `examples/risk-limit-evm`); Go, Java/Kotlin
  and JS are planned. It also covers how each binds to the oracle.

Licence: Apache-2.0 (`LICENSE`, `NOTICE`). Third-party tools and models are referenced, not
vendored (`THIRD-PARTY.md`). Commit ids cited in reports refer to the development history from
before this repository's single root commit.

## Layout

| Path | What |
|---|---|
| `config/hosts.example.env` | Site values (gate host alias, remote GPU host, ports); copy to `config/hosts.env` |
| `config/pins.env` | Toolchain and checker pins, CPU caps, axiom policy |
| `scripts/verify_proof.sh` | The gate (Module 4). Exit 0 PASS, 1 FAIL, 2 BLOCKED, 3 ERROR |
| `scripts/gate_inner.sh` | Audit stages; runs inside a fresh network namespace |
| `scripts/spec_lock.sh` | SPEC_LOCK: SHA-256 manifest of every trusted file |
| `scripts/solution_lint.sh` | Policy lint over `spec/solution/` (defence in depth) |
| `scripts/synth_sandbox.sh` | bwrap jail for synthesis-side tools: only `spec/solution/` and `.lake/` writable |
| `locks/` | Lock manifests. They live here, outside every agent-writable tree |
| `fixtures/conservation/` | Minimal arithmetic conservation fixture: ledger transfer with a rounded-down fee |
| `fixtures/conservation_cpp/` | Its production C++ (`impl/`) and differential fuzzer (`fuzz/`: binding, CMake, corpus) |
| `examples/risk-limit-evm/` | The same signed spec coupled to a Solidity contract (pinned solc, in-process EVM), with drift, checked-overflow and unchecked-wrap controls |
| `examples/risk-limit-py/` | The same signed spec coupled to a Python implementation (Atheris), with drift and 2^64-domain controls |
| `examples/risk-limit-rust/` | The same signed spec coupled to a Rust implementation (cargo-fuzz), with drift and overflow controls |
| `examples/risk-limit/` | A second, end-to-end example: a pre-trade risk check (signed lock `locks/risk-limit.*`), correct and buggy C++, `run.sh` |
| `fuzz/diff_oracle_template.cpp` | Reusable differential fuzzer (Module 5) |
| `fuzz/LeanOracle.cmake` | `lean_oracle_library()` and `add_diff_fuzzer()` CMake functions |
| `fuzz/run_fuzz.sh` | COUPLE stage: lock check, oracle build, corpus replay, campaign, corpus merge |
| `tests/harness_fv_controls/` | Acceptance controls (spec §4) and a neutral summary of a clean run (`evidence/`). Hosted CI runs the gate and C++ controls; the language controls (c15–c29) SKIP there and are verified on a gate host, not in CI (`docs/LANGUAGES.md`) |
| `scripts/lean_lsp_mcp.sh`, `scripts/preflight_lake_build.sh` | Module 1: sandboxed lean-lsp MCP server; pre-flight build |
| `prover/` | Module 3: Tier-2 endpoint (`tier2_server.sh`) and `dispatch_local_prover` (`dispatch.sh`) |
| `config/tier2.env` | Tier-2 endpoint and server settings (the endpoint is config only) |
| `agent-config/` | MCP registration, synthesis policy, settings template with the pre-flight hook |
| `docs/DESIGN-NOTES.md` | Early-wall escalation rule, CI fingerprint literal, fixture corpus, Mathlib deferral |
| `docs/USAGE.md`, `docs/APPLICATIONS.md`, `docs/CASE-STUDIES.md` | Walk-through, domains, first-use findings |
| `docs/DRY-RUN-REPORT-FV-01.md` | The first end-to-end run on the fixture |
| `prover/remote/`, `prover/relay/` | Remote GPU instances of the Tier-2 `main` stage; loopback relay |
| `tests/*/evidence/` | Neutral summaries of the dry run, the control suite and the rehearsal |

## Project contract

A verified project is a Lake project with:
- `spec/challenge/`: reference model and theorem statements whose proofs are `sorry`. Trusted and locked.
- `spec/solution/`: `Solution.lean` plus `Solution/**.lean`. This is the only agent-writable part.
- `lakefile.toml`, `lean-toolchain`, `lake-manifest.json` and `comparator.json`. All trusted and locked.

`comparator.json` names the challenge and solution modules, the `theorem_names` (and optional
`definition_names`), and `permitted_axioms`. The axioms must be exactly
`propext, Quot.sound, Classical.choice`; the gate refuses any other list.

## Gate stages

| Stage | Check | Catches |
|---|---|---|
| `lock` | `LOCK.sig` verifies, its signer matches the pinned fingerprint, and the trusted files equal the manifest (optional `--git-base` diff gate). Failure means BLOCKED and nothing is audited | Edits to the challenge or build config; a lock rewritten without the operator's key |
| `lint` | No sorry/admit/axiom/native_decide/extern/implemented_by/metaprogramming; files ≤ 1000 lines; only `Solution*.lean` | Policy violations, early |
| `netns` | The audit runs in a fresh network namespace (`sudo unshare --net`, then setpriv back to the user) | Network access during verification |
| `comparator_native` | `lake comparator --paranoid`: Lake builds and exports in bwrap, compares statements structurally, checks the axiom whitelist, then runs leanchecker, leanchecker-paranoid, lean4lean, nanoda, con-leche and con-ron | Weakened or shadowed statements, axioms, kernel bugs |
| `export` | The gate's own bwrap builds. The challenge comes from a solution-free tree. Writes inert NDJSON exports | Solutions that do not build |
| `comparator_export` | `lake comparator --*-from-export` on those exports | Same as `comparator_native`, from independent exports |
| `con_leche`, `con_ron` | Bundled checkers on the solution export. PASS requires exit 0 and `accepted N declarations` | sorry, custom axioms, native_decide, kernel bugs |
| `con_leche_compare` | con-leche master `--compare challenge solution` | Statement mismatch, shadowed definitions |

Facts the policy rests on, verified on Lean v4.36.0:
- Lean 4.36 removed `Lean.trustCompiler`, `reduceBool`, `ofReduceBool` and `ofReduceNat`.
- `native_decide` now emits an auxiliary axiom per use. comparator calls it illegal, and con-* decline it.
- con-leche and con-ron install a declaration named `Lean.trustCompiler : True` as sound by design, so only the comparator whitelist rejects it.
- con-leche and con-ron check consistency, not statement equality. A weakened statement passes them; comparator and `--compare` catch it.

## Signed SPEC_LOCK and the residual risk

A lock is three files in `locks/`, plus a pin:
- `<name>.sha256`: the manifest;
- `<name>.sha256.sig`: an `ssh-keygen -Y` signature, namespace `fv-spec-lock`;
- `<name>.allowed_signers`: the signer's public key, restricted to that namespace;
- the signer's fingerprint, pinned in `config/signer_pins.txt`.

`scripts/spec_lock.sh check` enforces three things in order. Any failure is BLOCKED (exit 2) before anything is audited:
1. **Signature**: it verifies against the allowed signers. A missing, foreign or bad signature fails.
2. **Pin**: the signer's fingerprint equals the pin, or `--expect-fingerprint`. A missing pin also fails.
3. **Content**: the trusted files equal the manifest.

The signer line `SPEC-LOCK SIGNER principal=… fingerprint=… pinned=… match=…` is the first line of
the gate's output. It is also the first key of `verdict.json`, and the first line of `closure.md`
and `closure.json`.

**For a real project, the operator signs on their own terminal**, with a key that never leaves it:

```sh
scripts/spec_lock.sh lock <project> locks/<name>.sha256          # anyone: writes the manifest
ssh-keygen -Y sign -f ~/.ssh/<operator key> -n fv-spec-lock locks/<name>.sha256   # operator only
ssh-keygen -lf ~/.ssh/<operator key>.pub                         # operator states this fingerprint
```

The operator's public key goes into `locks/<name>.allowed_signers` as
`<principal> namespaces="fv-spec-lock" ssh-ed25519 AAAA…`. The fingerprint, as the operator
states it in their own words, goes into `config/signer_pins.txt` and into the orchestrator's record.

The fixture uses a labelled **FIXTURE-ONLY** test key held by the gate operator
(`SHA256:R6l4wkshUPWT3e1nrbQysrKihLdvMoY9Sh+q9EfNtMw`). It must never be pinned for a real project.

**Residual risk, stated plainly.** If synthesis agents share an OS user (here with passwordless sudo on the gate host) and a
repository identity with the gate operator, as in the reference deployment, then an agent can replace a challenge
together with its lock, signature, allowed-signers file **and** the pin. The gate then passes:
nothing in-band can stop that.

What remains is detective:
- The signer fingerprint printed first in every report would differ from the operator's.
- The pin change is a visible diff in `config/signer_pins.txt`.
- The control suite compares against a recorded constant (control `c5d_key_swap`).

**The final assurance is the operator's ten-second check:** the fingerprint on the first line of
each CLOSE report must equal the one they stated. A report whose fingerprint differs is void.

Optionally, the operator can register the key as a GitHub SSH signing key in the web UI. Commits
that touch `spec/challenge/` or `locks/` then show "Verified". The agents' token has no
key-admin scope, so it cannot add signing keys.

## Oracle bridge and differential fuzzer (Module 5)

Pure state-transition functions are exported from **`spec/challenge/`** with `@[export]`. They
take and return 64-bit values and reduce outputs mod 2^64, matching C++ unsigned arithmetic.
`fuzz/run_fuzz.sh` checks the spec project against its lock, copies only the locked files, and
lets CMake build the Lean library's static facet from that copy. So the oracle never sees
`spec/solution/`.

`lean_oracle_library()` links that library with `libleanshared` and generates `fv_oracle_init()`.
`add_diff_fuzzer()` compiles `diff_oracle_template.cpp` against a binding header under
`-fsanitize=fuzzer,address,undefined`.

What the template does:
- Inputs are structure-aware: an initial state, then 1–64 operations or one operation repeated (saturation).
- Values favour boundaries: 0, 1, 9999/10000/10001, 2^32, 2^63, 2^64−1 and their neighbours.
- States are compared bit-exactly after every step.
- A mismatch prints both states, writes `mismatch-<hash>` and exits 86.

What `run_fuzz.sh` does:
- Checks vendored harness files. A project's fuzz directory lies outside the spec lock, so a copy of
  `LeanOracle.cmake` or `diff_oracle_template.cpp` there must match the harness's copy at the commit
  its "Vendored from fv-harness <commit>" header names (`fuzz/check_vendored.sh`,
  `fuzz/VENDORED.sha256`); otherwise COUPLE FAILs before anything is built. Both hashes go into
  `fuzz.json` and the closure bundle. Control `c8_vendored_tamper` covers it. The project's own
  `binding.hpp` and `CMakeLists.txt` remain agent-side: review them like any other test code.
- Applies per-project limits from `fv.toml` (`timeout`, `rss_limit_mb`, `malloc_limit_mb`, `report_slow_units`). Leaks, hangs and unbounded growth FAIL with their own detail (`LEAK`, `HANG`, `OOM`); see `docs/DESIGN-NOTES.md` §6.
- Replays the persisted corpus first (regression).
- After the verdict is settled, classifies the corpus for the reviewer (labels only, never part of
  the verdict). This is a separate replay through the oracle alone; the C++ is not called. It
  reports which edge cases were exercised:
  - boundary values of the fields the binding declares;
  - empty, single and tied collections;
  - exact vs remainder-boundary divisions;
  - outcome labels;
  - the project's own domain classes from `classes.hpp`.

  Classes with 0 hits are listed as **NOT EXERCISED**. A review deck of the smallest example per
  class goes to `classify/review_deck.md`. Control `c9_edge_not_exercised` proves a gap is
  reported. See `docs/DESIGN-NOTES.md` §5.
- Runs `-runs=N` (default 10^6) or `-max_total_time=S` (CI: 60).
- On PASS, merges new coverage into `fuzz/corpus/`.
- On FAIL, adds the reproducer to the corpus, so replay keeps failing until the C++ is fixed.
- Exit codes follow the gate: 0 PASS, 1 FAIL, 2 BLOCKED, 3 ERROR. Summary in `fuzz.json`.

Notes from bring-up on Lean 4.36:
- Each module initializer starts the runtime itself (`lean_initialize_runtime_module` is no
  longer in `lean.h`).
- LeakSanitizer reports 128 B in 12 objects at exit. These are GMP-backed big-natural constants
  that `Init.Prelude`'s initializer builds once and keeps for the life of the process.
- The template runs the runtime start, the module initializers and one warm-up oracle call (big
  values) inside `__lsan::ScopedDisabler` in `LLVMFuzzerInitialize`. Only allocations made in
  that block are exempt. There is no suppression file and no pattern that could match
  production frames.
- Measured: 0 leak reports over 10^6 runs.
- Control `c7_lsan_leak` proves production leaks are still caught. Its production header leaks
  32 B per call; LSan must report it with its `ledger.hpp` frame, or the suite fails.
- After the Lean runtime installs its signal handlers, libFuzzer's abort path crashed inside
  ASan. Hence the template exits 86 and writes the reproducer itself.

## Usage (on the gate host)

```sh
scripts/spec_lock.sh lock PROJECT locks/NAME.sha256     # spec author, at SPEC_LOCK
scripts/verify_proof.sh --project PROJECT --lock locks/NAME.sha256 [--out RUNDIR]
tests/harness_fv_controls/run_controls.sh [OUTDIR]       # acceptance controls
scripts/synth_sandbox.sh --project PROJECT [--net] -- lake build Solution
fuzz/run_fuzz.sh --lean-project fixtures/conservation --lock locks/conservation.sha256 \
  --cmake-dir fixtures/conservation_cpp/fuzz --target diff_transfer [--time 60 | --runs 1000000]
```

## Live LSP and Tier-2 prover (Modules 1 and 3)

The registration, policies, hook and tool are in `agent-config/README.md`.
- `scripts/lean_lsp_mcp.sh` serves `lean-lsp-mcp==0.33.0` inside the synthesis sandbox, with the remote search tools removed.
- `scripts/preflight_lake_build.sh` warms `lake serve`.
- `prover/dispatch.sh` is `dispatch_local_prover(file, lemma_name, budget)`:
  - K samples from the chat-completions-compatible endpoint (`/v1/chat/completions`) in `config/tier2.env`;
  - each candidate is spliced under the lemma's original statement, policy-linted, compiled, and its axioms checked;
  - up to `TIER2_ROUNDS` repair rounds with compiler messages; first success wins;
  - exit 1 is a wall event (escalate to Tier 1).
- Escalation budget is per task (`formal_task.py init|set --budget K --max-attempts N
  --same-failure-wall on|off`), default 1 attempt × K = 4 from `config/tier2.env`. A stub walls at
  once when every sample of an attempt failed the same way. Counters: `tier2_stats` in the task and
  the closure bundle. See `docs/DESIGN-NOTES.md` §1.
- `prover/tier2_server.sh start|stop|status fast|local` runs one llama-server profile on the gate
  host (one at a time on a 6 GB card): 127.0.0.1 only, CPU-pinned, all layers on the GPU.

### Production Tier 2: the cascade

`TIER2_CASCADE="fast main"` in `config/tier2.env`. A stage whose endpoints do not answer is
skipped without spending budget; the first stage that closes the lemma ends the cascade.

| Stage | Model | Where (reference deployment) | Endpoint (from the gate host) | Prompt | K / rounds |
|---|---|---|---|---|---|
| `fast` | DeepSeek-Prover-V2-7B Q4_K_M | gate host, RTX 3060 6 GB, `tier2_server.sh start fast` | `http://127.0.0.1:8082/v1`, 1 slot, ctx 6144, q4_0 KV | code only (`plain`) | 4 / 1 |
| `main` | Goedel-Prover-V2-8B Q6_K | remote GPU host, RTX 3060 12 GB per instance, `fv-tier2@<instance>` | `http://127.0.0.1:18100/v1` through the relay, 4 slots, ctx 4 × 8192, q8_0 KV | proof plan then code (`cot`) | task K / 3 |
| `local` (fallback) | Goedel-Prover-V2-8B IQ4_XS | gate host, `tier2_server.sh start local` | `http://127.0.0.1:8081/v1`, 1 slot | `cot` | task K / 3 |

Measured in the reference deployment:
- `fast`: 68 tok/s decode, about 1 s per sample, 4.9 of 6.1 GB VRAM.
- `main` per instance: 46 tok/s on one slot, 99 tok/s aggregate over 4 concurrent requests, 8.7 of 12.3 GB VRAM.

A stage's `BASE_URL` may list several endpoints serving the same model (space-separated). The
stage's samples are then spread over the endpoints that answer, `SLOTS` per endpoint. Each sample
logs its endpoint, and the report counts samples, rounds, closures and tokens per endpoint.

**Deployment of the `main` stage.** Site values live in `config/hosts.env` (copy
`config/hosts.example.env`).
- **Remote GPU host** (`prover/remote/`):
  - `fetch.sh` downloads and verifies the pinned files: the official llama.cpp b12387
    `ubuntu-cuda-12.8-x64` release, its cudart bundle and the model.
  - `install.sh` unpacks them into `~/fv-tier2`; no packages, no compiler.
  - `install.sh --unit` renders the system unit template `fv-tier2@.service.in`, one instance per GPU:
    - the GPU is pinned by UUID (`instances/<instance>.env`, see `instance.example.env`);
    - it is bound to `127.0.0.1`;
    - limits: `Nice=10`, `CPUQuota=400%`, `MemoryMax=16G`;
    - the model sha256 is checked on every start.

  Rollback: `sudo systemctl disable --now fv-tier2@<instance>`.
- **Relay** (`prover/relay/`), for sites where the gate host cannot reach the GPU host but a third
  host reaches both. The user unit `fv-tier2-relay.service` runs `relay.sh`, which holds two ssh
  forwards per port, both bound to 127.0.0.1:
  - `-L` from the relay host to the GPU host;
  - `-R` from the gate host to the relay host.

  Its ssh options are `ExitOnForwardFailure=yes`, `ServerAliveInterval=30`,
  `ServerAliveCountMax=3` and `BatchMode=yes`, with `Restart=always` and `RestartSec=10`.
  Afterwards, check with `ss -tlnp` on all three hosts that nothing listens on a LAN interface.
  **Rollback: `systemctl --user disable --now fv-tier2-relay`.**

### Tier-2 model provenance

All GGUF files are **community** quantizations (mradermacher), not first-party. Each server checks
its file's sha256 on every start.

| File | Source revision | Bytes | sha256 |
|---|---|---|---|
| `Goedel-Prover-V2-8B.Q6_K.gguf` (main) | huggingface.co/mradermacher/Goedel-Prover-V2-8B-GGUF @ 43fab68ec71738a75b0a84738e18b222d2d4e249 | 6,725,899,520 | `43a23c094fd495304726f1471a9e10ca48997573278e306a555be1d3371aff3a` |
| `Goedel-Prover-V2-8B.IQ4_XS.gguf` (local) | same revision | 4,593,296,640 | `e948e3a8a8077a3a4bb50d0291d394b291f6eaf8fb8b73d909e9f0b1b5352602` |
| `DeepSeek-Prover-V2-7B.Q4_K_M.gguf` (fast) | huggingface.co/mradermacher/DeepSeek-Prover-V2-7B-GGUF @ 23686f34b32c167b32dfe84e612c5b15fb5554eb | 4,223,362,016 | `1bcf1bd12cc8638c957a41818548019a686e37dadd3aa44cdf3a78e443182a44` |

**Goedel-Prover-V2-8B.**
- Weights: huggingface.co/Goedel-LM/Goedel-Prover-V2-8B, revision dfd02e6271a58375dfbf3ece0175277cf6b6a89a.
- Licence: Apache-2.0. Base model: Qwen3-8B.
- It was trained on Lean 4.9-era Mathlib, so expect name drift against Lean 4.36.

**DeepSeek-Prover-V2-7B.**
- Weights: huggingface.co/deepseek-ai/DeepSeek-Prover-V2-7B, revision a8d9e14432b2e8dd9df2a4d4e70f1ba9bc8d9b7b.
- Architecture: Llama, 30 layers, 32 KV heads (no grouped-query attention), built on
  DeepSeek-Prover-V1.5-Base.
- **Licence, as the source states it.** The two statements in the repository differ:
  - the `LICENSE` file at that revision is the MIT licence;
  - the model card says "The use of DeepSeek-Prover-V2 models is subject to the Model License",
    linking a `LICENSE-MODEL` that is not in the repository.

  The badge on the card points to the DeepSeek Model Agreement, the DeepSeek Model License with
  use-based restrictions. The harness treats the model as under that more restrictive licence.
- **Your call.** The reference deployment uses the 7B only, as the cascade's first pass, after its
  operator reviewed the licence: it restricts only listed prohibited uses, and proof search is not
  among them. Review it for your own use; the cascade runs without the `fast` stage if you drop it.

## Host prerequisites (gate host, as installed 2026-11-21)

| Component | Version / pin | How |
|---|---|---|
| OS | Ubuntu 26.04.1 LTS, kernel 7.0.0-44 | — |
| Lean | v4.36.0 release, commit 611c117b; elan 4.4.0 (installer sha256 a620ff16…bf53) | elan under `$FV_ROOT/elan`, `--no-modify-path` |
| con-leche master | 5ea446d5c79d23ef1f954215d094db2162f1ab6f, binary sha256 f38aae26…db4f | `lake build con-leche` in `$FV_ROOT/src/con-leche-master` |
| bubblewrap | 0.11.1 (distro); unprivileged through Ubuntu's `bwrap` AppArmor profile | preinstalled |
| clang / libFuzzer | Ubuntu clang 21.1.8; cmake 4.2.3 | preinstalled |
| CUDA | nvidia-cuda-toolkit 12.4.131~12.4.1-8 (nvcc V12.4.131), nvidia-cuda-dev 12.4.127~12.4.1-8, libcudart12 12.4.127~12.4.1-8, libcublas12 12.4.5.8~12.4.1-8; driver 580.178.04 untouched | apt, `--no-install-recommends`: 47 new packages, 0 upgraded, 0 removed |
| nvcc host compiler | g++-13 13.4.0-10ubuntu1 (the system default stays gcc 15) | apt (dependency of the toolkit) |
| ripgrep | 15.1.0-1ubuntu1 | apt |
| uv | 0.13.9 (tarball sha256 a7fbaff2b9a271d85c1bdb540941090fd1ce011797b4abeb48e4dcd39c2471d5) | standalone in `$FV_ROOT/bin` |
| lean-lsp-mcp | 0.33.0 (leanclient 0.13.2, mcp 2.2.0, Python 3.14.4) | `uv tool install` under `$FV_ROOT/uv` |
| llama.cpp | b12387 = a956a852c9c8bc1fb07206364838ddef299178c0, CUDA sm_86 | `$FV_ROOT/src/llama.cpp`, built with the web UI off |
| Other | jq, python3, bc; passwordless `sudo` (only for `unshare --net`) | preinstalled |
