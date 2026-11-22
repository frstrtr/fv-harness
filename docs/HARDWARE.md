# Hardware and models

**Short version.**
- The gate, the controls and the fuzzer need an ordinary Linux machine and **no GPU**.
- A GPU only speeds up proof *search* (Tier 2).
- The figures below are measured unless marked *estimate*.

## What you can skip

- **No GPU** is needed to run the gate, the acceptance controls or the differential fuzzer. None
  is needed to verify proofs that someone else wrote, either.
- **No local prover** is needed at all. Proofs can come from people, from a Tier-1 agent, or from
  any tool. The gate re-checks them all the same way.
- **No Mathlib.** Projects are core Lean only, so there is no multi-gigabyte library build.
- A GPU, llama.cpp and the prover models are optional. They make mechanical proof search
  cheaper and faster. They are never part of the trusted base.

## Profiles

### (a) Gate and acceptance controls (no GPU)

| | Minimum | Recommended |
|---|---|---|
| CPU | 2 cores (x86-64) | 8+ cores |
| RAM | 8 GB | 16 GB |
| Free disk | 6 GB | 20 GB (several projects, run directories, corpora) |
| OS | Ubuntu 24.04 or 26.04 | same |
| Privileges | passwordless `sudo` for the gate account (the audit runs in a fresh network namespace); on 24.04, one AppArmor profile for `bwrap` (`docs/USAGE.md` A1) | a dedicated gate account; agents and developers do not get that sudo rule |

Measured:
- **Minimum profile:** a clean GitHub-hosted Ubuntu 24.04 runner with 2 vCPUs ran the whole
  install from scratch, the 15 acceptance controls and the end-to-end example in **about 18
  minutes**.
  - The install covered distribution packages, elan with Lean 4.36.0, and the `--compare` checker
    built from source.
  - The controls' 10^6-run fuzz leg ran at about 8,500 exec/s.
- **Recommended profile:** the same suite takes about 6 minutes on 8 cores of a 16-thread
  workstation, with Lean, the checkers and the fuzzer already installed.

Disk, as installed:

| Item | Size |
|---|---|
| elan with the Lean 4.36.0 toolchain (kernel, Lake, comparator, the bundled checkers) | 1.4 GB |
| the `--compare` checker built from source | 0.4 GB |
| clang with libFuzzer and the sanitizer runtimes (distribution packages) | about 0.5 GB |
| a project's build (`.lake/`) and one gate run directory (exports, logs) | tens of MB for small projects |
| a fuzz corpus | KB to tens of MB (13,000 inputs of a real project: under 100 MB) |

### (b) A real project's COUPLE campaign

The differential campaign is the expensive part of a closure. Its speed depends on how much work
one input does:

| Target | exec/s (one process) | 10^6 runs |
|---|---|---|
| light: the shipped fixture, one transfer per step | 8,000–9,000 | about 2 minutes |
| light: the risk-limit example | 30,000–38,000 | about 30 seconds |
| heavy: a production routine where each input is a sequence of whole blocks with up to 34 outputs | about 115 | **about 2 h 25 min** |

- **RAM:** about **1 GB RSS per libFuzzer process** on the heavy target, and under 100 MB on the
  light ones.
- **Parallel campaigns:** `fuzz/run_fuzz.sh` runs one process per campaign. To use more cores,
  start several campaigns with separate `--out` directories and copies of the corpus, then merge
  the new inputs. For example, one earlier campaign on the heavy target ran 12 processes × 90,000 runs
  (1.08 × 10^6 in total). Wall time falls with the number of processes, as long as cores and RAM
  allow.
- **Sizing rule:** processes ≤ cores you can spare, and ≤ free RAM / 1.5 GB on heavy targets.
- **CI budget:** `--time 60` per pull request, as a regression replay plus a short campaign. Run
  the full 10^6 locally or on a schedule.

### (c) Local Tier-2 prover (optional), by GPU class

| GPU class | Model and quantisation | Setup | VRAM in use | Measured throughput | Use |
|---|---|---|---|---|---|
| none | — | — | — | — | skip Tier 2; the gate is unaffected |
| laptop-class **6 GB** (RTX 3060-class) | Goedel-Prover-V2-8B IQ4_XS (4.6 GB) | 1 slot, 8,192 context, q8_0 KV | 4.95 / 6.1 GB | **61 tok/s** decode, 1,280 tok/s prompt | development, small K, short prompts |
| laptop-class **6 GB** | DeepSeek-Prover-V2-7B Q4_K_M (4.2 GB) | 1 slot, 6,144 context, q4_0 KV, code-only prompt | 4.9 / 6.1 GB | **68 tok/s**; about 1 s per short sample | a cheap first pass |
| desktop **12 GB** (RTX 3060-class) | Goedel-Prover-V2-8B Q6_K (6.7 GB) | 4 slots × 8,192 context, q8_0 KV | 8.7 / 12.3 GB | **46 tok/s** single; **99 tok/s** aggregate over 4 concurrent; 80 tok/s over 2 concurrent through an ssh relay | the main stage; recommended |
| **24 GB** | Goedel-Prover-V2-32B Q4_K_M (19.8 GB) | 1 slot, about 12k context | *estimate*: about 23 GB | *estimate*: about 10 tok/s | large-VRAM only; not worth it for best-of-K (about 13 minutes per long sample) |

**Context per slot matters more than speed on real projects.** A real project's prompt carries
the definitions and lemma statements the target depends on. On a 12-leaf benchmark from a
production specification, that was **about 11,000 tokens per prompt**, after comments and proofs
were stripped from the imported context.

Plan for **16k context per slot** for the main stage. On a 12 GB card that is 4 slots × 16k, with
a q8_0 K cache and a q4_0 V cache (*estimate*: about 11 GB in use). A 6 GB card with 6–8k context fits the shipped fixture and
small projects, not large ones. A stage whose prompt does not fit should be skipped, not sent.

**Routing baseline**, measured on the fixture with the 6 GB setup:
- An easy leaf (linear arithmetic, one core lemma away) costs about **1.4k tokens and 23 s**.
- A nonlinear leaf **walled** after 2 attempts × 8 samples: 155k tokens, 48 minutes. Tier 1 then
  split it into a one-line product fact in seconds.
- So: split nonlinear goals in Tier 1 before dispatch. Keep the default early wall (1 attempt × 4
  samples, and an immediate wall when every sample fails the same way).

## Models

| Model | Sizes used here | Licence | Notes |
|---|---|---|---|
| Goedel-Prover-V2-8B | Q6_K 6.7 GB; IQ4_XS 4.6 GB | Apache-2.0 (base model Qwen3-8B, Apache-2.0) | proof plan then code; long replies (2–6k tokens); trained on an older Lean and its mathematics library, so expect name drift on Lean 4.36 core |
| DeepSeek-Prover-V2-7B | Q4_K_M 4.2 GB | DeepSeek License Agreement v1.0 (use-based restrictions; see `THIRD-PARTY.md`) | the code-only prompt gives short replies; it is the first pass; optional |
| Goedel-Prover-V2-32B | Q4_K_M 19.8 GB | Apache-2.0 | large-VRAM only; not used by default |

All GGUF files used here are **community quantisations**. Pin the source revision and the
**sha256** of every file (`config/tier2.env` and `prover/remote/` do), and let the server check it
on every start. The exact pins are in the README, under "Tier-2 model provenance".

Serving: llama.cpp `llama-server` at a pinned release, behind a chat-completions-compatible HTTP endpoint,
bound to 127.0.0.1. The cascade can list several endpoints per stage (`docs/USAGE.md`, README
"Production Tier 2").

## Tier 1, the planner

Tier 1 is an agent driven by a **strong general-purpose model**, using the `lean-lsp` MCP server
(`agent-config/`). It drafts specifications for the human owner to sign, decomposes theorems into
small lemmas, and handles the walls Tier 2 reports. No specific vendor is required. Any agent
that can read Lean goals through the MCP server and edit `spec/solution/` can do it. Tier 1 runs
wherever the agent runs and needs no local hardware beyond the gate.
