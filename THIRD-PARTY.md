# Third-party tools and models

The harness **references** these components; it does not vendor or redistribute any of them. The
scripts download or build them at the pinned versions on your hosts, and each keeps its own
licence. Each licence was checked at its source on 2026-11-22: the repository's licence file, or
the model card's licence field and the licence file at the pinned revision.

## Lean toolchain and checkers

| Component | Pinned version | Licence | Source |
|---|---|---|---|
| Lean 4 (compiler, kernel, Lake, `lake comparator`, bundled `leanexport`, bundled con-leche and con-ron binaries) | v4.36.0 release, commit 611c117b | Apache-2.0 | github.com/leanprover/lean4 |
| elan (toolchain manager) | 4.4.0 | Apache-2.0 or MIT | github.com/leanprover/elan |
| con-leche (master build, for `--compare`) | 5ea446d5c79d23ef1f954215d094db2162f1ab6f | Apache-2.0 | github.com/leanprover/con-leche |
| con-ron (bundled with Lean v4.36.0) | cb54c9a4 | Apache-2.0 | github.com/leanprover/con-ron |
| comparator (standalone; archived, superseded by `lake comparator`) | not used | Apache-2.0 | github.com/leanprover/comparator |
| lean4export (standalone; the bundled `leanexport` is used) | not used | Apache-2.0 | github.com/leanprover/lean4export |

## Synthesis-side tools

| Component | Pinned version | Licence | Source |
|---|---|---|---|
| lean-lsp-mcp | 0.33.0 (PyPI; dependency freeze in `config/lean-lsp-mcp.freeze.txt`) | MIT | github.com/oOo0oOo/lean-lsp-mcp |
| uv | 0.13.9 | Apache-2.0 or MIT | github.com/astral-sh/uv |
| llama.cpp (`llama-server`) | b12387 = a956a852c9c8bc1fb07206364838ddef299178c0: source build on the gate host; official `ubuntu-cuda-12.8-x64` release binaries on remote GPU hosts | MIT | github.com/ggml-org/llama.cpp |

## Sandbox, compiler and fuzzer (distribution packages)

| Component | Version used | Licence | Source |
|---|---|---|---|
| bubblewrap | 0.11.1 | LGPL (the repository's COPYING is the LGPL 2.1 text) | github.com/containers/bubblewrap |
| clang, libFuzzer, AddressSanitizer, UndefinedBehaviorSanitizer, LeakSanitizer | clang 21.1.8 | Apache-2.0 with LLVM Exceptions | github.com/llvm/llvm-project |
| CUDA toolkit and runtime | 12.4 (gate host, distribution packages); 12.8 cudart bundle of the llama.cpp release (remote hosts) | NVIDIA CUDA Toolkit EULA | developer.nvidia.com/cuda-toolkit |

## Prover models (Tier 2)

| Model | Pinned file and revision | Licence | Source |
|---|---|---|---|
| Goedel-Prover-V2-8B | weights revision dfd02e6271a58375dfbf3ece0175277cf6b6a89a; GGUF quantizations Q6_K and IQ4_XS at revision 43fab68ec71738a75b0a84738e18b222d2d4e249 (sha256 in README) | Apache-2.0 (model card); base model Qwen3-8B, Apache-2.0 | huggingface.co/Goedel-LM/Goedel-Prover-V2-8B; GGUF: huggingface.co/mradermacher/Goedel-Prover-V2-8B-GGUF (community quantization) |
| DeepSeek-Prover-V2-7B | weights revision a8d9e14432b2e8dd9df2a4d4e70f1ba9bc8d9b7b; GGUF Q4_K_M at revision 23686f34b32c167b32dfe84e612c5b15fb5554eb (sha256 in README) | DeepSeek License Agreement v1.0 (23 October 2023), use-based restrictions. See the note below | huggingface.co/deepseek-ai/DeepSeek-Prover-V2-7B; GGUF: huggingface.co/mradermacher/DeepSeek-Prover-V2-7B-GGUF (community quantization) |

**Note on DeepSeek-Prover-V2-7B.** At the pinned revision, the model repository's `LICENSE` file is
the MIT licence, but its model card says use "is subject to the Model License". That model licence
is `LICENSE-MODEL` in github.com/deepseek-ai/DeepSeek-Prover-V2: "DEEPSEEK LICENSE AGREEMENT,
Version 1.0, 23 October 2023". The harness treats the weights as under that agreement. The model is
optional: the cascade runs without its `fast` stage.

The prover models only propose proofs. Every proof they propose is re-checked by the Lean kernel
and by the independent checkers, so no model is part of the trusted base.
