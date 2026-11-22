#!/usr/bin/env bash
# fetch.sh — download the pinned Tier-2 artifacts into ~/fv-tier2 on the remote GPU host and verify
# their sha256: the llama.cpp b12387 release binaries for CUDA 12.8 and Goedel-Prover-V2-8B Q6_K.
set -euo pipefail
R=~/fv-tier2; mkdir -p "$R/dl" "$R/models"
fetch() { # url sha256 dest
  if [ -f "$3" ] && echo "$2  $3" | sha256sum -c --quiet - 2>/dev/null; then echo "have $3"; return 0; fi
  nice -n 15 curl -sSfL --retry 3 -o "$3.part" "$1"
  echo "$2  $3.part" | sha256sum -c --quiet - || { echo "SHA MISMATCH $3" >&2; exit 1; }
  mv "$3.part" "$3"; echo "ok $3"
}
GH=https://github.com/ggml-org/llama.cpp/releases/download/b12387
fetch "$GH/llama-b12387-bin-ubuntu-cuda-12.8-x64.tar.gz" \
  dd2231d2708a17d8f5e1b0455017d3cb7f446281607eaaece3935882e172a299 "$R/dl/llama-b12387-bin-ubuntu-cuda-12.8-x64.tar.gz"
fetch "$GH/cudart-llama-b12387-bin-ubuntu-cuda-12.8-x64.tar.gz" \
  57c1f0e468422671fd49f88eb4fe444b0272a5977db23f31374250f7f08e180b "$R/dl/cudart-llama-b12387-bin-ubuntu-cuda-12.8-x64.tar.gz"
fetch https://huggingface.co/mradermacher/Goedel-Prover-V2-8B-GGUF/resolve/43fab68ec71738a75b0a84738e18b222d2d4e249/Goedel-Prover-V2-8B.Q6_K.gguf \
  43a23c094fd495304726f1471a9e10ca48997573278e306a555be1d3371aff3a "$R/models/Goedel-Prover-V2-8B.Q6_K.gguf"
