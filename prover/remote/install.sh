#!/usr/bin/env bash
# install.sh — run on the remote GPU host as the Tier-2 account, from a copy of prover/remote/.
#   install.sh          verify and unpack the pinned llama.cpp release binaries into
#                       ~/fv-tier2/llama-b12387 (run fetch.sh first), copy instance env files
#                       (*.env other than the example), check the server loads, print the unit;
#   install.sh --unit   render fv-tier2@.service.in as /etc/systemd/system/fv-tier2@.service (sudo).
# Installs no packages and builds nothing.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
R=~/fv-tier2; D=$R/dl
render() { sed -e "s#@USER@#$(id -un)#g" -e "s#@HOME@#$HOME#g" "$HERE/fv-tier2@.service.in"; }
if [ "${1:-}" = "--unit" ]; then
  render | sudo tee /etc/systemd/system/fv-tier2@.service > /dev/null
  sudo systemctl daemon-reload
  echo "installed /etc/systemd/system/fv-tier2@.service; enable an instance: sudo systemctl enable --now fv-tier2@<instance>"
  exit 0
fi
echo "dd2231d2708a17d8f5e1b0455017d3cb7f446281607eaaece3935882e172a299  $D/llama-b12387-bin-ubuntu-cuda-12.8-x64.tar.gz
57c1f0e468422671fd49f88eb4fe444b0272a5977db23f31374250f7f08e180b  $D/cudart-llama-b12387-bin-ubuntu-cuda-12.8-x64.tar.gz
43a23c094fd495304726f1471a9e10ca48997573278e306a555be1d3371aff3a  $R/models/Goedel-Prover-V2-8B.Q6_K.gguf" | sha256sum -c --quiet -
rm -rf "$R/llama-b12387.new" "$R/cudart.tmp"; mkdir -p "$R/llama-b12387.new" "$R/cudart.tmp" "$R/instances"
tar -xzf "$D/llama-b12387-bin-ubuntu-cuda-12.8-x64.tar.gz" -C "$R/llama-b12387.new" --strip-components=1
tar -xzf "$D/cudart-llama-b12387-bin-ubuntu-cuda-12.8-x64.tar.gz" -C "$R/cudart.tmp"
find "$R/cudart.tmp" -name '*.so*' -exec cp -a {} "$R/llama-b12387.new/" \;
rm -rf "$R/cudart.tmp" "$R/llama-b12387"; mv "$R/llama-b12387.new" "$R/llama-b12387"
for f in "$HERE"/*.env; do case "$f" in *example*) ;; *) cp "$f" "$R/instances/" ;; esac; done
LD_LIBRARY_PATH="$R/llama-b12387" "$R/llama-b12387/llama-server" --version 2>&1 | tail -2
render
