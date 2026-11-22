#!/usr/bin/env bash
# relay.sh — loopback-to-loopback relay for the Tier-2 "main" endpoint, for sites where the gate
# host cannot reach the remote GPU host but a third host (this one) reaches both:
#   here 127.0.0.1:PORT --(ssh -L)--> remote GPU host 127.0.0.1:PORT   (llama-server)
#   gate 127.0.0.1:PORT --(ssh -R)--> here 127.0.0.1:PORT
# Nothing listens on a LAN interface. If either forward fails, both stop (the unit restarts them).
# Reads FV_REMOTE_GPU_HOST, FV_GATE_HOST and FV_TIER2_PORTS (space-separated) from
# ~/.config/fv-harness/relay.env (same keys as config/hosts.example.env).
set -uo pipefail
. "${FV_RELAY_ENV:-$HOME/.config/fv-harness/relay.env}"
O=(-N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o BatchMode=yes)
L=(); R=()
for p in ${FV_TIER2_PORTS:-${FV_TIER2_PORT:-18100}}; do
  L+=(-L "127.0.0.1:$p:127.0.0.1:$p"); R+=(-R "127.0.0.1:$p:127.0.0.1:$p")
done
ssh "${O[@]}" "${L[@]}" "$FV_REMOTE_GPU_HOST" &
ssh "${O[@]}" "${R[@]}" "$FV_GATE_HOST" &
wait -n
exit 1
