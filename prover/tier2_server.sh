#!/usr/bin/env bash
# tier2_server.sh start|stop|status [fast|local] — the Tier-2 prover endpoints on the gate host.
#
#   fast   DeepSeek-Prover-V2-7B Q4_K_M on 127.0.0.1:8082: the cascade's cheap first pass
#   local  Goedel-Prover-V2-8B IQ4_XS on 127.0.0.1:8081: fallback when the remote GPU host is unavailable
# The 6 GB card holds one model, so only one profile runs at a time (start refuses otherwise).
# The cascade's "main" stage runs on a remote GPU host as a system unit (prover/remote/).
#
# Runs llama-server as a detached process (setsid, pidfile in $FV_ROOT/run): bound to
# 127.0.0.1, CPU-pinned (TIER2_CPUSET) at nice 10, all layers on the GPU, with the profile's KV
# cache type and size so the card keeps headroom for the desktop. Nothing persists across a reboot.
#
# Not a systemd user unit: the gate user has no lingering session, so a unit started over ssh is
# stopped when the ssh session ends (observed). Enabling linger would be a persistent change to
# the operator's account, so it is not done. Without a cgroup there is no hard RAM cap; the
# server's measured peak is 4.5 GB of host RAM on a 57 GB machine.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/../scripts/lib.sh"
. "$FV_HARNESS_DIR/config/tier2.env"
cmd="${1:-}"; prof="${2:-fast}"
case "$prof" in fast|local) ;; *) die "unknown profile $prof (fast|local)" ;; esac
P=$(tr a-z A-Z <<< "$prof")
v() { local n="TIER2_SRV_${P}_$1"; printf '%s' "${!n}"; }
GGUF=$(v GGUF); SHA=$(v SHA256); ALIAS=$(v ALIAS); PORT=$(v PORT); CTX=$(v CTX); PAR=$(v PARALLEL); CACHE=$(v CACHE)
RUNDIR="$FV_ROOT/run"; PIDF="$RUNDIR/tier2-$prof.pid"; LOG="$FV_ROOT/logs/tier2-server-$prof.log"
mkdir -p "$RUNDIR" "$(dirname "$LOG")"

alive() { [ -f "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null; }

case "$cmd" in
  start)
    [ -x "$TIER2_SERVER_BIN" ] || die "llama-server not built: $TIER2_SERVER_BIN"
    alive "$PIDF" && { echo "tier2 $prof already running (pid $(cat "$PIDF"))"; exit 0; }
    for other in "$RUNDIR"/tier2*.pid; do
      [ -e "$other" ] && [ "$other" != "$PIDF" ] && alive "$other" && die "another profile is running ($other); stop it first"
    done
    echo "$SHA  $GGUF" | sha256sum -c --quiet - || die "model sha256 mismatch: $GGUF"
    setsid bash -c 'echo $$ > "$0"; exec "$@"' "$PIDF" \
      taskset -c "$TIER2_CPUSET" nice -n 10 \
      "$TIER2_SERVER_BIN" -m "$GGUF" --alias "$ALIAS" \
        --host "$TIER2_HOST" --port "$PORT" \
        -c "$CTX" -np "$PAR" -ngl 99 --flash-attn on \
        --cache-type-k "$CACHE" --cache-type-v "$CACHE" \
        -t "$TIER2_THREADS" --metrics \
      < /dev/null > "$LOG" 2>&1 &
    for _ in $(seq 1 120); do
      if curl -sf "http://$TIER2_HOST:$PORT/health" > /dev/null; then
        echo "tier2 $prof ready on $TIER2_HOST:$PORT (pid $(cat "$PIDF")): $ALIAS, ctx $CTX, $PAR slot(s), KV $CACHE"
        nvidia-smi --query-gpu=memory.used,memory.total --format=csv,noheader
        exit 0
      fi
      sleep 1
      alive "$PIDF" || { tail -20 "$LOG"; die "llama-server exited"; }
    done
    die "llama-server did not become healthy in 120 s"
    ;;
  stop)
    if alive "$PIDF"; then kill "$(cat "$PIDF")"; sleep 2; fi
    rm -f "$PIDF"; echo "tier2 $prof stopped"
    ;;
  status)
    if alive "$PIDF"; then echo "$prof running (pid $(cat "$PIDF"))"; else echo "$prof stopped"; fi
    curl -sf "http://$TIER2_HOST:$PORT/health" || true; echo
    nvidia-smi --query-gpu=memory.used,memory.total,utilization.gpu --format=csv,noheader
    ;;
  *) echo "usage: $0 start|stop|status [fast|local]" >&2; exit 3 ;;
esac
