# Shared helpers for the verification gate. Sourced, not executed.
# shellcheck shell=bash

FV_HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../config/pins.env
. "$FV_HARNESS_DIR/config/pins.env"

die() { echo "error: $*" >&2; exit 3; }
note() { echo "[$(date +%H:%M:%S)] $*"; }

# Paths of a project that belong to the agent. Everything else is locked.
FV_SOLUTION_REL="spec/solution"

# Run a command at the configured CPU and priority caps.
capped() { taskset -c "$FV_CPUSET" nice -n "$FV_NICE" "$@"; }
# The same caps inside a fresh network namespace (only lo): builds, package managers, toolchain
# auto-downloads and telemetry cannot reach the network, whatever their environment says. Not for a
# command that enters a namespace itself (bwrap cannot nest on the gate host).
capped_off() { capped bwrap --dev-bind / / --unshare-net -- "$@"; }

# sbx [--rw DIR] [--ro PATH] [--chdir DIR] [--env NAME VALUE] [--share-net] -- CMD ARGS...
# Unprivileged bwrap jail: whole filesystem read-only, home/tmp masked, no network, no
# namespaces shared, the Lean toolchain bound back read-only. Only --rw paths are writable.
# Always runs at the CPU and priority caps.
sbx() {
  local a=(--unshare-all --die-with-parent --new-session
           --ro-bind / /
           --tmpfs /home --tmpfs /root --tmpfs /tmp --tmpfs /run/user
           --dev /dev --proc /proc
           --dir /tmp/home
           --ro-bind "$LEAN_TC" "$LEAN_TC"
           --clearenv
           --setenv HOME /tmp/home
           --setenv PATH "$LEAN_TC/bin:/usr/bin:/bin"
           --setenv LEAN_ABORT_ON_PANIC 1)
  while [ $# -gt 0 ] && [ "$1" != "--" ]; do
    case "$1" in
      --rw) a+=(--bind "$2" "$2"); shift 2 ;;
      --ro) a+=(--ro-bind "$2" "$2"); shift 2 ;;
      --chdir) a+=(--chdir "$2"); shift 2 ;;
      --env) a+=(--setenv "$2" "$3"); shift 3 ;;
      --share-net) a+=(--share-net); shift ;;   # synthesis only (Tier-2 endpoint); never the gate
      *) die "sbx: unknown option $1" ;;
    esac
  done
  [ "${1:-}" = "--" ] || die "sbx: missing --"
  shift
  taskset -c "$FV_CPUSET" nice -n "$FV_NICE" bwrap "${a[@]}" -- "$@"
}

# Stage bookkeeping: each stage writes $RUN/stages/<name>.status (PASS|FAIL|ERROR|SKIP) and
# <name>.log.
stage_set() { printf '%s\n' "$2" > "$RUN/stages/$1.status"; }
stage_get() { cat "$RUN/stages/$1.status" 2>/dev/null || echo "MISSING"; }

json_names() { # json_names FILE KEY -> one name per line (missing key = nothing)
  jq -r --arg k "$2" '(.[$k] // [])[]' "$1"
}
