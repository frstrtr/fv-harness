#!/usr/bin/env bash
# c67_restart_window.sh BUNDLE_TAR OUTDIR — control c67: the lease's restart window. Where the lease names
# the chain node's restart unit (FV_LEASE_RESTART_UNIT), a pause that began with the node silent while the
# unit started at most FV_GUARD_RESTART_WINDOW before resumes after FV_GUARD_FAST_RESUME of good chain;
# every other pause, and an unreadable unit start time, keeps FV_GUARD_CHAIN_RESUME; BLOCK after
# FV_GUARD_UNREACHABLE_MAX applies in both branches. On FAKE readings, shortened clock (window 30 s, fast
# resume 4 s, normal resume 20 s):
#   (a) unit started 10 s ago, node silent 6 s: PAUSE "restart-window", RESUME within 15 s of recovery;
#   (b) unit started 1 h ago, node silent 6 s: PAUSE "non-window", no RESUME before 20 s of good chain;
#   (c) unit start time unreadable: PAUSE "non-window" (why: unreadable), no RESUME before 20 s;
#   (d) restart window, node never answers again: BLOCK after the limit (12 s here), as without the window.
# Prints "c67_restart_window OK|WRONG ..."; exit 0 iff OK.
set -uo pipefail
TAR="$1"; X="${2:?}"; rm -rf "${X:?}"; mkdir -p "$X/fake"; F="$X/fake"
echo yes > "$F/ntp"; echo "1.00 1.00 1.00 1/100 1" > "$F/loadavg"; : > "$F/infer.pids"
printf 'MemTotal: 100000000 kB\nMemAvailable: 90000000 kB\n' > "$F/meminfo"
num=1000; mode=fresh
newhead() { if [ "$mode" = fresh ]; then num=$((num + 3)); printf '{"block_header":{"raw_data":{"number":%s,"timestamp":%s000}}}\n' "$num" "$(date +%s)"
            fi > "$F/tron.json.tmp"; mv "$F/tron.json.tmp" "$F/tron.json"; }
rts() { date -d "@$(( $(date +%s) - $1 ))" '+%a %Y-%m-%d %H:%M:%S %Z' > "$F/rts"; }   # unit started N s ago
export FV_GUARD_INTERVAL=2 FV_GUARD_CPU_WINDOW=1 FV_GUARD_AGE_BAD=5 FV_GUARD_AGE_GOOD=3 FV_GUARD_CHAIN_RESUME=20 \
  FV_GUARD_INFER_RESUME=2 FV_GUARD_START_WAIT=30 FV_GUARD_UNREACHABLE_MAX=60 FV_GUARD_RESTART_WINDOW=30 FV_GUARD_FAST_RESUME=4 \
  FV_GUARD_TRON_CMD="cat $F/tron.json" FV_GUARD_NTP_CMD="cat $F/ntp" FV_GUARD_INFER_CMD="cat $F/infer.pids" \
  FV_GUARD_LOADAVG="$F/loadavg" FV_GUARD_MEMINFO="$F/meminfo" FV_GUARD_RESTART_TS_CMD="cat $F/rts" \
  FV_LEASE_RESTART_UNIT=chain-node-restart.service
tick() { local i; for ((i = 0; i < $1; i++)); do newhead; sleep 1; done; }
kill_tree() { local c; for c in $(pgrep -P "$1" 2>/dev/null); do kill_tree "$c"; done; kill "$1" 2>/dev/null; }
alive() { local p w st n=0; while read -r p w st; do [ -d "/proc/$p" ] && n=$((n + 1)); done < "$1" 2>/dev/null; echo $n; }
worker() { mkdir -p "$X/$1"; tar -xf "$TAR" -C "$X/$1"; B="$X/$1/bundle"; O="$B/out"
  FV_GUARDS=1 bash "$B/fv_worker.sh" "$B" 0 2 "" 900 1 -timeout=10 > "$X/$1.out" 2>&1 & wpid=$!; }
r=""; bad=0
outage() { # outage N LABEL : node silent 6 s, then answering; prints "branch resume_seconds_after_recovery"
  local k=$1 t1 i
  mode=silent; tick 6; mode=fresh; t1=$(date +%s)
  for ((i = 0; i < 45; i++)); do [ "$(grep -c '"event":"RESUME"' "$O/pauses.jsonl")" -ge "$k" ] && break; tick 1; done
  local br; br=$(jq -r 'select(.event == "PAUSE") | .branch // ""' "$O/pauses.jsonl" | sed -n "${k}p")
  if [ "$(grep -c '"event":"RESUME"' "$O/pauses.jsonl")" -ge "$k" ]; then echo "$br $(( $(date +%s) - t1 ))"; else echo "$br none"; fi
  for ((i = 0; i < 15; i++)); do [ "$(alive "$O/pids")" -ge 1 ] && break; tick 1; done; tick 3
}
mode=fresh; newhead; rts 3600; worker abc
for i in $(seq 1 30); do [ "$(alive "$O/pids")" -ge 2 ] && break; tick 1; done; tick 3
rts 10;    read -r ba ta <<< "$(outage 1 a)"
rts 3600;  read -r bb tb <<< "$(outage 2 b)"
echo "not a date" > "$F/rts"; read -r bc tc <<< "$(outage 3 c)"
whyc=$(jq -r 'select(.event == "PAUSE") | .why // ""' "$O/pauses.jsonl" | sed -n 3p)
touch "$O/guard.stop"; while read -r p _; do kill -INT "$p" 2>/dev/null; done < "$O/pids"; sleep 2; kill_tree "$wpid"; wait "$wpid" 2>/dev/null
[ "$ba" = restart-window ] && [[ "$ta" =~ ^[0-9]+$ ]] && [ "$ta" -lt 15 ] && r+="(a) restart-window, RESUME ${ta}s after recovery; " || { r+="(a) WRONG branch=$ba resume=$ta; "; bad=1; }
[ "$bb" = non-window ] && [[ "$tb" =~ ^[0-9]+$ ]] && [ "$tb" -ge 20 ] && r+="(b) non-window, RESUME ${tb}s after recovery; " || { r+="(b) WRONG branch=$bb resume=$tb; "; bad=1; }
[ "$bc" = non-window ] && [[ "$whyc" == *unreadable* ]] && [[ "$tc" =~ ^[0-9]+$ ]] && [ "$tc" -ge 20 ] && r+="(c) unreadable -> non-window, RESUME ${tc}s; " || { r+="(c) WRONG branch=$bc why=[$whyc] resume=$tc; "; bad=1; }
# (d) restart window, the node never answers again: BLOCK after the limit
export FV_GUARD_UNREACHABLE_MAX=12; mode=fresh; newhead; rts 10; worker d
for i in $(seq 1 30); do [ "$(alive "$O/pids")" -ge 2 ] && break; tick 1; done; tick 2
mode=silent; t0=$(date +%s); for i in $(seq 1 40); do kill -0 "$wpid" 2>/dev/null || break; tick 1; done
if kill -0 "$wpid" 2>/dev/null; then rd=124; kill_tree "$wpid"; wait "$wpid" 2>/dev/null; else wait "$wpid"; rd=$?; fi; td=$(( $(date +%s) - t0 ))
bd=$(jq -r 'select(.event == "PAUSE") | .branch // ""' "$O/pauses.jsonl" | head -1)
[ $rd -eq 2 ] && [ "$bd" = restart-window ] && grep -q '^BLOCKED: chain node unreachable' "$X/d.out" && r+="(d) restart-window pause, BLOCK after ${td}s" \
  || { r+="(d) WRONG exit=$rd branch=$bd after ${td}s [$(grep '^BLOCKED' "$X/d.out" | head -1 | cut -c1-80)]"; bad=1; }
[ $bad -eq 0 ] && echo "c67_restart_window OK $r" || { echo "c67_restart_window WRONG $r"; exit 1; }
