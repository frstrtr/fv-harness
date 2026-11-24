#!/usr/bin/env bash
# c66_chain_unreachable.sh BUNDLE_TAR OUTDIR — control c66: a chain node that does not answer (connection
# refused or timed out, as during its scheduled restarts) PAUSEs the campaign and is retried; only when
# it stays silent past FV_GUARD_UNREACHABLE_MAX does the worker stop, BLOCKED, saying so. On FAKE readings
# (the limit is 12 s here, 600 s by default):
#   start: (a) silent for 6 s, then answering: the worker starts, no BLOCK; (b) silent throughout: BLOCKED
#          "chain node unreachable for N s at start" (not before the limit);
#   running: (c) silent for 6 s: PAUSE at once (reason "chain node unreachable"), no fuzzer alive and no
#          new batch while paused, then RESUME and a new batch, no BLOCK; (d) silent past the limit: a
#          BLOCK event, the worker ends BLOCKED "chain node unreachable for N s".
# Prints "c66_chain_unreachable OK|WRONG ..."; exit 0 iff OK.
set -uo pipefail
TAR="$1"; X="${2:?}"; rm -rf "${X:?}"; mkdir -p "$X/fake"; F="$X/fake"
echo yes > "$F/ntp"; echo "1.00 1.00 1.00 1/100 1" > "$F/loadavg"; : > "$F/infer.pids"
printf 'MemTotal: 100000000 kB\nMemAvailable: 90000000 kB\n' > "$F/meminfo"
num=1000; mode=fresh
newhead() { if [ "$mode" = fresh ]; then num=$((num + 3)); printf '{"block_header":{"raw_data":{"number":%s,"timestamp":%s000}}}\n' "$num" "$(date +%s)"
            else : ; fi > "$F/tron.json.tmp"; mv "$F/tron.json.tmp" "$F/tron.json"; }
export FV_GUARD_INTERVAL=2 FV_GUARD_CPU_WINDOW=1 FV_GUARD_AGE_BAD=5 FV_GUARD_AGE_GOOD=3 FV_GUARD_CHAIN_RESUME=4 \
  FV_GUARD_INFER_RESUME=4 FV_GUARD_START_WAIT=60 FV_GUARD_UNREACHABLE_MAX=12 FV_GUARD_TRON_CMD="cat $F/tron.json" \
  FV_GUARD_NTP_CMD="cat $F/ntp" FV_GUARD_INFER_CMD="cat $F/infer.pids" FV_GUARD_LOADAVG="$F/loadavg" FV_GUARD_MEMINFO="$F/meminfo"
tick() { local i; for ((i = 0; i < $1; i++)); do newhead; sleep 1; done; }
kill_tree() { local c; for c in $(pgrep -P "$1" 2>/dev/null); do kill_tree "$c"; done; kill "$1" 2>/dev/null; }
alive() { local p w st n=0; while read -r p w st; do [ -d "/proc/$p" ] && n=$((n + 1)); done < "$1" 2>/dev/null; echo $n; }
worker() { # worker NAME : a fresh copy of the bundle, its runner in the background (pid in $wpid, out dir in $O)
  mkdir -p "$X/$1"; tar -xf "$TAR" -C "$X/$1"; B="$X/$1/bundle"; O="$B/out"
  FV_GUARDS=1 bash "$B/fv_worker.sh" "$B" 0 2 "" 600 1 -timeout=10 > "$X/$1.out" 2>&1 & wpid=$!; }
r=""; bad=0
# (a) silent for 6 s at start, then answering
mode=silent; newhead; worker a; tick 6; mode=fresh
for i in $(seq 1 30); do [ -s "$O/pids" ] && break; tick 1; done
if [ -s "$O/pids" ] && ! grep -q '^BLOCKED' "$X/a.out" && [ "$(grep -c 'chain node unreachable' "$O/start-check")" -ge 1 ]; then r+="(a) started after $(grep -c 'unreachable' "$O/start-check") silent check(s); "
else r+="(a) WRONG [$(head -1 "$X/a.out")]; "; bad=1; fi
touch "$O/guard.stop"; while read -r p _; do kill -INT "$p" 2>/dev/null; done < "$O/pids"; wait "$wpid" 2>/dev/null
# (b) silent throughout at start
mode=silent; newhead; t0=$(date +%s); worker b
for i in $(seq 1 90); do kill -0 "$wpid" 2>/dev/null || break; sleep 1; done
if kill -0 "$wpid" 2>/dev/null; then rb=124; kill_tree "$wpid"; wait "$wpid" 2>/dev/null; else wait "$wpid"; rb=$?; fi; tb=$(( $(date +%s) - t0 ))
if [ $rb -eq 2 ] && grep -q '^BLOCKED: chain node unreachable for [0-9]* s at start' "$X/b.out" && [ "$tb" -ge 12 ]; then r+="(b) BLOCKED after ${tb}s [$(head -1 "$X/b.out" | cut -c1-60)]; "
else r+="(b) WRONG exit=$rb after ${tb}s [$(head -1 "$X/b.out")]; "; bad=1; fi
# (c) running: silent for 6 s, then answering; (d) silent past the limit
mode=fresh; newhead; worker c
for i in $(seq 1 30); do [ "$(alive "$O/pids")" -ge 2 ] && break; tick 1; done; tick 3
nb0=$(ls "$O"/w*.b*.log 2>/dev/null | wc -l); mode=silent; tick 4
pz=$(grep -c '"event":"PAUSE"' "$O/pauses.jsonl" 2>/dev/null); al=$(alive "$O/pids"); nb1=$(ls "$O"/w*.b*.log 2>/dev/null | wc -l)
reason=$(jq -r 'select(.event == "PAUSE") | .reason' "$O/pauses.jsonl" 2>/dev/null | head -1)
mode=fresh; for i in $(seq 1 30); do grep -q '"event":"RESUME"' "$O/pauses.jsonl" 2>/dev/null && break; tick 1; done
for i in $(seq 1 15); do [ "$(alive "$O/pids")" -ge 2 ] && break; tick 1; done
rs=$(grep -c '"event":"RESUME"' "$O/pauses.jsonl" 2>/dev/null); al2=$(alive "$O/pids"); nb2=$(ls "$O"/w*.b*.log 2>/dev/null | wc -l)
if [ "${pz:-0}" -ge 1 ] && [[ "$reason" == *"chain node unreachable"* ]] && [ "$al" -eq 0 ] && [ "$nb1" -eq "$nb0" ] && [ "${rs:-0}" -ge 1 ] \
   && [ "$al2" -ge 1 ] && [ "$nb2" -gt "$nb1" ] && ! grep -q '"event":"BLOCK"' "$O/pauses.jsonl"; then
  r+="(c) PAUSE within 4 s [$reason], 0 fuzzers alive and no new batch while paused ($nb0 -> $nb1 batch logs), RESUME and a new batch ($nb2), no BLOCK; "
else r+="(c) WRONG pauses=$pz reason=[$reason] alive=$al batches $nb0->$nb1->$nb2 resumes=$rs alive_after=$al2; "; bad=1; fi
mode=silent; t0=$(date +%s); for i in $(seq 1 40); do kill -0 "$wpid" 2>/dev/null || break; tick 1; done
if kill -0 "$wpid" 2>/dev/null; then rd=124; kill_tree "$wpid"; wait "$wpid" 2>/dev/null   # never BLOCKED: the control ends it
else wait "$wpid"; rd=$?; fi; td=$(( $(date +%s) - t0 ))
if [ $rd -eq 2 ] && grep -q '"event":"BLOCK"' "$O/pauses.jsonl" && grep -q '^BLOCKED: chain node unreachable for [0-9]* s' "$X/c.out" && [ "$td" -ge 12 ]; then
  r+="(d) BLOCK after ${td}s [$(grep '^BLOCKED' "$X/c.out" | head -1 | cut -c1-70)]"
else r+="(d) WRONG exit=$rd after ${td}s [$(grep '^BLOCKED' "$X/c.out" | head -1)] events=$(jq -r .event "$O/pauses.jsonl" 2>/dev/null | tr '\n' ,)"; bad=1; fi
kill "$wpid" 2>/dev/null
[ $bad -eq 0 ] && echo "c66_chain_unreachable OK $r" || { echo "c66_chain_unreachable WRONG $r"; exit 1; }
