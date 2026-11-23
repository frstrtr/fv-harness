#!/usr/bin/env bash
# fv_guard.sh — keeps this campaign off a shared worker host when the host is busy.
#
#   fv_guard.sh --start-ok           exit 0 iff a campaign may START now (prints the reading)
#   fv_guard.sh OUT_DIR BUNDLE_DIR RUNNER_PID
#
# It never stops or signals anything but this campaign's own fuzz workers. A PAUSE ends the running
# batch: it creates OUT_DIR/paused and sends SIGINT (libFuzzer then exits 72 with its final stats) to
# the PIDs listed in OUT_DIR/pids, each only if /proc/PID/exe is BUNDLE_DIR/bin/fuzzer and its start
# time equals the one recorded at launch (no PID reuse). A RESUME removes OUT_DIR/paused; fv_worker.sh
# then starts the next batch. Every PAUSE and RESUME goes to OUT_DIR/pauses.jsonl with its reading.
# It ends when OUT_DIR/guard.stop exists or RUNNER_PID is gone.
#
# Readings (commands and files are overridable, so a control can substitute fakes):
#   chain head: FV_GUARD_TRON_CMD (curl -s -m 5 http://127.0.0.1:8090/wallet/getnowblock), one call per
#               check; age = now - block_header.raw_data.timestamp / 1000 (parsed with python3 when
#               present, else an anchored match); NTP: FV_GUARD_NTP_CMD (timedatectl show -p
#               NTPSynchronized --value) must be "yes", or the age cannot be trusted;
#   inference:  PIDs whose process name is llama-server, or whose command line contains
#               /llama.cpp-cuda/build/bin/llama-server or "ollama runner" (FV_GUARD_INFER_CMD overrides);
#               their CPU over each FV_GUARD_CPU_WINDOW (10) s window, back to back, from FV_GUARD_PROC
#               (/proc)/<pid>/stat; a PID that vanishes during a window counts as busy for that window;
#   host:       FV_GUARD_LOADAVG (/proc/loadavg), FV_GUARD_MEMINFO (/proc/meminfo).
# Rules (the host's lease; thresholds overridable only for controls):
#   START       head age <= 15 s, NTP synchronised, timestamp parsed;
#   chain bad   head age > 60 s, NTP not synchronised, endpoint failed / timed out / unparsable, or the
#               head advanced by fewer than 5 blocks since the previous chain check (every
#               FV_GUARD_INTERVAL, 30 s);  chain good = head age <= 15 s with NTP;
#   busy        inference CPU > 200 % in a window;   calm = < 50 %;
#   host bad    1-min loadavg > 48 or MemAvailable < 40 GB;
#   PAUSE       on 2 consecutive bad chain checks, 2 consecutive busy windows, or 2 consecutive host-bad
#               readings;
#   RESUME      when the chain has been good for 600 s, inference calm for 300 s, the host good, and the
#               current reading has no bad condition at all.
set -uo pipefail
IV="${FV_GUARD_INTERVAL:-30}"; CW="${FV_GUARD_CPU_WINDOW:-10}"
AGE_BAD="${FV_GUARD_AGE_BAD:-60}"; AGE_GOOD="${FV_GUARD_AGE_GOOD:-15}"; MIN_BLOCKS="${FV_GUARD_MIN_BLOCKS:-5}"
BUSY="${FV_GUARD_BUSY_PCT:-200}"; CALM="${FV_GUARD_CALM_PCT:-50}"
LOAD_MAX="${FV_GUARD_LOAD_MAX:-48}"; MEM_MIN_KB="${FV_GUARD_MEM_MIN_KB:-41943040}"
CHAIN_RESUME="${FV_GUARD_CHAIN_RESUME:-600}"; INFER_RESUME="${FV_GUARD_INFER_RESUME:-300}"
PROC="${FV_GUARD_PROC:-/proc}"; HZ=$(getconf CLK_TCK)
tron() { if [ -n "${FV_GUARD_TRON_CMD:-}" ]; then bash -c "$FV_GUARD_TRON_CMD"; else curl -s -m 5 http://127.0.0.1:8090/wallet/getnowblock; fi 2>/dev/null; }
ntp() { if [ -n "${FV_GUARD_NTP_CMD:-}" ]; then bash -c "$FV_GUARD_NTP_CMD"; else timedatectl show -p NTPSynchronized --value; fi 2>/dev/null; }
head_field() { # head_field JSON NAME -> block_header.raw_data.NAME, or nothing
  if command -v python3 > /dev/null; then
    python3 -I -c 'import json, sys
try: v = json.loads(sys.argv[1])["block_header"]["raw_data"][sys.argv[2]]; print(int(v))
except Exception: pass' "$1" "$2"
  else
    sed -nE 's/.*"block_header" *: *\{ *"raw_data" *: *\{([^}]*)\}.*/\1/p' <<< "$1" | grep -oE "\"$2\" *: *[0-9]+" | grep -oE '[0-9]+$'
  fi
}
infer_pids() { if [ -n "${FV_GUARD_INFER_CMD:-}" ]; then bash -c "$FV_GUARD_INFER_CMD"; else
  { pgrep -x llama-server; pgrep -f '/llama.cpp-cuda/build/bin/llama-server'; pgrep -f 'ollama runner'; } | sort -u; fi 2>/dev/null; }
ticks() { awk '{print $14 + $15}' "$PROC/$1/stat" 2>/dev/null; }
chain_reading() { # sets age, num, sync, chain_ok_parse
  local js; js=$(tron); sync=$(ntp); ts=$(head_field "$js" timestamp); num=$(head_field "$js" number)
  if [[ "$ts" =~ ^[0-9]+$ ]] && [[ "$num" =~ ^[0-9]+$ ]]; then age=$(( $(date +%s) - ts / 1000 )); chain_ok_parse=1
  else age=""; num=""; chain_ok_parse=0; fi
}
if [ "${1:-}" = --start-ok ]; then
  chain_reading
  [ "$chain_ok_parse" = 1 ] || { echo "start: chain head unavailable or unparsable"; exit 1; }
  [ "$sync" = yes ] || { echo "start: NTP not synchronised ($sync): the head age cannot be trusted; not starting"; exit 1; }
  echo "start: head age ${age}s"; [ "$age" -le "$AGE_GOOD" ]; exit $?
fi
O="$1"; BD="$2"; RUNNER="$3"; FUZZER=$(readlink -f "$BD/bin/fuzzer")
log() { printf '%s\n' "$1" >> "$O/pauses.jsonl"; }
ours() { # PIDs in OUT/pids whose exe is the bundle's fuzzer and whose start time is the recorded one
  local pid w st; while read -r pid w st; do
    [ "$(readlink -f "/proc/$pid/exe" 2>/dev/null)" = "$FUZZER" ] && [ "$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null)" = "$st" ] && echo "$pid"
  done < "$O/pids"; }
paused=0; chain_bad_n=0; busy_n=0; host_bad_n=0; prev_num=""; next_chain=0
chain_good_since=""; calm_since=""; seen_infer=""
age=""; num=""; sync=""; chain_ok_parse=0; chain_bad=0; chain_good=0; why_c=""
while [ ! -e "$O/guard.stop" ] && kill -0 "$RUNNER" 2> /dev/null; do
  now=$(date +%s)
  if [ "$now" -ge "$next_chain" ]; then  # chain check every IV seconds
    chain_reading; chain_bad=0; chain_good=0; why_c=""
    if [ "$chain_ok_parse" != 1 ]; then chain_bad=1; why_c="endpoint failed or unparsable"
    else
      [ "$sync" = yes ] || { chain_bad=1; why_c+="NTP not synchronised, "; }
      [ "$age" -gt "$AGE_BAD" ] && { chain_bad=1; why_c+="head age ${age}s, "; }
      # MIN_BLOCKS per IV seconds, scaled to the time actually elapsed since the last reading (the loop
      # also spends the CPU window, so readings are not exactly IV apart).
      if [ -n "$prev_num" ]; then
        el=$(( now - prev_t )); [ "$el" -ge 1 ] || el=1; need=$(( MIN_BLOCKS * el / IV ))
        [ $(( num - prev_num )) -ge "$need" ] || { chain_bad=1; why_c+="head advanced $(( num - prev_num )) blocks in ${el}s (need ${need}), "; }
      fi
      [ "$sync" = yes ] && [ "$age" -le "$AGE_GOOD" ] && chain_good=1
      prev_num=$num; prev_t=$now
    fi
    if [ $chain_bad -eq 1 ]; then chain_bad_n=$((chain_bad_n + 1)); else chain_bad_n=0; fi
    next_chain=$(( now + IV ))
  fi
  # inference CPU over one window; a PID gone during the window = busy
  ip=($(infer_pids)); m=$(for p in "${ip[@]}"; do tr '\0' ' ' < "$PROC/$p/cmdline" 2>/dev/null | cut -c1-80; echo; done | tr '\n' '|')
  [ "$m" = "$seen_infer" ] || { [ -n "$m" ] && log "{\"event\":\"INFERENCE_PIDS\",\"t\":$now,\"commands\":\"${m//\"/}\"}"; seen_infer=$m; }
  t0=0; for p in "${ip[@]}"; do t=$(ticks "$p"); t0=$((t0 + ${t:-0})); done
  sleep "$CW"
  t1=0; vanished=0; for p in "${ip[@]}"; do t=$(ticks "$p"); [ -n "$t" ] || vanished=1; t1=$((t1 + ${t:-0})); done
  cpu=$(( (t1 - t0) * 100 / HZ / CW )); [ $vanished -eq 1 ] && cpu=$(( BUSY + 1 ))
  if [ "$cpu" -gt "$BUSY" ]; then busy_n=$((busy_n + 1)); else busy_n=0; fi
  # host
  load=$(cut -d' ' -f1 "${FV_GUARD_LOADAVG:-/proc/loadavg}"); mem=$(awk '/^MemAvailable:/ {print $2}' "${FV_GUARD_MEMINFO:-/proc/meminfo}")
  host_bad=0; awk -v a="$load" -v b="$LOAD_MAX" 'BEGIN { exit !(a > b) }' && host_bad=1; [ "${mem:-0}" -lt "$MEM_MIN_KB" ] && host_bad=1
  if [ $host_bad -eq 1 ]; then host_bad_n=$((host_bad_n + 1)); else host_bad_n=0; fi
  now=$(date +%s)
  reading=$(printf '{"t":%s,"head_age_s":%s,"head_number":%s,"ntp":"%s","inference_cpu_pct":%s,"inference_vanished":%s,"loadavg1":%s,"mem_available_kb":%s}' \
    "$now" "${age:-null}" "${num:-null}" "$sync" "$cpu" "$vanished" "$load" "${mem:-0}")
  if [ $chain_good -eq 1 ]; then chain_good_since=${chain_good_since:-$now}; else chain_good_since=""; fi
  if [ "$cpu" -lt "$CALM" ]; then calm_since=${calm_since:-$now}; else calm_since=""; fi
  reasons=""
  [ $chain_bad_n -ge 2 ] && reasons+="chain: ${why_c%, }; "
  [ $busy_n -ge 2 ] && reasons+="inference busy: ${cpu}%$([ $vanished -eq 1 ] && echo ' (a PID vanished)'); "
  [ $host_bad_n -ge 2 ] && reasons+="host: load ${load}, MemAvailable ${mem} kB; "
  # While paused, signal any batch process still running every interval: one that started in the race
  # between the worker's pause check and the PAUSE above must end too (a lease breach otherwise).
  if [ $paused -eq 1 ]; then
    p=$(ours | tr '\n' ' '); [ -n "$p" ] && { kill -INT $p 2>/dev/null; log "{\"event\":\"RESIGNAL\",\"pids\":\"${p% }\"}"; }
  fi
  if [ $paused -eq 0 ] && [ -n "$reasons" ]; then
    touch "$O/paused"; p=$(ours | tr '\n' ' '); [ -n "$p" ] && kill -INT $p
    paused=1; log "{\"event\":\"PAUSE\",\"reason\":\"${reasons% }\",\"ended_batch_pids\":\"${p% }\",\"reading\":$reading}"
  elif [ $paused -eq 1 ] && [ $chain_bad -eq 0 ] && [ $host_bad -eq 0 ] && [ "$cpu" -le "$BUSY" ] \
       && [ -n "$chain_good_since" ] && [ $((now - chain_good_since)) -ge "$CHAIN_RESUME" ] \
       && [ -n "$calm_since" ] && [ $((now - calm_since)) -ge "$INFER_RESUME" ]; then
    rm -f "$O/paused"; paused=0; chain_bad_n=0; busy_n=0; host_bad_n=0
    log "{\"event\":\"RESUME\",\"reading\":$reading}"
  fi
done
rm -f "$O/paused"
exit 0
