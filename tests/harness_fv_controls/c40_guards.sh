#!/usr/bin/env bash
# c40_guards.sh BUNDLE_TAR OUTDIR — control c40: the shared-host guards (fuzz/worker/fv_guard.sh) on FAKE
# readings (no chain node or inference server needed).
#   start gate (C1, C4): NTP not synchronised, an unparsable head, a stale head, and a head whose
#     "timestamp" also appears outside block_header.raw_data are judged on the right field; only a
#     fresh head with NTP may start;
#   running: a stale head, a failing endpoint, NTP lost, busy inference, an inference PID that vanishes
#     (C3: counted as busy), low memory and high load each PAUSE: the running batch ENDS (our fuzzers
#     exit; none is ever left stopped) and, once cleared, RESUME starts a new batch;
#   C2: no RESUME while the current reading is still bad (load high after the chain recovered);
#   a decoy process named "java" is never stopped or signalled; matched inference commands are logged.
# Prints "c40_guards OK|WRONG ..."; exit 0 iff OK.
set -uo pipefail
TAR="$1"; X="${2:?}"; rm -rf "${X:?}"; mkdir -p "$X/fake/proc/999999"
tar -xf "$TAR" -C "$X"; B="$X/bundle"; F="$X/fake"; G="$B/fv_guard.sh"
HZ=$(getconf CLK_TCK)
echo yes > "$F/ntp"; echo "1.00 1.00 1.00 1/100 1" > "$F/loadavg"
printf 'MemTotal: 100000000 kB\nMemAvailable: 90000000 kB\n' > "$F/meminfo"
echo 999999 > "$F/infer.pids"; printf 'llama-server\0-m\0fake.gguf\0' > "$F/proc/999999/cmdline"; utime=0
pstat() { echo "999999 (llama-server) S 1 1 1 0 -1 0 0 0 0 0 $1 0 0 0 20 0 1 0 0 0 0" > "$F/proc/999999/stat"; }
pstat 0
num=1000; mode=fresh   # head writer: fresh | stale | fail | slowstale
newhead() {
  case "$mode" in
    fresh) num=$((num + 3)); printf '{"block_header":{"raw_data":{"number":%s,"timestamp":%s000}}}\n' "$num" "$(date +%s)" ;;
    stale) printf '{"block_header":{"raw_data":{"number":%s,"timestamp":%s000}}}\n' "$num" "$(( $(date +%s) - 100 ))" ;;
    fail) echo "" ;;
  esac > "$F/tron.json.tmp"; mv "$F/tron.json.tmp" "$F/tron.json"
}
export FV_GUARD_INTERVAL=2 FV_GUARD_CPU_WINDOW=1 FV_GUARD_AGE_BAD=5 FV_GUARD_AGE_GOOD=3 \
  FV_GUARD_CHAIN_RESUME=4 FV_GUARD_INFER_RESUME=4 FV_GUARD_START_WAIT=20 FV_GUARD_PROC="$F/proc" \
  FV_GUARD_TRON_CMD="cat $F/tron.json" FV_GUARD_NTP_CMD="cat $F/ntp" FV_GUARD_INFER_CMD="cat $F/infer.pids" \
  FV_GUARD_LOADAVG="$F/loadavg" FV_GUARD_MEMINFO="$F/meminfo"
# --- start gate
sg=""; sgbad=0
start() { # start LABEL WANT(0|1) : run --start-ok on the current fake readings
  bash "$G" --start-ok > "$X/start.out" 2>&1; local rc=$?
  [ $rc -eq "$2" ] && sg+="$1 -> $([ $rc -eq 0 ] && echo start || echo refused); " || { sg+="$1 WRONG rc=$rc [$(cat "$X/start.out")]; "; sgbad=1; }
}
newhead; echo no > "$F/ntp"; start "no NTP" 1; echo yes > "$F/ntp"
echo '{"block_header":{"raw_data":{"number":"x"' > "$F/tron.json"; start "unparsable head" 1
mode=stale; newhead; start "stale head" 1
printf '{"other":{"timestamp":%s000},"block_header":{"raw_data":{"number":7,"timestamp":%s000}}}\n' "$(date +%s)" "$(( $(date +%s) - 100 ))" > "$F/tron.json"
start "stale head + fresh decoy timestamp elsewhere" 1
mode=fresh; newhead; start "fresh head, NTP" 0
# --- running campaign
bash -c 'exec -a java sleep 900' & decoy=$!
FV_GUARDS=1 bash "$B/fv_worker.sh" "$B" 0 2 "" 600 1 -timeout=10 > "$X/worker.out" 2>&1 & wpid=$!
O="$B/out"; decoy_stopped=0; busy=0
alive() { local p w st n=0; while read -r p w st; do [ -d "/proc/$p" ] && n=$((n + 1)); done < "$1"; echo $n; }
tick() { # tick SECONDS : keep the fake readings moving, watch the decoy and that nothing of ours is stopped
  local i p w st; for ((i = 0; i < $1; i++)); do
    newhead; [ "$busy" = 1 ] && utime=$((utime + HZ * 3)); [ -e "$F/proc/999999/stat" ] && pstat "$utime"
    [ "$(awk '{print $3}' /proc/$decoy/stat 2>/dev/null)" = T ] && decoy_stopped=1
    while read -r p w st; do [ "$(awk '{print $3}' "/proc/$p/stat" 2>/dev/null)" = T ] && stopped_seen=1; done < "$O/pids" 2>/dev/null
    sleep 1
  done
}
stopped_seen=0
wait_event() { # wait_event PAUSE|RESUME N [SECONDS]
  local i; for ((i = 0; i < ${3:-60}; i++)); do
    [ "$(grep -c "\"event\":\"$1\"" "$O/pauses.jsonl" 2>/dev/null)" -ge "$2" ] && return 0; tick 1
  done; return 1
}
for i in $(seq 1 30); do [ -s "$O/pids" ] && break; tick 1; done; tick 4
wait_batch() { local i; for ((i = 0; i < 15; i++)); do [ "$(alive "$O/pids")" -ge 2 ] && { tick 1; return 0; }; tick 1; done; return 1; }
results=(); n=0
clear_bad() { mode=fresh; echo yes > "$F/ntp"; busy=0; echo 999999 > "$F/infer.pids"; pstat "$utime"
  echo "1.00 1.00 1.00 1/100 1" > "$F/loadavg"; printf 'MemTotal: 100000000 kB\nMemAvailable: 90000000 kB\n' > "$F/meminfo"; }
trigger() { # trigger NAME : the bad state is set by the caller
  n=$((n + 1)); cp "$O/pids" "$X/before.$n" 2>/dev/null
  if wait_event PAUSE $n; then tick 3; ended="$(alive "$X/before.$n") of $(wc -l < "$X/before.$n") alive, paused=$([ -e "$O/paused" ] && echo y || echo n), running=$(alive "$O/pids")"
  else ended=none; fi
  [ -n "${HOLD:-}" ] && { eval "$HOLD"; }
  clear_bad
  if wait_event RESUME $n; then wait_batch; res="new batch running=$(alive "$O/pids")"; else res=none; fi
  results+=("$1: pause[$ended] resume[$res]")
}
mode=stale; trigger "stale head"
mode=fail; trigger "endpoint fails"
echo no > "$F/ntp"; trigger "NTP lost"
busy=1; trigger "inference busy"
echo 999998 > "$F/infer.pids"; trigger "inference PID vanished"
printf 'MemTotal: 100000000 kB\nMemAvailable: 1000000 kB\n' > "$F/meminfo"; trigger "MemAvailable low"
echo "99.0 99.0 99.0 1/100 1" > "$F/loadavg"; trigger "load high"
# C2: chain bad -> PAUSE; then the chain recovers but the load stays high for 10 s: no RESUME meanwhile
echo no > "$F/ntp"; n=$((n + 1))
if wait_event PAUSE $n; then
  echo yes > "$F/ntp"; echo "99.0 99.0 99.0 1/100 1" > "$F/loadavg"; r0=$(grep -c '"RESUME"' "$O/pauses.jsonl"); tick 10
  r1=$(grep -c '"RESUME"' "$O/pauses.jsonl"); clear_bad
  if wait_event RESUME $n; then wait_batch; c2="no RESUME during 10 s of high load after the chain recovered ($r0 -> $r1), RESUME once cleared"; c2ok=$([ "$r0" = "$r1" ] && echo 1 || echo 0)
  else c2="no RESUME after clearing"; c2ok=0; fi
else c2="no PAUSE"; c2ok=0; fi
touch "$O/guard.stop"; while read -r p w st; do kill -INT "$p" 2>/dev/null; done < "$O/pids"; wait "$wpid" 2>/dev/null
decoy_alive=0; [ -d "/proc/$decoy" ] && decoy_alive=1; kill "$decoy" 2>/dev/null
ok=1; for r in "${results[@]}"; do [[ "$r" == *"pause[0 of 2 alive, paused=y, running=0]"* ]] && [[ "$r" == *"resume[new batch running=2]"* ]] || ok=0; done
reasons=$(jq -r 'select(.event == "PAUSE") | .reason' "$O/pauses.jsonl" | tr '\n' '|')
cmds=$(jq -r 'select(.event == "INFERENCE_PIDS") | .commands' "$O/pauses.jsonl" | head -1)
if [ $sgbad -eq 0 ] && [ $ok -eq 1 ] && [ ${#results[@]} -eq 7 ] && [ "$c2ok" = 1 ] && [ $decoy_stopped -eq 0 ] && [ $decoy_alive -eq 1 ] \
   && [ $stopped_seen -eq 0 ] && [[ "$cmds" == *llama-server* ]]; then
  echo "c40_guards OK start gate: ${sg% }; 7 running triggers each ended the batch (0 of 2 fuzzers alive while paused, none stopped) and RESUME started a new one; C2: $c2; decoy 'java' alive, never stopped; inference logged as [$cmds]; pause reasons: $reasons"
else
  echo "c40_guards WRONG start gate: $sg | $(printf '%s; ' "${results[@]}") | C2: $c2 | decoy stopped=$decoy_stopped alive=$decoy_alive | ours stopped=$stopped_seen | cmds=[$cmds] | reasons: $reasons"; exit 1
fi
