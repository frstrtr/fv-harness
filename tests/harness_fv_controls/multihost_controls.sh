#!/usr/bin/env bash
# multihost_controls.sh OUTDIR BUNDLE_TAR — controls for --jobs / --remote (run by run_fuzz_controls.sh
# after c39, on c39's bundle). FV_CONTROL_RUN_FUZZ runs the controls against another run_fuzz.sh (a
# red-without-feature check on an older harness).
#   c43_merge          the verdict from worker batches (fuzz/worker/merge.py): a batch without a numeric
#                      exit, exit 0 without final stats, and exit 72 without a guard pause are each ERROR; a
#                      batch paused during its corpus replay counts 0 executions (not ERROR); a failure line
#                      in a batch that exited 0 or 72 is a FAIL; stats the target printed itself are not read;
#                      a mismatch is named before another failure and before an ERROR; only post-replay
#                      executions count, so a corpus-only run is not countable; and at the gate, a worker
#                      runner killed mid-run (no exits, no post-check) is ERROR, never PASS.
#   c44_bundle_strict  a bundle with an extra file, a symbolic link, an out/ directory, or a tar member
#                      outside bundle/ is BLOCKED by the gate before any worker starts, with the
#                      strictness check's own reason (not the later "not this build's"), and by the worker
#                      runner itself.
#   c45_pause_no_hang  a guard pause longer than the per-input timeout (fv.toml timeout = 10 s; pause held
#                      25 s) ends the batch and resumes with a new one: PASS, never HANG, a batch ended
#                      "paused" (exit 72), and the post-replay total still reaches --runs.
#   c46_ssh_localhost  the ssh transport end to end against a test-only sshd on 127.0.0.1 (a random high
#                      port, keys and config under $FV_ROOT/ssh-test, stopped by this script's trap):
#                      PASS over ssh with one ControlMaster, the worker in its own systemd scope with
#                      CPUQuota and MemoryMax enforced, guards on fake probes; afterwards the remote work
#                      dir, the scope and the control socket are gone and the port is closed. Skipped (and
#                      said so) if /usr/sbin/sshd is absent or there is no user systemd manager. The test sshd runs without PAM, so its
#                      config sets XDG_RUNTIME_DIR (systemd-run --user needs it; PAM sets it on a real host).
#   c58_remote_same_name  two ssh runs with the same --out name at once, on the same worker: the second
#                      must neither fail on nor remove the first one's work dir or scope; both PASS (each run
#                      has its own random name suffix, and cleanup removes only what its own run created).
#   c60_runs_time      --runs 0, --runs -5, --runs 1e6, --time 0 and values from 2^31 on are each refused (exit 3)
#                      before any build:
#                      a replay-only run never counts as a campaign.
#   c61_out_unpack     what a remote worker sends back (fuzz/worker/unpack_out.py): an out/ of regular files
#                      unpacks; a symbolic link, a hard link, a FIFO, a member outside out/, a '..' path and
#                      a name twice are each refused (exit 3) with nothing written.
#   c47_run_name       a run name with characters outside [A-Za-z0-9._-] is refused (ERROR) before any
#                      build or ssh connection.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT/scripts/lib.sh"
OUT="${1:?}"; TAR="${2:?}"; mkdir -p "$OUT"
RF="${FV_CONTROL_RUN_FUZZ:-$ROOT/fuzz/run_fuzz.sh}"
FIX="$ROOT/fixtures/conservation"; LOCK="$ROOT/locks/conservation.sha256"; CPP="$ROOT/fixtures/conservation_cpp/fuzz"
fails=0
campaign() { # campaign ID ARGS...
  local id="$1"; shift
  rm -rf "${OUT:?}/$id"; mkdir -p "$OUT/$id"; cp -r "$CPP/corpus" "$OUT/$id/corpus"
  "$RF" --lean-project "$FIX" --lock "$LOCK" --cmake-dir "$CPP" --target diff_transfer --corpus "$OUT/$id/corpus" \
    --no-merge --out "$OUT/$id/run" "$@" > "$OUT/$id/run_fuzz.out" 2>&1
}
MERGE="$ROOT/fuzz/worker/merge.py"

# --- c43: merge rules (synthetic batches) + a killed worker runner at the gate
M="$OUT/c43"; rm -rf "${M:?}"; mkdir -p "$M"
okl() { printf '#%s\tINITED cov: 1 ft: 1 corp: 1/1b\nstat::number_of_executed_units: %s\n' "$1" "$2" > "$M/$3"; }
okl 107 5107 ok.log; okl 107 107 replay-only.log; echo "no stats here" > "$M/nostats.log"
echo "==1== diff-oracle: MISMATCH" > "$M/mm.log"; echo "ERROR: AddressSanitizer: heap-buffer-overflow" > "$M/asan.log"
t() { printf '%s\n' "$@" > "$M/case.tsv"; python3 -I "$MERGE" --list "$M/case.tsv" ${R:+--runs "$R"}; }
R=""
r=""; T=$'\t'
chk() { # chk LABEL JQ JSON
  if jq -e "$2" <<< "$3" > /dev/null; then r+="$1 ok; "; else r+="$1 WRONG [$(jq -c '{rc, reason, fail}' <<< "$3")]; "; c43bad=1; fi; }
c43bad=0
chk no-exit '.rc == 3 and (.reason | contains("no numeric exit"))' "$(t "0${T}1${T}0${T}5${T}done${T}${T}$M/ok.log")"
chk no-stats '.rc == 3 and (.reason | contains("without final stats"))' "$(t "0${T}0${T}0${T}5${T}done${T}0${T}$M/nostats.log")"
chk 72-unpaused '.rc == 3 and (.reason | contains("without a guard pause"))' "$(t "0${T}1${T}0${T}5${T}done${T}72${T}$M/ok.log")"
chk 72-paused '.rc == 0 and .total_executions == 10000' "$(t "0${T}1${T}0${T}5${T}paused${T}72${T}$M/ok.log" "0${T}1${T}1${T}6${T}done${T}0${T}$M/ok.log")"
chk mismatch-first '.rc == 1 and .fail.worker == 3 and .fail.exit == 86' \
  "$(t "0${T}0${T}0${T}5${T}done${T}1${T}$M/asan.log" "1${T}0${T}0${T}5${T}done${T}${T}$M/ok.log" "3${T}1${T}0${T}5${T}done${T}86${T}$M/mm.log")"
chk fail-over-error '.rc == 1 and .fail.worker == 0' "$(t "0${T}0${T}0${T}5${T}done${T}1${T}$M/asan.log" "1${T}0${T}0${T}5${T}done${T}${T}$M/ok.log")"
R=1000; chk corpus-only '.rc == 3 and (.reason | contains("not countable: 0 post-replay"))' "$(t "0${T}0${T}0${T}5${T}done${T}0${T}$M/replay-only.log")"
R=5000; chk countable '.rc == 0 and .total_executions == 5000' "$(t "0${T}0${T}0${T}5${T}done${T}0${T}$M/ok.log")"
R=5001; chk short-by-one '.rc == 3 and (.reason | contains("5000 post-replay executions < 5001"))' "$(t "0${T}0${T}0${T}5${T}done${T}0${T}$M/ok.log")"
R=""
printf 'stat::number_of_executed_units: 50\n' > "$M/paused-replay.log"
{ cat "$M/ok.log"; echo "==7== diff-oracle: MISMATCH at step 3"; } > "$M/ok-but-mismatch.log"
printf '#999999 INITED\nstat::number_of_executed_units: 999999\n#107\tINITED cov: 1 ft: 1 corp: 1/1b\nstat::number_of_executed_units: 5107\n' > "$M/forged.log"
chk paused-in-replay '.rc == 0 and .total_executions == 5000' "$(t "0${T}1${T}0${T}5${T}paused${T}72${T}$M/paused-replay.log" "0${T}1${T}1${T}6${T}done${T}0${T}$M/ok.log")"
chk failure-line-exit-0 '.rc == 1 and .fail.worker == 2 and .fail.exit == 0' "$(t "0${T}1${T}0${T}5${T}done${T}0${T}$M/ok.log" "2${T}1${T}0${T}5${T}done${T}0${T}$M/ok-but-mismatch.log")"
chk failure-line-exit-72 '.rc == 1 and .fail.worker == 2' "$(t "2${T}1${T}0${T}5${T}paused${T}72${T}$M/ok-but-mismatch.log")"
chk forged-stats '.rc == 0 and .total_executions == 5000' "$(t "0${T}0${T}0${T}5${T}done${T}0${T}$M/forged.log")"
R=""
# gate: kill the bundle worker runner (and its fuzzers) a few seconds into a 60 s campaign
campaign c43_killed --jobs 1 --remote local:1 --time 60 & cpid=$!
for i in $(seq 1 240); do p=$(pgrep -f "^bash $OUT/c43_killed/run/remote-local/bundle/fv_worker.sh" | head -1); [ -n "$p" ] && [ -s "$OUT/c43_killed/run/remote-local/bundle/out/pids" ] && break; sleep 1; done
sleep 3; [ -n "${p:-}" ] && kill -9 "$p"; while read -r fp _; do kill -9 "$fp" 2>/dev/null; done < "$OUT/c43_killed/run/remote-local/bundle/out/pids"
wait "$cpid"; krc=$?; J="$OUT/c43_killed/run/fuzz.json"
if [ -n "${p:-}" ] && [ $krc -eq 3 ] && jq -e '.verdict == "ERROR" and (.detail | test("post-check|exited|no batches"))' "$J" > /dev/null; then r+="killed-runner ok ($(jq -r .detail "$J" | cut -c1-80))"
else r+="killed-runner WRONG (pid=${p:-none} exit=$krc $(jq -c '{verdict, detail}' "$J" 2>/dev/null))"; c43bad=1; fi
[ $c43bad -eq 0 ] && echo "c43_merge OK $r" || { echo "c43_merge WRONG $r"; fails=1; }

# --- c44: bundle strictness
X="$OUT/c44"; rm -rf "${X:?}"; mkdir -p "$X"; r=""; c44bad=0
mk() { # mk NAME : a copy of the bundle, changed per NAME, as $X/NAME.tar and dir $X/NAME/bundle
  rm -rf "${X:?}/$1"; mkdir -p "$X/$1"; tar -xf "$TAR" -C "$X/$1"; local b="$X/$1/bundle"
  case "$1" in
    extra) echo hello > "$b/corpus/zz-extra" ;;
    symlink) ln -s /etc/hostname "$b/corpus/zz-link" ;;
    outdir) mkdir -p "$b/out"; echo 1 > "$b/out/exits" ;;
  esac
  if [ "$1" = outside ]; then mkdir -p "$X/$1/evil"; echo x > "$X/$1/evil/x"; tar -cf "$X/$1.tar" -C "$X/$1" bundle evil
  else tar -cf "$X/$1.tar" -C "$X/$1" bundle; fi
}
for c in extra symlink outdir outside; do
  mk $c
  campaign c44_$c --jobs 1 --remote local:1 --runs 2000 --bundle "$X/$c.tar"; grc=$?
  J="$OUT/c44_$c/run/fuzz.json"; started=0; [ -e "$OUT/c44_$c/run/remote-local/bundle/out/worker-env.json" ] && started=1
  if [ "$c" != outside ]; then
    [ "$c" = outdir ] || rm -rf "$X/$c/bundle/out"
    bash "$X/$c/bundle/fv_worker.sh" "$X/$c/bundle" 0 1 100 "" 1 > "$X/$c.worker.out" 2>&1; wrc=$?
    wl=$(head -1 "$X/$c.worker.out")
  else wrc=2; wl="(gate only: tar member)"; fi
  # The gate's reason must be the strictness check itself, not the later "not this build's" (the c39
  # bundle is another build's, so a gate without the strictness check would still say BLOCKED).
  want="the bundle is not exactly its manifest:"; [ "$c" = outside ] && want="the bundle $X/$c.tar has members outside bundle/"
  if [ $grc -eq 2 ] && [ $started -eq 0 ] && jq -e --arg w "$want" '.verdict == "BLOCKED" and (.detail | startswith($w))' "$J" > /dev/null \
     && [ $wrc -eq 2 ] && [[ "$wl" == BLOCKED:* || "$c" == outside ]]; then
    r+="$c: gate BLOCKED [$(jq -r .detail "$J" | cut -c1-70)], worker [${wl:0:60}]; "
  else r+="$c WRONG gate=$grc started=$started [$(jq -r .detail "$J" 2>/dev/null | cut -c1-90)] worker=$wrc [$wl]; "; c44bad=1; fi
done
[ $c44bad -eq 0 ] && echo "c44_bundle_strict OK $r" || { echo "c44_bundle_strict WRONG $r"; fails=1; }

# --- fake guard readings (c45, c46): a ticker keeps the head fresh; NTP and the rest are files
fake_guards() { # fake_guards DIR : start the ticker, export FV_GUARD_* pointing at DIR
  local F="$1"; rm -rf "${F:?}"; mkdir -p "$F/proc"; echo yes > "$F/ntp"; echo "1.00 1.00 1.00 1/100 1" > "$F/loadavg"
  printf 'MemTotal: 100000000 kB\nMemAvailable: 90000000 kB\n' > "$F/meminfo"; : > "$F/infer.pids"
  ( n=1000; while [ ! -e "$F/stop" ]; do n=$((n + 3))
      printf '{"block_header":{"raw_data":{"number":%s,"timestamp":%s000}}}\n' "$n" "$(date +%s)" > "$F/tron.tmp"; mv "$F/tron.tmp" "$F/tron.json"; sleep 1
    done ) & TICKER=$!
  export FV_GUARDS=1 FV_GUARD_INTERVAL=2 FV_GUARD_CPU_WINDOW=1 FV_GUARD_AGE_BAD=5 FV_GUARD_AGE_GOOD=3 FV_GUARD_CHAIN_RESUME=4 \
    FV_GUARD_INFER_RESUME=4 FV_GUARD_START_WAIT=30 FV_GUARD_PROC="$F/proc" FV_GUARD_TRON_CMD="cat $F/tron.json" \
    FV_GUARD_NTP_CMD="cat $F/ntp" FV_GUARD_INFER_CMD="cat $F/infer.pids" FV_GUARD_LOADAVG="$F/loadavg" FV_GUARD_MEMINFO="$F/meminfo"
}
stop_fake() { touch "$1/stop"; wait "$TICKER" 2>/dev/null; unset FV_GUARDS $(compgen -e | grep '^FV_GUARD_'); }

# --- c45: a pause longer than the per-input timeout
F45="$OUT/c45-fake"; fake_guards "$F45"
campaign c45_pause --jobs 1 --remote local:1 --runs 400000 & cpid=$!
RO="$OUT/c45_pause/run/remote-local/bundle/out"
for i in $(seq 1 300); do [ -s "$RO/pids" ] && break; sleep 1; done
sleep 2; echo no > "$F45/ntp"                                   # chain bad -> PAUSE
for i in $(seq 1 30); do grep -q '"PAUSE"' "$RO/pauses.jsonl" 2>/dev/null && break; sleep 1; done
sleep 25; echo yes > "$F45/ntp"                                 # held 25 s > timeout 10 s, then RESUME
wait "$cpid"; prc=$?; stop_fake "$F45"; J="$OUT/c45_pause/run/fuzz.json"
if [ $prc -eq 0 ] && jq -e '.verdict == "PASS" and .total_executions >= 400000
     and ([.workers[] | select(.remote) | .batches[] | select(.ended == "paused" and .exit == 72)] | length) >= 1
     and ([.workers[] | select(.remote) | .batches | length] | max) >= 2
     and ([.remote.pauses[] | .event] | index("PAUSE") != null and index("RESUME") != null)' "$J" > /dev/null \
   && ! grep -q 'libFuzzer: timeout' "$OUT/c45_pause/run/campaign.log"; then
  echo "c45_pause_no_hang OK paused 25 s (timeout 10 s): PASS, no HANG; remote batches $(jq -r '[.workers[] | select(.remote) | .batches[] | "\(.ended)/\(.exit)"] | join(",")' "$J"); $(jq -r .total_executions "$J") post-replay executions >= 400000"
else
  echo "c45_pause_no_hang WRONG exit=$prc $(jq -c '{verdict, detail, total_executions, b: [.workers[]? | select(.remote) | .batches[]? | {ended, exit}], ev: [.remote.pauses[]?.event]}' "$J" 2>/dev/null)"; fails=1
fi

# --- c46: ssh transport against a test-only sshd on 127.0.0.1
S="$FV_ROOT/ssh-test"
# The ssh path needs a test sshd and a user systemd manager (systemd-run --user, for the worker's scope);
# a host without either (a CI runner without a user session) SKIPs c46 and c58 and says why.
ssh_skip=""
[ -x /usr/sbin/sshd ] || ssh_skip="/usr/sbin/sshd is absent"
[ -n "$ssh_skip" ] || systemd-run --user --scope --quiet true > /dev/null 2>&1 || ssh_skip="no user systemd manager (systemd-run --user fails)"
if [ -n "$ssh_skip" ]; then
  echo "c46_ssh_localhost SKIPPED $ssh_skip: the ssh path is covered only by the worker dry run"
else
  rm -rf "${S:?}"; mkdir -m 0700 -p "$S"
  ssh-keygen -q -t ed25519 -N '' -C fv-ssh-test-host -f "$S/host_ed25519" && ssh-keygen -q -t ed25519 -N '' -C fv-ssh-test-only -f "$S/client_ed25519"
  cp "$S/client_ed25519.pub" "$S/authorized_keys"; chmod 600 "$S/authorized_keys"
  for i in $(seq 1 50); do port=$(( 20000 + $(od -An -N2 -tu2 /dev/urandom) % 40000 )); ss -ltnH "sport = :$port" | grep -q . || break; done
  cat > "$S/sshd_config" <<EOF
ListenAddress 127.0.0.1:$port
HostKey $S/host_ed25519
PidFile $S/sshd.pid
AuthorizedKeysFile $S/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
AllowUsers $(id -un)
UsePAM no
StrictModes no
X11Forwarding no
AllowTcpForwarding no
SetEnv XDG_RUNTIME_DIR=/run/user/$(id -u)
EOF
  /usr/sbin/sshd -D -e -f "$S/sshd_config" > "$S/sshd.log" 2>&1 & SSHD=$!
  trap 'kill "$SSHD" 2>/dev/null; wait "$SSHD" 2>/dev/null; rm -rf "${S:?}"' EXIT
  for i in $(seq 1 20); do ss -ltnH "sport = :$port" | grep -q . && break; sleep 0.5; done
  ver=$(/usr/sbin/sshd -V 2>&1 | head -1)
  export FV_WORKER_SSH_LOCALTEST="-p $port -i $S/client_ed25519 -o IdentitiesOnly=yes -o UserKnownHostsFile=$S/known_hosts -o StrictHostKeyChecking=accept-new $(id -un)@127.0.0.1"
  export FV_WORKER_ROOT_LOCALTEST="$S/fv-work" FV_WORKER_QUOTA_PCT=100 FV_WORKER_MEMMAX=6G
  # The worker is this host: its glibc / GLIBCXX target is this host's own (the gate checks the bundle against it).
  lsc=$(ldconfig -p 2>/dev/null | awk '/libstdc\+\+\.so\.6 .*x86-64/ { print $NF; exit }')
  export FV_WORKER_GLIBC_MAX_LOCALTEST="$(getconf GNU_LIBC_VERSION | awk '{ print $2 }')"
  export FV_WORKER_GLIBCXX_MAX_LOCALTEST="$(strings "${lsc:-/usr/lib/x86_64-linux-gnu/libstdc++.so.6}" | grep -oE '^GLIBCXX_[0-9.]+$' | sort -V | tail -1 | sed 's/^GLIBCXX_//')"
  F46="$OUT/c46-fake"; fake_guards "$F46"
  campaign c46_ssh --jobs 1 --remote ssh:LOCALTEST:1 --runs 20000; src=$?
  # c58: two runs named "run" at once on this worker (the first long enough to overlap the second).
  rm -rf "${OUT:?}/c58a" "${OUT:?}/c58b"; mkdir -p "$OUT/c58a" "$OUT/c58b"; cp -r "$CPP/corpus" "$OUT/c58a/corpus"; cp -r "$CPP/corpus" "$OUT/c58b/corpus"
  "$RF" --lean-project "$FIX" --lock "$LOCK" --cmake-dir "$CPP" --target diff_transfer --corpus "$OUT/c58a/corpus" --no-merge \
    --jobs 1 --remote ssh:LOCALTEST:1 --runs 400000 --out "$OUT/c58a/run" > "$OUT/c58a/run_fuzz.out" 2>&1 & p58=$!
  for i in $(seq 1 240); do [ -n "$(ls -A "$S/fv-work" 2>/dev/null)" ] && break; sleep 0.5; done
  seen58=$(ls -A "$S/fv-work" 2>/dev/null | tr '\n' ' ')
  "$RF" --lean-project "$FIX" --lock "$LOCK" --cmake-dir "$CPP" --target diff_transfer --corpus "$OUT/c58b/corpus" --no-merge \
    --jobs 1 --remote ssh:LOCALTEST:1 --runs 20000 --out "$OUT/c58b/run" > "$OUT/c58b/run_fuzz.out" 2>&1; r58b=$?
  alive58=$(kill -0 $p58 2>/dev/null && echo yes || echo no)
  wait $p58; r58a=$?
  stop_fake "$F46"; J="$OUT/c46_ssh/run/fuzz.json"; rid="fv-run"
  left_dir=$(ls -A "$S/fv-work" 2>/dev/null | tr '\n' ' '); left_sock=$(ls "$OUT/c46_ssh/run/ssh-ctl" 2>/dev/null)
  left_unit=$(systemctl --user list-units --all --no-legend 'fv-run*' 2>/dev/null | head -2)
  kill "$SSHD" 2>/dev/null; wait "$SSHD" 2>/dev/null; trap - EXIT
  closed=1; ss -ltnH "sport = :$port" | grep -q . && closed=0
  rm -rf "${S:?}"
  if [ $src -eq 0 ] && jq -e '.verdict == "PASS" and .remote.transport == "ssh:LOCALTEST" and .total_executions >= 20000
       and (.remote.worker_env.cgroup | contains("fv-run")) and (.remote.worker_env.cpu_max | startswith("100000 "))
       and (.remote.guard_overrides | length) > 0' "$J" > /dev/null \
     && [ -z "$left_dir" ] && [ -z "$left_sock" ] && [ -z "$left_unit" ] && [ $closed -eq 1 ]; then
    echo "c46_ssh_localhost OK $ver on 127.0.0.1:$port for this control only: PASS over ssh ($(jq -r .total_executions "$J") executions), scope $(jq -r .remote.worker_env.cgroup "$J" | sed 's|.*/||') cpu.max '$(jq -r .remote.worker_env.cpu_max "$J")' memory.max $(jq -r .remote.worker_env.memory_max "$J"); guards on fake probes ($(jq -r '.remote.guard_overrides | length' "$J") overrides); afterwards: work dir, scope and control socket gone, port closed"
  else
    echo "c46_ssh_localhost WRONG exit=$src $(jq -c '{verdict, detail, transport: .remote.transport, env: .remote.worker_env}' "$J" 2>/dev/null) left_dir=[$left_dir] sock=[$left_sock] unit=[$left_unit] closed=$closed ($ver, port $port; sshd log: $(tail -2 "$OUT/c46_ssh/run_fuzz.out" | tr '\n' ' ' | cut -c1-160))"; fails=1
  fi
fi

if [ -n "$ssh_skip" ]; then
  echo "c58_remote_same_name SKIPPED $ssh_skip (the same-name ssh case needs the test sshd of c46)"
else
  if [ -n "${seen58% }" ] && [ "$alive58" = yes ] && [ $r58a -eq 0 ] && [ $r58b -eq 0 ] \
     && jq -e '.verdict == "PASS"' "$OUT/c58a/run/fuzz.json" > /dev/null && jq -e '.verdict == "PASS"' "$OUT/c58b/run/fuzz.json" > /dev/null; then
    echo "c58_remote_same_name OK two runs named 'run' at once on one worker: both PASS (first's work dir ${seen58% } while the second ran)"
  else
    echo "c58_remote_same_name WRONG first exit=$r58a [$(jq -r .detail "$OUT/c58a/run/fuzz.json" 2>/dev/null | cut -c1-90)] second exit=$r58b [$(jq -r .detail "$OUT/c58b/run/fuzz.json" 2>/dev/null | cut -c1-90)] overlap=$alive58 seen=[$seen58]"; fails=1
  fi
fi

# --- c47: run names
r=""; c47bad=0
export FV_WORKER_SSH_NOPE="-o BatchMode=yes -o ConnectTimeout=2 nobody@nonexistent.invalid"
for n in 'bad name' 'bad$(id)' 'bad;rm'; do
  Z="$OUT/c47/$n"; rm -rf "$Z"; mkdir -p "$Z"
  "$RF" --lean-project "$FIX" --lock "$LOCK" --cmake-dir "$CPP" --target diff_transfer --no-merge --runs 100 \
    --remote ssh:NOPE:1 --out "$Z" > "$OUT/c47.out" 2>&1; zrc=$?
  if [ $zrc -eq 3 ] && jq -e '.verdict == "ERROR" and (.detail | contains("run name"))' "$Z/fuzz.json" > /dev/null && [ ! -d "$Z/build" ] && [ ! -e "$Z/ssh-ctl" ]; then
    r+="[$n] refused; "; else r+="[$n] WRONG exit=$zrc; "; c47bad=1; fi
done
[ $c47bad -eq 0 ] && echo "c47_run_name OK $r before any build or ssh connection" || { echo "c47_run_name WRONG $r"; fails=1; }

# --- c60: --runs / --time must be positive whole numbers
r=""; c60bad=0
for args in "--runs 0" "--runs -5" "--runs 1e6" "--time 0" "--runs 2147483648" "--time 4294967296"; do
  Z="$OUT/c60/${args// /_}"; rm -rf "$Z"; mkdir -p "$Z"
  # shellcheck disable=SC2086
  "$RF" --lean-project "$FIX" --lock "$LOCK" --cmake-dir "$CPP" --target diff_transfer --no-merge $args --out "$Z/run" > "$Z/out" 2>&1; zrc=$?
  if [ $zrc -eq 3 ] && [ ! -d "$Z/run/build" ] && grep -q 'must be a positive whole number' "$Z/out"; then r+="[$args] refused; "
  else r+="[$args] WRONG exit=$zrc [$(tail -1 "$Z/out" | cut -c1-80)]; "; c60bad=1; fi
done
[ $c60bad -eq 0 ] && echo "c60_runs_time OK $r" || { echo "c60_runs_time WRONG $r"; fails=1; }

# --- c61: the gate's unpacking of a worker's out/
U="$OUT/c61"; rm -rf "${U:?}"; mkdir -p "$U"
python3 -I - "$U" <<'PY'
import io, sys, tarfile
d = sys.argv[1]
def mk(name, members):
    with tarfile.open(f"{d}/{name}.tar", "w") as tf:
        for n, kind, data in members:
            ti = tarfile.TarInfo(n)
            if kind == "f":
                ti.size = len(data); tf.addfile(ti, io.BytesIO(data))
            elif kind == "d":
                ti.type = tarfile.DIRTYPE; tf.addfile(ti)
            elif kind == "sym":
                ti.type = tarfile.SYMTYPE; ti.linkname = data; tf.addfile(ti)
            elif kind == "hard":
                ti.type = tarfile.LNKTYPE; ti.linkname = data; tf.addfile(ti)
            elif kind == "fifo":
                ti.type = tarfile.FIFOTYPE; tf.addfile(ti)
ok = [("out", "d", b""), ("out/exits", "f", b"0\n"), ("out/w1.b0.log", "f", b"log\n")]
mk("ok", ok)
mk("symlink", ok + [("out/w1.b1.log", "sym", "/etc/hostname")])
mk("hardlink", ok + [("out/w1.b1.log", "hard", "out/exits")])
mk("fifo", ok + [("out/f", "fifo", None)])
mk("outside", ok + [("evil/x", "f", b"x")])
mk("dotdot", ok + [("out/../x", "f", b"x")])
mk("twice", ok + [("out/exits", "f", b"1\n")])
PY
r=""; c61bad=0
for c in ok symlink hardlink fifo outside dotdot twice; do
  mkdir -p "$U/$c.d"; python3 -I "$ROOT/fuzz/worker/unpack_out.py" "$U/$c.tar" "$U/$c.d" 2> "$U/$c.err"; urc=$?
  nf=$(find "$U/$c.d" -mindepth 1 | wc -l)
  if [ $c = ok ]; then
    if [ $urc -eq 0 ] && [ "$(cat "$U/ok.d/out/exits" 2>/dev/null)" = 0 ] && [ -f "$U/ok.d/out/w1.b0.log" ]; then r+="ok unpacked; "; else r+="ok WRONG exit=$urc; "; c61bad=1; fi
  elif [ $urc -eq 3 ] && [ "$nf" -eq 0 ]; then r+="$c refused; "
  else r+="$c WRONG exit=$urc written=$nf [$(head -1 "$U/$c.err")]; "; c61bad=1; fi
done
[ $c61bad -eq 0 ] && echo "c61_out_unpack OK $r" || { echo "c61_out_unpack WRONG $r"; fails=1; }
exit $fails
