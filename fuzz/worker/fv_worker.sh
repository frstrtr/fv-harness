#!/usr/bin/env bash
# fv_worker.sh — runs a hash-pinned fuzz bundle on a worker host (shipped inside the bundle).
#
#   fv_worker.sh BUNDLE_DIR WORKER_BASE K RUNS_TOTAL_OR_EMPTY SECS_OR_EMPTY SEED0 [LIBFUZZER LIMITS...]
#
# The worker needs no installs, no root and no network: glibc and libstdc++ at least at the versions
# in bundle/REQUIRES, plus bash, coreutils (sha256sum, nproc, comm), grep, sed, awk, find, ldd/ldconfig;
# with FV_GUARDS=1 also curl, timedatectl, pgrep, getconf (python3 is used when present).
#
# Before anything starts it refuses (exit 2, "BLOCKED: ...") a bundle that holds a symbolic link, a
# file not listed in MANIFEST.sha256, a file whose hash differs, or an out/ directory from before;
# a host older than REQUIRES; and, when the caller asks for limits (FV_EXPECT_CPU_PCT,
# FV_EXPECT_MEM_BYTES), a cgroup that does not enforce them (the controller not delegated).
#
# It runs K workers (FV_FUZZ_WORKER = WORKER_BASE .. WORKER_BASE+K-1) in BATCHES on the bundle's
# corpus plus a shared out/new_corpus. RUNS_TOTAL counts post-replay executions over all K workers;
# each batch runs the rest. With FV_GUARDS=1, bundle/fv_guard.sh watches the host: a pause ENDS the
# batch (SIGINT: libFuzzer exits 72 with its final stats) and the next batch starts after the resume,
# so no worker is ever left stopped and libFuzzer's per-input timeout never sees a paused input.
# Every batch is listed in out/batches.tsv (worker, remote, batch, seed, ended, exit, log) for
# fuzz/worker/merge.py on the gate host. Exit: 0 batches ran, 2 refused, 3 bundle changed during the run.
set -uo pipefail
B=$(cd "$1" && pwd) || { echo "BLOCKED: no bundle directory $1"; exit 2; }
base="$2"; k="$3"; runs="$4"; secs="$5"; seed0="$6"; shift 6
for v in "$base" "$k" "$seed0"; do [[ "$v" =~ ^[0-9]+$ ]] || { echo "BLOCKED: bad numeric argument '$v'"; exit 2; }; done
[ -z "$runs" ] || [[ "$runs" =~ ^[0-9]+$ ]] || { echo "BLOCKED: bad runs '$runs'"; exit 2; }
[ -z "$secs" ] || [[ "$secs" =~ ^[0-9]+$ ]] || { echo "BLOCKED: bad seconds '$secs'"; exit 2; }
cd "$B" || exit 2
# Bundle strictness, before anything is created.
[ ! -e "$B/out" ] || { echo "BLOCKED: the bundle already holds out/ (a bundle is shipped without results)"; exit 2; }
lnk=$(find . -type l -printf '%P ' | head -c 300); [ -z "$lnk" ] || { echo "BLOCKED: the bundle holds symbolic links: $lnk"; exit 2; }
spc=$(find . ! -type f ! -type d -printf '%P ' | head -c 300); [ -z "$spc" ] || { echo "BLOCKED: the bundle holds special files (FIFO, device, socket): $spc"; exit 2; }
extra=$(comm -23 <(find . -type f ! -path ./MANIFEST.sha256 -printf '%P\n' | LC_ALL=C sort) <(awk '{ sub(/^[0-9a-f]+  /, ""); print }' MANIFEST.sha256 | LC_ALL=C sort))
[ -z "$extra" ] || { echo "BLOCKED: files not in MANIFEST.sha256: $(echo $extra | head -c 300)"; exit 2; }
chk=$(sha256sum --quiet -c MANIFEST.sha256 2>&1) || { echo "BLOCKED: bundle files differ from MANIFEST.sha256: $(echo "$chk" | head -3 | tr '\n' ' ')"; exit 2; }
O="$B/out"; mkdir -p "$O/artifacts" "$O/new_corpus"
need_glibc=$(sed -n 's/^glibc_max //p' REQUIRES); need_cxx=$(sed -n 's/^glibcxx_max //p' REQUIRES)
have_glibc=$(ldd --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+$')
libstdcxx=$(ldconfig -p 2>/dev/null | grep -m1 'libstdc++.so.6 ' | sed 's/.*=> //')
have_cxx=$(grep -aoE 'GLIBCXX_3\.4\.[0-9]+' "$libstdcxx" 2>/dev/null | sort -V | tail -1 | sed 's/GLIBCXX_//')
older() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$1" ] && [ "$1" != "$2" ]; }  # older A B: A < B
if [ -z "$have_glibc" ] || older "$have_glibc" "$need_glibc"; then
  echo "BLOCKED: host glibc ${have_glibc:-unknown} is older than the bundle needs ($need_glibc)"; exit 2
fi
if [ -z "$have_cxx" ] || older "$have_cxx" "$need_cxx"; then
  echo "BLOCKED: host libstdc++ GLIBCXX ${have_cxx:-unknown} is older than the bundle needs ($need_cxx)"; exit 2
fi
# The cgroup this runner is in, and whether it enforces the limits the caller asked for.
cg=$(sed -n 's/^0:://p' /proc/self/cgroup 2>/dev/null); cpu_max=$(cat "/sys/fs/cgroup$cg/cpu.max" 2>/dev/null); mem_max=$(cat "/sys/fs/cgroup$cg/memory.max" 2>/dev/null)
if [ -n "${FV_EXPECT_CPU_PCT:-}" ]; then
  q=${cpu_max%% *}; p=${cpu_max##* }
  [[ "$q" =~ ^[0-9]+$ ]] && [[ "$p" =~ ^[0-9]+$ ]] && [ $(( q * 100 / p )) -le "$FV_EXPECT_CPU_PCT" ] \
    || { echo "BLOCKED: CPUQuota not enforced in cgroup $cg (cpu.max '${cpu_max:-absent}'; is the cpu controller delegated?)"; exit 2; }
fi
if [ -n "${FV_EXPECT_MEM_BYTES:-}" ]; then
  [[ "$mem_max" =~ ^[0-9]+$ ]] && [ "$mem_max" -le "$FV_EXPECT_MEM_BYTES" ] \
    || { echo "BLOCKED: MemoryMax not enforced in cgroup $cg (memory.max '${mem_max:-absent}')"; exit 2; }
fi
printf '{"host": "%s", "nproc": %s, "glibc": "%s", "libstdcxx": "%s", "glibcxx_max": "%s", "libstdcxx_sha256": "%s", "workers": %s, "cgroup": "%s", "cpu_max": "%s", "memory_max": "%s"}\n' \
  "$(hostname)" "$(nproc)" "$have_glibc" "$libstdcxx" "$have_cxx" "$(sha256sum < "$libstdcxx" | cut -d' ' -f1)" "$k" \
  "$cg" "$cpu_max" "$mem_max" > "$O/worker-env.json"
: > "$O/batches.tsv"; : > "$O/pids"
# Guards: a start gate, then the watcher beside the batches.
if [ "${FV_GUARDS:-0}" = 1 ]; then
  deadline=$(( $(date +%s) + ${FV_GUARD_START_WAIT:-1800} )); unreach_since=""
  while :; do
    bash "$B/fv_guard.sh" --start-ok >> "$O/start-check" 2>&1; src=$?
    [ $src -eq 0 ] && break
    now=$(date +%s)
    if [ $src -eq 3 ]; then  # the chain node did not answer (a restart): retry, BLOCK after the limit
      unreach_since=${unreach_since:-$now}
      [ $((now - unreach_since)) -lt "${FV_GUARD_UNREACHABLE_MAX:-600}" ] \
        || { echo "BLOCKED: chain node unreachable for $((now - unreach_since)) s at start ($(tail -1 "$O/start-check"))"; exit 2; }
    else unreach_since=""; fi
    [ "$now" -lt "$deadline" ] || { echo "BLOCKED: start condition not met: $(tail -1 "$O/start-check")"; exit 2; }
    sleep "${FV_GUARD_INTERVAL:-30}"
  done
  : > "$O/pauses.jsonl"
  bash "$B/fv_guard.sh" "$O" "$B" $$ > "$O/guard.log" 2>&1 &
  gpid=$!
fi
remaining=(); for ((i = 0; i < k; i++)); do remaining+=("${runs:+$(( (runs + k - 1) / k ))}"); done
left_secs="$secs"; batch=0; failed=0
corpus_count() { find "$B/corpus" "$O/new_corpus" -maxdepth 1 -type f | wc -l; }
while :; do
  todo=0; for ((i = 0; i < k; i++)); do if [ -z "$runs" ] || [ "${remaining[$i]}" -gt 0 ]; then todo=1; fi; done
  if [ -n "$secs" ] && [ "$left_secs" -le 0 ]; then todo=0; fi
  [ $todo -eq 1 ] && [ $failed -eq 0 ] && [ $batch -lt 1000 ] || break
  [ ! -e "$O/guard.block" ] || { echo "BLOCKED: $(cat "$O/guard.block"); batches stopped after $batch"; exit 2; }
  if [ "${FV_GUARDS:-0}" = 1 ] && ! kill -0 "$gpid" 2>/dev/null; then  # never run unguarded
    echo "BLOCKED: the guard watcher exited ($(tail -1 "$O/guard.log" 2>/dev/null | cut -c1-160)); batches stopped after $batch"; exit 2
  fi
  while [ -e "$O/paused" ]; do
    [ ! -e "$O/guard.block" ] || { echo "BLOCKED: $(cat "$O/guard.block"); batches stopped after $batch"; exit 2; }
    sleep 1; kill -0 "${gpid:-$$}" 2>/dev/null || break
  done   # the guard removes it at RESUME
  # Checked again right before a batch starts: the guard may have BLOCKED or ended during the wait above
  # (a batch must never start after either).
  [ ! -e "$O/guard.block" ] || { echo "BLOCKED: $(cat "$O/guard.block"); batches stopped after $batch"; exit 2; }
  if [ "${FV_GUARDS:-0}" = 1 ] && ! kill -0 "$gpid" 2>/dev/null; then
    echo "BLOCKED: the guard watcher exited ($(tail -1 "$O/guard.log" 2>/dev/null | cut -c1-160)); batches stopped after $batch"; exit 2
  fi
  extra_runs=$(( $(corpus_count) + 1 ))  # the corpus replay counts toward -runs; it is not counted as work
  t0=$(date +%s); : > "$O/pids.batch"
  for ((i = 0; i < k; i++)); do
    w=$((base + i)); if [ -n "$runs" ] && [ "${remaining[$i]}" -le 0 ]; then continue; fi
    lim=(); [ -n "$runs" ] && lim+=(-runs=$(( remaining[i] + extra_runs ))); [ -n "$secs" ] && lim+=(-max_total_time="$left_secs")
    env FV_FUZZ_WORKER="$w" FV_FUZZ_ARTIFACT_DIR="$O/artifacts" LD_LIBRARY_PATH="$B/lib" \
      "$B/bin/fuzzer" "${lim[@]}" "$@" -seed=$((seed0 + w + 1000003 * batch)) -print_final_stats=1 -artifact_prefix="$O/artifacts/w$w-b$batch-" \
      "$O/new_corpus" "$B/corpus" > "$O/w$w.b$batch.log" 2>&1 &
    pid=$!; echo "$pid $w $(awk '{print $22}' /proc/$pid/stat 2>/dev/null)" >> "$O/pids.batch"
  done
  cp "$O/pids.batch" "$O/pids"
  # A pause that began while this batch was starting: end it now (the guard re-signals as well).
  if [ -e "$O/paused" ]; then while read -r pid _ _; do kill -INT "$pid" 2>/dev/null; done < "$O/pids.batch"; fi
  while read -r pid w st; do
    wait "$pid"; e=$?
    ended=done; [ -e "$O/paused" ] && ended=paused
    i=$(( w - base )); s=$((seed0 + w + 1000003 * batch))
    printf '%s\t1\t%s\t%s\t%s\t%s\t%s\n' "$w" "$batch" "$s" "$ended" "$e" "w$w.b$batch.log" >> "$O/batches.tsv"
    if [ "$e" -ne 0 ] && [ "$e" -ne 72 ]; then failed=1; fi
    if [ "$e" -eq 72 ] && [ "$ended" != paused ]; then failed=1; fi
    if [ -n "$runs" ] && [ "$failed" -eq 0 ]; then
      ex=$(grep -E '^stat::number_of_executed_units: *[0-9]+ *$' "$O/w$w.b$batch.log" | tail -1 | grep -oE '[0-9]+')   # as merge.py
      ini=$(grep -m1 -oE '^#[0-9]+[[:space:]]+INITED[[:space:]]+cov:' "$O/w$w.b$batch.log" | grep -oE '^#[0-9]+' | tr -d '#')
      if [[ "$ex" =~ ^[0-9]+$ ]] && [[ "$ini" =~ ^[0-9]+$ ]]; then remaining[$i]=$(( remaining[i] - (ex - ini) ))
      elif [ "$e" -eq 72 ] && [ "$ended" = paused ] && [[ "$ex" =~ ^[0-9]+$ ]]; then :  # paused in its replay: no work done
      else failed=1; fi
    fi
  done < "$O/pids.batch"
  : > "$O/pids"
  [ -n "$secs" ] && left_secs=$(( left_secs - ($(date +%s) - t0) ))
  batch=$((batch + 1))
done
if [ "${FV_GUARDS:-0}" = 1 ]; then touch "$O/guard.stop"; wait "$gpid"; fi
st=0
sha256sum --quiet -c MANIFEST.sha256 > "$O/post-check" 2>&1 || st=3
exit $st
