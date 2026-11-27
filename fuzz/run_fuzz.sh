#!/usr/bin/env bash
# run_fuzz.sh — differential fuzz campaign (COUPLE stage, Module 5).
#
#   fuzz/run_fuzz.sh --lean-project DIR --lock LOCKFILE --cmake-dir DIR --target NAME [--lang cpp|rust|python|evm]
#                    [--impl-dir DIR] [--runs N | --time SECONDS] [--corpus DIR]
#                    [--no-merge] [--out RUNDIR] [--draft] [--cmake-arg -DNAME=VALUE ...]
#
# --cmake-arg -DNAME=VALUE (repeatable), and FV_CMAKE_ARGS (config/hosts.env, whitespace-separated)
#    for site defaults: extra CMake definitions for the project's fuzz directory, e.g. where a host
#    keeps the project's prebuilt dependencies. Each must be ONE -D definition with no whitespace;
#    names the harness owns (CMAKE_*, FV_*, LEAN_*, IMPL_DIR) are refused, so these can never change
#    the compiler, flags, sanitizers or the oracle. Anything else is ERROR before a build. Every arg is
#    recorded in fuzz.json "cmake_args" with its source (site or command line) and, for each absolute
#    path in its value (";"-separated), the sha256 of the file or of the directory's file manifest.
#
# --draft: validate a DRAFT specification before its owner signs it. --lock is then an UNSIGNED
#    manifest (scripts/spec_lock.sh lock output) and step 1 is a content check only
#    (spec_lock.sh check-content); the oracle is still built only from the files it lists. Nothing a
#    draft run produces is countable: "DRAFT (unsigned, not countable)" is the first line of fuzz.log
#    and the first key of fuzz.json, the verdict reads "DRAFT PASS" / "DRAFT FAIL" / ... (never
#    "PASS"), the persisted corpus is never merged into (implies --no-merge), and the gate's COUPLE
#    and CLOSE (scripts/formal_task.py, which never passes --draft) refuse a draft fuzz.json.
#
# 1. The spec project must match its lock (else BLOCKED). The oracle is built from a copy that
#    holds only the locked files, so it comes from spec/challenge and never from spec/solution.
#    Harness files vendored into the fuzz directory (LeanOracle.cmake, diff_oracle_template.cpp)
#    must equal, below their "Vendored from fv-harness <commit>" header, the harness's copy at
#    that commit (fuzz/VENDORED.sha256), else FAIL before anything is built.
# 2. Configure and build the fuzzer (clang, libFuzzer + ASan + UBSan) against that copy.
#    --lang rust: CMAKE_DIR's CMakeLists.txt builds only <target>_oracle, the oracle as a shared
#    library (lean_oracle_shared); then `cargo fuzz build -a` (ASan, debug assertions and overflow
#    checks ON) builds the cargo-fuzz target <target> in CMAKE_DIR with FV_ORACLE_LIB_DIR pointing at
#    it, FV_IMPL_DIR at --impl-dir and FV_DIFF_RS at the harness's driver (fuzz/rust/fv_diff.rs),
#    which the target must use (fv_diff_main!, no fuzz_target! of its own). RUSTFLAGS forces
#    overflow checks and debug assertions on; a project setting either off (Cargo.toml, any
#    .cargo/config cargo would read) is ERROR. Toolchain: $FV_RUST_HOME (default $FV_ROOT/rust). A second
#    build with `--cfg fv_classify` is the labels-only classify binary (the binding's classes()).
#    --lang evm: a Rust target as above whose implementation is a contract. --impl-dir (default
#    CMAKE_DIR/../contract) holds the Solidity sources; [evm] in CMAKE_DIR/fv.toml names the contract,
#    evmVersion and optimizer settings. solc must be the pinned build ($FV_SOLC, default
#    $FV_ROOT/evm/solc-$FV_SOLC_VERSION, sha256 $FV_SOLC_SHA256), else ERROR. fuzz/evm/compile.py
#    compiles it; the bytecode is embedded through FV_EVM_CREATION/FV_EVM_RUNTIME and run by the
#    harness's EVM (fuzz/evm/fv_evm.rs, FV_EVM_RS). fuzz.json "evm" records the compiler sha256 and
#    version, the settings, and the sha256 of the sources and both bytecodes. If fv.toml sets
#    expect_runtime_sha256 (a deployed contract) and the runtime bytecode differs: BLOCKED. Cargo runs
#    offline and Cargo.lock must not change during the build.
#    --lang python: the same oracle library; the harness's driver fuzz/python/fv_diff.py (Atheris,
#    $FV_PY, default $FV_ROOT/py/venv/bin/python) loads CMAKE_DIR/binding.py and the implementation
#    from --impl-dir; implementation values outside [0, 2^64) FAIL as "domain: ...".
#    --lang tron-tvm: a Python binding (as --lang python, IMPL_MODULE = None) whose implementation is a
#    contract run on java-tron's own TRON-TVM (fuzz/tron-tvm/FvTronTvmDriver.java, client fuzz/tron-tvm/fv_tron_tvm.py),
#    offline in a network namespace (bwrap --unshare-net). java-tron must be the pinned commit with an
#    unmodified tree under $FV_TRON_TVM_HOME (default $FV_ROOT/tron-tvm), the TRON solc the pinned build; [tron-tvm]
#    in fv.toml names the contract (as [evm]). The TRON-TVM's cpu-time limit is off (--debug, as java-tron's
#    own VM tests run). Executor failures are ERROR (exit 87 of the client: driver will not start,
#    refuses the profile, runs without --debug, dies, errs) and never kept as reproducers; deployed
#    code other than the compiler's is BLOCKED (exit 88). A PASS needs the TRON-TVM observed to have run
#    (docs/TRON-TVM-REFERENCE.md). JAVA_TOOL_OPTIONS / _JAVA_OPTIONS / JDK_JAVA_OPTIONS are refused.
#    fuzz.json "tron_tvm" records the compiler, java-tron commit, classpath and JDK manifests, driver and
#    client sha256, both bytecodes (and the metadata-stripped runtime), and, as observed in the fuzz
#    processes, the network, the driver's config and the cpu-time limit. OUT_OF_TIME is not covered.
# 3. Regression replay: every file in the persisted corpus must pass.
# 4. Campaign: -runs=N (default 1000000) or -max_total_time=SECONDS (CI: 60).
#    --jobs N (N >= 2): N independent workers (W = 0..N-1), each with its own -seed, log
#    (RUNDIR/workers/wW.log) and artifact prefix (artifacts/wW-), all reading and adding to the same
#    corpus directories, with FV_FUZZ_WORKER=W in their environment. --runs R means R executions in
#    TOTAL, counted AFTER each process's corpus replay (stat::number_of_executed_units minus the
#    INITED count): each worker runs ceil(R/N) plus its replay, and a PASS needs a post-replay total
#    >= R, else ERROR (not countable). --time T: each worker runs T seconds. Every worker process is
#    one line in RUNDIR/batches.tsv; fuzz/worker/merge.py decides: a process without a numeric exit
#    status, or exit 0 without final stats, is ERROR; any failing worker makes the run FAIL, naming a
#    mismatch first (then the lowest worker), even when another worker is in ERROR; a batch that exited
#    0 or 72 with a failure line in its log is failing too, and a PASS with any saved failing input
#    (an artifact other than a slow unit) is FAIL. --runs and --time must be positive whole numbers.
#    --remote local:K (--lang cpp): K more workers from a hash-pinned BUNDLE, numbered after the local
#    ones: bin/fuzzer (this build), lib/libleanshared.so, the corpus snapshot, fuzz/worker/fv_worker.sh
#    and fv_guard.sh, REQUIRES (the highest GLIBC/GLIBCXX symbol versions the fuzzer needs) and
#    MANIFEST.sha256. The gate refuses (BLOCKED), before any worker starts, a bundle tar with members
#    outside bundle/, and a bundle that is not exactly its manifest (a file not listed, a symbolic
#    link, an out/ directory, a changed file) or not this build's; the worker runner refuses the same
#    on its side, and a host older than REQUIRES, or (ssh) a cgroup that does not enforce the
#    CPUQuota / MemoryMax asked for. After the run the worker re-checks the bundle (a change: BLOCKED);
#    it must exit 0 with a post-check, or the run is ERROR. fuzz.json "remote" records the bundle
#    sha256, the worker's host, cores, glibc, libstdc++ version and sha256, cgroup and its cpu.max /
#    memory.max, every guard PAUSE / RESUME with its reading, and the names of any FV_GUARD_* overrides.
#    --bundle FILE uses a given bundle instead of building one (it must still be this build's);
#    --bundle-out FILE keeps the built one. "local" runs the worker on this host in a separate
#    directory. "ssh:NAME:K" runs it on a worker host: ssh arguments from FV_WORKER_SSH_<NAME>
#    (config/hosts.env), ONE ssh ControlMaster connection for the whole campaign, absolute paths and
#    every remote word quoted; the bundle in FV_WORKER_ROOT_<NAME> (default ~/fv-work)/<run> (0700; the
#    run name must be [A-Za-z0-9._-], checked before anything is built; a random suffix makes it unique
#    per run, and an existing unit of that name is refused); the workers inside
#    `systemd-run --user --scope --unit=<run> -p CPUQuota=... -p MemoryMax=... -p RuntimeMaxSec=...`
#    (FV_WORKER_QUOTA_PCT, default 100 x K; FV_WORKER_MEMMAX, default 32G, at least K x rss_limit_mb +
#    FV_WORKER_MEM_MARGIN_MB [2048] or ERROR; FV_WORKER_MAX_SEC, default 3 x T + 3600 or 48 h) at nice
#    19 and idle I/O priority, with the shared-host guards on (FV_WORKER_GUARDS, default 1). The gate
#    waits at most that cap plus 10 minutes. out/ is copied back over the same connection as a tar the
#    gate unpacks itself (fuzz/worker/unpack_out.py: regular files and directories under out/ only, no
#    links, special files, '..' or repeated names), each batch record must name its own log
#    w<worker>.b<batch>.log, once, and then it is checked exactly as for "local"; whatever happens, the
#    gate's exit stops the scope and removes the remote run directory if this run created them (a
#    clash with another run's never touches that run's), and closes the connection.
#    Guards (fuzz/worker/fv_guard.sh): a PAUSE ENDS the running batch (SIGINT to this campaign's own
#    fuzzers only, checked by executable and start time; libFuzzer exits 72 with its final stats, a
#    batch "paused"); after the RESUME the next batch runs the remaining executions on the shared
#    corpus. No process is ever stopped, so neither libFuzzer's per-input timeout nor
#    -max_total_time sees paused time; exit 72 counts only for a batch the guards ended.
# 5. On PASS, merge new coverage into the persisted corpus (unless --no-merge).
# 6. Edge-case classification, labels only (fuzz/fv_classify.hpp, classify_report.py): a separate
#    replay of the corpus through the oracle alone counts each class (generic boundary classes from
#    the binding's describe(), domain classes from classes.hpp next to the binding), lists the
#    classes never hit as NOT EXERCISED and writes RUNDIR/classify/review_deck.md. On FAIL, the
#    reproducers are classified instead. It never changes the verdict; FV_NO_CLASSIFY=1 skips it.
#
# Limits per project, from [fuzz] in CMAKE_DIR/fv.toml (defaults in brackets), applied to the replay,
# the campaign, the merge and the classification replay:
#   timeout = seconds per input [10]       -> FAIL "HANG: input exceeded N s" (infinite or runaway loops)
#   rss_limit_mb [2048], malloc_limit_mb [= rss_limit_mb] -> FAIL "OOM: ..." (unbounded growth, huge mallocs)
#   report_slow_units = seconds [2]        -> slow inputs are listed in fuzz.json (slow_units), not a failure
# Input length, campaign only (libFuzzer's own defaults when absent):
#   max_len = bytes (a positive whole number)  -> -max_len; the longest input the campaign generates
#   len_control = N (0 or a positive number)   -> -len_control; 0 starts at max_len at once instead of
#                                                 growing from short inputs (structured, multi-case targets)
# They are not applied to the replay, the merge or the classification: -max_len would truncate longer
# corpus inputs there. Both are recorded in fuzz.json .limits (null when absent).
# Leaks (LeakSanitizer, per input and at exit) FAIL as "LEAK: ...". A leak is memory no longer
# reachable; memory that stays reachable while it grows is not a leak, and only the RSS limit stops it.
#
# Exit: 0 PASS, 1 FAIL (mismatch, sanitizer, leak, hang or OOM), 2 BLOCKED, 3 ERROR. Summary: RUNDIR/fuzz.json.
set -uo pipefail
# The verdict binary contains no classify code (see diff_oracle_template.cpp); these variables only
# matter to the separate classify build, and are cleared so nothing inherited can reach either.
unset FV_CLASSIFY FV_CLASSIFY_RENDER FV_CLASSIFY_TIME_IMPL
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/../scripts/lib.sh"

proj=""; lock=""; cmake_dir=""; target=""; impl=""; runs=""; secs=""; corpus=""; merge=1; out=""; lang=cpp; draft=0; jobs=1
remote=""; bundle_in=""; bundle_out=""
cli_cmake_args=()
while [ $# -gt 0 ]; do
  case "$1" in
    --lean-project) proj="$2"; shift 2 ;;
    --lock) lock="$2"; shift 2 ;;
    --cmake-dir) cmake_dir="$2"; shift 2 ;;
    --target) target="$2"; shift 2 ;;
    --impl-dir) impl="$2"; shift 2 ;;
    --lang) lang="$2"; shift 2 ;;
    --runs) runs="$2"; shift 2 ;;
    --time) secs="$2"; shift 2 ;;
    --corpus) corpus="$2"; shift 2 ;;
    --no-merge) merge=0; shift ;;
    --draft) draft=1; shift ;;
    --jobs) jobs="$2"; shift 2 ;;
    --remote) remote="$2"; shift 2 ;;
    --bundle) bundle_in="$2"; shift 2 ;;
    --bundle-out) bundle_out="$2"; shift 2 ;;
    --cmake-arg) cli_cmake_args+=("$2"); shift 2 ;;
    --out) out="$2"; shift 2 ;;
    *) die "unknown argument $1" ;;
  esac
done
[ -d "$proj" ] && [ -f "$lock" ] && [ -d "$cmake_dir" ] && [ -n "$target" ] || die "missing required arguments (see header)"
proj="$(cd "$proj" && pwd)"; cmake_dir="$(cd "$cmake_dir" && pwd)"
lock="$(cd "$(dirname "$lock")" && pwd)/$(basename "$lock")"
[ -n "$runs" ] || [ -n "$secs" ] || runs=1000000
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || die "--jobs must be a positive whole number"
[ -z "$runs" ] || { [[ "$runs" =~ ^[1-9][0-9]{0,9}$ ]] && [ "$runs" -le 2147483647 ]; } || die "--runs must be a positive whole number below 2^31 (got '$runs')"
[ -z "$secs" ] || { [[ "$secs" =~ ^[1-9][0-9]{0,9}$ ]] && [ "$secs" -le 2147483647 ]; } || die "--time must be a positive whole number of seconds below 2^31 (got '$secs')"
rk=0; rname=""
if [ -n "$remote" ]; then
  if [[ "$remote" =~ ^local:([1-9][0-9]*)$ ]]; then rk=${BASH_REMATCH[1]}
  elif [[ "$remote" =~ ^ssh:([A-Za-z0-9_]+):([1-9][0-9]*)$ ]]; then rname=${BASH_REMATCH[1]}; rk=${BASH_REMATCH[2]}
  else die "--remote must be local:K or ssh:NAME:K"; fi
fi
corpus="${corpus:-$cmake_dir/corpus}"; mkdir -p "$corpus"
cfg() { # cfg KEY DEFAULT -> [fuzz] KEY from CMAKE_DIR/fv.toml, or DEFAULT
  python3 -I -c 'import sys, tomllib
try: print(tomllib.load(open(sys.argv[1], "rb")).get("fuzz", {}).get(sys.argv[2], sys.argv[3]))
except OSError: print(sys.argv[3])' "$cmake_dir/fv.toml" "$1" "$2"
}
T_OUT=$(cfg timeout 10); RSS_MB=$(cfg rss_limit_mb 2048); MAL_MB=$(cfg malloc_limit_mb "$RSS_MB"); SLOW_S=$(cfg report_slow_units 2)
BAD_LIMIT=""  # 0 means "no limit" to libFuzzer, so it would silently switch HANG/OOM off: refused
for kv in "timeout=$T_OUT" "rss_limit_mb=$RSS_MB" "malloc_limit_mb=$MAL_MB" "report_slow_units=$SLOW_S"; do
  [[ "${kv#*=}" =~ ^[1-9][0-9]*$ ]] || BAD_LIMIT+="${kv} "
done
MAX_LEN=$(cfg max_len ""); LEN_CTL=$(cfg len_control "")
[ -z "$MAX_LEN" ] || [[ "$MAX_LEN" =~ ^[1-9][0-9]*$ ]] || BAD_LIMIT+="max_len=$MAX_LEN "
[ -z "$LEN_CTL" ] || [[ "$LEN_CTL" =~ ^(0|[1-9][0-9]*)$ ]] || BAD_LIMIT+="len_control=$LEN_CTL "
[ -z "$BAD_LIMIT" ] || { T_OUT=0; RSS_MB=0; MAL_MB=0; SLOW_S=0; MAX_LEN=""; LEN_CTL=""; }
LENS=(); [ -n "$MAX_LEN" ] && LENS+=(-max_len="$MAX_LEN"); [ -n "$LEN_CTL" ] && LENS+=(-len_control="$LEN_CTL")
LIMITS=(-timeout="$T_OUT" -rss_limit_mb="$RSS_MB" -malloc_limit_mb="$MAL_MB" -report_slow_units="$SLOW_S")
# Class-guided retention (step 4b): an execution budget and a fixed seed (libFuzzer's -seed=0 would be random).
RETAIN_RUNS=$(cfg retain_runs 200000); RETAIN_SEED=$(cfg retain_seed 1); BAD_RETAIN=""
[[ "$RETAIN_RUNS" =~ ^(0|[1-9][0-9]{0,9})$ ]] && [ "$RETAIN_RUNS" -lt 2147483648 ] || BAD_RETAIN+="retain_runs=$RETAIN_RUNS "
[[ "$RETAIN_SEED" =~ ^[1-9][0-9]{0,9}$ ]] && [ "$RETAIN_SEED" -lt 4294967296 ] || BAD_RETAIN+="retain_seed=$RETAIN_SEED "
[ -z "$BAD_RETAIN" ] || { RETAIN_RUNS=0; RETAIN_SEED=1; }
RETAIN_JSON=null
# Test hooks (FV_TEST_HOOK_*): for controls only. Each one set is recorded in fuzz.json (test_hooks), and CLOSE
# refuses such a run. Unset, no hook changes anything: every hook below is a no-op unless its variable is set.
#   FV_TEST_HOOK_RETAIN_NO_ARTIFACT=1  the retention generation's artifact directory is not writable and the classify
#     build does not record its current input, so a stop leaves nothing behind
#   FV_TEST_HOOK_REPLAY_STATUS=retention|merge  (--lang tron-tvm) after that replay, append one forged "ready"
#     observation (a driver that saw an interface other than lo), as a driver started in that replay would write
#     it; the driver checks that follow that replay must then refuse the run.
# Shell variables, not only the environment: one set in config/hosts.env without export acts all the same.
TEST_HOOKS_JSON=$(compgen -v | grep -E '^FV_TEST_HOOK_[A-Z0-9_]*$' | LC_ALL=C sort | jq -Rsc 'split("\n") | map(select(. != ""))')
test_hook_replay_status() { # test_hook_replay_status PHASE
  [ "$lang" = tron-tvm ] && [ -n "${FV_TEST_HOOK_REPLAY_STATUS:-}" ] && [ "$FV_TEST_HOOK_REPLAY_STATUS" = "$1" ] || return 0
  jq -nc --arg c "$(jq -r -s '[.[] | select(.event == "ready") | .config][0] // ""' "$RUN/tron-tvm/status.jsonl" 2>/dev/null)" \
    '{event: "ready", pid: 0, driver: "ready (test hook)", config: $c, net_ifaces: ["lo", "test0"], test_hook: true}' >> "$RUN/tron-tvm/status.jsonl"
}
RUN="${out:-$FV_ROOT/runs/fuzz-$target-$(date +%Y%m%dT%H%M%S)-$$}"
mkdir -p "$RUN"; RUN="$(cd "$RUN" && pwd)"
# One gate per run directory, for the gate's whole lifetime: a second run on the same --out would delete
# this run's artifacts, truncate its batch list and overwrite its logs.
exec 9> "$RUN/.lock"
flock -n 9 || die "another run holds $RUN (its .lock): use another --out"
# A reused --out never shows an earlier run's record or logs.
rm -f "$RUN/fuzz.json" "$RUN/fuzz.json.tmp" "$RUN/campaign.log" "$RUN/merge.log" "$RUN/replay.log" "$RUN/merge.json"
# Interrupted, the gate takes its local fuzz processes and workers with it, each with its whole process
# tree (the remote side: remote_cleanup).
kill_tree() { local c; for c in $(pgrep -P "$1" 2>/dev/null); do kill_tree "$c"; done; kill "$1" 2>/dev/null; }
kill_local() { local p; for p in $(jobs -pr); do kill_tree "$p"; done; }
trap kill_local EXIT; trap 'exit 130' INT TERM HUP
LOG="$RUN/fuzz.log"; : > "$LOG"
if [ -n "$rname" ] && ! [[ "fv-$(basename "$RUN")" =~ ^[A-Za-z0-9._-]+$ ]]; then  # checked before anything is built
  jq -n --arg d "run name 'fv-$(basename "$RUN")' has characters other than A-Z a-z 0-9 . _ -" '{verdict: "ERROR", exit: 3, detail: $d}' > "$RUN/fuzz.json"
  echo "ERROR: run name 'fv-$(basename "$RUN")' has characters other than A-Z a-z 0-9 . _ -" >&2; exit 3
fi
DRAFT_STAMP="DRAFT (unsigned, not countable)"
if [ "$draft" -eq 1 ]; then
  merge=0
  echo "$DRAFT_STAMP: run_fuzz.sh --draft, lock $lock is an unsigned manifest" | tee -a "$LOG" >&2
fi
verdict() { # verdict EXIT VERDICT DETAIL
  if [ "$lang" = tron-tvm ] && [ -f "$RUN/tron-tvm/runtime.bin" ] && [ -n "${EVM_JSON:-}" ] && [ "$EVM_JSON" != null ]; then
    # Contract coverage over every fuzz process of the run (labels only, never the verdict).
    python3 -I "$HERE/tron-tvm/contract_coverage.py" --runtime "$RUN/tron-tvm/runtime.bin" --solc-output "$RUN/tron-tvm/solc-output.json" \
      --source "$(jq -r .source <<< "$EVM_JSON")" --contract "$(jq -r .contract <<< "$EVM_JSON")" --pcs "$RUN/tron-tvm/coverage.pcs" \
      --out "$RUN/tron-tvm" > "$RUN/tron-tvm/coverage.json" 2> "$RUN/tron-tvm/coverage.err" \
      || echo '{"labels_only": true, "error": "coverage report failed"}' > "$RUN/tron-tvm/coverage.json"
    EVM_JSON=$(jq -c --slurpfile c "$RUN/tron-tvm/coverage.json" '. + {contract_coverage: $c[0]}' <<< "$EVM_JSON")
  fi
  local v="$2"; [ "$draft" -eq 1 ] && v="DRAFT $2"
  # Large JSON parts go through files: an argument over the kernel's 128 KiB limit would fail jq.
  local J="$RUN/.verdict-parts"; mkdir -p "$J"
  printf '%s' "${EVM_JSON:-null}" > "$J/evm.json"; printf '%s' "${WORKERS_JSON:-null}" > "$J/workers.json"
  printf '%s' "${CLASSES_JSON:-null}" > "$J/classes.json"; printf '%s' "${REMOTE_JSON:-null}" > "$J/remote.json"
  jq -n --arg v "$v" --arg draft "$([ "$draft" -eq 1 ] && echo "$DRAFT_STAMP")" --argjson e "$1" --arg d "$3" --arg t "$target" --arg runs "${runs:-}" \
    --arg secs "${secs:-}" --arg corpus "$corpus" --arg impl "${impl:-default}" \
    --arg lock "$(sha256sum "$lock" | cut -d' ' -f1)" --arg el "${elapsed:-}" \
    --arg mm "$(cat "$RUN/campaign.log" "$RUN/merge.log" 2>/dev/null | grep -m1 'diff-oracle: MISMATCH')" \
    --arg art "$(ls "$RUN"/artifacts/ 2>/dev/null | head -1)" \
    --arg stats "$(grep -E '^(stat::number_of_executed_units|stat::average_exec_per_sec|stat::new_units_added)' "$RUN/campaign.log" 2>/dev/null | tr '\n' ' ')" \
    --argjson vend "${VENDORED_JSON:-{\}}" --slurpfile clsf "$J/classes.json" --argjson cmk "${CMAKE_ARGS_JSON:-[]}" --slurpfile evmf "$J/evm.json" --arg lang "$lang" \
    --argjson jobs "$jobs" --slurpfile workersf "$J/workers.json" --argjson total "${TOTAL_EXEC:-null}" \
    --slurpfile remotef "$J/remote.json" \
    --argjson lim "{\"timeout_s\":$T_OUT,\"rss_limit_mb\":$RSS_MB,\"malloc_limit_mb\":$MAL_MB,\"report_slow_units_s\":$SLOW_S,\"max_len\":${MAX_LEN:-null},\"len_control\":${LEN_CTL:-null}}" \
    --arg slow "$(ls "$RUN"/artifacts/ 2>/dev/null | grep 'slow-unit-' | tr '\n' ' ')" \
    --argjson hooks "${TEST_HOOKS_JSON:-[]}" \
    '$evmf[0] as $evm | $clsf[0] as $cls | $workersf[0] as $workers | $remotef[0] as $remote |
    (if $draft != "" then {draft:$draft} else {} end) + {lang:$lang, verdict:$v, exit:$e, detail:$d, target:$t, runs:$runs, max_total_time:$secs, impl_dir:$impl,
      corpus:$corpus, lock_digest:$lock, campaign_seconds:$el, mismatch:$mm, artifact:$art, stats:$stats,
      jobs:$jobs, workers:$workers, total_executions:$total, remote:$remote,
      vendored:$vend, classes:$cls, cmake_args:$cmk, evm:(if $lang == "tron-tvm" then null else $evm end),
      tron_tvm:(if $lang == "tron-tvm" then $evm else null end), limits:$lim, slow_units:($slow | split(" ") | map(select(. != ""))), test_hooks:$hooks}' \
    > "$RUN/fuzz.json.tmp" && jq -e '.verdict and .lang and (.limits | type) == "object"
        and (.lang != "tron-tvm" or (.verdict | test("PASS") | not)
             or (.tron_tvm.java_tron_commit and .tron_tvm.chain_profile.sha256 and .tron_tvm.driver_config
                 and .tron_tvm.classpath_manifest_sha256 and .tron_tvm.jdk_tree_sha256
                 and (.tron_tvm.processes.with_transactions // 0) >= 1))' "$RUN/fuzz.json.tmp" > /dev/null \
    && mv "$RUN/fuzz.json.tmp" "$RUN/fuzz.json" \
    || { echo "ERROR: fuzz.json could not be written completely; the intended verdict was $v (exit $1): $3" >&2
         rm -f "$RUN/fuzz.json.tmp"
         printf '{"verdict": "ERROR", "exit": 3, "detail": "fuzz.json could not be written completely"}\n' > "$RUN/fuzz.json"
         note "fuzz verdict ERROR (exit 3): fuzz.json not written (intended $v)"; exit 3; }
  rm -rf "$RUN"/tron-tvm/db.* 2> /dev/null  # the TRON-TVM node stores of this run's processes
  note "fuzz verdict $v (exit $1): $3"
  exit "$1"
}

[ -z "$BAD_LIMIT" ] || verdict 3 ERROR "fv.toml: limits must be positive whole numbers (0 disables a limit; len_control may be 0): ${BAD_LIMIT% }"
[ -z "$BAD_RETAIN" ] || verdict 3 ERROR "fv.toml: retain_runs must be a whole number below 2^31 (0 skips retention) and retain_seed one from 1 to 2^32-1 (0 would be random): ${BAD_RETAIN% }"

# 1. Lock and trusted oracle copy.
if [ "$draft" -eq 1 ]; then
  "$HERE/../scripts/spec_lock.sh" check-content "$proj" "$lock" >> "$LOG" 2>&1 \
    || verdict 2 BLOCKED "draft spec project differs from its unsigned manifest; oracle not built"
elif ! "$HERE/../scripts/spec_lock.sh" check "$proj" "$lock" >> "$LOG" 2>&1; then
  verdict 2 BLOCKED "spec project differs from its lock; oracle not built"
fi
# 1b. Vendored harness files in the fuzz directory.
VENDORED_JSON=$("$HERE/check_vendored.sh" "$cmake_dir" 2>> "$LOG"); vrc=$?
[ -n "$VENDORED_JSON" ] || VENDORED_JSON="{}"
if [ $vrc -ne 0 ]; then
  verdict 1 FAIL "vendored harness file differs from the harness copy at its cited commit: $(jq -r 'to_entries[] | select(.value.match | not) | "\(.key) (commit \(.value.cited_commit | if . == "" then "none" else . end))"' <<< "$VENDORED_JSON" | tr '\n' ' ')"
fi

mkdir -p "$RUN/oracle_project"
(cd "$proj" && cut -d' ' -f3- "$lock" | tr '\n' '\0' | xargs -0 cp --parents -t "$RUN/oracle_project")

# 2. Build.
cfg=(-S "$cmake_dir" -B "$RUN/build" -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_COMPILER=clang
     -DCMAKE_BUILD_TYPE=RelWithDebInfo
     -DFV_HARNESS_DIR="$FV_HARNESS_DIR" -DLEAN_PROJECT="$RUN/oracle_project" -DLEAN_BIN_DIR="$LEAN_TC/bin")
# Extra project definitions (site defaults, then the command line); see the header.
read -r -a site_cmake_args <<< "${FV_CMAKE_ARGS:-}"
CMAKE_ARGS_JSON="[]"; bad_args=""
for src in site cli; do
  if [ "$src" = site ]; then list=("${site_cmake_args[@]}"); else list=("${cli_cmake_args[@]}"); fi
  for a in "${list[@]}"; do
    if ! [[ "$a" =~ ^-D([A-Za-z_][A-Za-z0-9_]*)(:[A-Z]+)?=([^[:space:]]*)$ ]]; then bad_args+="'$a' (not one -DNAME=VALUE) "; continue; fi
    name=${BASH_REMATCH[1]}; val=${BASH_REMATCH[3]}
    if [[ "$name" =~ ^(CMAKE_|FV_|LEAN_) ]] || [ "$name" = IMPL_DIR ]; then bad_args+="'$a' (harness-owned name $name) "; continue; fi
    paths="[]"
    IFS=';' read -r -a parts <<< "$val"
    for v in "${parts[@]}"; do
      if [[ "$v" == /* ]]; then
        if [ -f "$v" ]; then h=$(sha256sum < "$v" | cut -d' ' -f1); k=file
        elif [ -d "$v" ]; then h=$( (cd "$v" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum) | sha256sum | cut -d' ' -f1); k=dir_manifest
        else h=""; k=missing; fi
        paths=$(jq -c --arg p "$v" --arg k "$k" --arg h "$h" '. + [{path: $p, kind: $k, sha256: $h}]' <<< "$paths")
      fi
    done
    CMAKE_ARGS_JSON=$(jq -c --arg a "$a" --arg s "$src" --argjson p "$paths" '. + [{arg: $a, source: $s, paths: $p}]' <<< "$CMAKE_ARGS_JSON")
    cfg+=("$a")
  done
done
[ -z "$bad_args" ] || verdict 3 ERROR "cmake args refused: ${bad_args% }"
# The build sysroot (fuzz/sysroot/): with FV_BUILD_SYSROOT set on the gate host, the C/C++ build links
# against that pinned Ubuntu 24.04 tree (glibc 2.39) and libstdc++/libgcc statically, so what the gate
# ships runs on older worker hosts. The tree must hash to FV_BUILD_SYSROOT_SHA256 (config/pins.env).
SYSROOT_SHA=""
if [ -n "${FV_BUILD_SYSROOT:-}" ]; then
  [ -d "$FV_BUILD_SYSROOT" ] || verdict 3 ERROR "FV_BUILD_SYSROOT $FV_BUILD_SYSROOT is not a directory"
  SYSROOT_SHA=$( (cd "$FV_BUILD_SYSROOT" && { find . -type f ! -name SYSROOT.sha256 -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
                                                find . -type l -printf 'link %p -> %l\n' | LC_ALL=C sort; }) | sha256sum | cut -d' ' -f1)
  [ "$SYSROOT_SHA" = "${FV_BUILD_SYSROOT_SHA256:-}" ] \
    || verdict 3 ERROR "the build sysroot $FV_BUILD_SYSROOT (sha256 $SYSROOT_SHA) is not the pinned one (${FV_BUILD_SYSROOT_SHA256:-unset})"
  cfg+=(-DCMAKE_SYSROOT="$FV_BUILD_SYSROOT" -DCMAKE_EXE_LINKER_FLAGS="-static-libstdc++ -static-libgcc"
        -DCMAKE_SHARED_LINKER_FLAGS="-static-libstdc++ -static-libgcc")
fi
BIN_CLS=""; CLS_FILE=()
case "$lang" in
  cpp)
    [ -n "$impl" ] && cfg+=(-DIMPL_DIR="$(cd "$impl" && pwd)")
    if ! { capped_off cmake "${cfg[@]}" && capped_off cmake --build "$RUN/build" --target "$target" -j "$FV_JOBS"; } >> "$LOG" 2>&1; then
      verdict 3 ERROR "fuzzer build failed (see $LOG)"
    fi
    BIN="$RUN/build/$target"
    # The labels-only classify build is optional: without it (e.g. an older vendored
    # LeanOracle.cmake) the run is simply not classified. It never affects the verdict.
    if capped_off cmake --build "$RUN/build" --target "${target}_classify" -j "$FV_JOBS" >> "$RUN/build-classify.log" 2>&1 \
       && [ -x "$RUN/build/${target}_classify" ]; then
      BIN_CLS="$RUN/build/${target}_classify"
    fi
    ;;
  rust|evm)
    rh="${FV_RUST_HOME:-$FV_ROOT/rust}"
    [ -x "$rh/cargo/bin/cargo-fuzz" ] || verdict 3 ERROR "cargo-fuzz not installed under $rh (docs/LANGUAGES.md)"
    if [ "$lang" = evm ]; then
      impl_dir="$(cd "${impl:-$cmake_dir/../contract}" && pwd)"
    else
      impl_dir="$(cd "${impl:-$cmake_dir/../impl}" && pwd)"
    fi
    # The comparison loop is the harness's (fuzz/rust/fv_diff.rs): the target must use it.
    tsrc="$cmake_dir/fuzz_targets/$target.rs"
    [ -f "$tsrc" ] || verdict 3 ERROR "no fuzz target source $tsrc"
    if grep -q 'fuzz_target!' "$tsrc" || ! grep -q 'fv_diff_main!' "$tsrc"; then
      verdict 3 ERROR "the Rust fuzz target must end with fv_diff_main!(...) and define no fuzz_target! of its own (fuzz/rust/fv_diff.rs)"
    fi
    # Overflow checks and debug assertions cannot be switched off by the project.
    off=$( { grep -HnE '^[[:space:]]*(overflow-checks|debug-assertions)[[:space:]]*=[[:space:]]*false' "$cmake_dir/Cargo.toml" 2>/dev/null
             d="$cmake_dir"; while :; do
               for c in "$d/.cargo/config" "$d/.cargo/config.toml"; do
                 [ -f "$c" ] && grep -HnE '(overflow-checks|debug-assertions)[[:space:]]*=[[:space:]]*false|overflow-checks=off|debug-assertions=off' "$c"
               done
               [ "$d" = / ] && break; d=$(dirname "$d")
             done
             for c in "$rh/cargo/config" "$rh/cargo/config.toml"; do
               [ -f "$c" ] && grep -HnE '(overflow-checks|debug-assertions)[[:space:]]*=[[:space:]]*false|overflow-checks=off|debug-assertions=off' "$c"
             done; } | head -3)
    [ -z "$off" ] || verdict 3 ERROR "overflow checks or debug assertions switched off for the Rust build: $(echo "$off" | tr '\n' ' ')"
    while IFS= read -r v; do unset "$v"; done < <(env | sed -n 's/^\(CARGO_PROFILE_[A-Z0-9_]*\)=.*/\1/p')
    unset CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS
    xenv=()
    if [ "$lang" = evm ]; then
      solc="${FV_SOLC:-$FV_ROOT/evm/solc-$FV_SOLC_VERSION}"
      [ -x "$solc" ] || verdict 3 ERROR "solc not installed at $solc (docs/LANGUAGES.md)"
      ssha=$(sha256sum < "$solc" | cut -d' ' -f1)
      [ "$ssha" = "$FV_SOLC_SHA256" ] || verdict 3 ERROR "solc at $solc is not the pinned build: sha256 $ssha, pinned $FV_SOLC_SHA256"
      if ! EVM_JSON=$(capped_off python3 -I "$HERE/evm/compile.py" --solc "$solc" --src-dir "$impl_dir" \
                      --fv-toml "$cmake_dir/fv.toml" --out "$RUN/evm" 2> "$RUN/evm-compile.err"); then
        EVM_JSON=null; verdict 3 ERROR "contract compilation failed: $(tail -1 "$RUN/evm-compile.err" | cut -c1-300)"
      fi
      EVM_JSON=$(jq -c --arg s "$ssha" '. + {solc_sha256: $s}' <<< "$EVM_JSON")
      exp=$(jq -r .expect_runtime_sha256 <<< "$EVM_JSON"); got=$(jq -r .runtime_sha256 <<< "$EVM_JSON")
      [ -z "$exp" ] || [ "$exp" = "$got" ] \
        || verdict 2 BLOCKED "runtime bytecode sha256 $got differs from expect_runtime_sha256 $exp (fv.toml); not coupled"
      xenv=(FV_EVM_RS="$HERE/evm/fv_evm.rs" FV_EVM_CREATION="$RUN/evm/creation.bin" FV_EVM_RUNTIME="$RUN/evm/runtime.bin"
            FV_EVM_SPEC="$(jq -r .settings.evm_version <<< "$EVM_JSON")" CARGO_NET_OFFLINE=true)
    fi
    cargo_build() { # cargo_build TARGET_DIR EXTRA_RUSTFLAGS
      (cd "$cmake_dir" && capped_off env RUSTUP_HOME="$rh/rustup" CARGO_HOME="$rh/cargo" PATH="$rh/cargo/bin:$PATH" CARGO_NET_OFFLINE=true \
         FV_ORACLE_LIB_DIR="$RUN/build" FV_ORACLE_LIB="${target}_oracle" FV_IMPL_DIR="$impl_dir" \
         FV_DIFF_RS="$HERE/rust/fv_diff.rs" "${xenv[@]}" RUSTFLAGS="-C overflow-checks=on -C debug-assertions=on$2" \
         cargo fuzz build -a --fuzz-dir "$cmake_dir" --target-dir "$1" "$target")
    }
    TSRC_SHA=$(sha256sum < "$tsrc" | cut -d' ' -f1)  # the fv_class! sources as built (classify_report.py checks them)
    CLS_FILE=("--classes-file" "$tsrc" "--classes-file-sha256" "$TSRC_SHA")
    lock0=$(sha256sum < "$cmake_dir/Cargo.lock" 2>/dev/null)
    if ! { capped_off cmake "${cfg[@]}" && capped_off cmake --build "$RUN/build" --target "${target}_oracle" -j "$FV_JOBS" \
           && cargo_build "$RUN/cargo-target" ""; } >> "$LOG" 2>&1; then
      verdict 3 ERROR "fuzzer build failed (see $LOG)"
    fi
    if [ "$lang" = evm ] && { [ ! -f "$cmake_dir/Cargo.lock" ] || [ "$(sha256sum < "$cmake_dir/Cargo.lock")" != "$lock0" ]; }; then
      verdict 3 ERROR "Cargo.lock is missing or changed during the build: dependencies must be pinned in the committed Cargo.lock"
    fi
    BIN="$RUN/cargo-target/x86_64-unknown-linux-gnu/release/$target"
    [ -x "$BIN" ] || verdict 3 ERROR "cargo fuzz produced no binary at $BIN"
    # The labels-only classify binary: a separate build with --cfg fv_classify (never compares).
    if [ "${FV_NO_CLASSIFY:-0}" != 1 ] && cargo_build "$RUN/cargo-target-classify" " --cfg fv_classify" >> "$RUN/build-classify.log" 2>&1 \
       && [ -x "$RUN/cargo-target-classify/x86_64-unknown-linux-gnu/release/$target" ]; then
      BIN_CLS="$RUN/cargo-target-classify/x86_64-unknown-linux-gnu/release/$target"
    fi
    impl="$impl_dir"
    ;;
  python)
    py="${FV_PY:-$FV_ROOT/py/venv/bin/python}"
    { [ -x "$py" ] && "$py" -I -c 'import atheris' 2>/dev/null; } || verdict 3 ERROR "atheris not available to $py (docs/LANGUAGES.md)"
    impl_dir="$(cd "${impl:-$cmake_dir/../impl}" && pwd)"
    bnd="$cmake_dir/binding.py"
    [ -f "$bnd" ] || verdict 3 ERROR "no Python binding $bnd"
    # The loop is the harness's (fuzz/python/fv_diff.py): the binding must not drive the fuzzer.
    if grep -qE '^[^#]*(def[[:space:]]+TestOneInput|atheris\.(Setup|Fuzz))' "$bnd"; then
      verdict 3 ERROR "the Python binding must not define TestOneInput or call atheris.Setup/Fuzz (fuzz/python/fv_diff.py drives the fuzzer)"
    fi
    if ! { capped_off cmake "${cfg[@]}" && capped_off cmake --build "$RUN/build" --target "${target}_oracle" -j "$FV_JOBS"; } >> "$LOG" 2>&1; then
      verdict 3 ERROR "oracle build failed (see $LOG)"
    fi
    so="$RUN/build/lib${target}_oracle.so"; [ -f "$so" ] || verdict 3 ERROR "no oracle library $so"
    BIN="$RUN/fuzz-$target"
    # FV_SELF: libFuzzer re-executes argv[0] for the corpus merge; fv_diff.py makes that this wrapper.
    printf '#!/bin/sh\nexec env FV_SELF=%q FV_BINDING=%q FV_IMPL_DIR=%q FV_ORACLE_SO=%q %q -I %q "$@"\n' \
      "$BIN" "$bnd" "$impl_dir" "$so" "$py" "$HERE/python/fv_diff.py" > "$BIN"
    chmod +x "$BIN"
    # The labels-only replay (fuzz/python/fv_classify.py): its own wrapper, never the implementation.
    if [ "${FV_NO_CLASSIFY:-0}" != 1 ]; then
      BIN_CLS="$RUN/classify-$target"
      # Fixed string hashing (PYTHONHASHSEED=0), so the retention pass is reproducible; every other PYTHON*
      # variable of the caller is removed (-s -P instead of -I, which would also ignore PYTHONHASHSEED).
      printf '#!/bin/sh\nfor v in $(env | sed -n "s/^\\(PYTHON[A-Za-z0-9_]*\\)=.*/\\1/p"); do unset "$v"; done\nPYTHONHASHSEED=0 exec env FV_BINDING=%q FV_ORACLE_SO=%q FV_CLASSES_PY=%q %q -s -P %q "$@"\n' \
        "$bnd" "$so" "$cmake_dir/classes.py" "$py" "$HERE/python/fv_classify.py" > "$BIN_CLS"
      chmod +x "$BIN_CLS"
      CLS_FILE=(--classes-file "$cmake_dir/classes.py")
    fi
    impl="$impl_dir"
    ;;
  tron-tvm)
    py="${FV_PY:-$FV_ROOT/py/venv/bin/python}"
    { [ -x "$py" ] && "$py" -I -c 'import atheris' 2>/dev/null; } || verdict 3 ERROR "atheris not available to $py (docs/LANGUAGES.md)"
    th="${FV_TRON_TVM_HOME:-$FV_ROOT/tron-tvm}"; jdk="$th/$FV_TRON_TVM_JDK"; jt="$th/java-tron"
    [ -x "$jdk/bin/java" ] && [ -f "$th/framework-test-classpath.txt" ] || verdict 3 ERROR "TRON-TVM reference executor not installed under $th (docs/LANGUAGES.md)"
    command -v bwrap > /dev/null && bwrap --dev-bind / / --unshare-net -- true 2> /dev/null \
      || verdict 3 ERROR "cannot create a network namespace (bwrap --unshare-net): the TRON-TVM must run offline"
    old=$(compgen -v | grep '^FV_TVM_' | tr '\n' ' ')   # the pack's names before the TRON-TVM rename: never silently ignored
    [ -z "$old" ] || verdict 3 ERROR "old variable name(s) set: ${old% } (renamed to FV_TRON_TVM_*; set the new names in config/pins.env or hosts.env)"
    for v in FV_TRON_TVM_CLASSPATH_SHA256 FV_TRON_TVM_JDK_TREE_SHA256 FV_TRON_TVM_NODE_CONFIG_SHA256; do
      [[ "${!v:-}" =~ ^[0-9a-f]{64}$ ]] || verdict 3 ERROR "$v is not set to a sha256 (config/pins.env): the executed TRON-TVM build must be pinned"
    done
    for v in JAVA_TOOL_OPTIONS _JAVA_OPTIONS JDK_JAVA_OPTIONS LD_PRELOAD LD_LIBRARY_PATH; do
      [ -z "${!v+x}" ] || verdict 3 ERROR "$v is set in the environment ('${!v}'): it would change the reference executor; unset it"
    done
    jtc=$(git -C "$jt" rev-parse HEAD 2>/dev/null)
    [ "$jtc" = "$FV_JAVA_TRON_COMMIT" ] || verdict 3 ERROR "java-tron at $jt is ${jtc:-not a git tree}, pinned $FV_JAVA_TRON_COMMIT"
    [ -z "$(git -C "$jt" status --porcelain --untracked-files=no 2>/dev/null)" ] || verdict 3 ERROR "java-tron tree at $jt has local changes"
    solc="${FV_TRON_SOLC:-$th/tron-solc-$FV_TRON_SOLC_VERSION}"
    [ -x "$solc" ] || verdict 3 ERROR "TRON solc not installed at $solc (docs/LANGUAGES.md)"
    ssha=$(sha256sum < "$solc" | cut -d' ' -f1)
    [ "$ssha" = "$FV_TRON_SOLC_SHA256" ] || verdict 3 ERROR "TRON solc at $solc is not the pinned build: sha256 $ssha, pinned $FV_TRON_SOLC_SHA256"
    impl_dir="$(cd "${impl:-$cmake_dir/../contract}" && pwd)"
    bnd="$cmake_dir/binding.py"
    [ -f "$bnd" ] || verdict 3 ERROR "no Python binding $bnd"
    if grep -qE '^[^#]*(def[[:space:]]+TestOneInput|atheris\.(Setup|Fuzz))' "$bnd"; then
      verdict 3 ERROR "the Python binding must not define TestOneInput or call atheris.Setup/Fuzz (fuzz/python/fv_diff.py drives the fuzzer)"
    fi
    mkdir -p "$RUN/tron-tvm"
    if ! EVM_JSON=$(capped_off python3 -I "$HERE/evm/compile.py" --section tron-tvm --solc "$solc" --src-dir "$impl_dir" \
                    --fv-toml "$cmake_dir/fv.toml" --out "$RUN/tron-tvm" 2> "$RUN/tron-tvm-compile.err"); then
      EVM_JSON=null; verdict 3 ERROR "contract compilation failed: $(tail -1 "$RUN/tron-tvm-compile.err" | cut -c1-300)"
    fi
    exp=$(jq -r .expect_runtime_sha256 <<< "$EVM_JSON"); got=$(jq -r .runtime_sha256 <<< "$EVM_JSON")
    [ -z "$exp" ] || [ "$exp" = "$got" ] \
      || verdict 2 BLOCKED "runtime bytecode sha256 $got differs from expect_runtime_sha256 $exp (fv.toml); not coupled"
    od -An -v -tx1 "$RUN/tron-tvm/creation.bin" | tr -d ' \n' > "$RUN/tron-tvm/creation.hex"
    od -An -v -tx1 "$RUN/tron-tvm/runtime.bin" | tr -d ' \n' > "$RUN/tron-tvm/runtime.hex"
    cp=$(cat "$th/framework-test-classpath.txt")
    # The executor as built, pinned: every classpath entry must lie under the TRON-TVM home (no stale
    # path elsewhere can run); jars by sha256, directories (java-tron's build/classes and resources with
    # config-test.conf) by the sha256 of their file manifest, paths taken relative to the home, so the
    # manifest's sha256 is the same on any host. The JDK by the sha256 of its whole tree. Both must equal
    # FV_TRON_TVM_CLASSPATH_SHA256 / FV_TRON_TVM_JDK_TREE_SHA256 (config/pins.env), else ERROR.
    # A tree's sha256: every regular file's sha256, and every symbolic link's target (a link cannot
    # point somewhere unhashed without changing the value).
    tree_sha() { (cd "$1" && { find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum
                                find . -type l -printf 'link %p -> %l\n' | LC_ALL=C sort; }) | sha256sum | cut -d' ' -f1; }
    thr=$(readlink -f "$th")
    tr ':' '\n' <<< "$cp" | while read -r e; do
      [ -n "$e" ] || continue
      r=$(readlink -f "$e" 2>/dev/null || echo "$e")
      case "$r" in "$thr"/*) ;; *) echo "outside  $e"; continue ;; esac
      if [ -f "$r" ]; then echo "$(sha256sum < "$r" | cut -d' ' -f1)  ${r#$thr/}"
      elif [ -d "$r" ]; then echo "$(tree_sha "$r")  ${r#$thr/}/"
      else echo "absent  $e"; fi
    done > "$RUN/tron-tvm/classpath.manifest"
    grep -q '^outside ' "$RUN/tron-tvm/classpath.manifest" && verdict 3 ERROR "TRON-TVM classpath entries outside $th: $(grep '^outside ' "$RUN/tron-tvm/classpath.manifest" | head -3 | tr '\n' ' ')"
    grep -q '^absent ' "$RUN/tron-tvm/classpath.manifest" && verdict 3 ERROR "TRON-TVM classpath entries missing: $(grep '^absent ' "$RUN/tron-tvm/classpath.manifest" | head -3 | tr '\n' ' ')"
    cpsha=$(sha256sum < "$RUN/tron-tvm/classpath.manifest" | cut -d' ' -f1)
    jdksha=$(tree_sha "$jdk")
    [ "$cpsha" = "$FV_TRON_TVM_CLASSPATH_SHA256" ] \
      || verdict 3 ERROR "the TRON-TVM executor's classpath (manifest sha256 $cpsha) is not the pinned build ($FV_TRON_TVM_CLASSPATH_SHA256)"
    [ "$jdksha" = "$FV_TRON_TVM_JDK_TREE_SHA256" ] \
      || verdict 3 ERROR "the JDK tree at $jdk (sha256 $jdksha) is not the pinned one ($FV_TRON_TVM_JDK_TREE_SHA256)"
    mkdir -p "$RUN/tron-tvm/drv"
    if ! capped_off "$jdk/bin/javac" -nowarn -cp "$cp" -d "$RUN/tron-tvm/drv" "$HERE/tron-tvm/FvTronTvmDriver.java" > "$RUN/tron-tvm/javac.log" 2>&1; then
      verdict 3 ERROR "TRON-TVM driver build failed (see $RUN/tron-tvm/javac.log)"
    fi
    prof=$(python3 -I -c 'import sys, tomllib
try: print(tomllib.load(open(sys.argv[1], "rb")).get("tron-tvm", {}).get("profile", ""))
except OSError: print("")' "$cmake_dir/fv.toml")
    pf="$HERE/tron-tvm/profiles/$prof.json"; pm="$HERE/tron-tvm/profiles/$prof.meta.json"
    [[ "$prof" =~ ^[a-z0-9][a-z0-9._-]*$ ]] && [ -f "$pf" ] && [ -f "$pm" ] \
      || verdict 3 ERROR "[tron-tvm] profile must name a chain-parameter profile in fuzz/tron-tvm/profiles/ (got '$prof')"
    psha=$(sha256sum < "$pf" | cut -d' ' -f1)
    [ "$psha" = "$(jq -r .sha256 "$pm")" ] || verdict 3 ERROR "chain-parameter profile $prof.json is not the recorded one: sha256 $psha, recorded $(jq -r .sha256 "$pm")"
    # The JVM loads only the pinned JDK's own extension directory and no preloaded or extra libraries.
    printf '#!/bin/sh\ncd "$1" || exit 2\nexec env -u LD_PRELOAD -u LD_LIBRARY_PATH %q -Xmx4g -Djava.ext.dirs=%q -cp %q FvTronTvmDriver "$1" %q 2>> %q\n' "$jdk/bin/java" "$jdk/jre/lib/ext" "$RUN/tron-tvm/drv:$cp" \
      "$pf" "$RUN/tron-tvm/driver.log" > "$RUN/tron-tvm/driver.sh"
    chmod +x "$RUN/tron-tvm/driver.sh"
    EVM_JSON=$(jq -c --arg s "$ssha" --arg jt "$jtc" --arg jdk "$FV_TRON_TVM_JDK" --arg prof "$prof" --arg psha "$psha" --argjson pmeta "$(cat "$pm")" \
      --arg jv "$("$jdk/bin/java" -version 2>&1 | sed -n 2p)" --arg ds "$(sha256sum < "$HERE/tron-tvm/FvTronTvmDriver.java" | cut -d' ' -f1)" \
      --arg cs "$(sha256sum < "$HERE/tron-tvm/fv_tron_tvm.py" | cut -d' ' -f1)" \
      --arg cpsha "$cpsha" --arg jdksha "$jdksha" \
      '{executor: "java-tron TRON-TVM (reference)", java_tron_commit: $jt, jdk: $jdk, jdk_version: $jv, jdk_tree_sha256: $jdksha,
        classpath_manifest_sha256: $cpsha, driver_sha256: $ds, client_sha256: $cs, jvm_heap: "-Xmx4g",
        chain_profile: {name: $prof, network: $pmeta.network, source: $pmeta.source, fetched: $pmeta.fetched, sha256: $psha},
        solc_sha256: $s} + .' <<< "$EVM_JSON")
    : > "$RUN/tron-tvm/status.jsonl"; : > "$RUN/tron-tvm/coverage.pcs"   # this run's own observations only
    if ! { capped_off cmake "${cfg[@]}" && capped_off cmake --build "$RUN/build" --target "${target}_oracle" -j "$FV_JOBS"; } >> "$LOG" 2>&1; then
      verdict 3 ERROR "oracle build failed (see $LOG)"
    fi
    so="$RUN/build/lib${target}_oracle.so"; [ -f "$so" ] || verdict 3 ERROR "no oracle library $so"
    BIN="$RUN/fuzz-$target"
    # The merge's inner process (FV_SELF) runs inside this namespace already: no second bwrap, and a
    # fresh node store of its own (the outer process's node still holds its store).
    printf '#!/bin/sh\nFV_TRON_TVM_DB=$(mktemp -d %q) exec %q -I %q "$@"\n' "$RUN/tron-tvm/db.XXXXXX" "$py" "$HERE/python/fv_diff.py" > "$BIN.inner"
    chmod +x "$BIN.inner"
    printf '#!/bin/sh\ndb=$(mktemp -d %q)\nexec bwrap --dev-bind / / --unshare-net -- env FV_SELF=%q FV_BINDING=%q FV_IMPL_DIR=%q FV_ORACLE_SO=%q FV_HARNESS_PY=%q FV_TRON_TVM_CMD=%q FV_TRON_TVM_CREATION=%q FV_TRON_TVM_RUNTIME=%q FV_TRON_TVM_DB="$db" FV_TRON_TVM_COVERAGE=%q FV_TRON_TVM_STATUS=%q %q -I %q "$@"\n' \
      "$RUN/tron-tvm/db.XXXXXX" "$BIN.inner" "$bnd" "$impl_dir" "$so" "$HERE/tron-tvm" "$RUN/tron-tvm/driver.sh" "$RUN/tron-tvm/creation.hex" "$RUN/tron-tvm/runtime.hex" "$RUN/tron-tvm/coverage.pcs" "$RUN/tron-tvm/status.jsonl" \
      "$py" "$HERE/python/fv_diff.py" > "$BIN"
    chmod +x "$BIN"
    # The labels-only replay: the same deploy (warm_up) offline, then the oracle only; its own executor
    # store, status and coverage files, so nothing it does counts as the run's TRON-TVM observation.
    if [ "${FV_NO_CLASSIFY:-0}" != 1 ]; then
      BIN_CLS="$RUN/classify-$target"; mkdir -p "$RUN/classify"
      printf '#!/bin/sh\nfor v in $(env | sed -n "s/^\\(PYTHON[A-Za-z0-9_]*\\)=.*/\\1/p"); do unset "$v"; done\ndb=$(mktemp -d %q)\nPYTHONHASHSEED=0 exec bwrap --dev-bind / / --unshare-net -- env FV_BINDING=%q FV_ORACLE_SO=%q FV_CLASSES_PY=%q FV_HARNESS_PY=%q FV_TRON_TVM_CMD=%q FV_TRON_TVM_CREATION=%q FV_TRON_TVM_RUNTIME=%q FV_TRON_TVM_DB="$db" FV_TRON_TVM_COVERAGE=%q FV_TRON_TVM_STATUS=%q %q -s -P %q "$@"\n' \
        "$RUN/tron-tvm/db.XXXXXX" "$bnd" "$so" "$cmake_dir/classes.py" "$HERE/tron-tvm" "$RUN/tron-tvm/driver.sh" "$RUN/tron-tvm/creation.hex" "$RUN/tron-tvm/runtime.hex" \
        "$RUN/classify/tron-tvm-coverage.pcs" "$RUN/classify/tron-tvm-status.jsonl" "$py" "$HERE/python/fv_classify.py" > "$BIN_CLS"
      chmod +x "$BIN_CLS"
      CLS_FILE=(--classes-file "$cmake_dir/classes.py")
    fi
    impl="$impl_dir"
    ;;
  *) verdict 3 ERROR "unknown --lang $lang (cpp|rust|python|evm|tron-tvm)" ;;
esac
classify_line_in() { # a verdict log must never come from the classify build
  local f; for f in "$@"; do [ -f "$f" ] && grep -q 'diff-oracle: CLASSIFY BUILD' "$f" && return 0; done; return 1
}
mkdir -p "$RUN/artifacts" "$RUN/new_corpus"
export LSAN_OPTIONS="detect_leaks=1"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"
export FV_FUZZ_ARTIFACT_DIR="$RUN/artifacts"

classify() { # classify corpus|findings — labels only; sets CLASSES_JSON, never the verdict
  # FV_NO_CLASSIFY=1 is recorded, never silent: no labels, and no retention inputs were generated or compared.
  [ "${FV_NO_CLASSIFY:-0}" = 1 ] && { CLASSES_JSON='{"labels_only": true, "skipped": "FV_NO_CLASSIFY=1 in the environment: no classification, and the class-guided retention pass did not run (no retained inputs were compared)", "retention": {"runs": 0, "skipped": "FV_NO_CLASSIFY=1"}}'; return 0; }
  [ -n "$BIN_CLS" ] || { CLASSES_JSON='{"labels_only": true, "error": "no classify build (add_diff_fuzzer from an older LeanOracle.cmake?)"}'; return 0; }
  local C="$RUN/classify" hdr=() src=() fnd=() rrc=0
  mkdir -p "$C"; rm -f "$C/log.jsonl"
  [ -f "$cmake_dir/classes.hpp" ] && hdr=(--classes-header "$cmake_dir/classes.hpp")
  if [ "$1" = corpus ]; then
    src=("$corpus"); [ "$merge" -eq 1 ] || src+=("$RUN/new_corpus")
    [ -d "$C/retained" ] && src+=("$C/retained")  # class-guided inputs, each compared by the verdict binary (4b)
    FV_CLASSIFY="$C/log.jsonl" FV_CLASSIFY_TIME_IMPL=1 $CAP_CLS "$BIN_CLS" "${LIMITS[@]}" -runs=0 -artifact_prefix="$C/replay-artifact-" "${src[@]}" > "$C/replay.log" 2>&1
    rrc=$?  # a replay that stopped (a describe() or predicate that raised or panicked) classified only part of the corpus
  else
    for f in "$RUN"/artifacts/*; do [ -f "$f" ] && fnd+=("$f"); done
    [ ${#fnd[@]} -gt 0 ] || return 0
    fnd=(--findings "${fnd[@]}")
  fi
  if ! CLASSES_JSON=$($CAP_CLS python3 -I "$HERE/classify_report.py" --log "$C/log.jsonl" --bin "$BIN_CLS" --out "$C" \
       --corpus "${src[@]}" "${hdr[@]}" "${CLS_FILE[@]}" --retention "$RETAIN_JSON" "${fnd[@]}" 2>> "$C/report.log") || [ -z "$CLASSES_JSON" ]; then
    CLASSES_JSON='{"labels_only": true, "error": "classification failed (see classify/report.log)"}'
  fi
  if [ "$rrc" -ne 0 ]; then
    local why; why=$(grep -m1 -E 'CLASSIFY ERROR|panicked at|Error:|Exception|ERROR: (AddressSanitizer|libFuzzer|UndefinedBehaviorSanitizer)|runtime error:' "$C/replay.log" | cut -c1-200)
    CLASSES_JSON=$(jq -c --arg e "the classification replay exited $rrc, so only part of the corpus is classified: ${why:-see classify/replay.log}" \
      '.error = ((if .error then .error + "; " else "" end) + $e)' <<< "$CLASSES_JSON" 2>/dev/null || echo "$CLASSES_JSON")
  fi
  # Any retention error (a generation that stopped on its own error, one stopped by the time guard, a classify
  # build without retention) means the classification is not what a complete pass would give: classes.error.
  CLASSES_JSON=$(jq -c --argjson r "$RETAIN_JSON" '. + {retention: $r}
    | if (($r // {}).error // null) != null then .error = ((if .error then .error + "; " else "" end) + "retention: " + $r.error) else . end' \
    <<< "$CLASSES_JSON" 2>/dev/null || echo "$CLASSES_JSON")
}

fail_kind() { # fail_kind LOG -> a verdict detail naming what went wrong, or nothing
  local l="$1"
  if grep -q 'diff-oracle: DOMAIN' "$l"; then  # Python: a value outside the declared integer width
    echo "domain: $(grep -m1 -oE 'diff-oracle: DOMAIN at step [0-9]+ \(.*\)' "$l" | sed 's/^diff-oracle: DOMAIN //' | cut -c1-140)"
  elif grep -q 'diff-oracle: MISMATCH' "$l"; then echo "oracle/implementation mismatch"
  elif grep -q 'ERROR: libFuzzer: timeout' "$l"; then echo "HANG: input exceeded ${T_OUT} s"
  elif grep -q 'ERROR: libFuzzer: out-of-memory' "$l"; then
    echo "OOM: $(grep -m1 -oE 'out-of-memory \([^)]*\)' "$l")"
  elif grep -q 'ERROR: LeakSanitizer' "$l"; then
    echo "LEAK: $(grep -m1 -oE '(Direct|Indirect) leak of [0-9]+ byte\(s\) in [0-9]+ object\(s\)' "$l")"
  elif grep -q 'Uncaught Python exception' "$l"; then
    echo "python exception: $(grep -A40 'Uncaught Python exception' "$l" | grep -m1 -E '^[A-Za-z_.]*(Error|Exception)' | cut -c1-140)"
  elif grep -q "panicked at" "$l"; then  # Rust: overflow checks, explicit panics, unwraps
    echo "panic: $(grep -m1 -A1 'panicked at' "$l" | tr '\n' ' ' | sed -E "s/^thread '[^']*' //" | cut -c1-160)"
  elif grep -qE 'ERROR: (AddressSanitizer|UndefinedBehaviorSanitizer)|runtime error:' "$l"; then
    echo "sanitizer: $(grep -m1 -oE '(AddressSanitizer|UndefinedBehaviorSanitizer): [A-Za-z-]+|runtime error: .{0,80}' "$l")"
  elif grep -q 'ERROR: libFuzzer' "$l"; then echo "fuzzer: $(grep -m1 -oE 'ERROR: libFuzzer: [a-z-]+' "$l")"
  fi
}

keep_reproducers() { # a failing input joins the persisted corpus, so replay fails until it is fixed
  [ "$merge" -eq 1 ] || return 0
  for f in "$RUN"/artifacts/*; do [ -f "$f" ] && cp "$f" "$corpus/"; done
}

# Every process that runs the implementation under test runs offline: inside capped_off, except for a
# language whose driver wrapper enters its own network namespace (TRON-TVM; nested namespaces are not
# allowed on every host), whose wrapper must then say so, else ERROR.
CAP_BIN=capped_off; CAP_CLS=capped_off
if [ "$lang" = tron-tvm ]; then
  for w in "$BIN" ${BIN_CLS:+"$BIN_CLS"}; do
    grep -q -- '--unshare-net' "$w" 2>/dev/null || verdict 3 ERROR "the $lang wrapper $w does not enter its own network namespace"
  done
  CAP_BIN=capped; [ -n "$BIN_CLS" ] && CAP_CLS=capped
fi
# 3. Regression replay of the persisted corpus.
$CAP_BIN "$BIN" "${LIMITS[@]}" -runs=0 -artifact_prefix="$RUN/artifacts/" "$corpus" > "$RUN/replay.log" 2>&1
replay_rc=$?
classify_line_in "$RUN/replay.log" && verdict 3 ERROR "the replay ran a classify build, which never compares"
executor_verdict() { # executor_verdict LOG: an executor failure is ERROR / BLOCKED, never a finding
  if grep -q '^fv_tron_tvm: DEPLOYED CODE MISMATCH' "$1"; then
    verdict 2 BLOCKED "$(grep -m1 '^fv_tron_tvm: DEPLOYED CODE MISMATCH' "$1" | sed 's/^fv_tron_tvm: //' | cut -c1-200)"
  elif grep -q '^fv_tron_tvm: EXECUTOR ERROR' "$1"; then
    verdict 3 ERROR "TRON-TVM reference executor: $(grep -m1 '^fv_tron_tvm: EXECUTOR ERROR' "$1" | sed 's/^fv_tron_tvm: EXECUTOR ERROR: //' | cut -c1-200)"
  elif grep -q '^diff-oracle: ORACLE ERROR' "$1"; then
    verdict 3 ERROR "oracle: $(grep -m1 '^diff-oracle: ORACLE ERROR' "$1" | sed 's/^diff-oracle: ORACLE ERROR: //' | cut -c1-200)"
  elif [ "$lang" = tron-tvm ] && grep -q 'ERROR: libFuzzer: timeout' "$1"; then
    # The contract's own execution is bounded by energy; an input over the per-input timeout means the
    # reference executor was slow (JVM, trace, host), not a contract finding: ERROR, nothing kept.
    verdict 3 ERROR "TRON-TVM reference executor: an input exceeded the per-input timeout (${T_OUT} s): the executor's time, not a finding"
  fi
}
if [ $replay_rc -ne 0 ]; then
  executor_verdict "$RUN/replay.log"
  cp "$RUN/replay.log" "$RUN/campaign.log"
  classify findings
  rkind=$(fail_kind "$RUN/replay.log")
  [ -n "$rkind" ] || verdict 3 ERROR "regression replay exited $replay_rc without a finding (see $RUN/replay.log)"
  verdict 1 FAIL "regression replay failed on the persisted corpus: $rkind"
fi
rm -f "$RUN"/artifacts/*

# 4. Campaign.
# Every worker's -runs adds the corpus replay libFuzzer does first (one unit per input plus the empty
# input); only executions after INITED are counted (fuzz/worker/merge.py), and with --runs R the run
# is countable only when that total reaches R.
t0=$(date +%s.%N)
if [ -n "$remote" ] && [ "$lang" != cpp ]; then verdict 3 ERROR "--remote supports --lang cpp"; fi
replay_units() { echo $(( $(find "$@" -maxdepth 1 -type f 2>/dev/null | wc -l) + 1 )); }
q() { printf '%q ' "$@"; }
to_bytes() { # 32G / 512M / 1024K / plain bytes -> bytes, or nothing
  [[ "$1" =~ ^([0-9]+)([KMGT]?)$ ]] || return 0
  local n=${BASH_REMATCH[1]}; case "${BASH_REMATCH[2]}" in K) n=$((n << 10)) ;; M) n=$((n << 20)) ;; G) n=$((n << 30)) ;; T) n=$((n << 40)) ;; esac; echo "$n"; }
bundle_strict() { # bundle_strict DIR -> nothing if DIR holds exactly its manifest's files, else why not
  ( cd "$1" 2>/dev/null || { echo "no bundle directory"; exit 0; }
    [ -f MANIFEST.sha256 ] || { echo "no MANIFEST.sha256"; exit 0; }
    [ ! -e out ] || { echo "holds out/"; exit 0; }
    l=$(find . -type l -printf '%P ' | head -c 200); [ -z "$l" ] || { echo "holds symbolic links: $l"; exit 0; }
    o=$(find . ! -type f ! -type d -printf '%P ' | head -c 200); [ -z "$o" ] || { echo "holds special files (FIFO, device, socket): $o"; exit 0; }
    x=$(comm -23 <(find . -type f ! -path ./MANIFEST.sha256 -printf '%P\n' | LC_ALL=C sort) \
                 <(awk '{ sub(/^[0-9a-f]+  /, ""); print }' MANIFEST.sha256 | LC_ALL=C sort) | head -5 | tr '\n' ' ')
    [ -z "$x" ] || { echo "holds files not in MANIFEST.sha256: $x"; exit 0; }
    c=$(sha256sum --quiet -c MANIFEST.sha256 2>&1) || echo "files differ from MANIFEST.sha256: $(echo "$c" | head -3 | tr '\n' ' ')" )
}
per=""; [ -n "$runs" ] && per=$(( (runs + jobs + rk - 1) / (jobs + rk) ))   # post-replay executions per worker
if [ -n "$remote" ]; then
  # The bundle: this build's fuzzer and everything it needs at run time, hash-pinned.
  BD="$RUN/bundle"; rm -rf "${BD:?}"; mkdir -p "$BD/bin" "$BD/lib" "$BD/corpus"
  cp "$BIN" "$BD/bin/fuzzer"; cp "$LEAN_TC/lib/lean/libleanshared.so" "$BD/lib/"
  cp "$HERE/worker/fv_worker.sh" "$HERE/worker/fv_guard.sh" "$BD/"; find "$corpus" -maxdepth 1 -type f -exec cp -t "$BD/corpus" {} +
  # The symbol versions are read with objdump, which must succeed: a failed read would look like "needs nothing".
  dyn=$(objdump -T "$BD/bin/fuzzer" "$BD/lib/libleanshared.so" 2> "$RUN/objdump.err") \
    || verdict 3 ERROR "objdump -T could not read the bundle's binaries: $(head -c 200 "$RUN/objdump.err")"
  dynx=$(objdump -T "$BD/bin/fuzzer" 2>> "$RUN/objdump.err") || verdict 3 ERROR "objdump -T could not read the fuzzer: $(head -c 200 "$RUN/objdump.err")"
  { echo "glibc_max $(grep -oE 'GLIBC_[0-9.]+' <<< "$dyn" | sed 's/GLIBC_//' | sort -V | tail -1)"
    echo "glibcxx_max $(grep -oE 'GLIBCXX_[0-9.]+' <<< "$dynx" | sed 's/GLIBCXX_//' | sort -V | tail -1)"; } > "$BD/REQUIRES"
  # The worker's target, checked here, before anything is shipped or any ssh connection opens: an ssh
  # worker must declare it (FV_WORKER_GLIBC_MAX_<NAME>, FV_WORKER_GLIBCXX_MAX_<NAME>); a local one may
  # (_LOCAL). A bundle needing newer symbol versions than the target is BLOCKED.
  tn=${rname:-LOCAL}; gv="FV_WORKER_GLIBC_MAX_$tn"; xv="FV_WORKER_GLIBCXX_MAX_$tn"
  need_g=$(sed -n 's/^glibc_max //p' "$BD/REQUIRES"); need_x=$(sed -n 's/^glibcxx_max //p' "$BD/REQUIRES")
  # A dynamically linked fuzzer always needs some GLIBC_ version (GLIBCXX_ may be absent: libstdc++ linked statically).
  [ -n "$need_g" ] || verdict 3 ERROR "no GLIBC_ symbol version found in the bundle's binaries (objdump -T): the requirement cannot be checked"
  for v in "$gv" "$xv"; do   # a target is a version: digits and dots (anything else would compare arbitrarily)
    [ -z "${!v:-}" ] || [[ "${!v}" =~ ^[0-9]+(\.[0-9]+)*$ ]] || verdict 3 ERROR "$v=\"${!v}\" (config/hosts.env) is not a version such as 2.39 or 3.4.32"
  done
  if [ -n "$rname" ] && { [ -z "${!gv:-}" ] || [ -z "${!xv:-}" ]; }; then
    verdict 3 ERROR "worker $rname has no glibc / libstdc++ target ($gv, $xv in config/hosts.env): the gate checks a bundle against it before shipping"
  fi
  newer() { [ -n "$1" ] && [ -n "$2" ] && [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ]; }  # newer A B: A > B
  if newer "$need_g" "${!gv:-}" || newer "$need_x" "${!xv:-}"; then
    verdict 2 BLOCKED "the bundle needs glibc ${need_g:-none} / GLIBCXX ${need_x:-none}, worker ${rname:-local} provides ${!gv:-?} / ${!xv:-?} (build with the pinned sysroot: FV_BUILD_SYSROOT)"
  fi
  (cd "$BD" && find . -type f ! -name MANIFEST.sha256 -printf '%P\n' | LC_ALL=C sort | xargs sha256sum > MANIFEST.sha256)
  built_sha=$(sha256sum < "$BD/MANIFEST.sha256" | cut -d' ' -f1)
  tar -cf "$RUN/bundle.tar" -C "$RUN" bundle
  [ -z "$bundle_out" ] || cp "$RUN/bundle.tar" "$bundle_out"
  ship="${bundle_in:-$RUN/bundle.tar}"
  # The gate checks what it ships: only bundle/ members, no '..', then (extracted) exactly the
  # manifest's files with their hashes, and the manifest must be this build's.
  bad=$(tar -tf "$ship" 2>/dev/null | grep -vE '^bundle(/[^/]+)*/?$' | head -3); tar -tf "$ship" > /dev/null 2>&1 || bad="unreadable"
  [ -z "$bad" ] && ! tar -tf "$ship" | grep -qE '(^|/)\.\.(/|$)' \
    || verdict 2 BLOCKED "the bundle $ship has members outside bundle/: $(echo $bad | head -c 200)"
  RB="$RUN/remote-local"; rm -rf "${RB:?}"; mkdir -p "$RB"; tar -xf "$ship" -C "$RB" || verdict 3 ERROR "cannot read bundle $ship"
  why=$(bundle_strict "$RB/bundle")
  [ -z "$why" ] || verdict 2 BLOCKED "the bundle is not exactly its manifest: $why"
  given_sha=$(sha256sum < "$RB/bundle/MANIFEST.sha256" | cut -d' ' -f1)
  [ "$given_sha" = "$built_sha" ] || { REMOTE_JSON=$(jq -n --arg t "$([ -n "$rname" ] && echo "ssh:$rname" || echo local)" --arg b "$given_sha" --arg bb "$built_sha" '{transport: $t, bundle_sha256: $b, built_sha256: $bb}')
    verdict 2 BLOCKED "the remote bundle (manifest sha256 $given_sha) is not this build's ($built_sha)"; }
fi
rseed=$(( $(od -An -N4 -tu4 /dev/urandom) % 1000000000 + 1 ))
seed0=$rseed
rruns=""; [ -n "$runs" ] && rruns=$(( per * rk ))
# Remote worker over ssh: one ControlMaster per campaign, absolute paths, every word quoted, its own
# systemd scope with a run-time cap; whatever happens, the gate's exit stops the scope, removes the
# remote work dir and closes the connection.
# Cleanup touches only what this run created: the scope once this run started it, the work dir once
# this run's own mkdir made it (a name clash with another run never removes that run's files).
unit_started=0; rd_owned=0
remote_cleanup() {
  [ -n "${ctl:-}" ] && [ -S "$ctl" ] || return 0
  local c=""
  [ "$unit_started" = 1 ] && c+="systemctl --user stop $(q "$unit.scope") 2>/dev/null; "
  [ "$rd_owned" = 1 ] && c+="rm -rf -- $(q "$RD"); "
  [ -z "$c" ] || "${SSH[@]}" "$c" < /dev/null > /dev/null 2>&1
  ssh -o ControlPath="$ctl" -O exit "${dest[@]}" > /dev/null 2>&1
}
if [ -n "$rname" ]; then
  dv="FV_WORKER_SSH_$rname"; read -r -a dest <<< "${!dv:-}"
  [ ${#dest[@]} -gt 0 ] || verdict 3 ERROR "no ssh arguments for worker $rname (set $dv in config/hosts.env)"
  rid="fv-$(basename "$RUN")"; [[ "$rid" =~ ^[A-Za-z0-9._-]+$ ]] || verdict 3 ERROR "run name '$rid' has characters other than A-Z a-z 0-9 . _ -"
  rid="$rid-$(od -An -N4 -tx4 /dev/urandom | tr -d ' \n')"   # unique per run: two runs with one --out name never share
  unit="$rid"
  quota="${FV_WORKER_QUOTA_PCT:-$((rk * 100))}"; [[ "$quota" =~ ^[0-9]+$ ]] || verdict 3 ERROR "FV_WORKER_QUOTA_PCT '$quota' is not a number"
  memb=$(to_bytes "${FV_WORKER_MEMMAX:-32G}"); [ -n "$memb" ] || verdict 3 ERROR "FV_WORKER_MEMMAX '${FV_WORKER_MEMMAX:-}' is not a size"
  need=$(( rk * RSS_MB * 1048576 + ${FV_WORKER_MEM_MARGIN_MB:-2048} * 1048576 ))
  [ "$memb" -ge "$need" ] || verdict 3 ERROR "MemoryMax $memb B is below $rk x rss_limit_mb $RSS_MB + margin ($need B); lower K or raise FV_WORKER_MEMMAX"
  maxsec="${FV_WORKER_MAX_SEC:-$([ -n "$secs" ] && echo $(( secs * 3 + 3600 )) || echo 172800)}"
  [[ "$maxsec" =~ ^[0-9]+$ ]] || verdict 3 ERROR "FV_WORKER_MAX_SEC '$maxsec' is not a number"
  ctl="$RUN/ssh-ctl"; SSH=(ssh -o ControlPath="$ctl" -o BatchMode=yes "${dest[@]}")
  ssh -o ControlMaster=yes -o ControlPath="$ctl" -o ControlPersist=no -o BatchMode=yes -o ConnectTimeout=20 -fN "${dest[@]}" \
    || { ctl=""; verdict 3 ERROR "cannot open the ssh connection to worker $rname"; }
  trap 'remote_cleanup; kill_local' EXIT; trap 'exit 130' INT TERM HUP
  rhome=$("${SSH[@]}" 'printf %s "$HOME"' < /dev/null)
  [[ "$rhome" =~ ^/[A-Za-z0-9._/-]+$ ]] || verdict 3 ERROR "worker $rname reports an unusable home directory '$rhome'"
  rv="FV_WORKER_ROOT_$rname"; wroot="${!rv:-$rhome/fv-work}"   # the worker's work root (default ~/fv-work)
  [[ "$wroot" =~ ^/[A-Za-z0-9._/-]+$ ]] || verdict 3 ERROR "worker $rname: unusable work root '$wroot'"
  RD="$wroot/$rid"
  if "${SSH[@]}" "systemctl --user list-units --all --plain --no-legend $(q "$unit.scope") 2>/dev/null | grep -q ." < /dev/null; then
    verdict 3 ERROR "worker $rname already has a unit $unit.scope: refusing to run under its name"
  fi
  "${SSH[@]}" "mkdir -p -m 0700 $(q "$wroot") && mkdir -m 0700 $(q "$RD")" < /dev/null \
    || verdict 3 ERROR "cannot create the work directory $RD on worker $rname (it may exist: another run's; left untouched)"
  rd_owned=1
  "${SSH[@]}" "cat > $(q "$RD/bundle.tar")" < "$ship" || verdict 3 ERROR "cannot copy the bundle to worker $rname"
  # Guard overrides (FV_GUARD_*: fake probes and thresholds) reach the worker only if the gate's
  # environment sets them, and fuzz.json lists their names: a production run shows none.
  genv=(); while IFS= read -r v; do [[ "$v" =~ ^FV_GUARD_[A-Z0-9_]+$ ]] && genv+=("$v=${!v}"); done < <(compgen -e | LC_ALL=C sort)
  # The lease's restart unit for this worker (config/hosts.env), if any: a site policy, not an override.
  lrv="FV_WORKER_RESTART_UNIT_$rname"; lru="${!lrv:-}"
  [ -z "$lru" ] || [[ "$lru" =~ ^[A-Za-z0-9@._-]+\.(service|timer)$ ]] || verdict 3 ERROR "$lrv '$lru' is not a systemd unit name"
  GUARD_OVERRIDES=$(printf '%s\n' "${genv[@]%%=*}" | jq -Rsc 'split("\n") | map(select(. != ""))')
  rcmd="tar -xf $(q "$RD/bundle.tar") -C $(q "$RD") && rm -f -- $(q "$RD/bundle.tar") && $(q env "${genv[@]}" FV_GUARDS="${FV_WORKER_GUARDS:-1}" \
    FV_EXPECT_CPU_PCT="$quota" FV_EXPECT_MEM_BYTES="$memb" FV_LEASE_RESTART_UNIT="$lru" systemd-run --user --scope --quiet --unit="$unit" \
    -p CPUQuota="$quota%" -p MemoryMax="$memb" -p RuntimeMaxSec="$maxsec" nice -n 19 ionice -c3 \
    bash "$RD/bundle/fv_worker.sh" "$RD/bundle" "$jobs" "$rk" "$rruns" "${secs:-}" "$seed0" "${LIMITS[@]}" "${LENS[@]}")"
  unit_started=1   # from here the scope may exist: cleanup stops it
  "${SSH[@]}" "$rcmd" < /dev/null > "$RUN/remote.log" 2>&1 &
  rpid=$!
elif [ -n "$remote" ]; then
  # The local worker inherits this environment: record the FV_GUARD_* names it sees.
  GUARD_OVERRIDES=$(compgen -e | grep -E '^FV_GUARD_[A-Z0-9_]+$' | LC_ALL=C sort | jq -Rsc 'split("\n") | map(select(. != ""))')
  capped bash "$RB/bundle/fv_worker.sh" "$RB/bundle" "$jobs" "$rk" "$rruns" "${secs:-}" "$seed0" "${LIMITS[@]}" "${LENS[@]}" \
    > "$RUN/remote.log" 2>&1 &
  rpid=$!
fi
mkdir -p "$RUN/workers"; : > "$RUN/batches.tsv"; extra=$(replay_units "$RUN/new_corpus" "$corpus")
if [ "$jobs" -eq 1 ] && [ -z "$remote" ]; then
  limit=(); [ -n "$secs" ] && limit+=(-max_total_time="$secs"); [ -n "$runs" ] && limit+=(-runs="$(( runs + extra ))")
  $CAP_BIN "$BIN" "${limit[@]}" "${LIMITS[@]}" "${LENS[@]}" -print_final_stats=1 -artifact_prefix="$RUN/artifacts/" \
    "$RUN/new_corpus" "$corpus" > "$RUN/campaign.log" 2>&1
  e=$?; printf '0\t0\t0\t-\tdone\t%s\t%s\n' "$e" "$RUN/campaign.log" >> "$RUN/batches.tsv"
  single=1
else
  single=0; wlimit=(); [ -n "$secs" ] && wlimit+=(-max_total_time="$secs"); [ -n "$per" ] && wlimit+=(-runs="$(( per + extra ))")
  pids=()
  for ((w = 0; w < jobs; w++)); do
    $CAP_BIN env FV_FUZZ_WORKER="$w" "$BIN" "${wlimit[@]}" "${LIMITS[@]}" "${LENS[@]}" -seed=$((seed0 + w)) -print_final_stats=1 \
      -artifact_prefix="$RUN/artifacts/w$w-" "$RUN/new_corpus" "$corpus" > "$RUN/workers/w$w.log" 2>&1 &
    pids+=($!)
  done
  for ((w = 0; w < jobs; w++)); do
    wait "${pids[$w]}"; e=$?
    printf '%s\t0\t0\t%s\tdone\t%s\t%s\n' "$w" "$((seed0 + w))" "$e" "$RUN/workers/w$w.log" >> "$RUN/batches.tsv"
    { echo "=== worker $w (seed $((seed0 + w)), exit $e)"; cat "$RUN/workers/w$w.log"; } >> "$RUN/campaign.log"
  done
fi
if [ -n "$remote" ]; then
  # Wait for the remote side, at most its run-time cap plus 10 minutes.
  wdl=$(( $(date +%s) + ${maxsec:-172800} + 600 ))
  while kill -0 "$rpid" 2>/dev/null && [ "$(date +%s)" -lt "$wdl" ]; do sleep 5; done
  if kill -0 "$rpid" 2>/dev/null; then kill "$rpid" 2>/dev/null; verdict 3 ERROR "the remote worker did not finish within its cap (${maxsec:-172800} s + 600 s)"; fi
  wait "$rpid"; rrc=$?
  if [ -n "$rname" ]; then  # bring out/ back over the same connection; the EXIT trap removes the rest
    rm -rf "${RB:?}/bundle/out"
    ocap=$(( ${FV_OUT_MAX_BYTES:-17179869184} + 1073741824 ))   # file content cap + 1 GiB of tar headers
    "${SSH[@]}" "tar -cf - -C $(q "$RD/bundle") out" < /dev/null | head -c $((ocap + 1)) > "$RUN/out.tar" \
      || verdict 3 ERROR "could not copy out/ back from worker $rname"
    [ "$(stat -c %s "$RUN/out.tar")" -le "$ocap" ] || verdict 3 ERROR "worker $rname sent back more than $ocap bytes of out/"
    python3 -I "$HERE/worker/unpack_out.py" "$RUN/out.tar" "$RB/bundle" 2> "$RUN/unpack_out.err" \
      || verdict 3 ERROR "worker $rname sent back an out/ the gate refuses: $(head -1 "$RUN/unpack_out.err" | cut -c1-200)"
    rm -f "$RUN/out.tar"
    remote_cleanup; trap kill_local EXIT
  fi
  RO="$RB/bundle/out"
  REMOTE_JSON=$(jq -c --arg t "$([ -n "$rname" ] && echo "ssh:$rname" || echo local)" --arg b "$given_sha" --arg bb "$built_sha" --argjson k "$rk" \
    --arg rrc "$rrc" --argjson go "${GUARD_OVERRIDES:-[]}" --slurpfile pz <(cat "$RO/pauses.jsonl" 2>/dev/null) '{transport: $t, workers: $k, exit: $rrc, guard_overrides: $go,
    bundle_sha256: $b, built_sha256: $bb, worker_env: ., pauses: $pz,
    requires: {glibc: $ng, glibcxx: $nx}, target: {glibc: $tg, glibcxx: $tx}, build_sysroot_sha256: $sr,
    lease: {restart_unit: $lru}}' --arg lru "${lru:-}" \
    --arg ng "${need_g:-}" --arg nx "${need_x:-}" --arg tg "${!gv:-}" --arg tx "${!xv:-}" --arg sr "$SYSROOT_SHA" "$RO/worker-env.json" 2>/dev/null \
    || jq -nc --arg rrc "$rrc" --arg b "$given_sha" '{exit: $rrc, bundle_sha256: $b, worker_env: null}')
  if grep -q '^BLOCKED:' "$RUN/remote.log"; then
    verdict 2 BLOCKED "remote worker refused: $(grep -m1 '^BLOCKED:' "$RUN/remote.log" | sed 's/^BLOCKED: //' | cut -c1-200)"
  fi
  [ -f "$RO/post-check" ] || verdict 3 ERROR "the remote worker left no post-check (exit $rrc): $(tail -2 "$RUN/remote.log" | tr '\n' ' ' | cut -c1-200)"
  [ "$rrc" -ne 3 ] || verdict 2 BLOCKED "the bundle changed on the worker while it ran: $(head -2 "$RO/post-check" | tr '\n' ' ')"
  [ "$rrc" -eq 0 ] || verdict 3 ERROR "the remote worker exited $rrc: $(tail -2 "$RUN/remote.log" | tr '\n' ' ' | cut -c1-200)"
  [ -f "$RO/batches.tsv" ] || verdict 3 ERROR "the remote worker recorded no batches"
  # Remote batches: worker numbers jobs..jobs+rk-1, logs named wN.bM.log inside out/ (anything else is refused).
  declare -A seenwb=()
  while IFS=$'\t' read -r w _ b s en ex lg; do
    [[ "$w" =~ ^[0-9]+$ ]] && [[ "$b" =~ ^[0-9]+$ ]] && [ "$w" -ge "$jobs" ] && [ "$w" -lt $((jobs + rk)) ] && [ "$lg" = "w$w.b$b.log" ] \
      || verdict 3 ERROR "malformed remote batch record: worker '$w' batch '$b' log '$lg' (the log must be w<worker>.b<batch>.log)"
    [ -z "${seenwb[$w.$b]:-}" ] || verdict 3 ERROR "remote batch record for worker $w batch $b occurs twice"
    seenwb[$w.$b]=1
    [ -f "$RO/$lg" ] && [ ! -L "$RO/$lg" ] || verdict 3 ERROR "remote batch log $lg is missing or not a regular file"
    cp "$RO/$lg" "$RUN/workers/$lg"
    printf '%s\t1\t%s\t%s\t%s\t%s\t%s\n' "$w" "$b" "$s" "$en" "$ex" "$RUN/workers/$lg" >> "$RUN/batches.tsv"
    { echo "=== remote worker $w batch $b (seed $s, ended $en, exit ${ex:-?})"; cat "$RO/$lg"; } >> "$RUN/campaign.log"
  done < "$RO/batches.tsv"
  find "$RO/new_corpus" -maxdepth 1 -type f -exec cp -t "$RUN/new_corpus/" {} + 2>/dev/null
  find "$RO/artifacts" -maxdepth 1 -type f -exec cp -t "$RUN/artifacts/" {} + 2>/dev/null
fi
elapsed=$(echo "$(date +%s.%N) - $t0" | bc)
MERGE=$(python3 -I "$HERE/worker/merge.py" --list "$RUN/batches.tsv" ${runs:+--runs "$runs"}) || verdict 3 ERROR "merge.py failed"
echo "$MERGE" > "$RUN/merge.json"
TOTAL_EXEC=$(jq -r .total_executions <<< "$MERGE")
[ "$single" -eq 1 ] || WORKERS_JSON=$(jq -c '[.workers[] | {worker, remote, executions, batches: [.batches[] | {batch, seed, ended, exit, executed, inited, post_replay}]}]' <<< "$MERGE")
classify_line_in "$RUN/campaign.log" && verdict 3 ERROR "the campaign ran a classify build, which never compares"
mrc=$(jq -r .rc <<< "$MERGE")
if [ "$mrc" = 1 ]; then
  flog=$(jq -r .fail.log <<< "$MERGE"); fw=$(jq -r .fail.worker <<< "$MERGE"); rc=$(jq -r .fail.exit <<< "$MERGE")
  executor_verdict "$flog"
  keep_reproducers
  classify findings
  kind=$(fail_kind "$flog")
  [ "$single" -eq 1 ] || [ -z "$kind" ] || kind="$kind (worker $fw of $((jobs + rk))$([ "$fw" -ge "$jobs" ] && echo ", remote"))"
  if [ -n "$kind" ]; then verdict 1 FAIL "$kind"; else verdict 3 ERROR "fuzzer exited $rc"; fi
elif [ "$mrc" != 0 ]; then
  verdict 3 ERROR "$(jq -r .reason <<< "$MERGE")"
fi
# A PASS is cross-checked against what the batches left: a saved failing input (any artifact but a slow
# unit) means a failure that no exit status reported (e.g. a pause signal during its report): FAIL.
art=$(find "$RUN/artifacts" -maxdepth 1 -type f ! -name '*slow-unit-*' -printf '%f\n' | LC_ALL=C sort | head -3 | tr '\n' ' ')
if [ -n "$art" ]; then
  keep_reproducers
  classify findings
  kind=$(fail_kind "$RUN/campaign.log")
  verdict 1 FAIL "${kind:-a failing input was saved} (artifact ${art% }; no batch exit reported it)"
fi
# A PASS needs the TRON-TVM to have run: observed, not assumed. Every driver any verdict-binary process started
# (campaign, retention replay, merge) appends to status.jsonl, so this runs again after each of them.
tron_tvm_observed() {
  [ "$lang" = tron-tvm ] || return 0
  S="$RUN/tron-tvm/status.jsonl"
  nready=$(jq -s '[.[] | select(.event == "ready")] | length' "$S" 2>/dev/null || echo 0)
  ndebug=$(jq -s '[.[] | select(.event == "ready" and (.config | split(" ") | index("debug=true")))] | length' "$S" 2>/dev/null || echo 0)
  ncall=$(jq -s '[.[] | select(.event == "call")] | length' "$S" 2>/dev/null || echo 0)
  nlo=$(jq -s '[.[] | select(.event == "ready" and .net_ifaces == ["lo"])] | length' "$S" 2>/dev/null || echo 0)
  if [ "$nready" -lt 1 ] || [ "$ndebug" -ne "$nready" ] || [ "$ncall" -lt 1 ] || [ ! -s "$RUN/tron-tvm/coverage.pcs" ]; then
    verdict 3 ERROR "the TRON-TVM reference did not demonstrably run: $nready driver start(s), $ndebug with debug=true, $ncall process(es) with a transaction, coverage $( [ -s "$RUN/tron-tvm/coverage.pcs" ] && echo present || echo empty) (does the binding call fv_tron_tvm?)"
  fi
  [ "$nlo" -eq "$nready" ] || verdict 3 ERROR "a fuzz process saw network interfaces other than lo: $(jq -c -s '[.[] | select(.event == "ready") | .net_ifaces] | unique' "$S")"
  nfork=$(jq -s '[.[] | select(.event == "ready" and (.config | split(" ") | index("energy_limit_hard_fork=true")))] | length' "$S" 2>/dev/null || echo 0)
  [ "$nfork" -eq "$nready" ] || verdict 3 ERROR "the energy-limit fork was not active in every driver ($nfork of $nready): not mainnet semantics"
  ncfg=$(jq -s --arg c "node_config_sha256=$FV_TRON_TVM_NODE_CONFIG_SHA256" '[.[] | select(.event == "ready" and (.config | split(" ") | index($c)))] | length' "$S" 2>/dev/null || echo 0)
  [ "$ncfg" -eq "$nready" ] || verdict 3 ERROR "the node config (config-test.conf) differs from the pinned FV_TRON_TVM_NODE_CONFIG_SHA256 in $((nready - ncfg)) driver(s): observed $(jq -r -s '[.[] | select(.event == "ready") | .config | capture("node_config_sha256=(?<h>[^ ]*)").h] | unique | join(",")' "$S" 2>/dev/null)"
  cfg1=$(jq -r -s '[.[] | select(.event == "ready") | .config] | unique | join(" | ")' "$S")
  EVM_JSON=$(jq -c --arg c "$cfg1" --argjson n "$nready" --argjson k "$ncall" \
    '. + {network: "none (observed: only lo in every fuzz process, \($n) of \($n))", driver_config: $c,
          cpu_time_limit: (if ($c | contains("debug=true")) then "disabled (--debug, observed in every driver); OUT_OF_TIME not covered" else "UNKNOWN" end),
          processes: {driver_starts: $n, with_transactions: $k}}' <<< "$EVM_JSON")
}
tron_tvm_observed

# 4b. Class-guided retention. libFuzzer's corpus keeps only inputs that add coverage, so an edge class the
# campaign generated can be missing from it. The classify build (oracle only, never the implementation)
# runs as a fuzzer from the corpus with a FIXED seed and an execution budget ([fuzz] retain_runs, default
# 200000; retain_seed, default 1), with value profiling (it steers toward the equalities the classes
# test), and keeps the first input per class (FV_CLASSIFY_RETAIN). The same seed, budget, binary and
# corpus give the same retained set. Then the VERDICT binary replays those inputs, under the rules of the
# corpus replay: a finding is FAIL with the reproducer kept, an executor failure is ERROR. Retention only
# adds compared inputs; it never removes one. On the gate only, after the campaign's verdict. A classify
# build without retention support (an older vendored fv_classify.hpp), or a generation that did not
# complete its budget, is recorded and changes nothing (the inputs it kept are still replayed).
retention() {
  [ "${FV_NO_CLASSIFY:-0}" = 1 ] && { RETAIN_JSON='{"runs": 0, "skipped": "FV_NO_CLASSIFY=1"}'; return 0; }
  [ -n "$BIN_CLS" ] || { RETAIN_JSON='{"runs": 0, "skipped": "no classify build"}'; return 0; }
  local C="$RUN/classify" K="$RUN/classify/retained" W="$RUN/classify/retain-work" src=("$corpus") rc rr n done_ ok=true
  rm -rf "$K" "$W"   # a reused --out: an earlier run's retained inputs are never labelled as this run's
  [ "$RETAIN_RUNS" -gt 0 ] || { RETAIN_JSON='{"runs": 0, "skipped": "retain_runs = 0"}'; return 0; }
  mkdir -p "$C" "$K" "$W"
  find "$C" -maxdepth 1 -type f -name 'retain-artifact-*' -delete   # a reused --out: only this generation's stops count
  [ -d "$RUN/new_corpus" ] && src+=("$RUN/new_corpus")
  # The first directory receives libFuzzer's own new units (W, discarded); -reload=0: no timed re-reads.
  # The hook: an artifact directory that exists (libFuzzer checks that at start) but cannot be written.
  [ -z "${FV_TEST_HOOK_RETAIN_NO_ARTIFACT:-}" ] || { mkdir -p "$C/ro" && chmod a-w "$C/ro"; }
  # The C++ classify build also writes each input to retain-current before running it (the hook turns that off too).
  rm -f "$C/retain-current"; local cur="$C/retain-current"; [ -z "${FV_TEST_HOOK_RETAIN_NO_ARTIFACT:-}" ] || cur=""
  FV_CLASSIFY=/dev/null FV_CLASSIFY_RETAIN="$K" FV_CLASSIFY_RETAIN_CURRENT="$cur" $CAP_CLS "$BIN_CLS" "${LIMITS[@]}" "${LENS[@]}" -seed="$RETAIN_SEED" \
    -runs="$RETAIN_RUNS" -use_value_profile=1 -reload=0 -max_total_time="${FV_RETAIN_GUARD_S:-3600}" \
    -artifact_prefix="$C/${FV_TEST_HOOK_RETAIN_NO_ARTIFACT:+ro/}retain-artifact-" "$W" "${src[@]}" > "$C/retain.log" 2>&1
  rc=$?
  done_=$(grep -oE '^Done [0-9]+ runs' "$C/retain.log" | tail -1 | grep -oE '[0-9]+')  # libFuzzer, once -runs is reached
  [ -n "$done_" ] || done_=$(grep -oE '^#[0-9]+' "$C/retain.log" | tail -1 | tr -d '#')
  n=$(find "$K" -maxdepth 1 -type f | wc -l)
  local err=null
  if ! grep -q '^diff-oracle: CLASSIFY RETAIN' "$C/retain.log"; then
    err='"this classify build has no retention (an older vendored fv_classify.hpp?)"'; ok=false
  elif [ $rc -ne 0 ]; then
    err=$(jq -Rn --arg t "the generation exited $rc: $(grep -m1 -E 'ERROR|CLASSIFY ERROR|panicked|Uncaught' "$C/retain.log" | cut -c1-160)" '$t'); ok=false
  elif [ "${done_:-0}" -lt "$RETAIN_RUNS" ]; then
    err=$(jq -Rn --arg t "the generation stopped after ${done_:-0} of $RETAIN_RUNS executions (time guard): not reproducible" '$t'); ok=false
  fi
  # An input on which the generation itself stopped (libFuzzer's crash-, timeout-, oom- or leak- artifact) was
  # never compared: the verdict binary replays it with the retained inputs. If the verdict binary fails on it,
  # that is a finding; if not, the stop was the classifier's own (a describe() or predicate that raised).
  local A="$C/retain-replay-set" arts nk na f
  rm -rf "$A"; mkdir -p "$A"
  # Any non-zero exit of the generation is a stop on an input (a signal, libFuzzer's crash / timeout / OOM, an
  # AddressSanitizer / UndefinedBehaviorSanitizer / LeakSanitizer report, "fuzz target exited", an uncaught Python
  # exception, a Rust panic), except the classify build's own refusal (exit 3, "CLASSIFY ERROR": a classes file that
  # does not load, a describe() that sends a transaction), which is a classification error, not an input.
  local stop=0
  [ $rc -ne 0 ] && ! { [ $rc -eq 3 ] && grep -q 'CLASSIFY ERROR' "$C/retain.log"; } && stop=1
  have_art() { [ -n "$(find "$C" -maxdepth 1 -type f -name 'retain-artifact-*' ! -name '*slow-unit-*' -print -quit)" ]; }
  # A stop libFuzzer could not record (its crash handler died first: clang 18's ASan) is recorded from retain-current,
  # the input the classify build was running (an empty input too).
  if [ $stop = 1 ] && [ -f "$C/retain-current" ] && ! have_art; then
    cp -- "$C/retain-current" "$C/retain-artifact-current-$(sha1sum < "$C/retain-current" | cut -c1-40)"
  fi
  # Fail closed: a stop must have left its input behind, or it can never be compared. A stop with nothing captured
  # (libFuzzer killed inside its own handler and no recording, an unwritable artifact path) is ERROR, never a PASS.
  if [ $stop = 1 ] && ! have_art; then
    verdict 3 ERROR "the retention generation stopped on an input that was not captured (exit $rc: $(grep -m1 -E 'ERROR|Uncaught|panicked|fuzz target exited' "$C/retain.log" | cut -c1-120)), so it was never compared"
  fi
  arts=$(find "$C" -maxdepth 1 -type f -name 'retain-artifact-*' ! -name '*slow-unit-*' -printf '%f\n' | LC_ALL=C sort | tr '\n' ' ')
  nk=0; na=0
  while IFS= read -r -d '' f; do cp -- "$f" "$A/"; nk=$((nk + 1)); done < <(find "$K" -maxdepth 1 -type f -print0)
  while IFS= read -r -d '' f; do cp -- "$f" "$A/"; na=$((na + 1)); done \
    < <(find "$C" -maxdepth 1 -type f -name 'retain-artifact-*' ! -name '*slow-unit-*' -print0)
  RETAIN_JSON=$(jq -nc --argjson runs "$RETAIN_RUNS" --argjson seed "$RETAIN_SEED" --argjson done "${done_:-0}" --argjson err "$err" \
    --argjson complete "$ok" --arg hashes "$(find "$K" -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort | tr '\n' ' ')" --arg arts "$arts" \
    '{runs: $runs, seed: $seed, executions: $done, complete: $complete, error: $err, value_profile: true,
      retained: ($hashes | split(" ") | map(select(. != ""))), generation_artifacts: ($arts | split(" ") | map(select(. != ""))),
      replayed: null}')
  n=$(find "$A" -maxdepth 1 -type f | wc -l)
  # The set replayed must be exactly the retained inputs and the generation's stops: anything else (a name
  # collision, a copy that failed) would leave an input uncompared.
  [ "$n" -eq $((nk + na)) ] || verdict 3 ERROR "the retention replay set holds $n inputs, not the $nk retained and $na the generation stopped on"
  [ "$n" -gt 0 ] || return 0
  # The verdict binary compares every retained input, and every input the generation stopped on.
  local pre_art; pre_art=$(find "$RUN/artifacts" -maxdepth 1 -type f -printf '%f\n' 2>/dev/null | LC_ALL=C sort)
  $CAP_BIN "$BIN" "${LIMITS[@]}" -runs=0 -artifact_prefix="$RUN/artifacts/retain-" "$A" > "$RUN/retain-replay.log" 2>&1
  rr=$?
  classify_line_in "$RUN/retain-replay.log" && verdict 3 ERROR "the retention replay ran a classify build, which never compares"
  RETAIN_JSON=$(jq -c --argjson n "$n" '.replayed = $n' <<< "$RETAIN_JSON")
  if [ $rr -ne 0 ]; then
    executor_verdict "$RUN/retain-replay.log"
    cat "$RUN/retain-replay.log" >> "$RUN/campaign.log"
    # The verdict binary can die inside libFuzzer's crash handler too (clang 18's ASan) and leave no reproducer: every
    # input this replay ran is then kept as a candidate (the failing one is among them; libFuzzer did not name it).
    # A reproducer is any file this replay added to the artifacts other than a slow unit: libFuzzer's retain-* or the
    # oracle's own mismatch-<hash>.
    local note="" new_art
    new_art=$(comm -13 <(printf '%s\n' "$pre_art") <(find "$RUN/artifacts" -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort) \
      | grep -v 'slow-unit-' | grep -v '^$' || true)
    if [ -z "$new_art" ]; then
      while IFS= read -r -d '' f; do cp -- "$f" "$RUN/artifacts/retain-candidate-$(basename "$f")"; done \
        < <(find "$A" -maxdepth 1 -type f -print0)
      note=" (no reproducer written by libFuzzer: the $n inputs this replay ran are kept as retain-candidate-*, the failing one among them)"
    fi
    keep_reproducers
    classify findings
    rkind=$(fail_kind "$RUN/retain-replay.log")
    [ -n "$rkind" ] || verdict 3 ERROR "retention replay exited $rr without a finding (see $RUN/retain-replay.log)"
    verdict 1 FAIL "retention replay (class-guided inputs, seed $RETAIN_SEED, $RETAIN_RUNS executions) failed: $rkind$note"
  fi
}
retention
test_hook_replay_status retention
tron_tvm_observed   # the retention replay's drivers too

# 5. Corpus persistence.
# The merge re-runs every input in a fresh inner process. A failure there is a finding: libFuzzer would
# retry without that input and report success, so the run must not PASS. And with inputs to merge, the
# merge must complete in one attempt, or something went wrong that it did not report.
if [ "$merge" -eq 1 ]; then
  a0=$(find "$RUN/artifacts" -maxdepth 1 -type f ! -name '*slow-unit-*' | wc -l)
  nin=$(find "$corpus" "$RUN/new_corpus" -maxdepth 1 -type f | wc -l)
  $CAP_BIN "$BIN" "${LIMITS[@]}" -artifact_prefix="$RUN/artifacts/merge-" -merge=1 "$corpus" "$RUN/new_corpus" > "$RUN/merge.log" 2>&1
  mrc=$?
  classify_line_in "$RUN/merge.log" && verdict 3 ERROR "the merge ran a classify build"
  a1=$(find "$RUN/artifacts" -maxdepth 1 -type f ! -name '*slow-unit-*' | wc -l)
  executor_verdict "$RUN/merge.log"   # TRON-TVM: the executor's failure is ERROR / BLOCKED, never a finding
  # A finding (mismatch, sanitizer, panic, exception, timeout, OOM, deadly signal) or a new artifact: FAIL,
  # the reproducer joins the corpus. An inner process that died without a finding: ERROR.
  if grep -qE 'diff-oracle: (MISMATCH|DOMAIN)|ERROR: (AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|libFuzzer)|runtime error:|panicked at|Uncaught Python exception' "$RUN/merge.log" \
     || [ "$a1" -gt "$a0" ]; then
    keep_reproducers
    classify findings
    kind=$(fail_kind "$RUN/merge.log")
    verdict 1 FAIL "during the corpus merge: ${kind:-a new artifact in the inner merge process} ($(grep -c '^MERGE-OUTER: attempt' "$RUN/merge.log") attempt(s); the campaign itself passed)"
  fi
  if grep -q 'caused a failure at the previous merge step' "$RUN/merge.log"; then
    verdict 3 ERROR "an inner merge process failed without a finding: $(grep -m1 'caused a failure at the previous merge step' "$RUN/merge.log" | cut -c1-200) ($(grep -c '^MERGE-OUTER: attempt' "$RUN/merge.log") attempts)"
  fi
  [ $mrc -eq 0 ] || verdict 3 ERROR "corpus merge failed (exit $mrc)"
  if [ "$nin" -gt 0 ] && ! { grep -qx 'MERGE-OUTER: successful in 1 attempt(s)' "$RUN/merge.log" && grep -qE '^MERGE-OUTER: [0-9]+ new files' "$RUN/merge.log"; }; then
    verdict 3 ERROR "corpus merge did not complete in one attempt: $(grep -m1 -vE '^(MERGE-OUTER|INFO|WARNING|#)' "$RUN/merge.log" | cut -c1-160) ($(grep -c '^MERGE-OUTER: attempt' "$RUN/merge.log") attempts)"
  fi
fi
[ "$merge" -eq 1 ] && test_hook_replay_status merge
tron_tvm_observed   # and the merge's
# 6. Edge-case classification (labels only).
classify corpus
verdict 0 PASS "no mismatch"
