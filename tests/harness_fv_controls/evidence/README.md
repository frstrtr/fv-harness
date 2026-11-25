# Evidence: one full control run on the release head, and a re-run of one fixed control

`summary.txt` holds the one-line verdict of each acceptance control, `rehearsal.log` the task
state-machine rehearsal, and `lang_rehearsal.log` the state machine run end to end for every
implementation language. They come from `tests/harness_fv_controls/run_controls.sh`,
`tests/state_machine_rehearsal.sh` and `tests/lang_rehearsal.sh`, run once on the v0.3.1 release head
before its last commit (61ab7a6), on one gate host (Ubuntu, 4 cores reserved), with
`FV_REQUIRE_LANGS="rust python evm tron-tvm"`, so every language control ran and none could SKIP.

Result: 82 controls, 81 behaving as specified, 1 misbehaved (c58), 0 skipped. The rehearsal passed every
step. Every language (cpp, rust, python, evm, tron-tvm) reached CLOSED, with the closure naming its
language and implementation, and its drift implementation reached CPP_BUGFIX.

## c58: a control timing defect, fixed and re-run

c58 (two ssh runs with the same name at once on one worker) misbehaved: "first exit=0, second exit=0,
overlap=no". Both of its runs PASSed; what failed was the control's own assumption that the first run
would still be running when the second ended. The first run had an execution budget (400,000 runs, a
campaign of about 30 s) and the second spends minutes building before it starts; in this release the
retention pass adds work after each campaign, which moved both end times, and the first run ended 3 s
before the second. A control whose result depends on host speed is a control defect (as c27's time budget
was in v0.2.1); the harness code was not involved.

The last commit of the release (ac8d45e) changes only `tests/harness_fv_controls/multihost_controls.sh`:
- the first run of c58 runs on time (`--time 600`; c58 is about overlap, not search), which outlasts
  the second run's build and campaign at any host speed;
- the overlap is observed, not assumed: a watcher records two `fv-run-*` work directories on the
  worker at the same moment while the second run runs.

No harness source, library or pin changed, so the full run above evidences the release's code. The
multi-worker controls (c43–c47, c58, c60, c61, on the full run's c39 bundle) were then run twice on
ac8d45e: `multihost-rerun-1.txt`, `multihost-rerun-2.txt`.

Both re-runs: all 8 behave as specified (8 OK, 0 misbehaved); c58 observed the two runs' work
directories on the worker at the same moment each time, and both of its runs PASSed.

## Controls added in v0.3.1

Each was first run against the code without its feature, where it misbehaved:
- **Worker gate:**
  - c65: a worker bundle is checked against the worker's glibc / GLIBCXX target before shipping;
  - c66: a chain node that does not answer pauses the campaign, and only 10 minutes of silence block it;
  - c67: the restart window shortens the resume after the node's scheduled restart.
- **Edge-case classification and retention:**
  - c68–c71: a gap is reported in each language (Rust, Python, EVM, TRON-TVM);
  - c72: predicate sources that differ from what ran are reported;
  - c73: retention keeps a class the coverage corpus lacked (C++ and Python);
  - c74: a finding that only the retention pass reaches FAILs, with the same reproducer and the same
    retained set in three runs;
  - c75: the Python and TRON-TVM replay cannot weaken or reach the verdict, and a replay that stops is
    an error.

## Controls added in v0.3.0

Each drives the gate or the fuzzer with a deliberately broken input (a variant implementation, a
tampered file or bundle, a fake reading) and requires the verdict that input calls for:
- **TRON-TVM:**
  - c33–c37: known answers, a clean contract, drift, refusals, vendored copies;
  - c41: contract coverage;
  - c49: internal transactions;
  - c51: guidance from the binding;
  - c56: the profile read-back;
  - c57: the build pins;
  - c64: the run record and CLOSE.
- **Multi-worker campaigns:**
  - c38, c39: one failing worker among several;
  - c40: the shared-host guards;
  - c42: CMake arguments;
  - c43: the batch merge rules;
  - c44: bundle strictness;
  - c45: a pause longer than the per-input timeout;
  - c46, c58: the ssh transport, and two runs with the same name;
  - c47, c60: run names, and `--runs` / `--time`;
  - c61: the copy-back;
  - c62: slow units with several workers;
  - c63: one gate per run directory.
- **The ByteArray oracle ABI:** c50, and c55 for its errors through `run_fuzz.sh`.
- **Gate:** c48, the fuzz.json record; c53, c54 and c59, the corpus merge (as in v0.2.1).

## v0.2.1: what changed on that line since v0.2.0, and the controls for it

- **The Python corpus merge** did not run (libFuzzer re-executes `argv[0]`, which the Python driver is
  not): fixed, and a merge that did not run is ERROR (c52). Red without the fix: the same Python merge
  run PASSes with 48 new units while the corpus stays at 0 (35 inner starts refused).
- **A failure during the corpus merge** ended as PASS: the merge re-runs every input in a fresh
  process, and when one failed there libFuzzer retried without it and reported success. Now a finding
  during the merge is FAIL with its reproducer kept, an inner merge process that died without a finding
  is ERROR, and a merge must complete in one attempt. Controls and their reds:
  - c53 (an implementation wrong only inside the inner merge process): FAIL here; PASS on the head
    before the fix (750d6dd), with 9 mismatch artifacts ignored.
  - c54 (the inner merge process exits on some inputs): ERROR here; PASS on 750d6dd.
  - c59 (the inner merge process dies at start, before any input): ERROR "did not complete in one
    attempt" here. Red: this head with the one-attempt rule removed PASSes (108 attempts, none
    successful, corpus unchanged); 750d6dd as it was ends ERROR under its older check ("corpus merge
    did not run", 114 attempts).
- **Search controls run on execution budgets.** On an earlier run of this line (d9cc341), c27
  misbehaved once: its unchecked-wrap part ran 9,423 executions in its 10 s at 856 executions/s under
  host load and did not reach the overflow; six reruns alone found it after 5,450 to 8,166 executions.
  A control that can miss under load is a control defect, so every control that must find something by
  search now runs on an execution budget of at least 5 times the worst executions-to-find observed in
  all past runs, with a time limit only as a hang guard:

  | control | before | worst observed find | after |
  |---|---|---|---|
  | c16 | 10 s | 6,211 | 32,000 executions |
  | c17 | 10 s | 7,345 | 37,000 |
  | c22 | 10 s | 5,013 | 26,000 |
  | c23 | 10 s | 3,114 | 16,000 |
  | c26 | 60 s | 7,350 | 37,000 |
  | c27 | 10 s | 8,663 | 48,000 |
  | c27b | 10 s | 9,109 (one miss at 9,423) | 48,000 |

  c6, c7, c10 to c13 and c48's drift run find at the replay of the fixture corpus in every past run,
  so no search budget is involved.

Host paths are replaced by `<harness>`, `<fv_root>` and `<home>`. Hosted CI runs the gate and C++
controls; the language controls (c15–c29) are verified by runs like this one, on a host with the
toolchains.
