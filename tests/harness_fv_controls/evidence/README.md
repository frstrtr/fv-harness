# Evidence: one full control run on the release head

`summary.txt` holds the one-line verdict of each acceptance control, `rehearsal.log` the task
state-machine rehearsal, and `lang_rehearsal.log` the state machine run end to end for every
implementation language. They come from `tests/harness_fv_controls/run_controls.sh`,
`tests/state_machine_rehearsal.sh` and `tests/lang_rehearsal.sh`, run once on the release head
(dd87da9), on one gate host (Ubuntu, 4 cores reserved), with `FV_REQUIRE_LANGS="rust python evm"`,
so every language control ran and none could SKIP.

Result: 44 controls, 0 misbehaved, 0 skipped; the rehearsal passed every step; every language (cpp,
rust, python, evm) reached CLOSED with the closure naming its language and implementation, and its drift
implementation reached CPP_BUGFIX.

## What changed on this line since v0.2.0, and the controls for it

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
