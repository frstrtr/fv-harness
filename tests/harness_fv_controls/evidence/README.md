# Evidence: one full control run on the release head

`summary.txt` holds the one-line verdict of each acceptance control, `rehearsal.log` the task
state-machine rehearsal, and `lang_rehearsal.log` the state machine run end to end for every
implementation language. They come from `tests/harness_fv_controls/run_controls.sh`,
`tests/state_machine_rehearsal.sh` and `tests/lang_rehearsal.sh` on the v0.2.1 line (which commit each
line is from: below). The runs used
one gate host, Ubuntu, 4 cores reserved, with `FV_REQUIRE_LANGS="rust python evm"`. So every language
control ran, and none could SKIP.

Result: 41 controls, 0 misbehaved, 0 skipped (the 39 of v0.2.0 plus c48_record_failure and c52_py_merge); the rehearsal
passed every step; every language (cpp, rust, python, evm) reached CLOSED with the closure naming its
language and implementation, and its drift implementation reached CPP_BUGFIX.

The full suite ran on 138bffe. The release head adds the Python corpus-merge fix (FV_SELF, a merge that
did not run is ERROR; control c52), which changes only the Python driver and the merge step: the Python
controls (c21–c24, c52), c20 and the language rehearsal were re-run on the head, and their lines here are
from that run. Red without the fix (138bffe): the same Python merge run PASSes with 48 new units, but the
corpus stays at 0 (35 inner starts refused: the merge did not run).

Host paths are replaced by `<harness>`, `<fv_root>` and `<home>`. Hosted CI runs the gate and C++
controls; the language controls (c15–c29) are verified by runs like this one, on a host with the
toolchains.
