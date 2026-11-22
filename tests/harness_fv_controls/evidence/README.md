# Evidence: one full control run on the release head

`summary.txt` holds the one-line verdict of each acceptance control, `rehearsal.log` the task
state-machine rehearsal, and `lang_rehearsal.log` the state machine run end to end for every
implementation language. All three come from a single run of `tests/harness_fv_controls/run_controls.sh`,
`tests/state_machine_rehearsal.sh` and `tests/lang_rehearsal.sh` on the v0.2.1 release head. The run used
one gate host, Ubuntu, 4 cores reserved, with `FV_REQUIRE_LANGS="rust python evm"`. So every language
control ran, and none could SKIP.

Result: 40 controls, 0 misbehaved, 0 skipped (the 39 of v0.2.0 plus c48_record_failure); the rehearsal
passed every step; every language (cpp, rust, python, evm) reached CLOSED with the closure naming its
language and implementation, and its drift implementation reached CPP_BUGFIX.

Host paths are replaced by `<harness>`, `<fv_root>` and `<home>`. Hosted CI runs the gate and C++
controls; the language controls (c15–c29) are verified by runs like this one, on a host with the
toolchains.
