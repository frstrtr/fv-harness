# Evidence: one full control run on the release head

`summary.txt` holds the one-line verdict of each acceptance control, and `rehearsal.log` the task
state-machine rehearsal. Both come from a single run of `tests/harness_fv_controls/run_controls.sh`
and `tests/state_machine_rehearsal.sh` on the v0.2.0 release head. The run used one gate host,
Ubuntu, 4 cores reserved, with `FV_REQUIRE_LANGS="rust python evm"`. So every language control ran,
and none could SKIP.

Result: 39 controls, 0 misbehaved, 0 skipped; the rehearsal passed every step.

Host paths are replaced by `<harness>`. Hosted CI runs the gate and C++ controls; the language
controls (c15–c29) are verified by runs like this one, on a host with the toolchains.
