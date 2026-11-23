"""merge.py — merge the batches of a multi-worker fuzz campaign into one verdict (fuzz/run_fuzz.sh).

    merge.py --list BATCHES.tsv [--runs R]

BATCHES.tsv has one line per batch a worker ran, tab-separated:
    worker  remote(0|1)  batch  seed  ended(done|paused)  exit  log
`exit` is the libFuzzer process's exit status as recorded by the runner (empty if none was recorded).

Rules (every number is validated; nothing missing is ever read as success):
  - a batch without a recorded, numeric exit status is an ERROR;
  - exit 0 must have final stats and an INITED line; exit 72 (libFuzzer "run interrupted") is valid only
    for a batch the runner ended because the guards paused the campaign (ended = paused), and must also
    have final stats; exit 72 otherwise is an ERROR;
  - any other non-zero exit is a FAILING batch; a mismatch (exit 86) is preferred over other failures
    when choosing which worker the verdict names, then the lowest worker number;
  - executions counted are POST-REPLAY only: stat::number_of_executed_units minus the INITED count
    (the corpus replay libFuzzer does before mutating); with --runs R, a PASS needs a total >= R,
    else the campaign is not countable (ERROR). A batch the guards paused during its corpus replay
    (exit 72, final stats, no INITED yet) counts 0 executions, not an ERROR;
  - a batch that exited 0 or 72 but whose log holds a failure line (a mismatch, a sanitizer or
    libFuzzer error, a panic, a Python exception, an executor error: e.g. a pause signal that arrived
    while a failure was being reported) is a FAILING batch, never a pass;
  - the statistics are libFuzzer's last final-stats line and its first INITED status line (status
    lines carry "cov:"): the target's own output cannot easily stand in for them.
Prints JSON: {rc: 0|1|3, reason, fail: {worker, remote, log, exit} | null, workers: [...], total_executions}.
rc 0 = PASS so far, 1 = FAIL (run_fuzz.sh names the kind from fail.log), 3 = ERROR (reason says why).
"""
import argparse
import json
import re
import sys

MISMATCH, INTERRUPTED = 86, 72


FAILURE = re.compile(r"diff-oracle: (MISMATCH|DOMAIN|ORACLE ERROR)|^==[0-9]+==ERROR: |ERROR: (AddressSanitizer|LeakSanitizer|"
                     r"UndefinedBehaviorSanitizer|libFuzzer)|runtime error:|panicked at|Uncaught Python exception|"
                     r"^fv_tron_tvm: (EXECUTOR ERROR|DEPLOYED CODE MISMATCH)", re.M)


def read(log):
    try:
        return open(log, errors="replace").read()
    except OSError:
        return None


def stats(text):
    if text is None:
        return None, None
    ex = re.findall(r"^stat::number_of_executed_units:\s*([0-9]+)\s*$", text, re.M)
    ini = re.search(r"^#([0-9]+)\s+INITED\s+cov:", text, re.M)
    return (int(ex[-1]) if ex else None), (int(ini.group(1)) if ini else None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", required=True)
    ap.add_argument("--runs", type=int)
    a = ap.parse_args()
    workers, errors, fails = {}, [], []
    for n, line in enumerate(open(a.list).read().splitlines(), 1):
        if not line.strip():
            continue
        f = line.split("\t")
        if len(f) != 7:
            errors.append(f"batch list line {n}: {len(f)} fields, want 7")
            continue
        w, remote, batch, seed, ended, ex, log = f
        if not (w.isdigit() and batch.isdigit() and remote in ("0", "1") and ended in ("done", "paused")):
            errors.append(f"batch list line {n}: malformed ({line[:120]!r})")
            continue
        wk = workers.setdefault(int(w), {"worker": int(w), "remote": remote == "1", "batches": [], "executions": 0})
        b = {"batch": int(batch), "seed": seed, "ended": ended, "exit": None, "executed": None, "inited": None,
             "post_replay": None, "log": log}
        wk["batches"].append(b)
        if not re.fullmatch(r"[0-9]+", ex):
            errors.append(f"worker {w} batch {batch}: no numeric exit status recorded ({ex!r})")
            continue
        b["exit"] = code = int(ex)
        text = read(log)
        executed, inited = stats(text)
        b["executed"], b["inited"] = executed, inited
        if code in (0, INTERRUPTED) and text is not None and FAILURE.search(text):
            m = FAILURE.search(text).group(0)
            b["failure_line"] = m
            fails.append((0 if "MISMATCH" in m else 1, int(w), int(batch), wk["remote"], log, code))
            continue
        if code in (0, INTERRUPTED):
            if code == INTERRUPTED and ended != "paused":
                errors.append(f"worker {w} batch {batch}: interrupted (exit 72) without a guard pause")
            elif code == INTERRUPTED and executed is not None and inited is None:
                b["post_replay"] = 0  # paused during its corpus replay: no work counted, nothing wrong
            elif executed is None or inited is None:
                errors.append(f"worker {w} batch {batch}: exit {code} without final stats or INITED line")
            elif executed < inited:
                errors.append(f"worker {w} batch {batch}: executed {executed} < INITED {inited}")
            else:
                b["post_replay"] = executed - inited
                wk["executions"] += b["post_replay"]
        else:
            fails.append((0 if code == MISMATCH else 1, int(w), int(batch), wk["remote"], log, code))
    total = sum(w["executions"] for w in workers.values())
    out = {"workers": [workers[k] for k in sorted(workers)], "total_executions": total, "fail": None}
    if fails:
        _, w, _, remote, log, code = sorted(fails)[0]
        out.update(rc=1, reason="a worker failed", fail={"worker": w, "remote": remote, "log": log, "exit": code})
    elif errors:
        out.update(rc=3, reason="; ".join(errors[:5]) + (f" (+{len(errors) - 5} more)" if len(errors) > 5 else ""))
    elif not workers:
        out.update(rc=3, reason="no worker batches recorded")
    elif a.runs is not None and total < a.runs:
        out.update(rc=3, reason=f"not countable: {total} post-replay executions < {a.runs} requested")
    else:
        out.update(rc=0, reason="all batches passed")
    print(json.dumps(out))


if __name__ == "__main__":
    sys.exit(main())
