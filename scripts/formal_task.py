"""formal_task.py — the orchestrator's state machine for [FORMAL] tasks (spec §3).

    formal_task.py init      TASK --project DIR --lock LOCK --cmake-dir DIR --target NAME
                             [--impl-dir DIR] [--budget K] [--max-attempts N]
                             [--same-failure-wall on|off] [--fuzz-runs N | --fuzz-time S]
    formal_task.py set       TASK [--budget K] [--max-attempts N] [--same-failure-wall on|off]
    formal_task.py spec-lock TASK            # SPEC_LOCK: the human-set lock matches; record digests
    formal_task.py decompose TASK --by WHO   # DECOMPOSE done: record the skeleton and its stubs
    formal_task.py discharge TASK            # Tier 2 on every open stub; walls go back to DECOMPOSE
    formal_task.py audit     TASK            # scripts/verify_proof.sh; failure -> DECOMPOSE
    formal_task.py couple    TASK            # fuzz/run_fuzz.sh; a mismatch opens a C++ bugfix task
    formal_task.py close     TASK [--reduced-coverage REASON]  # closure bundle: closure.json + closure.md; a
                                             # record with reduced coverage stays in CLOSE (exit 11) without it
    formal_task.py run       TASK [--reduced-coverage REASON]  # discharge -> audit -> couple -> close until a stop
    formal_task.py status    TASK

States: SPEC_LOCK, DECOMPOSE, DISCHARGE, AUDIT, COUPLE, CLOSED, plus the halts BLOCKED (trusted
files changed: the human must act), CPP_BUGFIX (the C++ disagrees with the oracle; spec/challenge
is never touched) and ERROR. Each command checks that it is legal in the current state and
appends to the task's history. Task directories live in $FV_ROOT/tasks/TASK.

Escalation (DISCHARGE): each stub gets up to max_attempts dispatches of K samples (defaults
TIER2_MAX_ATTEMPTS=1, TIER2_BUDGET=4 in config/tier2.env; per task via init/set). A stub walls
(back to DECOMPOSE for Tier 1) when its attempts are spent, or AT ONCE when every sample of an
attempt failed the same way (same_failure in the dispatcher report: all Mathlib-rejected, the
same unsolved goal, ...). The counters are kept in state.json "tier2_stats" and the closure bundle.

Exit: 0 step done; 10 needs Tier 1 (DECOMPOSE); 11 needs a human (BLOCKED, or a CLOSE refused for reduced coverage); 12 C++ bugfix
opened; 3 error or illegal transition.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time

HARNESS = pathlib.Path(__file__).resolve().parent.parent
FV_ROOT = pathlib.Path(os.environ.get("FV_ROOT", pathlib.Path.home() / "fv-harness"))
spec = importlib.util.spec_from_file_location("dlp", HARNESS / "prover/dispatch_local_prover.py")
dlp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dlp)

LEGAL = {  # command -> states it may run from
    "spec-lock": {"SPEC_LOCK"},
    "decompose": {"DECOMPOSE"},
    "discharge": {"DISCHARGE"},
    "audit": {"AUDIT"},
    "couple": {"COUPLE"},
    "close": {"CLOSE"},
}
NEEDS_TIER1, NEEDS_HUMAN, CPP_BUGFIX = 10, 11, 12


def tier2_defaults() -> dict:
    cfg = dlp.load_env(HARNESS / "config/tier2.env", dict(os.environ))
    return {"budget": int(cfg.get("TIER2_BUDGET", 4)), "max_attempts": int(cfg.get("TIER2_MAX_ATTEMPTS", 1)),
            "same_failure_wall": cfg.get("TIER2_SAME_FAILURE_WALL", "1") not in ("0", "off", "no", "")}


STAT_KEYS = ("dispatches", "samples", "rounds", "completion_tokens", "seconds", "closed",
             "walls_budget", "walls_same_failure", "attempts_saved")


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def sha256(p: pathlib.Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


class Task:
    def __init__(self, tid: str):
        self.dir = FV_ROOT / "tasks" / tid
        self.file = self.dir / "state.json"

    def load(self) -> dict:
        if not self.file.is_file():
            sys.exit(f"error: no task {self.dir.name}; run init first")
        return json.loads(self.file.read_text())

    def save(self, st: dict):
        self.file.write_text(json.dumps(st, indent=2, ensure_ascii=False))

    def move(self, st: dict, to: str, note: str, **art):
        st["history"].append({"t": now(), "from": st["state"], "to": to, "note": note, **art})
        st["state"] = to
        self.save(st)
        print(f"[{st['task']}] {st['history'][-1]['from']} -> {to}: {note}")


def guard(st: dict, cmd: str):
    if st["state"] not in LEGAL[cmd]:
        print(f"error: '{cmd}' is not legal in state {st['state']} (legal from {sorted(LEGAL[cmd])})")
        sys.exit(3)


def solution_files(proj: pathlib.Path) -> list[pathlib.Path]:
    return sorted((proj / "spec/solution").rglob("*.lean"))


def scan_stubs(proj: pathlib.Path) -> tuple[dict, list]:
    """Theorems/lemmas whose proof contains `sorry` (DISCHARGE targets) and policy violations
    (`sorry` in a def/instance)."""
    stubs, bad = {}, []
    for f in solution_files(proj):
        lines = f.read_text().splitlines()
        i = 0
        while i < len(lines):
            m = dlp.DECL_START.match(lines[i])
            if not m:
                i += 1
                continue
            j = i + 1
            while j < len(lines) and not (lines[j] and not lines[j][0].isspace()
                                          and (dlp.DECL_START.match(lines[j]) or dlp.TOP_LEVEL_STOP.match(lines[j]))):
                j += 1
            body = re.sub(r"--[^\n]*", "", "\n".join(lines[i:j]))
            name = lines[i][m.end():].split()[0] if lines[i][m.end():].split() else "?"
            if re.search(r"\bsorry\b", body):
                rel = str(f.relative_to(proj))
                if m.group(1) in ("theorem", "lemma"):
                    stubs[name] = {"file": rel, "status": "open", "attempts": 0}
                else:
                    bad.append(f"{rel}: `sorry` in {m.group(1)} {name}")
            i = j
    return stubs, bad


def run_logged(cmd: list[str], log: pathlib.Path) -> int:
    with log.open("w") as fh:
        return subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT).returncode


def cmd_init(a):
    t = Task(a.task)
    if t.file.exists():
        sys.exit(f"error: task {a.task} exists")
    t.dir.mkdir(parents=True)
    st = {"task": a.task, "created": now(), "state": "SPEC_LOCK",
          "project": str(pathlib.Path(a.project).resolve()), "lock": str(pathlib.Path(a.lock).resolve()),
          # "cpp" is the historical name of the fuzz settings; "lang" says which language they are for.
          # impl_dir: as given; else, for C++ only, CMAKE_DIR/../impl (run_fuzz.sh picks the other
          # languages' defaults, and records the directory it used).
          "cpp": {"cmake_dir": str(pathlib.Path(a.cmake_dir).resolve()), "target": a.target, "lang": a.lang,
                  "impl_dir": (str(pathlib.Path(a.impl_dir).resolve()) if a.impl_dir else
                               str((pathlib.Path(a.cmake_dir) / ".." / "impl").resolve()) if a.lang == "cpp" else None),
                  "impl_dir_given": bool(a.impl_dir), "runs": a.fuzz_runs, "time": a.fuzz_time},
          "stubs": {}, "history": [], "rounds": 0, "tier2_stats": {k: 0 for k in STAT_KEYS}}
    d = tier2_defaults()
    st["budget"] = a.budget if a.budget is not None else d["budget"]
    st["max_attempts"] = a.max_attempts if a.max_attempts is not None else d["max_attempts"]
    st["same_failure_wall"] = (a.same_failure_wall == "on") if a.same_failure_wall else d["same_failure_wall"]
    t.save(st)
    print(f"[{a.task}] created in state SPEC_LOCK at {t.dir}; escalation {st['max_attempts']} x K={st['budget']}, "
          f"same-failure wall {'on' if st['same_failure_wall'] else 'off'}")


def cmd_set(a):
    """Change a task's escalation budget. Logged in the history; takes effect at the next dispatch."""
    t = Task(a.task); st = t.load()
    if st["state"] == "CLOSED":
        print("error: the task is CLOSED"); sys.exit(3)
    old = {k: st.get(k) for k in ("budget", "max_attempts", "same_failure_wall")}
    if a.budget is not None:
        st["budget"] = a.budget
    if a.max_attempts is not None:
        st["max_attempts"] = a.max_attempts
    if a.same_failure_wall:
        st["same_failure_wall"] = a.same_failure_wall == "on"
    new = {k: st.get(k) for k in old}
    st["history"].append({"t": now(), "event": "escalation budget set", "old": old, "new": new})
    t.save(st)
    print(f"[{a.task}] escalation budget {old} -> {new}")
    return 0


def spec_lock_cause(out: str, rc: int) -> str:
    """The actual reason spec_lock.sh check BLOCKED, from its output: signature or content."""
    why = next((l[len("BLOCKED: "):] for l in reversed(out.splitlines()) if l.startswith("BLOCKED: ")), "")
    if why.startswith("unsigned lock"):
        cause = "unsigned: no signature"
    elif why.startswith(("signature is not by any key", "no allowed-signers file")):
        cause = "signature by a key not in allowed_signers"
    elif why.startswith("bad signature"):
        cause = "invalid signature"
    elif why.startswith("no pinned fingerprint"):
        cause = "signer not pinned"
    elif why.startswith("the lock is not signed by the pinned key"):
        cause = "signed by a key other than the pinned one"
    elif why.startswith(("trusted files differ", "trusted tree is malformed")):
        cause = "content mismatch: the trusted files differ from the signed lock"
    else:
        cause = f"spec_lock.sh exit {rc}"
    return f"BLOCKED ({cause})" + (f": {why}" if why else "")


def cmd_spec_lock(a):
    t = Task(a.task); st = t.load(); guard(st, "spec-lock")
    log = t.dir / "spec_lock.log"
    rc = run_logged([str(HARNESS / "scripts/spec_lock.sh"), "check", st["project"], st["lock"]], log)
    if rc != 0:
        t.move(st, "BLOCKED", "spec lock " + spec_lock_cause(log.read_text() if log.is_file() else "", rc), log=str(log))
        return NEEDS_HUMAN
    st["lock_digest"] = sha256(pathlib.Path(st["lock"]))
    signer_line = next((l for l in log.read_text().splitlines() if l.startswith("SIGNER ")), "SIGNER -")
    st["spec_lock_signer"] = dict(kv.split("=", 1) for kv in signer_line.split()[1:] if "=" in kv)
    t.move(st, "DECOMPOSE", f"spec locked: manifest digest {st['lock_digest']}; "
           f"signed by {st['spec_lock_signer'].get('fingerprint')} (pinned, match)", log=str(log))
    return 0


def cmd_decompose(a):
    t = Task(a.task); st = t.load(); guard(st, "decompose")
    proj = pathlib.Path(st["project"])
    rc = subprocess.run([str(HARNESS / "scripts/spec_lock.sh"), "check", st["project"], st["lock"]],
                        capture_output=True, text=True).returncode
    if rc != 0:
        t.move(st, "BLOCKED", "trusted files changed during DECOMPOSE")
        return NEEDS_HUMAN
    stubs, bad = scan_stubs(proj)
    if bad:
        print("policy violations (fix before DISCHARGE):\n  " + "\n  ".join(bad))
        st["history"].append({"t": now(), "event": "decompose rejected", "violations": bad})
        t.save(st)
        return NEEDS_TIER1
    snap = t.dir / f"skeleton-{st['rounds']}"
    snap.mkdir(exist_ok=True)
    for f in solution_files(proj):
        (snap / f.name).write_text(f.read_text())
    st["stubs"] = stubs  # a re-decomposition is a new plan: every stub starts with a fresh budget
    t.move(st, "DISCHARGE", f"skeleton by {a.by}: {len(stubs)} open stub(s) {sorted(stubs)}", snapshot=str(snap))
    return 0


def cmd_discharge(a):
    t = Task(a.task); st = t.load(); guard(st, "discharge")
    pre = t.dir / f"preflight-{st['rounds']}.log"
    if run_logged([str(HARNESS / "scripts/preflight_lake_build.sh"), st["project"]], pre) != 0:
        t.move(st, "ERROR", "pre-flight build failed: the trusted modules do not build", log=str(pre))
        return 3
    stats = st.setdefault("tier2_stats", {k: 0 for k in STAT_KEYS})
    sfw = st.get("same_failure_wall", True)
    walls = {}
    for name, s in st["stubs"].items():
        while s["status"] == "open" and s["attempts"] < st["max_attempts"]:
            s["attempts"] += 1
            out = t.dir / f"discharge-{name}-{s['attempts']}"
            log = t.dir / f"discharge-{name}-{s['attempts']}.json"
            rc = run_logged([str(HARNESS / "prover/dispatch.sh"), "--project", st["project"], "--file", s["file"],
                             "--lemma", name, "--budget", str(st["budget"]), "--apply", "--out", str(out)], log)
            rep = json.loads((out / "result.json").read_text()) if (out / "result.json").is_file() else {}
            stats["dispatches"] += 1
            for k, rk in (("samples", "samples_run"), ("rounds", "rounds_total"),
                          ("completion_tokens", "completion_tokens"), ("seconds", "seconds")):
                stats[k] = round(stats[k] + (rep.get(rk) or 0), 1)
            s.setdefault("dispatches", []).append({k: rep.get(k) for k in (
                "closed", "budget", "samples_run", "rounds_total", "completion_tokens", "seconds",
                "failure_signatures", "same_failure", "model", "cascade", "closed_by_stage", "closed_by_endpoint", "stages_skipped")})
            t.save(st)
            if rc == 0:
                s["status"] = "closed"
                s["closed_by"] = f"tier2 attempt {s['attempts']}" + (
                    f", stage {rep['closed_by_stage']}" if rep.get("closed_by_stage") else "")
                stats["closed"] += 1
            elif rc != 1:
                t.move(st, "ERROR", f"dispatch error on {name} (exit {rc})", log=str(log))
                return 3
            elif sfw and rep.get("same_failure") and s["attempts"] < st["max_attempts"]:
                s["wall_reason"] = f"same failure in every sample: {rep['same_failure']}"
                stats["attempts_saved"] += st["max_attempts"] - s["attempts"]
                break
        if s["status"] == "open":
            if "wall_reason" in s:
                stats["walls_same_failure"] += 1
            else:
                s["wall_reason"] = f"budget spent: {s['attempts']} x K={st['budget']}"
                last = (s.get("dispatches") or [{}])[-1].get("same_failure")
                if last:
                    s["wall_reason"] += f" (every sample of the last attempt failed alike: {last})"
                stats["walls_budget"] += 1
            walls[name] = s["wall_reason"]
    if walls:
        st["rounds"] += 1
        t.move(st, "DECOMPOSE", f"wall event: {sorted(walls)} not closed ({'; '.join(f'{k}: {v}' for k, v in walls.items())}); "
               "Tier 1 re-decomposes", walls=sorted(walls), wall_reasons=walls)
        return NEEDS_TIER1
    t.move(st, "AUDIT", f"all {len(st['stubs'])} stub(s) closed by Tier 2")
    return 0


def gate_block_cause(verdict: dict) -> str:
    """Why verify_proof.sh exited 2, from the stage that blocked (no verdict.json: the run directory existed)."""
    if not verdict:
        return "no verdict (the run directory already existed, or the gate stopped before writing one)"
    stages = verdict.get("stages", {})
    if stages.get("lock") == "BLOCKED":
        return "the spec lock check failed (signature, signer pin or locked content)"
    if stages.get("held_out") == "BLOCKED":
        return "the trusted files or the gate's lock copy changed during the gate (no held-out copy matches the lock)"
    if stages.get("staged") == "BLOCKED":
        return "a staged tree or the gate's solution copy changed during the gate"
    return "blocked (" + " ".join(f"{k}={v}" for k, v in sorted(stages.items()) if v == "BLOCKED") + ")"


def cmd_audit(a):
    t = Task(a.task); st = t.load(); guard(st, "audit")
    n = sum(1 for h in st["history"] if h.get("from") == "AUDIT") + 1
    run = t.dir / f"audit-{n}"
    while os.path.lexists(run):   # the gate needs a fresh run directory (an earlier attempt may have left one, or a link)
        n += 1; run = t.dir / f"audit-{n}"
    rc = run_logged([str(HARNESS / "scripts/verify_proof.sh"), "--project", st["project"], "--lock", st["lock"],
                     "--out", str(run)], t.dir / f"audit-{n}.log")
    verdict = json.loads((run / "verdict.json").read_text()) if (run / "verdict.json").is_file() else {}
    st["last_audit"] = str(run)
    if rc == 0:
        t.move(st, "COUPLE", "gate PASS: " + " ".join(f"{k}={v}" for k, v in sorted(verdict.get("stages", {}).items())),
               verdict=str(run / "verdict.json"))
        return 0
    if rc == 2:
        t.move(st, "BLOCKED", "gate BLOCKED: " + gate_block_cause(verdict), verdict=str(run / "verdict.json"))
        return NEEDS_HUMAN
    if rc == 1:
        failed = [k for k, v in verdict.get("stages", {}).items() if v == "FAIL"]
        diags = {}
        for s in failed:
            lines = (run / "stages" / f"{s}.log").read_text().splitlines()
            diags[s] = [l for l in lines if re.search(r"error|rejected|declined|not permitted|Illegal|LINT", l)][:8]
        st["rounds"] += 1
        t.move(st, "DECOMPOSE", f"gate FAIL at {failed}; diagnostics recorded", diagnostics=diags,
               verdict=str(run / "verdict.json"))
        return NEEDS_TIER1
    t.move(st, "ERROR", f"gate ERROR (exit {rc})", verdict=str(run / "verdict.json"))
    return 3


def fuzz_lang(st) -> str:
    return st["cpp"].get("lang") or "cpp"   # tasks created before --lang are C++


def impl_dir_used(st, fz) -> pathlib.Path:
    """The implementation directory the campaign used: run_fuzz.sh records it (for C++ only when given)."""
    d = fz.get("impl_dir")
    return pathlib.Path(d if d and d != "default" else st["cpp"]["impl_dir"])


def cmd_couple(a):
    t = Task(a.task); st = t.load(); guard(st, "couple")
    n = sum(1 for h in st["history"] if h.get("from") == "COUPLE") + 1
    run = t.dir / f"couple-{n}"
    cmd = [str(HARNESS / "fuzz/run_fuzz.sh"), "--lean-project", st["project"], "--lock", st["lock"],
           "--cmake-dir", st["cpp"]["cmake_dir"], "--target", st["cpp"]["target"], "--out", str(run),
           "--lang", fuzz_lang(st)]
    if st["cpp"].get("impl_dir_given"):
        cmd += ["--impl-dir", st["cpp"]["impl_dir"]]
    cmd += ["--time", str(st["cpp"]["time"])] if st["cpp"].get("time") else ["--runs", str(st["cpp"]["runs"] or 1000000)]
    rc = run_logged(cmd, t.dir / f"couple-{n}.log")
    fz = json.loads((run / "fuzz.json").read_text()) if (run / "fuzz.json").is_file() else {}
    st["last_couple"] = str(run)
    if fz and fz.get("lang", "cpp") != fuzz_lang(st):  # the campaign must be the task's language
        t.move(st, "ERROR", f"fuzz ran --lang {fz.get('lang')!r}, the task is {fuzz_lang(st)!r}")
        return 3
    if rc == 0 and (fz.get("draft") or fz.get("verdict") != "PASS"):  # never countable
        t.move(st, "ERROR", f"fuzz result is not countable: verdict {fz.get('verdict')!r}, draft {fz.get('draft')!r}")
        return 3
    if rc == 0:
        t.move(st, "CLOSE", f"fuzz PASS: {fz.get('stats', '').strip()} in {fz.get('campaign_seconds')}s",
               fuzz=str(run / "fuzz.json"))
        return 0
    if rc == 1:
        bug = {"task": f"{st['task']}-cpp-bugfix-{n}", "opened": now(), "mismatch": fz.get("mismatch"),
               "detail": fz.get("detail"), "reproducers": sorted(p.name for p in (run / "artifacts").glob("*")),
               "lang": fuzz_lang(st),
               "rule": "fix the implementation; spec/challenge is not modified without human override"}
        (t.dir / f"cpp-bugfix-{n}.json").write_text(json.dumps(bug, indent=2))
        t.move(st, "CPP_BUGFIX", f"fuzz FAIL: {fz.get('detail')}; bugfix task {bug['task']} opened",
               bugfix=str(t.dir / f"cpp-bugfix-{n}.json"))
        return CPP_BUGFIX
    if rc == 2:
        t.move(st, "BLOCKED", "fuzz BLOCKED: spec project differs from lock")
        return NEEDS_HUMAN
    t.move(st, "ERROR", f"fuzz ERROR (exit {rc})")
    return 3


def closed_tree(proj: pathlib.Path, generated: list[pathlib.Path] | None = None) -> dict:
    """The tree a closure is about.
    commit:        the project's git HEAD, else a .source-commit file in the project or a parent (a git
                   archive of that commit);
    content_tree:  what the run actually used. With git, the tree id of the work tree's files written
                   through a throw-away index (git add -A, .gitignore respected); without git, the sha256 of
                   a sorted sha256 manifest of the tree under the .source-commit.
    excluded:      only the run's own generated directories, by exact path (the project's .lake, and any
                   further directories the caller names); a source directory that merely happens to be
                   called build or .lake elsewhere is NOT excluded.
    tracked_changes: whether tracked files differ from HEAD (git only)."""
    gen = [g.resolve() for g in ([proj / ".lake"] + list(generated or [])) if g.exists()]
    top = subprocess.run(["git", "-C", str(proj), "rev-parse", "--show-toplevel"], capture_output=True, text=True)
    if top.returncode == 0:
        root = pathlib.Path(top.stdout.strip()).resolve()
        rel = [str(g.relative_to(root)) for g in gen if root in g.parents]
        # Paths .gitignore already ignores are left out by `git add -A` itself (and git refuses an
        # exclude pathspec that names them); the record still lists them as excluded.
        need = [r for r in rel if subprocess.run(["git", "-C", str(root), "check-ignore", "-q", r]).returncode != 0]
        head = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        dirty = subprocess.run(["git", "-C", str(root), "status", "--porcelain", "--untracked-files=no"],
                               capture_output=True, text=True).stdout.strip()
        with tempfile.TemporaryDirectory() as td:
            env = dict(os.environ, GIT_INDEX_FILE=str(pathlib.Path(td) / "index"))
            subprocess.run(["git", "-C", str(root), "add", "-A", "--", ".", *[f":(exclude,literal){r}" for r in need]],
                           env=env, capture_output=True, check=True)
            content = subprocess.run(["git", "-C", str(root), "write-tree"], env=env, capture_output=True, text=True,
                                     check=True).stdout.strip()
        head_tree = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD^{tree}"], capture_output=True,
                                   text=True).stdout.strip()
        return {"commit": head or None, "source": "git HEAD", "content_tree": content, "content_kind": "git tree",
                "commit_tree": head_tree or None, "content_equals_commit": content == head_tree,
                "tracked_changes": bool(dirty), "excluded": rel}
    for d in [proj, *proj.parents]:
        f = d / ".source-commit"
        if f.is_file():
            d = d.resolve()
            rel = [str(g.relative_to(d)) for g in gen if d in g.parents]
            h = hashlib.sha256()
            for x in sorted(p for p in d.rglob("*") if p.is_file()):
                if any(g == x or g in x.resolve().parents for g in gen):
                    continue
                h.update(f"{sha256(x)}  {x.relative_to(d)}\n".encode())
            return {"commit": f.read_text().strip(), "source": str(f), "content_tree": h.hexdigest(),
                    "content_kind": "sha256 of a sorted sha256 manifest", "commit_tree": None,
                    "content_equals_commit": None, "tracked_changes": None, "excluded": rel}
    return {"commit": None, "source": "unknown", "content_tree": None, "content_kind": None,
            "commit_tree": None, "content_equals_commit": None, "tracked_changes": None, "excluded": []}


def harness_state() -> dict:
    """The harness the closure ran with, and whether its files differ from that commit.
    A deployment (DEPLOYED_COMMIT) is checked against DEPLOYED_MANIFEST.sha256, written at deploy time
    from the git archive (scripts/deploy_manifest.sh): a changed or missing file makes it dirty; files
    not in the manifest are listed as deployment data (site config, locks). A checkout uses git status."""
    f = HARNESS / "DEPLOYED_COMMIT"
    if f.is_file():
        commit = f.read_text().strip()
        m = HARNESS / "DEPLOYED_MANIFEST.sha256"
        if not m.is_file():
            return {"commit": commit, "kind": "deployment", "dirty": None, "changed": [], "extra": [],
                    "note": "no DEPLOYED_MANIFEST.sha256: cleanliness unknown"}
        listed, changed = set(), []
        for line in m.read_text().splitlines():
            h, _, rel = line.partition("  ")
            listed.add(rel)
            x = HARNESS / rel
            if not x.is_file() or sha256(x) != h:
                changed.append(rel)
        skip = {"DEPLOYED_COMMIT", "DEPLOYED_MANIFEST.sha256"}
        extra = sorted(str(x.relative_to(HARNESS)) for x in HARNESS.rglob("*")
                       if x.is_file() and str(x.relative_to(HARNESS)) not in listed | skip and "__pycache__" not in x.parts)
        return {"commit": commit, "kind": "deployment", "dirty": bool(changed), "changed": changed[:50], "extra": extra[:50]}
    r = subprocess.run(["git", "-C", str(HARNESS), "rev-parse", "--short=12", "HEAD"], capture_output=True, text=True)
    if r.returncode == 0:
        st = subprocess.run(["git", "-C", str(HARNESS), "status", "--porcelain", "--untracked-files=no"],
                            capture_output=True, text=True).stdout.splitlines()
        return {"commit": r.stdout.strip(), "kind": "git checkout", "dirty": bool(st), "changed": [l[3:] for l in st][:50], "extra": []}
    return {"commit": "unknown", "kind": "unknown", "dirty": None, "changed": [], "extra": []}


RETAIN_DEFAULT = 200000  # fuzz/run_fuzz.sh's default [fuzz] retain_runs


def retention_seeds(ec: dict) -> int:
    """The corpus inputs the retention generation replays before it generates: the classified inputs less the
    ones retention itself kept."""
    return max(0, int(ec.get("inputs") or 0) - len((ec.get("retention") or {}).get("retained") or []))


def cmd_close(a):
    t = Task(a.task); st = t.load(); guard(st, "close")
    proj = pathlib.Path(st["project"])
    audit = pathlib.Path(st["last_audit"]); couple = pathlib.Path(st["last_couple"])
    verdict = json.loads((audit / "verdict.json").read_text())
    fz = json.loads((couple / "fuzz.json").read_text())
    if fz.get("lang", "cpp") != fuzz_lang(st):
        t.move(st, "ERROR", f"CLOSE refused: the fuzz record is --lang {fz.get('lang')!r}, the task is {fuzz_lang(st)!r}")
        return 3
    if fz.get("draft") or fz.get("verdict") != "PASS" or verdict.get("verdict") != "PASS":
        t.move(st, "ERROR", f"CLOSE refused: not countable (fuzz verdict {fz.get('verdict')!r}, draft "
                            f"{fz.get('draft')!r}, gate verdict {verdict.get('verdict')!r})")
        return 3
    th = fz.get("test_hooks") or []
    if th:  # test hooks forge observations for controls, never for a countable campaign
        t.move(st, "ERROR", f"CLOSE refused: the campaign ran with test hooks {', '.join(th)}")
        return 3
    gth = verdict.get("test_hooks") or []
    if gth:  # the same for the gate: a hook edits trusted files to test the held-out copy
        t.move(st, "ERROR", f"CLOSE refused: the gate ran with test hooks {', '.join(gth)}")
        return 3
    go = (fz.get("remote") or {}).get("guard_overrides") or []
    if go:  # fake guard probes or thresholds are for controls, never for a countable campaign
        t.move(st, "ERROR", f"CLOSE refused: the campaign ran with guard overrides {', '.join(go)}")
        return 3
    # Reduced coverage, read from the record: no classification (FV_NO_CLASSIFY=1, a classification error) or
    # an incomplete class-guided retention pass (retain_runs = 0, its time guard, a stopped generation, a
    # classify build without retention) means the campaign compared fewer inputs than a full one. Never an
    # unqualified CLOSE: only with --reduced-coverage REASON, which the closure records first, next to the signer.
    ec = fz.get("classes") or {}
    rt = ec.get("retention") or {}
    gaps = []
    if not ec:
        gaps.append("no classification record")
    else:
        if ec.get("skipped"):
            gaps.append(f"classification skipped: {ec['skipped']}")
        if ec.get("error"):
            gaps.append(f"classification error: {str(ec['error'])[:200]}")
        if not rt:
            gaps.append("no class-guided retention record")
        elif rt.get("skipped"):
            gaps.append(f"class-guided retention skipped: {rt['skipped']}")
        elif rt.get("complete") is not True or not rt.get("runs"):
            gaps.append(f"class-guided retention incomplete: {str(rt.get('error') or 'complete=' + str(rt.get('complete')))[:200]}")
        elif rt.get("runs", 0) <= retention_seeds(ec):
            # libFuzzer counts the replay of the inputs it starts from toward -runs: a budget at or below their
            # number generated nothing, though the pass "completed"
            gaps.append(f"class-guided retention generated nothing: a budget of {rt['runs']} executions, at or below "
                        f"the {retention_seeds(ec)} corpus inputs it replays first")
    reduced = None
    if gaps:
        if not getattr(a, "reduced_coverage", None):
            # Stays in CLOSE: the same command with --reduced-coverage REASON (a person's decision) can close it.
            st["history"].append({"t": now(), "event": "close refused", "note": f"reduced coverage ({'; '.join(gaps)})"})
            t.save(st)
            print(f"[{st['task']}] CLOSE refused: reduced coverage ({'; '.join(gaps)}); the task stays in CLOSE: close it "
                  "only with --reduced-coverage REASON (formal_task.py close or run), which the closure records")
            return NEEDS_HUMAN
        reduced = {"reason": a.reduced_coverage, "fuzz_record": "; ".join(gaps)}
    if fz.get("lang") == "tron-tvm":  # the reference must be named and must have run
        tt = fz.get("tron_tvm") or {}
        miss = [k for k, ok in (("java_tron_commit", tt.get("java_tron_commit")),
                                ("chain_profile.sha256", (tt.get("chain_profile") or {}).get("sha256")),
                                ("driver_config", tt.get("driver_config")),
                                ("classpath_manifest_sha256", tt.get("classpath_manifest_sha256")),
                                ("jdk_tree_sha256", tt.get("jdk_tree_sha256")),
                                ("processes.with_transactions >= 1",
                                 ((tt.get("processes") or {}).get("with_transactions") or 0) >= 1)) if not ok]
        if miss:
            t.move(st, "ERROR", f"CLOSE refused: the TRON-TVM fuzz record lacks {', '.join(miss)}")
            return 3

    def grab(stage, pat):
        p = audit / "stages" / f"{stage}.log"
        return [l for l in p.read_text().splitlines() if re.search(pat, l)] if p.is_file() else []

    signer = verdict.get("spec_lock_signer") or {}
    bundle = {
        # First on purpose: the operator compares this fingerprint with the one they stated.
        "spec_lock_signer": signer,
        **({"reduced_coverage": reduced} if reduced else {}),
        "closed_tree": closed_tree(proj, [pathlib.Path(st["cpp"]["cmake_dir"]) / "build"]),
        "harness_commit": (hs := harness_state())["commit"], "harness": hs,
        "task": st["task"], "closed": now(),
        "source_digests": {
            "lock_manifest": st.get("lock_digest"),
            "solution": {str(f.relative_to(proj)): sha256(f) for f in solution_files(proj)},
            "impl": {"lang": fuzz_lang(st), "dir": str(impl_dir_used(st, fz)),
                     "files": {str(f): sha256(f) for f in sorted(impl_dir_used(st, fz).rglob("*"))
                               if f.is_file() and "__pycache__" not in f.parts}},
            "binding_dir": {str(f): sha256(f) for f in sorted(pathlib.Path(st["cpp"]["cmake_dir"]).rglob("*"))
                            if f.is_file() and not {"corpus", "target", "build", "__pycache__"} & set(f.relative_to(st["cpp"]["cmake_dir"]).parts)},
        },
        "exports_sha256": verdict.get("exports_sha256"),
        "gate": {"verdict": verdict.get("verdict"), "stages": verdict.get("stages"), "run": str(audit)},
        "comparator": {"native": grab("comparator_native", r"kernel accepts|okay|Illegal|mismatch"),
                       "from_export": grab("comparator_export", r"kernel accepts|okay|Illegal|mismatch")},
        "kernels": {"con_leche": grab("con_leche", r"^con-leche: (accepted|declined|rejected)"),
                    "con_ron": grab("con_ron", r"^con-ron: (accepted|declined|rejected)"),
                    "con_leche_compare": grab("con_leche_compare", r"^con-leche: (accepted|theorem)")},
        "fuzz": {k: fz.get(k) for k in ("lang", "verdict", "runs", "max_total_time", "campaign_seconds", "stats", "corpus",
                                        "impl_dir", "vendored", "cmake_args", "limits", "jobs", "workers",
                                        "total_executions", "remote", "evm", "tron_tvm")},
        # Edge-case classes: labels for the reviewer, never part of the verdict.
        "edge_cases": fz.get("classes"),
        "provenance": verdict.get("provenance"),
        "tier2": {"budget": st.get("budget"), "max_attempts": st.get("max_attempts"),
                  "same_failure_wall": st.get("same_failure_wall"), "stats": st.get("tier2_stats")},
        "stubs": st["stubs"], "rounds": st["rounds"], "history": st["history"],
    }
    (t.dir / "closure.json").write_text(json.dumps(bundle, indent=2, ensure_ascii=False))
    md = [f"SPEC-LOCK SIGNER: {signer.get('fingerprint', '-')} ({signer.get('principal', '-')}; "
          f"pinned {signer.get('pinned', '-')}, match={signer.get('match', '-')}). Compare with the fingerprint "
          "the operator stated; a report whose fingerprint differs is void.", "",
          *([f"REDUCED COVERAGE: {reduced['reason']} ({reduced['fuzz_record']})", ""] if reduced else []),
          f"# Closure report: {st['task']}", "", f"Closed {bundle['closed']}. Gate **{verdict.get('verdict')}**, "
          f"fuzz **{fz.get('verdict')}**.", "",
          f"Closed tree: `{bundle['closed_tree'].get('commit')}` ({bundle['closed_tree'].get('source')}"
          + ("; tracked files CHANGED" if bundle["closed_tree"].get("tracked_changes") else "")
          + f"), content tree `{bundle['closed_tree'].get('content_tree')}` ({bundle['closed_tree'].get('content_kind')}"
          + ("; equals the commit's tree" if bundle["closed_tree"].get("content_equals_commit")
             else "; differs from the commit's tree" if bundle["closed_tree"].get("content_equals_commit") is False else "")
          + "). "
          f"Harness: `{bundle['harness_commit']}` ({bundle['harness']['kind']}; "
          + {True: "DIRTY: " + ", ".join(bundle["harness"]["changed"][:5]), False: "clean",
             None: "cleanliness UNKNOWN"}[bundle["harness"]["dirty"]] + ").", "", "## Digests", f"- lock manifest: `{st.get('lock_digest')}`"]
    md += [f"- {k}: `{v}`" for k, v in bundle["source_digests"]["solution"].items()]
    md += [f"- {k}: `{v}`" for k, v in bundle["source_digests"]["impl"]["files"].items()]
    md += [f"- export {k}: `{v}`" for k, v in (verdict.get("exports_sha256") or {}).items()]
    md += ["", "## Gate stages"] + [f"- {k}: {v}" for k, v in sorted((verdict.get("stages") or {}).items())]
    md += ["", "## Kernel verdicts"] + [f"- {l}" for v in bundle["kernels"].values() for l in v]
    ts = st.get("tier2_stats") or {}
    md += ["", "## Tier 2", f"- escalation: {st.get('max_attempts')} attempt(s) x K={st.get('budget')}, same-failure wall "
           f"{'on' if st.get('same_failure_wall') else 'off'}",
           "- " + ", ".join(f"{k} {ts.get(k, 0)}" for k in STAT_KEYS)]
    md += [f"- {n}: {s['status']}" + (f" ({s['closed_by']})" if s.get("closed_by") else "")
           + (f"; walled: {s['wall_reason']}" if s.get("wall_reason") else "") for n, s in st["stubs"].items()]
    md += ["", "## Differential fuzz", f"- language: `{fz.get('lang', 'cpp')}`, implementation `{bundle['source_digests']['impl']['dir']}`",
           f"- {fz.get('stats', '').strip()}", f"- {fz.get('campaign_seconds')} s"]
    ex = fz.get("evm") or fz.get("tron_tvm")
    if ex:
        md += [f"- {fz.get('lang')} pins: " + ", ".join(f"{k} `{ex[k]}`" for k in sorted(ex) if isinstance(ex[k], (str, int))
                                                      and k not in ("contract_coverage",))[:2000]]
    md += [f"- vendored {k}: harness {v.get('cited_commit')}, body sha256 {v.get('body_sha256')}, match={v.get('match')}"
           for k, v in (fz.get("vendored") or {}).items()]
    ec = fz.get("classes") or {}
    md += ["", "## Edge-case coverage (labels only; never part of the verdict)"]
    if not ec:
        md += ["- not classified (no classification record)"]
    elif ec.get("skipped"):
        md += [f"- not classified: {ec['skipped']}"]
    elif ec.get("error"):
        md += [f"- {ec['error']}"]
    else:
        md += [f"- {ec.get('inputs')} distinct corpus inputs, {ec.get('steps')} steps; regular: "
               f"{ec.get('regular_inputs')} inputs, {ec.get('regular_steps')} steps",
               (f"- classes file `{ec.get('classes_file')}` sha256 `{ec.get('classes_file_sha256')}`; predicate sources "
                f"sha256 `{ec.get('classes_source_sha256')}`; review deck: `{ec.get('review_deck')}`" if ec.get("classes_file")
                else f"- classes.hpp sha256: `{ec.get('classes_header_sha256')}`; review deck: `{ec.get('review_deck')}`"),
               "- **NOT EXERCISED (in the retained corpus" + (", and the class-guided retention pass" if (ec.get("retention") or {}).get("complete")
                                                               and (ec.get("retention") or {}).get("runs", 0) > retention_seeds(ec) else "")
               + "):** " + (", ".join(ec.get("not_exercised") or []) or "none")]
        rt = ec.get("retention")
        if rt:
            md += [f"- class-guided retention: {rt.get('runs')} executions budgeted, {rt.get('executions')} done, seed {rt.get('seed')}, "
                   f"complete={rt.get('complete')}; {len(rt.get('retained') or [])} inputs kept, {rt.get('replayed')} replayed by the verdict binary"
                   + (f"; {rt['error']}" if rt.get("error") else "") + (f"; {rt['skipped']}" if rt.get("skipped") else "")
                   + (f"; **budget below the default {RETAIN_DEFAULT}** ([fuzz] retain_runs)" if 0 < (rt.get("runs") or 0) < RETAIN_DEFAULT else ""),
                   "- retained inputs (fnv1a): " + (" ".join(rt.get("retained") or []) or "none")]
        md += [f"- {t['class']}: {t['inputs']} inputs ({t['pct_inputs']} %), {t['steps']} steps"
               + (f" — `{t['source']}`" if t.get("source") else "") for t in ec.get("classes", [])]
        if ec.get("finding_classes"):
            md += [f"- finding `{f}`: {', '.join(c) or 'regular'}" for f, c in ec["finding_classes"].items()]
    md += ["", "## Timeline"] + [f"- {h['t']} {h.get('from', '')} -> {h.get('to', h.get('event', ''))}: {h.get('note', '')}"
                                  for h in st["history"]]
    (t.dir / "closure.md").write_text("\n".join(md) + "\n")
    t.move(st, "CLOSED", f"closure bundle written: {t.dir / 'closure.json'}")
    return 0


def cmd_run(a):
    st = Task(a.task).load()
    step = {"DISCHARGE": cmd_discharge, "AUDIT": cmd_audit, "COUPLE": cmd_couple, "CLOSE": cmd_close}
    while st["state"] in step:
        rc = step[st["state"]](a)
        if rc != 0:
            return rc
        st = Task(a.task).load()
    print(f"[{a.task}] stopped in {st['state']}")
    return 0 if st["state"] == "CLOSED" else (NEEDS_TIER1 if st["state"] == "DECOMPOSE" else 3)


def cmd_status(a):
    st = Task(a.task).load()
    print(json.dumps({k: st[k] for k in ("task", "state", "stubs", "rounds")}, indent=2))
    for h in st["history"][-5:]:
        print(f"  {h['t']} {h.get('from', '')} -> {h.get('to', h.get('event', ''))}: {h.get('note', '')}")
    return 0


def main():
    ap = argparse.ArgumentParser(description="[FORMAL] task state machine")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init"); p.add_argument("task")
    p.add_argument("--project", required=True); p.add_argument("--lock", required=True)
    p.add_argument("--cmake-dir", required=True); p.add_argument("--target", required=True)
    p.add_argument("--impl-dir", help="production sources (default: run_fuzz.sh's for the language; C++: CMAKE_DIR/../impl)")
    p.add_argument("--lang", choices=("cpp", "rust", "python", "evm", "tron-tvm"), default="cpp",
                   help="the implementation's language, passed to fuzz/run_fuzz.sh --lang")
    p.add_argument("--budget", type=int); p.add_argument("--max-attempts", type=int)
    p.add_argument("--same-failure-wall", choices=("on", "off"))
    p.add_argument("--fuzz-runs", type=int); p.add_argument("--fuzz-time", type=int)
    p = sub.add_parser("set"); p.add_argument("task")
    p.add_argument("--budget", type=int); p.add_argument("--max-attempts", type=int)
    p.add_argument("--same-failure-wall", choices=("on", "off"))
    for c in ("spec-lock", "discharge", "audit", "couple", "run", "status", "close"):
        sub.add_parser(c).add_argument("task")
    for c in ("close", "run"):
        sub.choices[c].add_argument("--reduced-coverage", metavar="REASON",
                                    help="close a campaign whose record shows reduced coverage (no classification, a "
                                         "classification error, or a class-guided retention pass that was skipped, incomplete "
                                         "or generated nothing); REASON is recorded right after the signer in the closure")
    p = sub.add_parser("decompose"); p.add_argument("task"); p.add_argument("--by", required=True)
    p = sub.add_parser("tree", help="print the closed_tree record of a project directory (no task)")
    p.add_argument("project")
    sub.add_parser("harness", help="print the harness record (commit, clean or dirty) of this harness")
    a = ap.parse_args()
    if a.cmd == "tree":
        print(json.dumps(closed_tree(pathlib.Path(a.project).resolve())))
        sys.exit(0)
    if a.cmd == "harness":
        print(json.dumps(harness_state()))
        sys.exit(0)
    fn = {"init": cmd_init, "set": cmd_set, "spec-lock": cmd_spec_lock, "decompose": cmd_decompose, "discharge": cmd_discharge,
          "audit": cmd_audit, "couple": cmd_couple, "close": cmd_close, "run": cmd_run, "status": cmd_status}[a.cmd]
    sys.exit(fn(a) or 0)


if __name__ == "__main__":
    main()
