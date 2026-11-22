"""dispatch_local_prover — Tier-2 tactic search for one `sorry` stub.

    dispatch_local_prover.py --project DIR --file spec/solution/X.lean --lemma NAME --budget K
                             [--rounds R] [--apply] [--out DIR]

Runs the cascade of config/tier2.env (TIER2_CASCADE, e.g. "fast main"): each stage asks its own
chat-completions-compatible endpoint for whole-proof candidates of the lemma (its SLOTS at a time;
K = the stage's BUDGET, or --budget for a stage without one). A stage whose endpoint does not
answer is skipped without spending budget; the first stage that closes the lemma ends the cascade. Each candidate is spliced into a copy of the file under the
lemma's ORIGINAL statement, policy-linted, compiled with the project's toolchain, and its axioms
printed. A candidate counts only if the file compiles without errors and the lemma rests on
propext / Classical.choice / Quot.sound alone. A failing candidate goes back to the model with
the compiler's messages, up to R repair rounds. The first success wins and the rest are
cancelled.

Run it inside the synthesis sandbox (prover/dispatch.sh does), so it can write only
spec/solution/ and .lake/. With --apply the winning proof replaces the stub in the file.

Exit: 0 closed, 1 not closed within budget (escalate to Tier 1), 3 error (bad input, endpoint
down). A JSON report goes to stdout and to OUT/result.json; every attempt is logged under OUT.
--budget defaults to TIER2_BUDGET (4). The report's `failure_signatures` counts how the failed
samples ended, and `same_failure` is set when they all ended the same way (see same_failure());
the state machine then walls at once instead of spending further attempts.
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures as cf
import json
import os
import pathlib
import queue
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

ALLOWED_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}
DECL_START = re.compile(
    r"^(?:@\[[^\]]*\]\s*)?(?:(?:private|protected|noncomputable|nonrec|partial|unsafe)\s+)*"
    r"(theorem|lemma|def|abbrev|instance|structure|inductive|class|axiom|opaque|example)\b")
TOP_LEVEL_STOP = re.compile(r"^(end\b|namespace\b|section\b|open\b|variable\b|set_option\b|#|/--|/-!|--)")
FORBIDDEN = re.compile(
    r"\b(sorry|admit|axiom|native_decide|implemented_by|extern|unsafe|trustCompiler|ofReduceBool|"
    r"ofReduceNat|skipKernelTC|elab|elab_rules|macro|macro_rules|syntax|initialize|run_cmd|"
    r"run_elab|run_meta)\b|#eval|#exit|@\[\s*(extern|implemented_by|export|csimp|init)")
PROMPT = """Complete the following Lean 4 code:

```lean4
{code}```

Before producing the Lean 4 code to formally prove the given theorem, provide a detailed proof plan outlining the main proof steps and strategies.
The plan should highlight key ideas, intermediate lemmas, and proof structures that will guide the construction of the final formal proof."""
# "plain": the code-only request (no proof plan); used for a cheap non-reasoning first pass.
PROMPT_PLAIN = """Complete the following Lean 4 code:

```lean4
{code}```"""
PROMPTS = {"cot": PROMPT, "plain": PROMPT_PLAIN}
# Repair requests are single-turn: the problem (in the stage's prompt style), the previous CODE and
# the compiler's messages. The previous reply's reasoning is not resent: it runs to thousands of
# tokens, and appending it overflowed an 8192-token context by repair round 2 (dry run 01: 8 x HTTP 400).
REPAIR_TAIL = """

A previous attempt at this proof does not compile:

```lean4
{attempt}```

Lean reports:

```
{errors}
```

Fix the proof of `{name}`. Keep the theorem statement exactly as given."""

# Tactics that exist only with Mathlib (or Aesop/Batteries add-ons it brings). In a core-only project a
# candidate using one cannot compile; it is rejected before compiling and sent back for repair
# (dry run 02: 63 of 64 feeOf_le rounds failed this way).
MATHLIB_TACTIC = re.compile(
    r"\b(nlinarith|linarith|positivity|norm_num|ring_nf|ring|field_simp|polyrith|gcongr|"
    r"interval_cases|push_cast|linear_combination|aesop|tauto|norm_num1|abel|noncomm_ring|"
    r"zify|qify|rify|fin_cases)\b")  # words that double as identifiers (group, lift, bound) left out
CORE_ONLY_NOTE = """-- Environment: Lean 4 core only, no Mathlib. Use core tactics and lemmas (omega, simp, decide,
-- rfl, exact, apply, Nat.* lemmas from core). Not available: nlinarith, linarith, positivity,
-- norm_num, ring, field_simp, and Mathlib lemma names.
"""


ERROR_HEAD = re.compile(r"^\S+\.lean:\d+:\d+: error: ?(.*)$")


def unsolved_goals(msg: str) -> set[str]:
    """The `⊢` goals of every "unsolved goals" error in Lean's messages, whitespace collapsed."""
    goals = set()
    for block in re.split(r"\n(?=\S+\.lean:\d+:\d+: )", msg):
        lines = block.split("\n")
        m = ERROR_HEAD.match(lines[0])
        if not m or not m.group(1).startswith("unsolved goals"):
            continue
        cur = None
        for ln in lines[1:] + [""]:
            if ln.startswith("⊢"):
                if cur is not None:
                    goals.add(cur)
                cur = ln[1:].strip()
            elif cur is not None and ln[:1].isspace():
                cur += " " + ln.strip()
            elif cur is not None:
                goals.add(cur)
                cur = None
    return {re.sub(r"\s+", " ", g) for g in goals}


def failure_signature(msg: str) -> str:
    """How one failed round failed, normalised so that equal failures compare equal.

    mathlib            rejected for Mathlib-only tactics (core-only project)
    policy:<construct> a forbidden construct
    no-code            no usable code block
    axioms:<list>      compiles but rests on a disallowed axiom
    unsolved:<goals>   the set of `⊢` goals Lean reports unsolved
    error:<heads>      otherwise, the set of error first lines without file positions
    """
    if msg.startswith("mathlib:"):
        return "mathlib"
    if msg.startswith("policy:"):
        m = re.search(r"`([^`]*)`", msg)
        return f"policy:{m.group(1) if m else '?'}"
    if msg.startswith("no usable code"):
        return "no-code"
    if msg.startswith("lemma rests on disallowed axioms"):
        return "axioms:" + msg.split(":", 1)[1].strip()
    goals = unsolved_goals(msg)
    if goals:
        return "unsolved:" + " | ".join(sorted(goals))
    heads = set()
    for block in re.split(r"\n(?=\S+\.lean:\d+:\d+: )", msg):
        m = ERROR_HEAD.match(block.split("\n")[0])
        if m:
            heads.add(re.sub(r"\s+", " ", m.group(1).strip())[:160])
    if heads:
        return "error:" + " | ".join(sorted(heads))
    return "other:" + re.sub(r"\s+", " ", msg.strip())[:160]


def conclusion(statement: str) -> str:
    """The proposition after the last top-level ':' of a theorem statement, whitespace collapsed."""
    depth, cut = 0, None
    for i, ch in enumerate(statement):
        if ch in "([{⟨":
            depth += 1
        elif ch in ")]}⟩":
            depth -= 1
        elif ch == ":" and depth == 0 and not statement.startswith(":=", i):
            cut = i
    return re.sub(r"\s+", " ", statement[cut + 1:] if cut is not None else statement).strip()


def same_failure(samples: list[dict], own_goal: str) -> str | None:
    """The early-wall rule: every sample of the attempt failed the same way.

    Applies only when at least 2 samples ran and every one of them failed for its own reasons
    (none closed, none cancelled, no endpoint error). Two ways count as "the same":
      - every sample's final round has the same signature (all Mathlib-rejected, all the same
        policy violation, all without code, the same error set, the same unsolved-goal set);
      - every sample's final round leaves one common unsolved goal other than the lemma's own
        statement (the same unsolved goal, whatever else each sample left open).
    Returns a description of the shared failure, or None.
    """
    failed = [s for s in samples if s.get("rounds")]
    if len(failed) < 2 or any(s.get("ok") or s.get("cancelled") or s.get("endpoint_error") or "sig" not in s
                              for s in failed):
        return None
    sigs = {s["sig"] for s in failed}
    if len(sigs) == 1:
        return sigs.pop()
    if all(s["sig"].startswith("unsolved:") for s in failed):
        flat = lambda g: re.sub(r"\s+", "", g)
        common = set.intersection(*({flat(g) for g in s.get("goals", [])} for s in failed)) - {flat(own_goal)}
        if common:
            shown = sorted(g for g in failed[0]["goals"] if flat(g) in common)
            return "unsolved-common:" + " | ".join(shown)
    return None


def load_env(path: pathlib.Path, base: dict) -> dict:
    """Evaluate a shell env file with bash and return its TIER2_* variables."""
    out = subprocess.run(
        ["bash", "-c", f'set -a; . "{path.parent.parent / "config/pins.env"}"; . "{path}"; env -0'],
        capture_output=True, text=True, env=base, check=True).stdout
    env = dict(kv.split("=", 1) for kv in out.split("\0") if "=" in kv)
    return {k: v for k, v in env.items() if k.startswith(("TIER2_", "FV_", "LEAN_"))}


def stages(cfg: dict, budget: int, rounds: int | None) -> list[dict]:
    """The cascade stages from TIER2_CASCADE. TIER2_<STAGE>_<KEY> overrides TIER2_<KEY> for each of
    BASE_URL, MODEL, SLOTS, BUDGET, ROUNDS, MAX_TOKENS, TEMPERATURE, TOP_P, TIMEOUT, PROMPT.
    BASE_URL may list several endpoints serving the same model (space-separated); SLOTS is per
    endpoint, and the stage's samples are spread over the endpoints that answer."""
    out = []
    for name in cfg.get("TIER2_CASCADE", "main").split():
        g = lambda k, d=None: cfg.get(f"TIER2_{name.upper()}_{k}") or cfg.get(f"TIER2_{k}") or d
        st = {"stage": name, "base_urls": (g("BASE_URL") or "").split(), "model": g("MODEL"), "slots": int(g("SLOTS", 1)),
              "budget": int(cfg.get(f"TIER2_{name.upper()}_BUDGET") or budget),
              "rounds": int(rounds if rounds is not None else g("ROUNDS", 3)),
              "max_tokens": int(g("MAX_TOKENS", 6144)), "temperature": float(g("TEMPERATURE", 0.9)),
              "top_p": float(g("TOP_P", 0.95)), "timeout": float(g("TIMEOUT", 1200)), "prompt": g("PROMPT", "cot")}
        if not st["base_urls"] or not st["model"] or st["prompt"] not in PROMPTS:
            raise SystemExit(f"error: cascade stage {name}: BASE_URL, MODEL and PROMPT (cot|plain) are required")
        out.append(st)
    return out


def reachable(base_url: str, timeout: float = 5.0) -> bool:
    """True if anything answers HTTP at the endpoint (an HTTP error status still counts)."""
    try:
        urllib.request.urlopen(base_url.rstrip("/") + "/models", timeout=timeout).close()
        return True
    except urllib.error.HTTPError:
        return True
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def find_decl(lines: list[str], name: str) -> tuple[int, int]:
    """Line range [start, end) of the top-level declaration `name` (short or qualified)."""
    short = name.split(".")[-1]
    start = None
    for i, ln in enumerate(lines):
        m = DECL_START.match(ln)
        rest = ln[m.end():].split() if m else []
        if m and m.group(1) in ("theorem", "lemma") and rest and rest[0] in (name, short):
            start = i
            break
    if start is None:
        raise SystemExit(f"error: theorem {name} not found")
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if lines[j] and not lines[j][0].isspace() and (DECL_START.match(lines[j]) or TOP_LEVEL_STOP.match(lines[j])):
            end = j
            break
    while end > start + 1 and not lines[end - 1].strip():
        end -= 1
    return start, end


def split_statement(decl: str) -> tuple[str, str]:
    """Split a declaration into (statement up to and excluding ':=', proof after ':=')."""
    depth = 0
    for i, ch in enumerate(decl):
        if ch in "([{⟨":
            depth += 1
        elif ch in ")]}⟩":
            depth -= 1
        elif ch == ":" and depth == 0 and decl.startswith(":=", i):
            return decl[:i].rstrip(), decl[i + 2:]
    raise ValueError("no ':=' in declaration")


def project_context(proj: pathlib.Path, text: str, seen: set) -> str:
    """Source of project-local modules imported by `text` (recursively), imports stripped."""
    chunks = []
    for mod in re.findall(r"^import\s+(\S+)", text, re.M):
        if mod in seen:
            continue
        seen.add(mod)
        rel = pathlib.Path(*mod.split(".")).with_suffix(".lean")
        for root in ("spec/challenge", "spec/solution"):
            p = proj / root / rel
            if p.is_file():
                src = p.read_text()
                chunks.append(project_context(proj, src, seen))
                chunks.append(re.sub(r"^import\s+\S+\s*$", "", src, flags=re.M).strip() + "\n")
    return "\n".join(c for c in chunks if c)


def extract_code(reply: str) -> str | None:
    blocks = re.findall(r"```(?:lean4|lean)?\s*\n(.*?)```", reply, re.S)
    return blocks[-1] if blocks else None


class SetupError(RuntimeError):
    """The environment, not the candidate, is broken: stop instead of burning the budget."""


class Prover:
    def __init__(self, a, cfg):
        self.a, self.cfg = a, cfg
        self.proj = pathlib.Path(a.project).resolve()
        self.file = (self.proj / a.file).resolve()
        if not str(self.file).startswith(str(self.proj / "spec/solution") + "/"):
            raise SystemExit("error: --file must be under spec/solution/")
        self.src = self.file.read_text()
        self.lines = self.src.splitlines(keepends=True)
        self.s, self.e = find_decl([l.rstrip("\n") for l in self.lines], a.lemma)
        decl = "".join(self.lines[self.s:self.e])
        self.statement, proof = split_statement(decl)
        if not re.search(r"\bsorry\b", proof):
            raise SystemExit(f"error: {a.lemma} has no sorry to discharge")
        self.qualified = self._qualified_name()
        ctx = project_context(self.proj, self.src, set())
        prefix = re.sub(r"^import\s+\S+\s*$", "", "".join(self.lines[:self.s]), flags=re.M)
        self.problem = (ctx + "\n" + prefix.strip() + "\n\n" + self.statement + " := by\n  sorry\n")
        self.core_only = not self._uses_mathlib()
        if self.core_only:
            self.problem = CORE_ONLY_NOTE + "\n" + self.problem
        self.out = pathlib.Path(a.out).resolve()
        self.out.mkdir(parents=True, exist_ok=True)
        self.scratch = self.proj / ".lake" / "fv-prover" / f"{a.lemma}-{os.getpid()}"
        self.scratch.mkdir(parents=True, exist_ok=True)
        self.done = threading.Event()
        self.tokens = 0
        self.lock = threading.Lock()

    def _uses_mathlib(self) -> bool:
        manifest = self.proj / "lake-manifest.json"
        try:
            pkgs = json.loads(manifest.read_text()).get("packages", [])
        except (OSError, json.JSONDecodeError):
            return True  # unknown: do not claim the environment is core-only
        return any(p.get("name", "").lower() == "mathlib" for p in pkgs)

    def _qualified_name(self) -> str:
        ns = []
        for ln in self.lines[:self.s]:
            m = re.match(r"^namespace\s+(\S+)", ln)
            if m:
                ns.append(m.group(1))
            m = re.match(r"^end\s+(\S+)", ln)
            if m and ns and ns[-1] == m.group(1):
                ns.pop()
        short = self.a.lemma.split(".")[-1]
        return ".".join(ns + [short]) if "." not in self.a.lemma else self.a.lemma

    def ask(self, messages, url: str) -> str:
        body = json.dumps({
            "model": self.st["model"], "messages": messages, "max_tokens": self.st["max_tokens"],
            "temperature": self.st["temperature"], "top_p": self.st["top_p"],
        }).encode()
        req = urllib.request.Request(url.rstrip("/") + "/chat/completions",
                                     data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.st["timeout"]) as r:
            resp = json.load(r)
        with self.lock:
            n = resp.get("usage", {}).get("completion_tokens", 0)
            self.tokens += n
            self.ep_tokens[url] = self.ep_tokens.get(url, 0) + n
        return resp["choices"][0]["message"]["content"] or ""

    def splice(self, code: str) -> str | None:
        """Original file with the stub replaced by the candidate's proof under the original statement."""
        cl = code.splitlines()
        try:
            s, e = find_decl(cl, self.a.lemma)
            _, proof = split_statement("\n".join(cl[s:e]) + "\n")
        except (SystemExit, ValueError):
            return None
        return "".join(self.lines[:self.s]) + self.statement + " :=" + proof.rstrip() + "\n\n" + "".join(self.lines[self.e:]).lstrip("\n")

    def check(self, text: str, tag: str) -> tuple[bool, str]:
        body = text[len("".join(self.lines[:self.s])):]
        body = body[:len(body) - len("".join(self.lines[self.e:]).lstrip("\n"))]
        stripped = re.sub(r"--[^\n]*", "", re.sub(r"/-.*?-/", "", body, flags=re.S))
        bad = FORBIDDEN.search(stripped)
        if bad:
            return False, f"policy: forbidden construct `{bad.group(0)}` in the proof"
        if self.core_only:
            ml = MATHLIB_TACTIC.search(stripped)
            if ml:
                return False, (f"mathlib: tactic `{ml.group(0)}` needs Mathlib, which this project does not "
                               "have; use core tactics (omega, simp, decide, exact with core Nat lemmas)")
        f = self.scratch / f"{tag}.lean"
        f.write_text(text + f"\n#print axioms {self.qualified}\n")
        r = subprocess.run([str(pathlib.Path(self.cfg["LEAN_TC"]) / "bin/lake"), "env", "lean", str(f)],
                           cwd=self.proj, capture_output=True, text=True, timeout=600)
        out = r.stdout + r.stderr
        (self.out / f"{tag}.lean").write_text(text)
        (self.out / f"{tag}.log").write_text(out)
        if re.search(r"unknown module prefix|object file .* does not exist|No directory '.*' or file", out):
            raise SetupError("project imports are not built; run scripts/preflight_lake_build.sh first:\n"
                             + out[-800:])
        errors = [b for b in re.split(r"\n(?=\S+\.lean:\d+:\d+: )", out) if ": error" in b.split("\n")[0]]
        if r.returncode != 0 or errors:
            return False, "\n".join(errors)[:4000] or out[-4000:]
        m = re.search(rf"'{re.escape(self.qualified)}' depends on axioms: \[([^\]]*)\]", out)
        axioms = {x.strip() for x in m.group(1).split(",")} if m else set()
        if "does not depend on any axioms" not in out and not m:
            return False, "could not read the axioms of the lemma:\n" + out[-2000:]
        if axioms - ALLOWED_AXIOMS:
            return False, f"lemma rests on disallowed axioms: {sorted(axioms - ALLOWED_AXIOMS)}"
        return True, f"axioms: {sorted(axioms)}"

    def sample(self, k: int) -> dict:
        url = self.slots.get()  # an endpoint slot; every round of this sample goes to the same endpoint
        try:
            return self._sample(k, url)
        finally:
            self.slots.put(url)

    def _sample(self, k: int, url: str) -> dict:
        rec = {"stage": self.st["stage"], "sample": k, "endpoint": url, "rounds": []}
        prompt = PROMPTS[self.st["prompt"]]
        messages = [{"role": "user", "content": prompt.format(code=self.problem)}]
        for rnd in range(self.st["rounds"] + 1):
            if self.done.is_set():
                rec["cancelled"] = True
                return rec
            t0 = time.time()
            try:
                reply = self.ask(messages, url)
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                rec["rounds"].append({"round": rnd, "error": f"endpoint: {e}"})
                rec["endpoint_error"] = True
                return rec
            tag = f"{self.st['stage']}-s{k:03d}r{rnd}"
            (self.out / f"{tag}.reply.md").write_text(reply)
            code = extract_code(reply)
            text = self.splice(code) if code else None
            if text is None:
                rec["rounds"].append({"round": rnd, "seconds": round(time.time() - t0, 1),
                                      "result": "no usable code block (reply cut off or lemma missing)"})
                rec["sig"] = "no-code"
                return rec  # nothing to repair from
            ok, msg = self.check(text, tag)
            rec["rounds"].append({"round": rnd, "seconds": round(time.time() - t0, 1), "ok": ok, "msg": msg[:500]})
            if ok:
                rec["ok"], rec["text"] = True, text
                self.done.set()
                return rec
            rec["sig"] = failure_signature(msg)  # how the latest round failed
            if rec["sig"].startswith("unsolved:"):
                rec["goals"] = sorted(unsolved_goals(msg))
            else:
                rec.pop("goals", None)
            messages = [{"role": "user", "content": (prompt + REPAIR_TAIL).format(
                code=self.problem, errors=msg[:3000], attempt=code, name=self.a.lemma)}]
        return rec

    def run(self) -> dict:
        t0 = time.time()
        results, win, per_stage = [], None, []
        for st in self.stages:
            self.st = st
            up = [u for u in st["base_urls"] if reachable(u)]
            down = [u for u in st["base_urls"] if u not in up]
            if not up:
                per_stage.append({"stage": st["stage"], "endpoints": st["base_urls"], "model": st["model"],
                                  "skipped": "no endpoint reachable"})
                continue
            self.slots = queue.Queue()
            for _ in range(st["slots"]):
                for u in up:  # interleaved, so samples alternate between endpoints
                    self.slots.put(u)
            self.ep_tokens = {}
            ts, tok0, mine = time.time(), self.tokens, []
            with cf.ThreadPoolExecutor(max_workers=st["slots"] * len(up)) as ex:
                futs = [ex.submit(self.sample, k) for k in range(st["budget"])]
                for f in cf.as_completed(futs):
                    if f.cancelled():  # never started: the lemma was already closed
                        continue
                    r = f.result()
                    mine.append(r)
                    if r.get("ok") and win is None:
                        win = r
                        for g in futs:
                            g.cancel()
            results += mine
            per_stage.append({
                "stage": st["stage"], "endpoints": up, "endpoints_down": down, "model": st["model"],
                "slots_per_endpoint": st["slots"],
                "per_endpoint": {u: {"samples": sum(1 for r in mine if r.get("endpoint") == u and r["rounds"]),
                                     "rounds": sum(len(r["rounds"]) for r in mine if r.get("endpoint") == u),
                                     "closed": sum(1 for r in mine if r.get("endpoint") == u and r.get("ok")),
                                     "completion_tokens": self.ep_tokens.get(u, 0)} for u in up},
                "budget": st["budget"], "rounds_per_sample": st["rounds"], "prompt": st["prompt"],
                "closed": bool(win), "samples_run": sum(1 for r in mine if r["rounds"]),
                "rounds_total": sum(len(r["rounds"]) for r in mine),
                "completion_tokens": self.tokens - tok0, "seconds": round(time.time() - ts, 1),
                "endpoint_errors": sum(1 for r in mine if r.get("endpoint_error")),
                "failure_signatures": dict(collections.Counter(r["sig"] for r in mine if r.get("sig") and not r.get("ok"))),
                "same_failure": None if win else same_failure(mine, conclusion(self.statement)),
            })
            if win:
                break
        ran = [x for x in per_stage if "skipped" not in x]
        report = {
            "lemma": self.a.lemma, "qualified": self.qualified, "file": self.a.file,
            "closed": win is not None, "closed_by_stage": win["stage"] if win else None,
            "budget": sum(x["budget"] for x in ran), "cascade": [x["stage"] for x in per_stage],
            "samples_run": sum(1 for r in results if r["rounds"]),
            "winning_sample": win["sample"] if win else None,
            "completion_tokens": self.tokens, "seconds": round(time.time() - t0, 1),
            "endpoints": ran[-1]["endpoints"] if ran else None, "model": ran[-1]["model"] if ran else None,
            "closed_by_endpoint": win.get("endpoint") if win else None,
            "endpoint_errors": sum(1 for r in results if r.get("endpoint_error")),
            "stages_skipped": [x["stage"] for x in per_stage if "skipped" in x],
            "core_only": self.core_only,
            "rounds_total": sum(len(r["rounds"]) for r in results),
            "rounds_rejected_mathlib": sum(1 for r in results for x in r["rounds"]
                                           if str(x.get("msg", "")).startswith("mathlib:")),
            "rounds_rejected_policy": sum(1 for r in results for x in r["rounds"]
                                          if str(x.get("msg", "")).startswith("policy:")),
            "rounds_no_code": sum(1 for r in results for x in r["rounds"] if "result" in x),
            # Early-wall inputs: how each failed sample ended, and whether the samples of the last
            # stage that ran (the strongest model) all ended alike.
            "failure_signatures": dict(collections.Counter(r["sig"] for r in results
                                                           if r.get("sig") and not r.get("ok"))),
            "same_failure": None if win or not ran else ran[-1]["same_failure"],
            "stages": per_stage,
            "attempts": [{k: v for k, v in r.items() if k != "text"}
                         for r in sorted(results, key=lambda r: (r["stage"], r["sample"]))],
        }
        if win:
            proof = win["text"][len("".join(self.lines[:self.s])):]
            report["proof"] = proof[:len(proof) - len("".join(self.lines[self.e:]).lstrip("\n"))].strip()
            if self.a.apply:
                self.file.write_text(win["text"])
                report["applied"] = True
        return report


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--project", required=True)
    ap.add_argument("--file", required=True)
    ap.add_argument("--lemma", required=True)
    ap.add_argument("--budget", type=int)
    ap.add_argument("--rounds", type=int)
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--out")
    ap.add_argument("--config", default=str(pathlib.Path(__file__).resolve().parent.parent / "config/tier2.env"))
    a = ap.parse_args()
    cfg = load_env(pathlib.Path(a.config), dict(os.environ))
    a.budget = a.budget if a.budget is not None else int(cfg.get("TIER2_BUDGET", 4))
    a.out = a.out or str(pathlib.Path(a.project) / ".lake" / "fv-prover" / f"run-{a.lemma}-{int(time.time())}")
    try:
        prover = Prover(a, cfg)
        prover.stages = stages(cfg, a.budget, a.rounds)
        report = prover.run()
    except SetupError as e:
        print(json.dumps({"lemma": a.lemma, "closed": False, "setup_error": str(e)}, indent=2))
        sys.exit(3)
    pathlib.Path(a.out, "result.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    print(json.dumps(report, indent=2, ensure_ascii=False))
    if report["closed"]:
        sys.exit(0)
    no_stage = not report["samples_run"] and report["stages_skipped"]
    sys.exit(3 if no_stage or (report["endpoint_errors"] == report["samples_run"] and report["samples_run"]) else 1)


if __name__ == "__main__":
    main()
