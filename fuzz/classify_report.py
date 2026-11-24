"""classify_report.py — edge-case coverage table and review deck from a classification replay.

    classify_report.py --log LOG --bin FUZZER --out DIR [--corpus DIR...] [--classes-header FILE]
                       [--findings FILE...] [--per-class 3] [--max-deck 60]

LOG is the FV_CLASSIFY log the fuzzer wrote while replaying the corpus with the oracle only
(fuzz/fv_classify.hpp). Inputs are counted once each (by content hash). Writes DIR/classes.json
and DIR/review_deck.md, and prints a summary for fuzz.json on stdout.

Labels only: nothing here can change a verdict. A class with 0 hits among the classes the
binding declared possible is listed as NOT EXERCISED.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile


def fnv1a(data: bytes) -> str:
    h = 1469598103934665603
    for b in data:
        h = ((h ^ b) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return f"{h:016x}"


def read_log(path: pathlib.Path, headers: list | None = None, errors: list | None = None) -> dict:
    """Per-input records by hash; the replay's class headers and errors go to `headers` / `errors`."""
    seen = {}
    if path.is_file():
        for line in path.read_text(errors="replace").splitlines():
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(r, dict):
                continue
            if "classes_header" in r:
                if headers is not None:
                    headers.append(r["classes_header"])
            elif "error" in r:
                if errors is not None:
                    errors.append(str(r["error"]))
            elif "h" in r:
                seen.setdefault(r["h"], r)  # one record per distinct input
    return seen


def squash(s: str) -> str:
    return re.sub(r"\s+", "", s)


def macro_sources(path: pathlib.Path, macro: str, closure: bool) -> dict:
    """MACRO("name", expression) -> {name: expression source}: FV_CLASS in classes.hpp, or
    fv_class!("name", |before, op, after| expression) in a Rust target (closure=True)."""
    src = re.sub(r"//[^\n]*", "", path.read_text())
    out, i = {}, 0
    while True:
        i = src.find(macro, i)
        if i < 0:
            break
        j = i + len(macro)
        m = re.match(r'\s*"((?:[^"\\]|\\.)*)"\s*,', src[j:])
        if not m:
            i = j
            continue
        name = bytes(m.group(1), "utf-8").decode("unicode_escape")
        k = j + m.end()
        depth, e = 1, k
        while e < len(src) and depth:
            depth += {"(": 1, ")": -1}.get(src[e], 0)
            e += 1
        body = src[k:e - 1]
        if closure:
            body = re.sub(r"^\s*\|[^|]*\|", "", body)
        out[name] = re.sub(r"\s+", " ", body).strip()
        i = e
    return out


def py_sources(path: pathlib.Path) -> dict:
    """fv_class("name", lambda before, op, after: expression) in classes.py -> {name: expression source}."""
    import ast
    text = path.read_text()
    out = {}
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", None)) == "fv_class":
            if (len(node.args) == 2 and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)
                    and isinstance(node.args[1], ast.Lambda)):
                out[node.args[0].value] = " ".join(ast.get_source_segment(text, node.args[1].body).split())
            else:
                raise ValueError(f"{path.name} line {node.lineno}: fv_class needs a string name and a lambda")
    return out


def check_sources(headers: list, sources: dict, file_sha: str | None, ran_sha: str | None) -> str | None:
    """The class predicates the replay ran must be the ones in the file the report shows."""
    if not headers:
        return None
    first = headers[0]
    for h in headers[1:]:
        if h.get("classes") != first.get("classes") or h.get("file_sha256") != first.get("file_sha256"):
            return "class sources differ from what ran: the replay processes reported different class sets"
    ran = {c["name"]: c["source"] for c in first.get("classes", [])}
    if sorted(ran) != sorted(sources):
        return f"class sources differ from what ran: names in the file {sorted(sources)}, in the replay {sorted(ran)}"
    for n in ran:
        if squash(ran[n]) != squash(sources[n]):
            return f"class sources differ from what ran: '{n}' is `{sources[n]}` in the file, `{ran[n]}` in the replay"
    ran_sha = first.get("file_sha256") or ran_sha
    if ran_sha and file_sha != ran_sha:
        return f"class sources differ from what ran: the classes file's sha256 is {file_sha} now, {ran_sha} when it ran"
    return None


def domain_sources(header: pathlib.Path | None) -> dict:
    """FV_CLASS("name", expression) -> {name: expression source}."""
    return macro_sources(header, "FV_CLASS(", False) if header and header.is_file() else {}


def kind(c: str) -> str:
    return c.split(":", 1)[0]


def render(binary: str, files: list[str], env: dict) -> dict:
    """FV_CLASSIFY_RENDER output of the oracle-only replay, split per input hash."""
    if not files:
        return {}
    e = dict(env)
    e.pop("FV_CLASSIFY", None)
    e.pop("FV_CLASSIFY_TIME_IMPL", None)
    e["FV_CLASSIFY_RENDER"] = "1"
    r = subprocess.run([binary, "-runs=0", "-timeout=30", *files], capture_output=True, text=True, env=e, timeout=600)
    blocks, cur = {}, None
    for line in r.stdout.splitlines():
        m = re.match(r"=== input ([0-9a-f]{16})", line)
        if m:
            cur = m.group(1)
            blocks[cur] = [line]
        elif cur:
            blocks[cur].append(line)
    return blocks


def excerpt(block: list[str], first: int, context: int = 1) -> list[str]:
    """The header, then steps max(0, first-context) .. first."""
    out, keep = [block[0]], False
    for line in block[1:]:
        m = re.match(r"--- step (\d+)", line)
        if m:
            s = int(m.group(1))
            keep = first - context <= s <= first
            if s == first - context and s > 0:
                out.append(f"  ... {s} earlier step(s) not shown")
        if keep:
            out.append(line)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True)
    ap.add_argument("--bin", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--corpus", nargs="*", default=[])
    ap.add_argument("--classes-header")
    ap.add_argument("--classes-file", help="the Rust fuzz target (fv_class!) or classes.py (fv_class)")
    ap.add_argument("--classes-file-sha256", help="the classes file's sha256 when its build ran (Rust)")
    ap.add_argument("--findings", nargs="*", default=[])
    ap.add_argument("--retention", default="null", help="the retention pass's record (fuzz/run_fuzz.sh step 4b), JSON")
    ap.add_argument("--per-class", type=int, default=2)
    ap.add_argument("--max-deck", type=int, default=40)
    a = ap.parse_args()
    out = pathlib.Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)

    headers, errors = [], []
    recs = read_log(pathlib.Path(a.log), headers, errors)
    header = pathlib.Path(a.classes_header) if a.classes_header else None
    cfile = pathlib.Path(a.classes_file) if a.classes_file else (header if header and header.is_file() else None)
    src_error = None
    if a.classes_file:
        try:
            sources = (py_sources(cfile) if cfile.suffix == ".py" else macro_sources(cfile, "fv_class!(", True)) \
                if cfile.is_file() else {}
        except (ValueError, SyntaxError) as e:
            sources, src_error = {}, f"classes file: {e}"
    else:
        sources = domain_sources(header)
    cfile_sha = hashlib.sha256(cfile.read_bytes()).hexdigest() if cfile and cfile.is_file() else None
    src_error = src_error or check_sources(headers, sources, cfile_sha, a.classes_file_sha256)
    if a.classes_file and not headers and sources:
        src_error = "class sources differ from what ran: the replay reported no class header"
    canon = json.dumps([{"name": n, "source": sources[n]} for n in sorted(sources)], separators=(",", ":"))
    n_in = len(recs)
    n_steps = sum(r["steps"] for r in recs.values())
    reg_steps = sum(r["regular"] for r in recs.values())
    reg_inputs = sum(1 for r in recs.values() if r["regular"] == r["steps"])
    universe = set()
    for r in recs.values():
        universe.update(r["universe"])
    universe.update("domain: " + n for n in sources)
    stats = {c: {"inputs": 0, "steps": 0} for c in universe}
    for r in recs.values():
        for c, (first, cnt) in r["hits"].items():
            st = stats.setdefault(c, {"inputs": 0, "steps": 0})
            st["inputs"] += 1
            st["steps"] += cnt
    # timing (informational): the slowest 1 % of inputs by C++ time per step
    timed = sorted(((r.get("impl_ns", 0) / max(r["steps"], 1), h) for h, r in recs.items() if r.get("impl_ns")),
                   reverse=True)
    slow_cls = "timing: slowest 1% (C++ time per step)"
    slowest = timed[:max(1, len(timed) // 100)] if timed else []
    for ns, h in slowest:
        recs[h]["hits"][slow_cls] = [0, recs[h]["steps"]]
    if slowest:
        stats[slow_cls] = {"inputs": len(slowest), "steps": sum(recs[h]["steps"] for _, h in slowest)}
    order = {"domain": 0, "generic": 1, "outcome": 2, "timing": 3}
    names = sorted(stats, key=lambda c: (order.get(kind(c), 3), c))
    table = []
    for c in names:
        st = stats[c]
        table.append({"class": c, "kind": kind(c), "inputs": st["inputs"], "steps": st["steps"],
                      "pct_inputs": round(100 * st["inputs"] / n_in, 2) if n_in else 0.0,
                      "pct_steps": round(100 * st["steps"] / n_steps, 2) if n_steps else 0.0,
                      **({"source": sources.get(c.split(": ", 1)[1], "")} if kind(c) == "domain" else {})})
    # outcome labels are informational unless the binding declared them (universe): then a 0 counts
    not_exercised = [t["class"] for t in table if t["inputs"] == 0 and t["kind"] in ("generic", "domain", "outcome")]

    # exemplars: the smallest inputs per class, domain classes first, every hit class at least one
    by_hash = {}
    for d in a.corpus:
        for f in sorted(pathlib.Path(d).glob("*")) if pathlib.Path(d).is_dir() else []:
            if f.is_file():
                by_hash.setdefault(fnv1a(f.read_bytes()), str(f))
    picks = {}
    for c in names:
        if stats[c]["inputs"] == 0:
            continue
        cand = sorted(((r["n"], h, r["hits"][c][0]) for h, r in recs.items() if c in r["hits"] and h in by_hash))
        picks[c] = cand[:a.per_class if kind(c) == "domain" else 1]  # domain classes get more
    deck_items, budget = [], a.max_deck
    for rnd in range(a.per_class):  # round-robin so every class gets one before any gets three
        for c in names:
            if c in picks and len(picks[c]) > rnd and budget > 0:
                deck_items.append((c, picks[c][rnd]))
                budget -= 1
    blocks = render(a.bin, sorted({by_hash[h] for _, (_, h, _) in deck_items}), env)

    hdr_sha = hashlib.sha256(header.read_bytes()).hexdigest() if header and header.is_file() else None
    md = ["# Edge-case review deck", "",
          "Labels only: these classes never decide PASS/FAIL. They come from a replay of the corpus",
          "through the Lean oracle alone, after the campaign; the implementation is not called in",
          "that replay. For every corpus input below, the campaign checked that the implementation's output equals the oracle",
          "output at every step.", "",
          f"- inputs classified: {n_in} (distinct), steps: {n_steps}",
          f"- regular (no edge class): {reg_inputs} inputs, {reg_steps} steps",
          f"- domain classes: `{cfile.name if cfile else 'classes.hpp'}` sha256 {cfile_sha or '(none)'}",
          f"- class sources checked against what ran: {src_error or 'yes' if a.classes_file else 'n/a (C++: classes.hpp)'}", ""]
    try:
        ret = json.loads(a.retention) if a.retention else None
    except json.JSONDecodeError:
        ret = None
    if ret and ret.get("complete") and ret.get("runs"):
        md += ["## NOT EXERCISED (corpus and class-guided retention)", "",
               f"No input in the corpus hits these, and none of {ret['runs']} executions of the generator by the",
               f"retention pass did (oracle only, seed {ret['seed']}, value profiling; {len(ret.get('retained') or [])}",
               "inputs kept, one per class first hit, each then compared by the verdict binary). Read each entry",
               "as 'not generated in that budget': add a seed for it, or widen the generator, and re-run.", ""]
    else:
        md += ["## NOT EXERCISED (in the retained corpus)", "",
               "The corpus keeps only inputs that added code coverage, so an edge case can be generated during",
               "the campaign and still be missing here. Treat each entry as 'not shown to be covered': add a",
               "seed for it, or widen the generator, and re-run."
               + (f" (Retention: {ret.get('error') or ret.get('skipped')}.)" if ret else ""), ""]
    md += ([f"- **{c}**" for c in not_exercised] or ["- none"]) + [""]
    md += ["## Coverage", "", "| Class | Inputs | % inputs | Steps | % steps |", "|---|---|---|---|---|"]
    md += [f"| {t['class']}{' (NOT EXERCISED)' if t['class'] in not_exercised else ''} | {t['inputs']} | "
           f"{t['pct_inputs']} | {t['steps']} | {t['pct_steps']} |" for t in table]
    if sources:
        md += ["", f"## Domain class predicates ({cfile.name if cfile else 'classes.hpp'})", ""]
        md += [f"- **{n}**: `{s}`" for n, s in sources.items()]
    if timed:
        md += ["", "## Slowest inputs (C++ time per step, from the replay; informational)", "",
               "| Input | Bytes | Steps | µs per step |", "|---|---|---|---|"]
        md += [f"| {h} | {recs[h]['n']} | {recs[h]['steps']} | {ns / 1000:.1f} |" for ns, h in timed[:5]]
        med = timed[len(timed) // 2][0]
        md += ["", f"Median: {med / 1000:.1f} µs per step over {len(timed)} inputs. A slowest input far above the median",
               "on a short sequence can mean an accidental quadratic or a loop over a growing structure."]
    md += ["", "## Exemplars (the smallest inputs per class; one step of context before the first hit)", ""]
    for c, (n, h, first) in deck_items:
        md += [f"### {c}", "", f"input {h}, {n} bytes, first hit at step {first}" +
               (f"; predicate: `{sources.get(c.split(': ', 1)[1], '')}`" if kind(c) == "domain" else ""),
               "", "```text"] + excerpt(blocks.get(h, ["(not rendered)"]), first) + ["```", ""]

    finding_classes = {}
    if a.findings:
        with tempfile.TemporaryDirectory() as td:
            log = pathlib.Path(td) / "findings.jsonl"
            e = dict(env, FV_CLASSIFY=str(log))
            e.pop("FV_CLASSIFY_RENDER", None)
            e.pop("FV_CLASSIFY_TIME_IMPL", None)  # a hanging reproducer must not hang the report
            subprocess.run([a.bin, "-runs=0", "-timeout=30", *a.findings], capture_output=True, env=e, timeout=600)
            fr = read_log(log)
            for f in a.findings:
                h = fnv1a(pathlib.Path(f).read_bytes())
                finding_classes[pathlib.Path(f).name] = sorted(fr.get(h, {}).get("hits", {}))
        md += ["## Findings and their classes", ""] + [f"- `{f}`: {', '.join(c) or 'regular'}"
                                                       for f, c in finding_classes.items()] + [""]

    (out / "review_deck.md").write_text("\n".join(md) + "\n")
    summary = {"timing_us_per_step": {"median": round(timed[len(timed) // 2][0] / 1000, 2) if timed else None,
                                      "slowest": [{"input": h, "us_per_step": round(ns / 1000, 2)} for ns, h in timed[:5]]},
               "labels_only": True, "inputs": n_in, "steps": n_steps, "regular_inputs": reg_inputs,
               "regular_steps": reg_steps, "classes": table, "not_exercised": not_exercised,
               "classes_header_sha256": hdr_sha, "review_deck": str(out / "review_deck.md"),
               "classes_file": str(cfile) if cfile else None, "classes_file_sha256": cfile_sha,
               "classes_source_sha256": hashlib.sha256(canon.encode()).hexdigest() if sources else None,
               "finding_classes": finding_classes}
    errs = ([src_error] if src_error else []) + sorted(set(errors))
    if errs:
        summary["error"] = "; ".join(errs)[:2000]
    (out / "classes.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
