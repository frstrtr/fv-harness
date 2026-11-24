# fv_classify.py — the labels-only replay for Python and TRON-TVM bindings (never compares).
#
# The Python counterpart of the C++ <target>_classify build and the Rust `--cfg fv_classify` build.
# fuzz/run_fuzz.sh runs it through its own wrapper ($RUN/classify-<target>), never as the verdict
# driver; it prints "diff-oracle: CLASSIFY BUILD", and a verdict log holding that line is ERROR.
#
# It walks each input through the ORACLE only, with the verdict driver's decode (fv_input.py):
#   - the implementation module (IMPL_MODULE) is never imported and impl_step is never called;
#   - TRON-TVM: warm_up() deploys the contract (oracle_step builds the expected outcome from the
#     deployed address); after that the client's transaction count must not change, else every
#     further input is refused and the log records the error;
#   - the classes come from FV_CLASSES_PY (classes.py next to binding.py; fuzz/python/fv_sink.py).
# classes.py is read once; its sha256 is taken over the bytes that are compiled and run, and each
# fv_class's lambda source is taken from those same bytes. The first log line of every process is a
# header {"classes_header": {file, file_sha256, classes: [{name, source}]}}; classify_report.py
# re-reads the file and requires the same sha256, names and sources.
#
# Modes (as the C++ template): FV_CLASSIFY=<log> appends one JSON line per input;
# FV_CLASSIFY_RENDER=1 prints each step with its classes; FV_CLASSIFY_RETAIN=<dir> (the class-guided
# retention pass, run as a fuzzer with a fixed -seed) writes the first input that hits each class to
# <dir>/<fnv1a>. Arguments are libFuzzer's (-runs=0 FILES/DIRS, or -seed/-runs for retention).

import ast
import hashlib
import json
import os
import sys

import atheris

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fv_input import Input, fnv1a, harness_paths, load, load_oracle, prefix  # noqa: E402
import fv_sink  # noqa: E402

sys.stderr.write("diff-oracle: CLASSIFY BUILD (labels only, no comparison)\n")
LOG = os.environ.get("FV_CLASSIFY") or None
RENDER = os.environ.get("FV_CLASSIFY_RENDER") is not None
RETAIN = os.environ.get("FV_CLASSIFY_RETAIN") or None
RETAINED = set()  # classes that already have an input in RETAIN (this process)
if RETAIN:
    sys.stderr.write(f"diff-oracle: CLASSIFY RETAIN {RETAIN}\n")


def class_sources(text: str) -> list:
    """[(name, source)] of the literal fv_class("name", lambda ...: expr) calls, in file order."""
    out = []
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", None)) == "fv_class":
            if (len(node.args) != 2 or not isinstance(node.args[0], ast.Constant) or not isinstance(node.args[0].value, str)
                    or not isinstance(node.args[1], ast.Lambda)):
                raise ValueError(f"line {node.lineno}: fv_class needs a string name and a lambda (its source is shown to the reviewer)")
            src = ast.get_source_segment(text, node.args[1].body)
            out.append((node.args[0].value, " ".join(src.split())))
    return sorted(out, key=lambda t: t[0])


def _header_error(msg: str) -> None:
    if LOG:
        with open(LOG, "a") as f:
            f.write(json.dumps({"error": msg}) + "\n")
    sys.stderr.write(f"diff-oracle: CLASSIFY ERROR: {msg}\n")


def load_classes():
    """describe, CLASSES, UNIVERSE from FV_CLASSES_PY, and the header record (hash-what-you-exec)."""
    path = os.environ.get("FV_CLASSES_PY") or ""
    hdr = {"file": path or None, "file_sha256": None, "classes": []}
    if not path or not os.path.isfile(path):
        return None, [], [], hdr
    raw = open(path, "rb").read()
    hdr["file_sha256"] = hashlib.sha256(raw).hexdigest()
    text = raw.decode()
    srcs = class_sources(text)
    mod = type(sys)("fv_classes")
    mod.__file__ = path
    exec(compile(raw, path, "exec"), mod.__dict__)
    classes = list(getattr(mod, "CLASSES", []))
    if sorted(c.name for c in classes) != [n for n, _ in srcs]:
        raise ValueError("CLASSES must be literal fv_class(\"name\", lambda ...) calls, one per class: names in the file "
                         f"{[n for n, _ in srcs]}, at run time {sorted(c.name for c in classes)}")
    hdr["classes"] = [{"name": n, "source": s} for n, s in srcs]
    return getattr(mod, "describe", None), classes, list(getattr(mod, "UNIVERSE", [])), hdr


harness_paths()
B = load(os.environ["FV_BINDING"], "fv_binding")
LIB = load_oracle(B)
TRON_TVM = bool(os.environ.get("FV_TRON_TVM_CMD"))
try:
    DESCRIBE, CLASSES, UNIVERSE, HEADER = load_classes()
except Exception as e:  # noqa: BLE001 — labels only: record and stop, never a verdict
    _header_error(f"classes.py: {type(e).__name__}: {e}")
    sys.exit(3)
if LOG:
    with open(LOG, "a") as f:
        f.write(json.dumps({"classes_header": HEADER}) + "\n")
if hasattr(B, "warm_up"):
    B.warm_up()  # TRON-TVM: start the reference executor and deploy (no step is ever sent)


def _tx_count() -> int:
    m = sys.modules.get("fv_tron_tvm")
    return m.TX_COUNT if m is not None else -1


TX0 = _tx_count()
PHASE = ["start"]


def TestOneInput(data: bytes) -> None:
    if TRON_TVM and _tx_count() != TX0:
        _header_error(f"the TRON-TVM client sent {_tx_count() - TX0} transaction(s) during the oracle-only replay")
        os._exit(3)
    inp = Input(data)
    s, steps, saturate, repeated = prefix(B, inp, PHASE)
    hits, universe, regular = {}, set(UNIVERSE), 0
    universe.update("domain: " + c.name for c in CLASSES)
    if RENDER:
        print(f"=== input {fnv1a(data):016x} ({len(data)} bytes, {steps} steps{', one operation repeated' if saturate else ''})")
    for i in range(steps):
        op = repeated if saturate else B.make_op(inp, s)
        want = B.oracle_step(LIB, s, op)
        k = fv_sink.Sink()
        if DESCRIBE:
            DESCRIBE(k, s, op, want)
        dom = [c.name for c in CLASSES if c.pred(s, op, want)]
        universe.update("generic: " + c for c in k.universe)
        names = ["generic: " + c for c in k.hits] + ["domain: " + c for c in dom]
        if not names:
            regular += 1
        for c in names + k.infos:
            first, n = hits.get(c, (i, 0))
            hits[c] = (first, n + 1)
        if RENDER:
            print(f"--- step {i}\n  before {B.show_state(s)}\n  op     {B.show_op(op)}\n  oracle {B.show_state(want)}")
            print("  classes:" + "".join(f" [{c}]" for c in names + k.infos))
        s = want
    if TRON_TVM and _tx_count() != TX0:
        _header_error(f"the TRON-TVM client sent {_tx_count() - TX0} transaction(s) during the oracle-only replay")
        os._exit(3)
    if RETAIN:
        new = [c for c in hits if c not in RETAINED]
        if new:
            RETAINED.update(new)
            path = os.path.join(RETAIN, f"{fnv1a(data):016x}")
            if not os.path.exists(path):
                with open(path, "wb") as f:
                    f.write(data)
    if LOG:
        rec = {"h": f"{fnv1a(data):016x}", "n": len(data), "steps": steps, "regular": regular, "impl_ns": 0,
               "hits": {c: list(v) for c, v in sorted(hits.items())}, "universe": sorted(universe)}
        with open(LOG, "a") as f:
            f.write(json.dumps(rec) + "\n")
    if RENDER:
        sys.stdout.flush()


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
