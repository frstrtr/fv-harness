# fv_diff.py — harness-owned differential driver for Python implementations (Atheris / libFuzzer).
#
# The Python counterpart of fuzz/diff_oracle_template.cpp and fuzz/rust/fv_diff.rs. The project
# supplies only a binding module (fuzz/binding.py); this file owns everything a project must not
# be able to weaken:
#   - loading the Lean oracle (oracle_shared, built from the locked spec) through ctypes;
#   - decoding: an admissible initial state, 1..64 operations or one operation repeated;
#   - the step loop: after EVERY step the oracle's and the implementation's states must be equal;
#   - the integer domain: Python integers are unbounded, so every value the implementation returns
#     must lie in [0, 2^64) (the oracle's C boundary); a value outside FAILs ("DOMAIN") instead of
#     being reduced, so a difference that only shows above 2^64 cannot be masked;
#   - the mismatch report: both states printed, the input written to
#     $FV_FUZZ_ARTIFACT_DIR/mismatch-<fnv1a>, exit status 86.
# fuzz/run_fuzz.sh --lang python runs it as `python -I fv_diff.py <libFuzzer args>` with
#   FV_BINDING    the project's binding.py      FV_IMPL_DIR  the implementation's directory
#   FV_ORACLE_SO  the oracle shared library
#   FV_HARNESS_PY (optional) harness module directories the binding may import (--lang tron-tvm: fuzz/tron-tvm)
# and refuses a binding that defines its own TestOneInput or calls atheris.Setup/Fuzz.
#
# The binding module defines:
#   ORACLE_FUNCS = {"c_name": n_args, ...}      exported oracle functions (uint64 in, uint64 out)
#   IMPL_MODULE  = "name" or None                module in FV_IMPL_DIR (instrumented for coverage);
#                                                None when the implementation runs elsewhere (a contract)
#   initial_state(inp) -> state                  an ADMISSIBLE state (the statements' hypotheses)
#   make_op(inp, state) -> op
#   oracle_step(lib, state, op) -> state         lib = the loaded oracle
#   impl_step(impl, state, op) -> state          impl = the imported implementation module
#   u64_values(state) -> [(name, value), ...]    the values that must lie in [0, 2^64)
#   same(a, b) -> bool;  show_state(state) -> str;  show_op(op) -> str

import os
import sys

import atheris

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # fv_input (python -I adds no script dir)
from fv_input import U64, Input, fnv1a as _fnv1a, harness_paths, load, load_oracle, prefix  # noqa: E402

MISMATCH_EXIT = 86

harness_paths()
B = load(os.environ["FV_BINDING"], "fv_binding")
LIB = load_oracle(B)
TRON_TVM = bool(os.environ.get("FV_TRON_TVM_CMD"))  # the implementation is a contract on the TRON-TVM


def _executor_error(msg: str) -> None:
    """TRON-TVM: a failure that is the binding's or the executor's, never a finding: ERROR (exit 87)."""
    sys.stderr.write(f"fv_tron_tvm: EXECUTOR ERROR: {msg}\n")
    sys.stderr.flush()
    os._exit(87)


def _tx_count() -> int:
    m = sys.modules.get("fv_tron_tvm")
    return m.TX_COUNT if m is not None else -1


IMPL = None
if B.IMPL_MODULE:
    sys.path.insert(0, os.environ["FV_IMPL_DIR"])
    with atheris.instrument_imports():
        IMPL = __import__(B.IMPL_MODULE)
else:
    # No implementation module (TRON-TVM: the implementation runs outside Python, so nothing above gives
    # coverage feedback). Instrument the binding's own functions: their branches follow the outcome
    # cases the binding distinguishes, which guides the fuzzer over those. Harness modules (the
    # executor client) are not instrumented. Guidance only: nothing here changes what is compared.
    import inspect
    _n_instr = 0
    for _k, _v in list(vars(B).items()):
        if inspect.isfunction(_v) and _v.__module__ == B.__name__:
            setattr(B, _k, atheris.instrument_func(_v))
            _n_instr += 1
    sys.stderr.write(f"diff-oracle: no IMPL_MODULE: {_n_instr} binding function(s) instrumented for coverage guidance\n")
if hasattr(B, "warm_up"):
    try:
        B.warm_up()  # e.g. start the reference executor and deploy, before the first input
    except Exception as _e:
        if TRON_TVM:
            _executor_error(f"warm_up raised {type(_e).__name__}: {str(_e)[:200]}")
        raise



def _fail(kind: str, data: bytes, step: int, before, op, want, got, extra: str = "") -> None:
    e = sys.stderr
    e.write(f"diff-oracle: {kind} at step {step}{extra}\n")
    e.write(f"  before {B.show_state(before)}\n  op     {B.show_op(op)}\n")
    e.write(f"  oracle {B.show_state(want)}\n  impl   {B.show_state(got)}\n")
    d = os.environ.get("FV_FUZZ_ARTIFACT_DIR") or "."
    path = f"{d}/mismatch-{_fnv1a(data):016x}"
    try:
        with open(path, "wb") as f:
            f.write(data)
        e.write(f"diff-oracle: reproducer written to {path}\n")
    except OSError as err:
        e.write(f"diff-oracle: could not write reproducer to {path}: {err}\n")
    e.flush()
    os._exit(MISMATCH_EXIT)


PHASE = ["start"]  # where in one input the loop is (named when the binding raises)


def TestOneInput(data: bytes) -> None:
    if not TRON_TVM:
        return _test_one(data)
    try:
        _test_one(data)
    except Exception as e:  # TRON-TVM has no Python implementation: an exception is the binding's or the harness's
        # Kept for debugging as artifacts/binding-error-<fnv1a> (the run is ERROR; the input never joins
        # the corpus).
        path = f"{os.environ.get('FV_FUZZ_ARTIFACT_DIR') or '.'}/binding-error-{_fnv1a(data):016x}"
        try:
            with open(path, "wb") as f:
                f.write(data)
        except OSError:
            path = "(could not be written)"
        _executor_error(f"the binding or the client raised {type(e).__name__} in {PHASE[0]}: {str(e)[:200]} (input: {path})")


def _test_one(data: bytes) -> None:
    inp = Input(data)
    s, steps, saturate, repeated = prefix(B, inp, PHASE)
    for i in range(steps):
        PHASE[0] = f"make_op (step {i})"
        op = repeated if saturate else B.make_op(inp, s)
        PHASE[0] = f"oracle_step (step {i})"
        want = B.oracle_step(LIB, s, op)
        c0 = _tx_count()
        PHASE[0] = f"impl_step (step {i})"
        got = B.impl_step(IMPL, s, op)
        if TRON_TVM and (c0 < 0 or _tx_count() <= c0):
            _executor_error(f"step {i}: impl_step sent no transaction to the TRON-TVM (every step must run on the reference)")
        PHASE[0] = f"u64_values / same (step {i})"
        for name, v in B.u64_values(got):
            if not isinstance(v, int) or not 0 <= v < U64:
                _fail("DOMAIN", data, i, s, op, want, got, f" ({name} = {v!r} is outside [0, 2^64))")
        if not B.same(want, got):
            _fail("MISMATCH", data, i, s, op, want, got)
        s = want


if __name__ == "__main__":
    if os.environ.get("FV_SELF"):  # the corpus merge re-executes argv[0]: make it the run's wrapper
        sys.argv[0] = os.environ["FV_SELF"]
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
