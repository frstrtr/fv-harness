"""make_variants.py DIES_BINDING NOTVM_BINDING [WARMONLY_BINDING] — control c36: rewrite copies of the faucet binding.

DIES_BINDING:  the driver process is killed at the 40th implementation step (the executor dies mid-run).
NOTVM_BINDING: never touches the TRON-TVM; its "implementation" answers from the Lean oracle itself, so every
               comparison agrees. A harness that does not check that the TRON-TVM ran would call this PASS.
WARMONLY_BINDING: deploys and sends ONE transaction in warm_up (so the TRON-TVM demonstrably ran, with
               coverage), then answers every step from the Lean oracle. A harness that checks only that the
               TRON-TVM ran at some point, not on every step, would call this PASS.
"""
import sys

DIES = """    global CALLS
    CALLS = globals().get("CALLS", 0) + 1
    if CALLS == 40:
        T.p.kill()
        T.p.wait()
"""

NOTVM_WARM_UP = """def warm_up():
    global T, TID, LIB
    import ctypes
    import os

    class _Stub:  # no TRON-TVM at all
        contract = bytes.fromhex("41" + "cc" * 20)

    T, TID = _Stub(), 1000001
    LIB = ctypes.CDLL(os.environ["FV_ORACLE_SO"])
    for f in ORACLE_FUNCS:
        getattr(LIB, f).argtypes = [ctypes.c_uint64] * 7
        getattr(LIB, f).restype = ctypes.c_uint64


"""

WARMONLY_TAIL = """    global LIB
    import ctypes
    import os
    LIB = ctypes.CDLL(os.environ["FV_ORACLE_SO"])
    for f in ORACLE_FUNCS:
        getattr(LIB, f).argtypes = [ctypes.c_uint64] * 7
        getattr(LIB, f).restype = ctypes.c_uint64
    T.call(USER, fv_tron_tvm.calldata("dispense(address)", [fv_tron_tvm.addr_word(USER)]))  # the only transaction


"""

NOTVM_IMPL = """def impl_step(impl, s, op):
    return oracle_step(LIB, s, op)


"""


def main():
    dies, nocall = sys.argv[1], sys.argv[2]
    s = open(dies).read()
    head = "def impl_step(impl, s, op):\n"
    assert head in s, "impl_step not found"
    open(dies, "w").write(s.replace(head, head + DIES, 1))
    s = open(nocall).read()
    a = s[s.index("def warm_up():"):s.index("def initial_state(inp):")]
    s = s.replace(a, NOTVM_WARM_UP)
    b = s[s.index("def impl_step(impl, s, op):"):s.index("def u64_values(s):")]
    s = s.replace(b, NOTVM_IMPL)
    open(nocall, "w").write(s)
    if len(sys.argv) > 3:
        w = sys.argv[3]
        s = open(w).read()
        a = s[s.index("def warm_up():"):s.index("def initial_state(inp):")]
        s = s.replace(a, a.rstrip("\n") + "\n" + WARMONLY_TAIL)
        b = s[s.index("def impl_step(impl, s, op):"):s.index("def u64_values(s):")]
        s = s.replace(b, NOTVM_IMPL)
        open(w, "w").write(s)


if __name__ == "__main__":
    main()
