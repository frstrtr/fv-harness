"""Project-owned binding for the Python risk check. The decode, compare, integer-domain and
mismatch loop is the harness's (fuzz/python/fv_diff.py); this module only says how to build an
admissible state and an operation, and how to call the oracle and the implementation.

Modelling assumption (REVIEW-NOTE): the oracle's C boundary is unsigned 64-bit. The Python
implementation computes with unbounded integers; the harness requires every value it returns to
lie in [0, 2^64) instead of reducing it, so a result that differs only above 2^64 FAILs.
"""

ORACLE_FUNCS = {"fv_risk_pos": 5, "fv_risk_open": 5, "fv_risk_last": 5}
IMPL_MODULE = "risk"
KIND = ("submit", "cancel", "fill", "reduce")


def initial_state(inp):
    """Admissible states only: pos + open <= limit."""
    limit = inp.pick_u64()
    pos = inp.range(0, limit)
    open_ = inp.range(0, limit - pos)
    return (limit, pos, open_, 0)


def make_op(inp, s):
    return (inp.byte() % 4, inp.pick_u64())


def oracle_step(lib, s, op):
    limit, pos, open_, _ = s
    o, q = op
    return (limit, lib.fv_risk_pos(limit, pos, open_, o, q), lib.fv_risk_open(limit, pos, open_, o, q),
            lib.fv_risk_last(limit, pos, open_, o, q))


def impl_step(impl, s, op):
    return tuple(impl.step(s, op[0], op[1]))


def u64_values(s):
    return list(zip(("limit", "pos", "open", "last"), s))


def same(a, b):
    return tuple(a) == tuple(b)


def show_state(s):
    return "limit={} pos={} open={} last={}".format(*s)


def show_op(op):
    return f"{KIND[op[0] % 4]} q={op[1]}"
