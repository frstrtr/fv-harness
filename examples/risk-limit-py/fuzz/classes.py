"""Edge-case classes of the risk check (labels only; fuzz/python/fv_sink.py). Never part of the verdict:
the harness's labels-only replay (fuzz/python/fv_classify.py) walks each corpus input through the
oracle alone and counts which of these each step hits. The report shows each lambda's source as it ran.
"""
from fv_sink import fv_class

KIND = ("submit", "cancel", "fill", "reduce")


def describe(k, before, op, after):
    limit, pos, open_, _ = before
    o, q = op
    k.field("limit", limit)
    k.field("q", q)
    k.arith("pos+open+q", pos + open_, "+", q)  # the limit check's sum: past 2^64 a fixed-width implementation wraps
    k.float_exact("q", q)
    k.outcome(f"submit -> {'accepted' if after[3] else 'rejected'}" if o % 4 == 0 else KIND[o % 4])


CLASSES = [
    fv_class("order exactly fills the limit", lambda before, op, after: op[0] % 4 == 0 and before[1] + before[2] + op[1] == before[0]),
    fv_class("q at or above 2^32", lambda before, op, after: op[1] >= 1 << 32),
    fv_class("reduce more than the position", lambda before, op, after: op[0] % 4 == 3 and op[1] > before[1]),
]
UNIVERSE = ["outcome: submit -> accepted", "outcome: submit -> rejected"]
