"""Edge-case classes of the capped faucet (labels only; fuzz/python/fv_sink.py). Never part of the verdict:
the harness's labels-only replay (fuzz/python/fv_classify.py) deploys the contract as the verdict run
does, then walks each corpus input through the oracle alone (no transaction per step) and counts which
of these each step hits. The report shows each lambda's source as it ran.

State: (cap, given, pool, user, owner, ok, outcome); operation: (o, q), o % 4 one of binding.WHO.
"""
from fv_sink import fv_class

WHO = ("recipient asks for itself", "asks to send to the faucet", "owner withdraws", "non-owner withdraws")


def describe(k, before, op, after):
    cap, pool = before[0], before[2]
    o, q = op[0] % 4, op[1]
    k.field("cap", cap)
    k.field("q", q)
    if o >= 2:
        k.arith("pool-q", pool, "-", q)  # withdraw: the contract must refuse below 0
    k.outcome(f"{WHO[o]} -> {after[6].kind}")


CLASSES = [
    fv_class("cap reached exactly", lambda before, op, after: before[1] == before[0]),
    fv_class("last dispense before the cap", lambda before, op, after: op[0] % 4 == 0 and before[1] + 1 == before[0] and before[2] > 0),
    fv_class("owner withdraws the whole pool", lambda before, op, after: op[0] % 4 == 2 and op[1] == before[2]),
    fv_class("q at or above 2^32", lambda before, op, after: op[1] >= 1 << 32),
]
