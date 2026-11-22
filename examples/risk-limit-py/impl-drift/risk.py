"""DRIFT CONTROL variant of impl/risk.py: a reduction removes one unit less than it should.
The same rules as examples/risk-limit/cpp/impl/risk.hpp and the signed Lean model.
State is (limit, pos, open, last); quantities are unbounded Python ints."""


def step(s, op, q):
    limit, pos, open_, last = s
    k = op % 4
    if k == 0:  # submit a buy of q
        if pos + open_ + q <= limit:  # exact arithmetic: no wrap in Python
            return (limit, pos, open_ + q, 1)
        return (limit, pos, open_, 0)
    if k == 1:  # cancel q of the open quantity
        return (limit, pos, open_ - min(q, open_), 0)
    if k == 2:  # fill q of the open quantity
        f = min(q, open_)
        return (limit, pos + f, open_ - f, 0)
    return (limit, pos - max(min(q, pos) - 1, 0), open_, 0)  # DRIFT: one unit short
