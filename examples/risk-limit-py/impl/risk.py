"""Production pre-trade risk check in Python (the code under differential test).
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
    return (limit, pos - min(q, pos), open_, 0)  # reduce the position by q
