"""binding.py — the project-owned binding for the CappedFaucet contract on the TRON-TVM reference executor.

The decode, compare and mismatch loop is the harness's (fuzz/python/fv_diff.py); the TRON-TVM, its
deployment check and the outcome of each call are the harness's too (fuzz/tron-tvm/fv_tron_tvm.py). This file
says how a model state maps to the contract's storage and token balances, how a request becomes a
call, and which outcome the model implies. It is trusted and human-reviewed.

Compared after every call: cap and given (storage slot 2, unpacked; its bits above 128 must stay 0),
the faucet's, the recipient's and the owner's balances of the token, the outcome (success / exact
revert data / halt), the return data, the logs and the internal transactions (an ordered list: each
token transfer the contract makes, with its amount, even 0). Energy is not compared. The model's `ok` is the
outcome: success, or a revert with the Error(string) reason the contract states.

Modelling assumptions (state them in the review note):
- TRC-10 balances are 64-bit signed in the TRON-TVM, so admissible states keep the total below 2^63;
  the model's naturals need no wider type there (lean: step_fits);
- one recipient and one owner account; a request to dispense to the faucet itself is refused;
- the cpu-time limit is off in the reference executor (OUT_OF_TIME is not covered).
- both callers' TRX is reset every step, so energy fees never exhaust it (TRX is not compared).
"""
import fv_tron_tvm

ORACLE_FUNCS = {f"fv_faucet_{n}": 7 for n in ("given", "pool", "user", "owner", "ok")}
IMPL_MODULE = None  # the implementation is the contract, run by fv_tron_tvm

OWNER = bytes.fromhex("41" + "aa" * 19 + "01")
USER = bytes.fromhex("41" + "bb" * 19 + "02")
FN = ("dispense(address)", "dispense(address)", "withdraw(uint256)", "withdraw(uint256)")
WHO = ("recipient asks for itself", "asks to send to the faucet", "owner withdraws", "non-owner withdraws")
T = None
TID = None
LIMIT = 1 << 62  # each balance below 2^62, so the total stays below 2^63


def warm_up():
    global T, TID
    T = fv_tron_tvm.get()
    T.account(OWNER)
    T.account(USER)
    TID = T.asset()
    T.deploy(OWNER, [fv_tron_tvm.word(TID), fv_tron_tvm.word(1)])  # cap and counters are set per step


def initial_state(inp):
    cap = inp.pick_u64()
    given = cap if inp.bool() else inp.range(0, cap)
    pool, user, owner = (inp.range(0, 3) if inp.bool() else inp.range(0, LIMIT - 1) for _ in range(3))
    return (cap, given, pool, user, owner, 0, fv_tron_tvm.SUCCESS)


def make_op(inp, s):
    return (inp.byte() % 4, inp.pick_u64())


def _expected(s, op, ok, q):
    cap, given, pool = s[0], s[1], s[2]
    c20 = T.contract[-20:]
    if op == 0:
        if ok:
            return fv_tron_tvm.Outcome("success", b"", (fv_tron_tvm.Log(c20, (fv_tron_tvm.topic("Dispensed(address)"),
                                                                     fv_tron_tvm.addr_word(USER)), b""),),
                                  (fv_tron_tvm.Itx("call", T.contract, USER, 0, ((TID, 1),), False),))
        return fv_tron_tvm.Outcome("revert", fv_tron_tvm.error_string("cap reached" if given >= cap else "empty"), ())
    if op == 1:
        return fv_tron_tvm.Outcome("revert", fv_tron_tvm.error_string("cap reached" if given >= cap else "self"), ())
    if op == 2:
        if ok:
            return fv_tron_tvm.Outcome("success", b"", (fv_tron_tvm.Log(c20, (fv_tron_tvm.topic("Withdrawn(uint256)"),),
                                                              fv_tron_tvm.word(q)),),
                                  (fv_tron_tvm.Itx("call", T.contract, OWNER, 0, ((TID, q),), False),))
        return fv_tron_tvm.Outcome("revert", fv_tron_tvm.error_string("balance"), ())
    return fv_tron_tvm.Outcome("revert", fv_tron_tvm.error_string("owner only"), ())


def oracle_step(lib, s, op):
    o, q = op
    args = (s[0], s[1], s[2], s[3], s[4], o, q)
    given, pool, user, owner, ok = (getattr(lib, f"fv_faucet_{n}")(*args) for n in ("given", "pool", "user", "owner", "ok"))
    return (s[0], given, pool, user, owner, ok, _expected(s, o % 4, ok, q))


def impl_step(impl, s, op):
    o, q = op
    o %= 4
    cap, given, pool, user, owner = s[:5]
    T.account(OWNER)  # re-fund both callers' TRX every step: energy fees would drain it over a long campaign
    T.account(USER)
    T.sstore(2, cap | (given << 64))
    T.set_token(T.contract, TID, pool)
    T.set_token(USER, TID, user)
    T.set_token(OWNER, TID, owner)
    if o in (0, 1):
        to = USER if o == 0 else T.contract
        out, _energy = T.call(USER, fv_tron_tvm.calldata(FN[o], [fv_tron_tvm.addr_word(to)]))
    else:
        out, _energy = T.call(OWNER if o == 2 else USER, fv_tron_tvm.calldata(FN[o], [fv_tron_tvm.word(q)]))
    w = T.sload(2)
    mask = (1 << 64) - 1
    if w >> 128:
        out = fv_tron_tvm.Outcome(out.kind + f" [slot 2 bits above 128 = {w >> 128:#x}]", out.data, out.logs)
    ok = 1 if out.kind == "success" else 0
    return (w & mask, (w >> 64) & mask, T.token(T.contract, TID), T.token(USER, TID), T.token(OWNER, TID), ok, out)


def u64_values(s):
    return list(zip(("cap", "given", "pool", "user", "owner", "ok"), s[:6]))


def same(a, b):
    return a == b


def show_state(s):
    return (f"cap={s[0]} given={s[1]} pool={s[2]} user={s[3]} owner={s[4]} ok={s[5]} | "
            + s[6].show())


def show_op(op):
    return f"{FN[op[0] % 4]} ({WHO[op[0] % 4]}) q={op[1]}"
