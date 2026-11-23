"""known_answers.py — control c33: TRC-10 opcodes on the TRON-TVM reference executor against fixed answers.

Run by run_lang_controls.sh with the FV_TRON_TVM_* environment of run_fuzz.sh (driver, creation and runtime
bytecode of Trc10Probe). Prints one line per check and "c33 RESULT n/m"; exit 0 iff all pass.
"""
import sys

import fv_tron_tvm

T = fv_tron_tvm.get()
OWNER = bytes.fromhex("41" + "aa" * 19 + "01")
USER = bytes.fromhex("41" + "bb" * 19 + "02")
T.account(OWNER)
T.account(USER)
TID = T.asset()
C = T.deploy(OWNER)
T.set_token(C, TID, 5)
T.set_token(USER, TID, 10)
w = fv_tron_tvm.word
checks = []


def check(name, got, want):
    checks.append(got == want)
    print(("OK   " if got == want else "BAD  ") + f"{name}: got {got!r}" + ("" if got == want else f", want {want!r}"))


def words(data):
    return tuple(int.from_bytes(data[i:i + 32], "big") for i in range(0, len(data), 32))


out, _ = T.call(USER, fv_tron_tvm.calldata("probe()"), tvalue=7, tid=TID)
check("probe() with 7 of the token: CALLTOKENID, CALLTOKENVALUE, TOKENBALANCE", (out.kind, words(out.data)),
      ("success", (TID, 7, 12)))
check("balances after the call value", (T.token(C, TID), T.token(USER, TID)), (12, 3))
out, _ = T.call(USER, fv_tron_tvm.calldata("balanceOf(address,trcToken)", [fv_tron_tvm.addr_word(USER), w(TID)]))
check("TOKENBALANCE of another account", (out.kind, words(out.data)), ("success", (3,)))
out, _ = T.call(USER, fv_tron_tvm.calldata("send(address,uint256,trcToken)", [fv_tron_tvm.addr_word(USER), w(4), w(TID)]))
check("CALLTOKEN: transferToken(4) to the caller", out.kind, "success")
check("balances after transferToken", (T.token(C, TID), T.token(USER, TID)), (8, 7))
out, _ = T.call(USER, fv_tron_tvm.calldata("send(address,uint256,trcToken)", [fv_tron_tvm.addr_word(USER), w(9), w(TID)]))
check("transferToken of more than the contract holds is not a success", out.kind != "success", True)
check("balances unchanged by the failed transfer", (T.token(C, TID), T.token(USER, TID)), (8, 7))
FRESH = bytes.fromhex("41" + "9e" * 20)  # never created
check("reads create no account: balance and token of an unknown address", (T.balance(FRESH), T.token(FRESH, TID), T.exists(FRESH)),
      (0, 0, False))
check("exists() sees an existing account (the caller)", T.exists(USER), True)
n = sum(checks)
print(f"c33 {'PASS' if n == len(checks) else 'FAIL'} {n}/{len(checks)}")
sys.exit(0 if n == len(checks) else 1)
