"""c50 (e): the Python side of the ByteArray ABI (fuzz/python/fv_oracle_bytes.py) on the control's oracle.

py_path.py ORACLE_SO HARNESS_PY MODE
  good   fv_rev on 1,000 inputs: every result equals the reversed input plus its length byte -> "py good ok N"
  short  fv_rev declared one byte short: the call must end the process ("diff-oracle: ORACLE ERROR", 87)
  zero   ORACLE_BYTES length 0: refused at construction (OracleShapeError)
"""
import ctypes
import random
import sys

so, hp, mode = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, hp)
import fv_oracle_bytes  # noqa: E402

lib = ctypes.CDLL(so)
lib.fv_oracle_init.restype = ctypes.c_int
assert lib.fv_oracle_init() == 0, "oracle init"
if mode == "zero":
    try:
        fv_oracle_bytes.BytesOracle(lib, {"fv_rev": 0})
    except fv_oracle_bytes.OracleShapeError as e:
        print(f"py zero refused: {e}")
        sys.exit(0)
    print("py zero accepted")
    sys.exit(1)
rng = random.Random(50)
if mode == "good":
    n = 0
    for _ in range(1000):
        k = rng.randrange(0, 300)
        data = bytes(rng.randrange(256) for _ in range(k))
        o = fv_oracle_bytes.BytesOracle(lib, {"fv_rev": k + 1})
        got = o.call("fv_rev", data)
        if got != data[::-1] + bytes([k % 256]):
            print(f"py good WRONG at length {k}")
            sys.exit(1)
        n += 1
    print(f"py good ok {n}")
    sys.exit(0)
o = fv_oracle_bytes.BytesOracle(lib, {"fv_rev": 64})  # fv_rev of 64 bytes returns 65
o.call("fv_rev", bytes(64))
print("py short returned")  # must not be reached
sys.exit(1)
