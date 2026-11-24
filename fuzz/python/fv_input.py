# fv_input.py — the decode and the oracle loading shared by fuzz/python/fv_diff.py (the verdict driver)
# and fuzz/python/fv_classify.py (the labels-only replay).
#
# Both drivers must walk an input through the same sequence of states and operations, so the
# decoding lives here once: the fuzzer's bytes, an admissible initial state, 1..64 operations or one
# operation repeated. Nothing in this file compares or classifies.

import ctypes
import importlib.util
import os
import sys

U64 = 1 << 64
EDGES = (0, 1, 2, 3, 9999, 10000, 10001, 0xFF, 0x100, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x100000000,
         0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF)


class Input:
    """The fuzzer's bytes, read front to back; past the end every read is 0."""

    def __init__(self, data: bytes):
        self.d, self.i = data, 0

    def byte(self) -> int:
        b = self.d[self.i] if self.i < len(self.d) else 0
        self.i += 1
        return b

    def bool(self) -> bool:
        return self.byte() & 1 == 1

    def raw_u64(self) -> int:
        return int.from_bytes(bytes(self.byte() for _ in range(8)), "little")

    def range(self, lo: int, hi: int) -> int:
        """A value in [lo, hi] (lo <= hi)."""
        r = self.raw_u64()
        span = hi - lo
        return r if span == U64 - 1 else lo + r % (span + 1)

    def pick_u64(self) -> int:
        """Favours boundaries: an edge value, a neighbour of one (wrapping), a small value, any value."""
        k = self.byte() % 4
        if k == 0:
            return EDGES[self.byte() % len(EDGES)]
        if k == 1:
            e = EDGES[self.byte() % len(EDGES)]
            return (e + self.byte() % 7 - 3) % U64
        if k == 2:
            return self.range(0, 1 << 20)
        return self.raw_u64()


def prefix(B, inp: Input, phase: list):
    """The input's header: (initial state, number of steps, one operation repeated?, that operation)."""
    phase[0] = "initial_state"
    s = B.initial_state(inp)
    steps = 1 + inp.byte() % 64
    saturate = inp.bool()
    phase[0] = "make_op"
    repeated = B.make_op(inp, s)
    return s, steps, saturate, repeated


def load(path: str, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def harness_paths() -> None:
    for p in reversed([p for p in os.environ.get("FV_HARNESS_PY", "").split(":") if p]):
        sys.path.insert(0, p)


def load_oracle(B):
    """The Lean oracle library (FV_ORACLE_SO), typed from the binding's ORACLE_FUNCS / ORACLE_BYTES, initialised."""
    lib = ctypes.CDLL(os.environ["FV_ORACLE_SO"])
    for name, n in B.ORACLE_FUNCS.items():
        f = getattr(lib, name)
        f.argtypes = [ctypes.c_uint64] * n
        f.restype = ctypes.c_uint64
    if getattr(B, "ORACLE_BYTES", None):  # ByteArray oracle functions (fv_oracle_bytes.py, next to this file)
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import fv_oracle_bytes
        try:
            lib.bytes_oracle = fv_oracle_bytes.BytesOracle(lib, B.ORACLE_BYTES)
        except (fv_oracle_bytes.OracleShapeError, AttributeError) as e:
            fv_oracle_bytes.die(f"ORACLE_BYTES: {e}")
    lib.fv_oracle_init.restype = ctypes.c_int
    if lib.fv_oracle_init() != 0:
        sys.stderr.write("diff-oracle: Lean oracle initialisation failed\n")
        os.abort()
    return lib


def fnv1a(data: bytes) -> int:
    h = 1469598103934665603
    for b in data:
        h = ((h ^ b) * 1099511628211) % U64
    return h
