"""fv_oracle_bytes.py — the ByteArray oracle ABI for the harness's Python loop (fuzz/python/fv_diff.py).

A binding declares
    ORACLE_BYTES = {"fv_act_step": 96, ...}     # exported Lean function -> exact output length in bytes
for functions exported as `@[export fv_act_step] def f (input : ByteArray) : ByteArray` and listed
in the fuzz directory's CMakeLists as `lean_oracle_shared(... BYTES fv_act_step)`. The generated C
wrapper fv_bytes_<name> hands the input it builds to the function (a Lean export owns its arguments),
owns the result, copies it out only
if its length is exactly the declared one, and releases both. Here every call is checked: a wrapper
error or a length other than the declared one is a harness ERROR (OracleShapeError), never a truncated
or padded value: the process ends with "diff-oracle: ORACLE ERROR: ..." and exit 87, which
fuzz/run_fuzz.sh reports as ERROR without keeping the input.
"""
import ctypes
import os
import sys

ORACLE_ERROR_EXIT = 87  # the same exit as an executor failure: run_fuzz.sh reports ERROR, keeps nothing


class OracleShapeError(Exception):
    pass


def die(msg):
    sys.stderr.write(f"diff-oracle: ORACLE ERROR: {msg}\n")
    sys.stderr.flush()
    os._exit(ORACLE_ERROR_EXIT)


class BytesOracle:
    def __init__(self, lib, decl):
        self._f = {}
        for name, n in decl.items():
            if not (isinstance(n, int) and not isinstance(n, bool) and n >= 1):
                raise OracleShapeError(f"ORACLE_BYTES[{name!r}] must be a positive whole number of bytes, got {n!r}")
            f = getattr(lib, "fv_bytes_" + name)
            f.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
                          ctypes.POINTER(ctypes.c_size_t)]
            f.restype = ctypes.c_int
            self._f[name] = (f, n)

    def call(self, name, data: bytes) -> bytes:
        if name not in self._f:
            die(f"{name} is not declared in ORACLE_BYTES")
        f, n = self._f[name]
        out = ctypes.create_string_buffer(max(n, 1))
        got = ctypes.c_size_t(0)
        rc = f(bytes(data), len(data), out, n, ctypes.byref(got))
        if rc == 1:
            die(f"{name} returned {got.value} bytes, the binding declares {n}")
        if rc != 0:
            die(f"{name}: oracle wrapper error {rc} (result is not a ByteArray)")
        return out.raw[:n]
