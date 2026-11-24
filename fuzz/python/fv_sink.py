# fv_sink.py — what a Python or TRON-TVM binding's classes.py declares about one step (labels only).
#
# The Python counterpart of fvfuzz::Sink in fuzz/fv_classify.hpp: the class names are the same strings,
# so fuzz/classify_report.py treats every language alike. Imported only by classes.py and by the
# labels-only replay (fuzz/python/fv_classify.py); the verdict driver (fv_diff.py) never loads either.
#
# classes.py (next to binding.py) may define:
#   describe(k, before, op, after)   k: Sink; before/op: the step's input; after: the ORACLE's state after it
#   CLASSES = [fv_class("name", lambda before, op, after: <expression>), ...]   domain classes
#   UNIVERSE = ["outcome: ...", ...]  outcome labels a reviewer should see exercised (else informational)
# Each fv_class must be a literal call with a string name and a lambda: the replay shows the lambda's
# source to the reviewer and the report checks it against the file (fuzz/python/fv_classify.py).


class Class:
    __slots__ = ("name", "pred")

    def __init__(self, name: str, pred):
        self.name, self.pred = name, pred


def fv_class(name: str, pred) -> Class:
    if not isinstance(name, str) or not callable(pred):
        raise TypeError("fv_class(name, lambda before, op, after: ...)")
    return Class(name, pred)


def _pow2(x: int) -> bool:
    return x > 0 and x & (x - 1) == 0


class Sink:
    """Collects the edge classes one step hits, and the classes it could have hit (its universe)."""

    def __init__(self):
        self.hits, self.infos, self.universe = [], [], set()

    def add(self, c: str, hit: bool) -> None:
        self.universe.add(c)
        if hit:
            self.hits.append(c)

    # --- the C++ Sink's classes, identical names ---
    def field(self, name: str, v: int, bits: int = 64, signed: bool = False) -> None:
        mask = (1 << bits) - 1
        v &= mask  # two's complement for negative Python integers, as the C++ Sink sees the bit pattern
        if signed:
            sign = 1 << (bits - 1)
            self.add(f"{name} = -1", v == mask)
            self.add(f"{name} = 0", v == 0)
            self.add(f"{name} = 1", v == 1)
            self.add(f"{name} = min", v == sign)
            self.add(f"{name} = max", v == sign - 1)
            return
        self.add(f"{name} = 0", v == 0)
        self.add(f"{name} = 1", v == 1)
        self.add(f"{name} = max", v == mask)
        self.add(f"{name} = max-1", v == mask - 1)
        mid = 3 <= v <= mask - 2
        self.add(f"{name} = 2^k or 2^k±1", mid and (_pow2(v) or _pow2(v + 1) or _pow2(v - 1)))

    def size(self, name: str, n: int, has_equal_elements: bool = False) -> None:
        self.add(f"{name} empty", n == 0)
        self.add(f"{name} single element", n == 1)
        self.add(f"{name} has equal elements", bool(has_equal_elements))

    def division(self, name: str, num: int, den: int, signed: bool = False) -> None:
        if den == 0:
            self.add(f"{name}: divisor 0", True)
            return
        r = abs(num) % abs(den)
        self.add(f"{name}: exact", r == 0)
        self.add(f"{name}: remainder = divisor-1", abs(den) > 1 and r == abs(den) - 1)
        if signed:  # Python's // floors, C, Rust, Solidity and the TRON-TVM truncate: they differ here
            self.add(f"{name}: negative operand, inexact (floor and truncation differ)", r != 0 and (num < 0) != (den < 0))

    def outcome(self, label: str) -> None:
        self.infos.append(f"outcome: {label}")

    # --- arithmetic boundaries (new; Rust has the same) ---
    def arith(self, name: str, a: int, op: str, b: int, bits: int = 64, signed: bool = False) -> None:
        """The exact result of a op b (op in + - *) against the N-bit range: overflow, underflow, = max, = 0."""
        r = {"+": a + b, "-": a - b, "*": a * b}[op]
        lo, hi = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if signed else (0, (1 << bits) - 1)
        t = f"{'i' if signed else 'u'}{bits}"
        # only the boundaries the operation can reach: unsigned + and * never go below 0, unsigned - never above max
        if signed or op != "-":
            self.add(f"{name}: overflows {t}", r > hi)
            self.add(f"{name}: result = max", r == hi)
        if signed or op == "-":
            self.add(f"{name}: underflows {t}", r < lo)
        self.add(f"{name}: result = 0", r == 0)

    # --- Python ---
    def float_exact(self, name: str, v: int) -> None:
        """Above 2^53 an int is not exact as a float: int(a / b), float(x), math.* round there."""
        self.add(f"{name} > 2^53 (not exact as float)", abs(v) > (1 << 53))

    # --- EVM / TRON-TVM words and accounts ---
    def word(self, name: str, v: int, bits: int = 256, signed: bool = False) -> None:
        """A Solidity value at its declared type width (uint8..uint256, int8..int256)."""
        self.field(name, v, bits, signed)

    def address(self, name: str, a: bytes) -> None:
        """A 20-byte address: the zero address, a precompile (0x01..0x09)."""
        n = int.from_bytes(a[-20:], "big")
        self.add(f"{name} = zero address", n == 0)
        self.add(f"{name}: precompile (0x01..0x09)", 1 <= n <= 9)

    def calldata(self, name: str, data: bytes) -> None:
        self.add(f"{name} empty", len(data) == 0)
        self.add(f"{name} shorter than a selector", 0 < len(data) < 4)
        self.add(f"{name}: arguments not a multiple of 32 bytes", len(data) >= 4 and (len(data) - 4) % 32 != 0)

    def tron_address(self, name: str, a: bytes) -> None:
        """A 21-byte TRON address: the 0x41 prefix, a zero body."""
        self.add(f"{name}: no 0x41 prefix", len(a) != 21 or a[0] != 0x41)
        self.add(f"{name}: zero body", int.from_bytes(a[-20:], "big") == 0)

    def trx_amount(self, name: str, v: int) -> None:
        """A TRX or TRC-10 amount: a java long in the TRON-TVM (signed 64-bit)."""
        self.field(name, v, 64, True)

    def token_id(self, name: str, tid: int) -> None:
        self.add(f"{name} = 0 (TRX)", tid == 0)
