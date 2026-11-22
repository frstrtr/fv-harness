"""redecompose_feeOf_le.py SOLUTION.lean — the Tier-1 planner's response to the dry run's wall
event on `feeOf_le` (Goedel-Prover-V2-8B: 16 samples x 4 rounds did not close it).

Every failed candidate either reached for Mathlib tactics or never stated the nonlinear bound
x * min bps 10000 <= x * 10000. The plan splits that bound out as its own leaf stub
(`mul_min_le`, a DISCHARGE target) and proves `feeOf_le` from it: with the product as an atom,
the goal is linear arithmetic with a literal divisor, which `omega` decides.
Rewrites only the `feeOf_le` declaration; everything else (including Tier-2 proofs already
applied) is kept byte for byte.
"""
import pathlib
import sys

OLD = """theorem feeOf_le (x bps : Nat) : feeOf x bps ≤ x := by
  sorry
"""
NEW = """-- Tier-1 re-decomposition after the wall event on feeOf_le: the nonlinear product bound is
-- its own leaf (DISCHARGE target); feeOf_le follows from it by linear arithmetic.
theorem mul_min_le (x bps : Nat) : x * min bps 10000 ≤ x * 10000 := by
  sorry

theorem feeOf_le (x bps : Nat) : feeOf x bps ≤ x := by
  have h := mul_min_le x bps
  unfold feeOf
  omega
"""
p = pathlib.Path(sys.argv[1])
src = p.read_text()
if src.count(OLD) != 1:
    sys.exit("error: the feeOf_le stub is not in its DECOMPOSE form")
p.write_text(src.replace(OLD, NEW))
print(f"re-decomposed feeOf_le in {p}")
