/-!
# Reference model: ledger transfer with a fee

Executable reference model for the harness dry-run fixture. Trusted, spec-author owned.
Balances are unbounded naturals in the model; `FVSpec.Oracle` fixes the 64-bit C boundary.
-/

namespace FV

/-- Source balance, destination balance and the fee pool. -/
structure Ledger where
  a : Nat
  b : Nat
  fee : Nat
  deriving Repr, DecidableEq

/-- Sum of all three balances. -/
def Ledger.total (l : Ledger) : Nat := l.a + l.b + l.fee

/-- Fee on `x` at `bps` basis points (capped at 100%), rounded down. -/
def feeOf (x bps : Nat) : Nat := x * min bps 10000 / 10000

/-- Move up to `amt` out of `a` (clamped to the balance). The fee goes to the pool and the
rest to `b`. -/
def transfer (l : Ledger) (amt bps : Nat) : Ledger :=
  let x := min amt l.a
  let f := feeOf x bps
  { a := l.a - x, b := l.b + (x - f), fee := l.fee + f }

end FV
