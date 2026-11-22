import RiskSpec.Model

/-!
# C oracle for the differential fuzzer

One exported function per state field. Inputs and outputs are 64-bit; the model computes over
`Nat` and each output is reduced mod 2^64, the C++ unsigned wrap-around. For states that satisfy
the invariant with a 64-bit limit, `step_fits` shows no output actually wraps.
-/

namespace Risk

private def ofU (limit pos openQty : UInt64) : State := ⟨limit.toNat, pos.toNat, openQty.toNat, 0⟩

@[export fv_risk_pos]
def oraclePos (limit pos openQty op q : UInt64) : UInt64 :=
  (step (ofU limit pos openQty) op.toNat q.toNat).pos.toUInt64

@[export fv_risk_open]
def oracleOpen (limit pos openQty op q : UInt64) : UInt64 :=
  (step (ofU limit pos openQty) op.toNat q.toNat).openQty.toUInt64

@[export fv_risk_last]
def oracleLast (limit pos openQty op q : UInt64) : UInt64 :=
  (step (ofU limit pos openQty) op.toNat q.toNat).last.toUInt64

end Risk
