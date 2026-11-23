import FaucetSpec.Model

/-!
# C oracle for the differential fuzzer

One exported function per state field. Inputs and outputs are 64-bit; the model computes over
`Nat` and each output is reduced mod 2^64. For states whose total fits 64 bits, `step_fits` shows
no output actually wraps.
-/

namespace Faucet

/-- Arguments: cap, given, pool, user, owner. -/
private def ofU (c g p u w : UInt64) : State :=
  ⟨c.toNat, g.toNat, p.toNat, u.toNat, w.toNat, 0⟩

@[export fv_faucet_given]
def oracleGiven (c g p u w op q : UInt64) : UInt64 :=
  (step (ofU c g p u w) op.toNat q.toNat).given.toUInt64

@[export fv_faucet_pool]
def oraclePool (c g p u w op q : UInt64) : UInt64 :=
  (step (ofU c g p u w) op.toNat q.toNat).pool.toUInt64

@[export fv_faucet_user]
def oracleUser (c g p u w op q : UInt64) : UInt64 :=
  (step (ofU c g p u w) op.toNat q.toNat).user.toUInt64

@[export fv_faucet_owner]
def oracleOwner (c g p u w op q : UInt64) : UInt64 :=
  (step (ofU c g p u w) op.toNat q.toNat).owner.toUInt64

@[export fv_faucet_ok]
def oracleOk (c g p u w op q : UInt64) : UInt64 :=
  (step (ofU c g p u w) op.toNat q.toNat).ok.toUInt64

end Faucet
