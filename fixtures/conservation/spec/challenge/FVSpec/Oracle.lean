import FVSpec.Ledger

/-!
# C oracle for the differential fuzzer

Pure state-transition functions exported with C linkage. Inputs and outputs are 64-bit; the model
computes over `Nat` and each output is reduced mod 2^64 (`Nat.toUInt64`), the same wrap-around
as C++ unsigned arithmetic.
-/

namespace FV

@[export fv_oracle_transfer_a]
def oracleTransferA (a b fee amt bps : UInt64) : UInt64 :=
  (transfer ⟨a.toNat, b.toNat, fee.toNat⟩ amt.toNat bps.toNat).a.toUInt64

@[export fv_oracle_transfer_b]
def oracleTransferB (a b fee amt bps : UInt64) : UInt64 :=
  (transfer ⟨a.toNat, b.toNat, fee.toNat⟩ amt.toNat bps.toNat).b.toUInt64

@[export fv_oracle_transfer_fee]
def oracleTransferFee (a b fee amt bps : UInt64) : UInt64 :=
  (transfer ⟨a.toNat, b.toNat, fee.toNat⟩ amt.toNat bps.toNat).fee.toUInt64

end FV
