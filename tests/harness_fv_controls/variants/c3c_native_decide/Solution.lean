import FVSpec.Ledger

namespace FV

-- Closed by the compiler rather than the kernel (in Lean 4.36: an auxiliary axiom per use).
theorem small_fact : (2 : Nat) + 2 = 4 := by native_decide

theorem feeOf_le (x bps : Nat) : feeOf x bps ≤ x := by
  unfold feeOf
  have h : x * min bps 10000 ≤ x * 10000 := Nat.mul_le_mul_left _ (Nat.min_le_right _ _)
  omega

theorem transfer_conserves_core (l : Ledger) (amt bps : Nat) :
    (transfer l amt bps).total = l.total := by
  have hx : min amt l.a ≤ l.a := Nat.min_le_right _ _
  have hf := feeOf_le (min amt l.a) bps
  simp only [transfer, Ledger.total]
  omega

theorem transfer_conserves (l : Ledger) (amt bps : Nat) :
    (transfer l amt bps).total = l.total :=
  (fun (_ : (2 : Nat) + 2 = 4) => transfer_conserves_core l amt bps) small_fact

theorem transfer_source_le (l : Ledger) (amt bps : Nat) :
    (transfer l amt bps).a ≤ l.a := by
  simp only [transfer]
  omega

end FV
