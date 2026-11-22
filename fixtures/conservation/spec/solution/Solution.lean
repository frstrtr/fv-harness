import FVSpec.Ledger

namespace FV

theorem feeOf_le (x bps : Nat) : feeOf x bps ≤ x := by
  unfold feeOf
  have h : x * min bps 10000 ≤ x * 10000 := Nat.mul_le_mul_left _ (Nat.min_le_right _ _)
  omega

theorem transfer_conserves (l : Ledger) (amt bps : Nat) :
    (transfer l amt bps).total = l.total := by
  have hx : min amt l.a ≤ l.a := Nat.min_le_right _ _
  have hf := feeOf_le (min amt l.a) bps
  simp only [transfer, Ledger.total]
  omega

theorem transfer_source_le (l : Ledger) (amt bps : Nat) :
    (transfer l amt bps).a ≤ l.a := by
  simp only [transfer]
  omega

end FV
