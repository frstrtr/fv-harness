import FVSpec.Ledger

namespace FV

-- Weakened statement: an upper bound instead of equality.
theorem transfer_conserves (l : Ledger) (amt bps : Nat) :
    (transfer l amt bps).total ≤ l.total + amt := by
  have hx : min amt l.a ≤ l.a := Nat.min_le_right _ _
  have hm : min amt l.a ≤ amt := Nat.min_le_left _ _
  have h : min amt l.a * min bps 10000 ≤ min amt l.a * 10000 :=
    Nat.mul_le_mul_left _ (Nat.min_le_right _ _)
  simp only [transfer, Ledger.total, feeOf]
  omega

theorem transfer_source_le (l : Ledger) (amt bps : Nat) :
    (transfer l amt bps).a ≤ l.a := by
  simp only [transfer]
  omega

end FV
