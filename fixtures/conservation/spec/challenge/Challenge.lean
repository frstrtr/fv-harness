import FVSpec.Ledger

/-!
# Challenge: theorem statements only

Every theorem here is a hole (`sorry`) that `spec/solution/` must discharge under the same name
and the same statement.
-/

namespace FV

/-- A transfer never creates or destroys value. -/
theorem transfer_conserves (l : Ledger) (amt bps : Nat) :
    (transfer l amt bps).total = l.total := by
  sorry

/-- A transfer never increases the source balance. -/
theorem transfer_source_le (l : Ledger) (amt bps : Nat) :
    (transfer l amt bps).a ≤ l.a := by
  sorry

end FV
