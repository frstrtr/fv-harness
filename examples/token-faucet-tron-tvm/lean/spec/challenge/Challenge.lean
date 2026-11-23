import FaucetSpec.Model

/-!
# Challenge: theorem statements only

Every theorem here is a hole (`sorry`) that `spec/solution/` must discharge under the same name
and the same statement.
-/

namespace Faucet

/-- No request changes the cap. -/
theorem step_cap (s : State) (op q : Nat) : (step s op q).cap = s.cap := by
  sorry

/-- Every request preserves the invariant: the cap is never exceeded. -/
theorem step_preserves (s : State) (op q : Nat) (h : Inv s) : Inv (step s op q) := by
  sorry

/-- No sequence of requests, of any length, exceeds the cap. -/
theorem run_preserves (s : State) (evs : List (Nat × Nat)) (h : Inv s) : Inv (run s evs) := by
  sorry

/-- Tokens are neither created nor destroyed: the three balances always add up to the same total. -/
theorem step_conserves (s : State) (op q : Nat) : total (step s op q) = total s := by
  sorry

/-- A dispense moves at most one unit to the recipient, and only by counting it against the cap. -/
theorem dispense_one (s : State) (op q : Nat) :
    (step s op q).user ≤ s.user + 1 ∧
    ((step s op q).user = s.user + 1 → (step s op q).given = s.given + 1) := by
  sorry

/-- A refused request changes no balance and no count. -/
theorem refused_changes_nothing (s : State) (op q : Nat) (h : (step s op q).ok = 0) :
    (step s op q).pool = s.pool ∧ (step s op q).user = s.user ∧ (step s op q).owner = s.owner ∧
    (step s op q).given = s.given := by
  sorry

/-- If the total fits 64 bits, every balance after a request fits 64 bits, and so does `given`
when the cap does: the 64-bit implementation never wraps. -/
theorem step_fits (s : State) (op q : Nat) (ht : total s < 2 ^ 64) (hc : s.cap < 2 ^ 64)
    (h : Inv s) :
    (step s op q).pool < 2 ^ 64 ∧ (step s op q).user < 2 ^ 64 ∧ (step s op q).owner < 2 ^ 64 ∧
    (step s op q).given < 2 ^ 64 := by
  sorry

end Faucet
