import RiskSpec.Model

/-!
# Challenge: theorem statements only

Every theorem here is a hole (`sorry`) that `spec/solution/` must discharge under the same name
and the same statement.
-/

namespace Risk

/-- No event changes the limit. -/
theorem step_limit (s : State) (op q : Nat) : (step s op q).limit = s.limit := by
  sorry

/-- A buy is accepted exactly when it keeps position + open buys within the limit. -/
theorem accept_iff (s : State) (q : Nat) :
    (step s 0 q).last = 1 ↔ s.pos + s.openQty + q ≤ s.limit := by
  sorry

/-- Every event preserves the risk invariant. -/
theorem step_preserves (s : State) (op q : Nat) (h : Inv s) : Inv (step s op q) := by
  sorry

/-- No sequence of events, of any length, can breach the limit. -/
theorem run_preserves (s : State) (evs : List (Nat × Nat)) (h : Inv s) : Inv (run s evs) := by
  sorry

/-- Under the invariant with a 64-bit limit, every field after an event fits 64 bits, so the
C++ needs no wider type and never wraps. -/
theorem step_fits (s : State) (op q : Nat) (h : Inv s) (hl : s.limit < 2 ^ 64) :
    (step s op q).pos < 2 ^ 64 ∧ (step s op q).openQty < 2 ^ 64 := by
  sorry

end Risk
