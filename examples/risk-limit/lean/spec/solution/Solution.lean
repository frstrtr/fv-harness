import RiskSpec.Model

/-! Proofs of the challenge statements (agent-writable side; written here as the fixture's
reference solution). -/

namespace Risk

theorem step_limit (s : State) (op q : Nat) : (step s op q).limit = s.limit := by
  unfold step
  split
  · split <;> rfl
  all_goals rfl

theorem accept_iff (s : State) (q : Nat) :
    (step s 0 q).last = 1 ↔ s.pos + s.openQty + q ≤ s.limit := by
  unfold step
  simp only [Nat.zero_mod]
  split <;> simp_all

theorem step_preserves (s : State) (op q : Nat) (h : Inv s) : Inv (step s op q) := by
  unfold Inv at *
  unfold step
  split
  · split
    · simp only; omega
    · simpa using h
  all_goals (simp only; omega)

theorem run_preserves (s : State) (evs : List (Nat × Nat)) (h : Inv s) : Inv (run s evs) := by
  induction evs generalizing s with
  | nil => simpa [run] using h
  | cons e es ih =>
    simp only [run, List.foldl_cons]
    exact ih _ (step_preserves s e.1 e.2 h)

theorem step_fits (s : State) (op q : Nat) (h : Inv s) (hl : s.limit < 2 ^ 64) :
    (step s op q).pos < 2 ^ 64 ∧ (step s op q).openQty < 2 ^ 64 := by
  have h' := step_preserves s op q h
  have hlim := step_limit s op q
  unfold Inv at h'
  omega

end Risk
