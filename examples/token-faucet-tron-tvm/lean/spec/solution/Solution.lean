import FaucetSpec.Model

/-! Proofs of the challenge statements (agent-writable side; written here as the example's
reference solution). -/

namespace Faucet

theorem step_cap (s : State) (op q : Nat) : (step s op q).cap = s.cap := by
  unfold step
  split
  · split <;> rfl
  · rfl
  · split <;> rfl
  · rfl

theorem step_preserves (s : State) (op q : Nat) (h : Inv s) : Inv (step s op q) := by
  unfold Inv at *
  unfold step
  split
  · split
    · rename_i hc; simp only; omega
    · simpa using h
  · simpa using h
  · split <;> simpa using h
  · simpa using h

theorem run_preserves (s : State) (evs : List (Nat × Nat)) (h : Inv s) : Inv (run s evs) := by
  induction evs generalizing s with
  | nil => simpa [run] using h
  | cons e es ih =>
    simp only [run, List.foldl_cons] at *
    exact ih (step s e.1 e.2) (step_preserves s e.1 e.2 h)

theorem step_conserves (s : State) (op q : Nat) : total (step s op q) = total s := by
  unfold total step
  split
  · split
    · rename_i hc; simp only; omega
    · rfl
  · rfl
  · split
    · rename_i hq; simp only; omega
    · rfl
  · rfl

theorem dispense_one (s : State) (op q : Nat) :
    (step s op q).user ≤ s.user + 1 ∧
    ((step s op q).user = s.user + 1 → (step s op q).given = s.given + 1) := by
  unfold step
  split
  · split
    · simp
    · simp
  · simp
  · split <;> simp
  · simp

theorem refused_changes_nothing (s : State) (op q : Nat) (h : (step s op q).ok = 0) :
    (step s op q).pool = s.pool ∧ (step s op q).user = s.user ∧ (step s op q).owner = s.owner ∧
    (step s op q).given = s.given := by
  unfold step at *
  split <;> (try split) <;> simp_all

theorem step_fits (s : State) (op q : Nat) (ht : total s < 2 ^ 64) (hc : s.cap < 2 ^ 64)
    (h : Inv s) :
    (step s op q).pool < 2 ^ 64 ∧ (step s op q).user < 2 ^ 64 ∧ (step s op q).owner < 2 ^ 64 ∧
    (step s op q).given < 2 ^ 64 := by
  have hc' := step_conserves s op q
  have hi := step_preserves s op q h
  have hcap := step_cap s op q
  unfold total at ht hc'
  unfold Inv at hi
  refine ⟨by omega, by omega, by omega, by omega⟩

end Faucet
