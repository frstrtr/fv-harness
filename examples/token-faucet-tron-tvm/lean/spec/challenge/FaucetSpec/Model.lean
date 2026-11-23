/-!
# Reference model: a capped token faucet

A contract holds a pool of one token. Anyone may ask it to dispense exactly one unit to a
recipient, until a cap on the number of dispensed units is reached; a request to send to the
faucet itself is refused. Only the owner may withdraw from the pool, and only what is there.
Amounts are unbounded naturals in the model; `FaucetSpec.Oracle` fixes the 64-bit boundary.
-/

namespace Faucet

/-- The cap, the units dispensed so far, the faucet's token balance (pool), the recipient's and
the owner's token balances, and whether the last request was carried out (1) or refused (0). -/
structure State where
  cap : Nat
  given : Nat
  pool : Nat
  user : Nat
  owner : Nat
  ok : Nat
  deriving Repr, DecidableEq

/-- The faucet invariant: never more units dispensed than the cap. -/
def Inv (s : State) : Prop := s.given ≤ s.cap

/-- Tokens held by the three parties together. -/
def total (s : State) : Nat := s.pool + s.user + s.owner

/-- One request. `op % 4`: 0 dispense one unit to the recipient; 1 dispense to the faucet itself
(refused); 2 the owner withdraws `q`; 3 someone other than the owner withdraws `q` (refused). -/
def step (s : State) (op q : Nat) : State :=
  match op % 4 with
  | 0 => if s.given < s.cap ∧ 1 ≤ s.pool
         then { s with given := s.given + 1, pool := s.pool - 1, user := s.user + 1, ok := 1 }
         else { s with ok := 0 }
  | 1 => { s with ok := 0 }
  | 2 => if q ≤ s.pool
         then { s with pool := s.pool - q, owner := s.owner + q, ok := 1 }
         else { s with ok := 0 }
  | _ => { s with ok := 0 }

/-- A sequence of requests, oldest first. -/
def run (s : State) (evs : List (Nat × Nat)) : State :=
  evs.foldl (fun t e => step t e.1 e.2) s

end Faucet
