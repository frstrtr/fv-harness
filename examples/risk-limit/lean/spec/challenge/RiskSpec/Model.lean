/-!
# Reference model: a pre-trade risk check on one instrument

A buy order is accepted only if the position plus the open buy quantity plus the order stays
within the limit. Cancels release open quantity, fills move open quantity into the position, and
reductions (sells) lower the position. Quantities are unbounded naturals in the model;
`RiskSpec.Oracle` fixes the 64-bit C boundary.
-/

namespace Risk

/-- Limit, current position, open (unfilled) buy quantity, and the last decision
(1 = the last event was an accepted order, 0 otherwise). -/
structure State where
  limit : Nat
  pos : Nat
  openQty : Nat
  last : Nat
  deriving Repr, DecidableEq

/-- The risk invariant: position plus open buys never exceed the limit. -/
def Inv (s : State) : Prop := s.pos + s.openQty ≤ s.limit

/-- One event. `op % 4`: 0 submit a buy of `q`, 1 cancel `q` of the open quantity, 2 fill `q`
of the open quantity, 3 reduce the position by `q`. Over-large cancels, fills and reductions are
clamped. -/
def step (s : State) (op q : Nat) : State :=
  match op % 4 with
  | 0 => if s.pos + s.openQty + q ≤ s.limit
         then { s with openQty := s.openQty + q, last := 1 }
         else { s with last := 0 }
  | 1 => { s with openQty := s.openQty - min q s.openQty, last := 0 }
  | 2 => { s with openQty := s.openQty - min q s.openQty, pos := s.pos + min q s.openQty, last := 0 }
  | _ => { s with pos := s.pos - min q s.pos, last := 0 }

/-- A sequence of events, oldest first. -/
def run (s : State) (evs : List (Nat × Nat)) : State :=
  evs.foldl (fun t e => step t e.1 e.2) s

end Risk
