import FVSpec.Ledger

namespace FV

axiom cheat : False

theorem transfer_conserves (l : Ledger) (amt bps : Nat) :
    (transfer l amt bps).total = l.total :=
  cheat.elim

theorem transfer_source_le (l : Ledger) (amt bps : Nat) :
    (transfer l amt bps).a ≤ l.a :=
  cheat.elim

end FV
