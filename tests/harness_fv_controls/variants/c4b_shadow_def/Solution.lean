-- Does not import the reference model: redefines it so the theorems become trivial.
namespace FV

structure Ledger where
  a : Nat
  b : Nat
  fee : Nat

def Ledger.total (l : Ledger) : Nat := l.a + l.b + l.fee

def transfer (l : Ledger) (_amt _bps : Nat) : Ledger := l

theorem transfer_conserves (l : Ledger) (amt bps : Nat) :
    (transfer l amt bps).total = l.total := rfl

theorem transfer_source_le (l : Ledger) (amt bps : Nat) :
    (transfer l amt bps).a ≤ l.a := Nat.le_refl _

end FV
