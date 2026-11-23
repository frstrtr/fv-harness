/-! Control c50: a ByteArray oracle export. `fv_rev` returns its input reversed, followed by one
byte, the input length mod 256 (so the output is one byte longer than the input). Lean (4.36) does not
allow borrow annotations on @[export] declarations: the export owns its input. -/

def revPlus (b : ByteArray) : ByteArray :=
  (⟨b.data.reverse⟩ : ByteArray).push (UInt8.ofNat (b.size % 256))

@[export fv_rev]
def fvRev (input : ByteArray) : ByteArray := revPlus input
