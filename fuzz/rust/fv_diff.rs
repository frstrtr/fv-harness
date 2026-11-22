// fv_diff.rs — harness-owned differential driver for Rust implementations (cargo-fuzz / libfuzzer-sys).
//
// The Rust counterpart of fuzz/diff_oracle_template.cpp. The project supplies only a `Binding`
// (how to build an admissible state and an operation, how to call the oracle and the
// implementation, how to compare and print); this file owns everything a project must not be
// able to weaken:
//   - decoding: an admissible initial state, 1..64 operations or one operation repeated;
//   - the step loop: after EVERY step the oracle's and the implementation's states must be equal;
//   - the mismatch report: both states printed, the input written to
//     $FV_FUZZ_ARTIFACT_DIR/mismatch-<fnv1a>, exit status 86;
//   - oracle initialisation with LeakSanitizer disabled for that block only.
// A fuzz target includes it as
//   #[macro_use] #[allow(dead_code)] mod fv_diff { include!(env!("FV_DIFF_RS")); }
// (build.rs sets FV_DIFF_RS: the harness copy under fuzz/run_fuzz.sh, else a vendored copy that
// fuzz/check_vendored.sh pins) and ends with `fv_diff_main!(MyBinding);`, which defines the only
// fuzz entry point. fuzz/run_fuzz.sh refuses a target that defines its own `fuzz_target!`.

use std::io::Write;

/// Boundary values the generator favours (as fvfuzz::pick_u64 in the C++ template).
pub const EDGES: [u64; 17] = [
    0, 1, 2, 3, 9999, 10000, 10001, 0xFF, 0x100, 0xFFFF, 0x10000, 0xFFFF_FFFF, 0x1_0000_0000,
    0x7FFF_FFFF_FFFF_FFFF, 0x8000_0000_0000_0000, 0xFFFF_FFFF_FFFF_FFFE, 0xFFFF_FFFF_FFFF_FFFF,
];

/// The fuzzer's bytes, read front to back; past the end every read is 0.
pub struct Input<'a> {
    d: &'a [u8],
    i: usize,
}

impl<'a> Input<'a> {
    pub fn new(d: &'a [u8]) -> Self {
        Input { d, i: 0 }
    }
    pub fn byte(&mut self) -> u8 {
        let b = self.d.get(self.i).copied().unwrap_or(0);
        self.i += 1;
        b
    }
    pub fn bool(&mut self) -> bool {
        self.byte() & 1 == 1
    }
    pub fn raw_u64(&mut self) -> u64 {
        let mut v = [0u8; 8];
        for x in v.iter_mut() {
            *x = self.byte();
        }
        u64::from_le_bytes(v)
    }
    /// A value in [lo, hi] (lo <= hi).
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        let r = self.raw_u64();
        let span = hi - lo;
        if span == u64::MAX { r } else { lo + r % (span + 1) }
    }
    /// Favours boundaries: an edge value, a neighbour of one (wrapping), a small value, or any value.
    pub fn pick_u64(&mut self) -> u64 {
        match self.byte() % 4 {
            0 => EDGES[self.byte() as usize % EDGES.len()],
            1 => {
                let e = EDGES[self.byte() as usize % EDGES.len()];
                e.wrapping_add((self.byte() % 7) as u64).wrapping_sub(3)
            }
            2 => self.range(0, 1 << 20),
            _ => self.raw_u64(),
        }
    }
}

/// What a project provides: its state and operation types and the calls on both sides.
pub trait Binding {
    type State: Copy;
    type Op: Copy;
    /// An admissible initial state (one the statements' hypotheses allow).
    fn initial_state(inp: &mut Input) -> Self::State;
    fn make_op(inp: &mut Input, s: &Self::State) -> Self::Op;
    /// The Lean oracle (exported from the signed spec).
    fn oracle_step(s: &Self::State, op: &Self::Op) -> Self::State;
    /// The implementation under test.
    fn impl_step(s: &Self::State, op: &Self::Op) -> Self::State;
    /// Bit-exact equality of two states.
    fn same(a: &Self::State, b: &Self::State) -> bool;
    fn show_state(s: &Self::State) -> String;
    fn show_op(op: &Self::Op) -> String;
    /// One oracle call on large values, inside the LeakSanitizer exemption.
    fn warm_up();
}

extern "C" {
    fn fv_oracle_init() -> i32;
    // AddressSanitizer runtime (cargo fuzz builds with -Zsanitizer=address).
    fn __lsan_disable();
    fn __lsan_enable();
}

const MISMATCH_EXIT: i32 = 86;

/// Starts the Lean runtime and the oracle modules. The runtime keeps process-lifetime allocations
/// from its initialisation; only this block is exempt from LeakSanitizer (no suppression patterns).
pub fn init<B: Binding>() {
    unsafe {
        __lsan_disable();
        let rc = fv_oracle_init();
        if rc == 0 {
            B::warm_up();
        }
        __lsan_enable();
        if rc != 0 {
            eprintln!("diff-oracle: Lean oracle initialisation failed");
            std::process::abort();
        }
    }
}

fn fnv1a(data: &[u8]) -> u64 {
    let mut h: u64 = 1469598103934665603;
    for b in data {
        h = (h ^ *b as u64).wrapping_mul(1099511628211);
    }
    h
}

fn mismatch<B: Binding>(data: &[u8], step: usize, before: &B::State, op: &B::Op, want: &B::State, got: &B::State) -> ! {
    let mut e = std::io::stderr();
    let _ = writeln!(e, "diff-oracle: MISMATCH at step {step}");
    let _ = writeln!(e, "  before {}", B::show_state(before));
    let _ = writeln!(e, "  op     {}", B::show_op(op));
    let _ = writeln!(e, "  oracle {}", B::show_state(want));
    let _ = writeln!(e, "  impl   {}", B::show_state(got));
    let dir = std::env::var("FV_FUZZ_ARTIFACT_DIR").unwrap_or_default();
    let path = format!("{}/mismatch-{:016x}", if dir.is_empty() { "." } else { &dir }, fnv1a(data));
    match std::fs::write(&path, data) {
        Ok(()) => { let _ = writeln!(e, "diff-oracle: reproducer written to {path}"); }
        Err(err) => { let _ = writeln!(e, "diff-oracle: could not write reproducer to {path}: {err}"); }
    }
    let _ = e.flush();
    std::process::exit(MISMATCH_EXIT);
}

/// One fuzz input: decode, then compare the oracle and the implementation after every step.
pub fn run<B: Binding>(data: &[u8]) {
    let mut inp = Input::new(data);
    let mut s = B::initial_state(&mut inp);
    let steps = 1 + (inp.byte() % 64) as usize;
    let saturate = inp.bool();
    let repeated = B::make_op(&mut inp, &s);
    for i in 0..steps {
        let op = if saturate { repeated } else { B::make_op(&mut inp, &s) };
        let want = B::oracle_step(&s, &op);
        let got = B::impl_step(&s, &op);
        if !B::same(&want, &got) {
            mismatch::<B>(data, i, &s, &op, &want, &got);
        }
        s = want;
    }
}

/// The only fuzz entry point of a Rust target: `fv_diff_main!(MyBinding);`
#[macro_export]
macro_rules! fv_diff_main {
    ($b:ty) => {
        libfuzzer_sys::fuzz_target!(
            init: { fv_diff::init::<$b>(); },
            |data: &[u8]| { fv_diff::run::<$b>(data); }
        );
    };
}
