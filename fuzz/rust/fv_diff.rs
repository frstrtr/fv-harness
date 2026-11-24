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
//   - oracle initialisation with LeakSanitizer disabled for that block only;
//   - the classification replay (labels only), compiled ONLY into the separate classify binary
//     (`--cfg fv_classify`, built by fuzz/run_fuzz.sh). It walks each input through the ORACLE
//     only, records the binding's labels (`classes`) to $FV_CLASSIFY or prints them with
//     FV_CLASSIFY_RENDER=1, and never compares. It prints "diff-oracle: CLASSIFY BUILD", which
//     run_fuzz.sh refuses in any verdict log, so it can never stand in for the verdict binary.
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

/// What a binding's `describe` declares about one step (labels only). The class names are the
/// C++ Sink's (fuzz/fv_classify.hpp) and the Python Sink's (fuzz/python/fv_sink.py), so the report
/// treats every language alike. Only the classify build calls `describe`.
#[derive(Default)]
pub struct Sink {
    pub hits: Vec<String>,
    pub infos: Vec<String>,
    pub universe: std::collections::BTreeSet<String>,
}

fn pow2_u128(x: u128) -> bool {
    x != 0 && x & (x - 1) == 0
}

impl Sink {
    pub fn add(&mut self, c: String, hit: bool) {
        if hit {
            self.hits.push(c.clone());
        }
        self.universe.insert(c);
    }
    /// A value of `bits` bits (up to 128): = 0, = 1, = max, = max-1, = 2^k or 2^k±1; signed: = -1, = 0, = 1, = min, = max.
    pub fn field(&mut self, name: &str, v: u128, bits: u32, signed: bool) {
        let mask = if bits >= 128 { u128::MAX } else { (1u128 << bits) - 1 };
        let v = v & mask;
        if signed {
            let sign = 1u128 << (bits.min(128) - 1);
            self.add(format!("{name} = -1"), v == mask);
            self.add(format!("{name} = 0"), v == 0);
            self.add(format!("{name} = 1"), v == 1);
            self.add(format!("{name} = min"), v == sign);
            self.add(format!("{name} = max"), v == sign - 1);
            return;
        }
        self.add(format!("{name} = 0"), v == 0);
        self.add(format!("{name} = 1"), v == 1);
        self.add(format!("{name} = max"), v == mask);
        self.add(format!("{name} = max-1"), v == mask - 1);
        let mid = v >= 3 && v <= mask - 2;
        self.add(format!("{name} = 2^k or 2^k±1"), mid && (pow2_u128(v) || pow2_u128(v + 1) || pow2_u128(v - 1)));
    }
    pub fn size(&mut self, name: &str, n: usize, has_equal_elements: bool) {
        self.add(format!("{name} empty"), n == 0);
        self.add(format!("{name} single element"), n == 1);
        self.add(format!("{name} has equal elements"), has_equal_elements);
    }
    pub fn division(&mut self, name: &str, num: u128, den: u128) {
        if den == 0 {
            self.add(format!("{name}: divisor 0"), true);
            return;
        }
        self.add(format!("{name}: exact"), num % den == 0);
        self.add(format!("{name}: remainder = divisor-1"), den > 1 && num % den == den - 1);
    }
    pub fn outcome(&mut self, label: &str) {
        self.infos.push(format!("outcome: {label}"));
    }
    /// The exact result of `a op b` (op '+', '-', '*') on unsigned values of `bits` bits (up to 64)
    /// against that range: what overflow checks panic on.
    pub fn arith_u(&mut self, name: &str, a: u64, op: char, b: u64, bits: u32) {
        let (a, b) = (a as i128, b as i128);
        let r = match op { '+' => a + b, '-' => a - b, _ => a * b };
        let hi = if bits >= 64 { u64::MAX as i128 } else { (1i128 << bits) - 1 };
        self.arith_classes(name, r, 0, hi, &format!("u{bits}"), op);
    }
    /// As `arith_u` for signed values of `bits` bits (up to 64).
    pub fn arith_i(&mut self, name: &str, a: i64, op: char, b: i64, bits: u32) {
        let (a, b) = (a as i128, b as i128);
        let r = match op { '+' => a + b, '-' => a - b, _ => a * b };
        let lo = -(1i128 << (bits.min(64) - 1));
        self.arith_classes(name, r, lo, -lo - 1, &format!("i{bits}"), 's');
    }
    /// Only the boundaries the operation can reach: unsigned + and * never go below 0, unsigned -
    /// never above max (op 's': signed, all of them), as fv_sink.py.
    fn arith_classes(&mut self, name: &str, r: i128, lo: i128, hi: i128, t: &str, op: char) {
        if op != '-' {
            self.add(format!("{name}: overflows {t}"), r > hi);
            self.add(format!("{name}: result = max"), r == hi);
        }
        if op == '-' || op == 's' {
            self.add(format!("{name}: underflows {t}"), r < lo);
        }
        self.add(format!("{name}: result = 0"), r == 0);
    }
    /// A 256-bit EVM word (big-endian) at its Solidity type width (8..256 bits): the `field` classes.
    pub fn word(&mut self, name: &str, w: &[u8; 32], bits: u32, signed: bool) {
        let mut v = *w;
        let keep = (bits / 8) as usize; // Solidity widths are multiples of 8
        for x in v.iter_mut().take(32 - keep.min(32)) {
            *x = 0;
        }
        let low = 32 - keep;
        let is = |v: &[u8; 32], f: &dyn Fn(usize) -> u8| (low..32).all(|i| v[i] == f(i));
        let ones = |_: usize| 0xFFu8;
        if signed {
            let top = |i: usize| if i == low { 0x7F } else { 0xFF };
            let min = |i: usize| if i == low { 0x80 } else { 0 };
            self.add(format!("{name} = -1"), is(&v, &ones));
            self.add(format!("{name} = 0"), is(&v, &|_: usize| 0));
            self.add(format!("{name} = 1"), is(&v, &|i: usize| (i == 31) as u8));
            self.add(format!("{name} = min"), is(&v, &min));
            self.add(format!("{name} = max"), is(&v, &top));
            return;
        }
        self.add(format!("{name} = 0"), is(&v, &|_: usize| 0));
        self.add(format!("{name} = 1"), is(&v, &|i: usize| (i == 31) as u8));
        self.add(format!("{name} = max"), is(&v, &ones));
        self.add(format!("{name} = max-1"), is(&v, &|i: usize| if i == 31 { 0xFE } else { 0xFF }));
        // 2^k or 2^k±1 for 3 <= v <= max-2: v, v+1 or v-1 has exactly one bit set
        let ones_in = |v: &[u8; 32]| v[low..].iter().map(|b| b.count_ones()).sum::<u32>();
        let step = |v: &[u8; 32], up: bool| {
            let mut x = *v;
            for i in (low..32).rev() {
                let (n, c) = if up { x[i].overflowing_add(1) } else { x[i].overflowing_sub(1) };
                x[i] = n;
                if !c {
                    break;
                }
            }
            x
        };
        let small = |v: &[u8; 32], n: u8| v[low..31].iter().all(|b| *b == 0) && v[31] < n;
        let mid = !small(&v, 3) && !is(&v, &ones) && !is(&v, &|i: usize| if i == 31 { 0xFE } else { 0xFF });
        let p = ones_in(&v) == 1 || ones_in(&step(&v, true)) == 1 || ones_in(&step(&v, false)) == 1;
        self.add(format!("{name} = 2^k or 2^k±1"), mid && p);
    }
    /// A 20-byte address: the zero address, a precompile (0x01..0x09).
    pub fn address(&mut self, name: &str, a: &[u8; 20]) {
        let high_zero = a[..19].iter().all(|b| *b == 0);
        self.add(format!("{name} = zero address"), high_zero && a[19] == 0);
        self.add(format!("{name}: precompile (0x01..0x09)"), high_zero && (1..=9).contains(&a[19]));
    }
    pub fn calldata(&mut self, name: &str, d: &[u8]) {
        self.add(format!("{name} empty"), d.is_empty());
        self.add(format!("{name} shorter than a selector"), !d.is_empty() && d.len() < 4);
        self.add(format!("{name}: arguments not a multiple of 32 bytes"), d.len() >= 4 && (d.len() - 4) % 32 != 0);
    }
}

/// One domain class: its name, the predicate's source (shown to the reviewer and checked against the
/// target file by classify_report.py) and the predicate over the state before the step, the
/// operation and the ORACLE's state after it. Written with `fv_class!`.
pub struct Class<S, O> {
    pub name: &'static str,
    pub source: &'static str,
    pub pred: fn(&S, &O, &S) -> bool,
}

/// `fv_class!("name", |before, op, after| expression)`. In the verdict build the predicate is not
/// compiled at all (it never runs there); in the classify build its source is kept with it.
#[cfg(fv_classify)]
macro_rules! fv_class {
    ($n:literal, |$b:ident, $o:ident, $a:ident| $e:expr) => {
        crate::fv_diff::Class { name: $n, source: stringify!($e), pred: |$b, $o, $a| { let _ = (&$b, &$o, &$a); $e } }
    };
}
#[cfg(not(fv_classify))]
macro_rules! fv_class {
    ($n:literal, |$b:ident, $o:ident, $a:ident| $e:expr) => {
        crate::fv_diff::Class { name: $n, source: "", pred: |_, _, _| false }
    };
}

/// What a project provides: its state and operation types and the calls on both sides.
pub trait Binding {
    type State: Clone;
    type Op: Clone;
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
    /// Labels for the classification replay (labels only, never compared), computed from the
    /// step before, the operation and the ORACLE's state after it. Each label starts with
    /// "outcome: " or "domain: ". Default: none.
    fn classes(_before: &Self::State, _op: &Self::Op, _after: &Self::State) -> Vec<String> {
        Vec::new()
    }
    /// The labels a reviewer should see exercised: any of these with no hit in the retained corpus
    /// is reported NOT EXERCISED. Default: none.
    fn class_universe() -> Vec<String> {
        Vec::new()
    }
    /// Generic classes of one step (field, size, division, arith, word, address, calldata on `k`),
    /// from the step before, the operation and the ORACLE's state after it. Default: none.
    fn describe(_k: &mut Sink, _before: &Self::State, _op: &Self::Op, _after: &Self::State) {}
    /// Domain classes, each written `fv_class!("name", |before, op, after| expression)` in the
    /// target file, so classify_report.py can check each source against the one that ran. Default: none.
    fn domain_classes() -> Vec<Class<Self::State, Self::Op>> {
        Vec::new()
    }
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
    #[cfg(fv_classify)]
    eprintln!("diff-oracle: CLASSIFY BUILD (labels only, no comparison)");
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
#[cfg(not(fv_classify))]
pub fn run<B: Binding>(data: &[u8]) {
    let mut inp = Input::new(data);
    let mut s = B::initial_state(&mut inp);
    let steps = 1 + (inp.byte() % 64) as usize;
    let saturate = inp.bool();
    let repeated = B::make_op(&mut inp, &s);
    for i in 0..steps {
        let op = if saturate { repeated.clone() } else { B::make_op(&mut inp, &s) };
        let want = B::oracle_step(&s, &op);
        let got = B::impl_step(&s, &op);
        if !B::same(&want, &got) {
            mismatch::<B>(data, i, &s, &op, &want, &got);
        }
        s = want;
    }
}

#[cfg(fv_classify)]
fn json_str(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// Classification replay of one input (classify binary only): the oracle alone, labels only.
#[cfg(fv_classify)]
pub fn run<B: Binding>(data: &[u8]) {
    use std::collections::BTreeMap;
    let render = std::env::var_os("FV_CLASSIFY_RENDER").is_some();
    let log = std::env::var("FV_CLASSIFY").ok().filter(|p| !p.is_empty());
    if let Some(p) = log.as_ref() {
        static HEADER: std::sync::Once = std::sync::Once::new();
        HEADER.call_once(|| {
            // The predicates as compiled (stringify!), for classify_report.py to check against the target file.
            let mut cs: Vec<(&str, &str)> = B::domain_classes().iter().map(|c| (c.name, c.source)).collect();
            cs.sort();
            let list: Vec<String> = cs.iter().map(|(n, src)| format!("{{\"name\":{},\"source\":{}}}", json_str(n), json_str(src))).collect();
            let line = format!("{{\"classes_header\":{{\"file\":null,\"file_sha256\":null,\"classes\":[{}]}}}}\n", list.join(","));
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
                let _ = f.write_all(line.as_bytes());
            }
        });
    }
    let mut inp = Input::new(data);
    let mut s = B::initial_state(&mut inp);
    let steps = 1 + (inp.byte() % 64) as usize;
    let saturate = inp.bool();
    let repeated = B::make_op(&mut inp, &s);
    let mut hits: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut regular = 0usize;
    if render {
        println!("=== input {:016x} ({} bytes, {} steps{})", fnv1a(data), data.len(), steps,
                 if saturate { ", one operation repeated" } else { "" });
    }
    let domain = B::domain_classes();
    let mut universe: std::collections::BTreeSet<String> = B::class_universe().into_iter().collect();
    universe.extend(domain.iter().map(|c| format!("domain: {}", c.name)));
    for i in 0..steps {
        let op = if saturate { repeated.clone() } else { B::make_op(&mut inp, &s) };
        let want = B::oracle_step(&s, &op);
        let mut k = Sink::default();
        B::describe(&mut k, &s, &op, &want);
        universe.extend(k.universe.iter().map(|c| format!("generic: {c}")));
        let mut cls: Vec<String> = k.hits.iter().map(|c| format!("generic: {c}")).collect();
        cls.extend(domain.iter().filter(|c| (c.pred)(&s, &op, &want)).map(|c| format!("domain: {}", c.name)));
        cls.extend(B::classes(&s, &op, &want));
        cls.extend(k.infos.iter().cloned());
        if !cls.iter().any(|c| c.starts_with("domain: ") || c.starts_with("generic: ")) {
            regular += 1; // as in the C++ template: outcome labels alone leave a step regular
        }
        for c in &cls {
            hits.entry(c.clone()).or_insert((i, 0)).1 += 1;
        }
        if render {
            println!("--- step {i}");
            println!("  before {}", B::show_state(&s));
            println!("  op     {}", B::show_op(&op));
            println!("  oracle {}", B::show_state(&want));
            println!("  classes:{}", cls.iter().map(|c| format!(" [{c}]")).collect::<String>());
        }
        s = want;
    }
    if let Some(dir) = std::env::var("FV_CLASSIFY_RETAIN").ok().filter(|d| !d.is_empty()) {
        // Class-guided retention (run as a fuzzer with a fixed -seed): the first input per class.
        static RETAINED: std::sync::Mutex<Option<std::collections::BTreeSet<String>>> = std::sync::Mutex::new(None);
        static MARK: std::sync::Once = std::sync::Once::new();
        MARK.call_once(|| eprintln!("diff-oracle: CLASSIFY RETAIN {dir}"));
        let mut g = RETAINED.lock().unwrap();
        let set = g.get_or_insert_with(Default::default);
        let new: Vec<&String> = hits.keys().filter(|c| !set.contains(*c)).collect();
        if !new.is_empty() {
            for c in new {
                set.insert(c.clone());
            }
            let path = format!("{dir}/{:016x}", fnv1a(data));
            if !std::path::Path::new(&path).exists() {
                let _ = std::fs::write(&path, data);
            }
        }
    }
    if let Some(p) = log {
        let h: Vec<String> = hits.iter().map(|(c, (f, n))| format!("{}:[{f},{n}]", json_str(c))).collect();
        let u: Vec<String> = universe.iter().map(|c| json_str(c)).collect();
        let line = format!("{{\"h\":\"{:016x}\",\"n\":{},\"steps\":{steps},\"regular\":{regular},\"impl_ns\":0,\"hits\":{{{}}},\"universe\":[{}]}}\n",
                           fnv1a(data), data.len(), h.join(","), u.join(","));
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
            let _ = f.write_all(line.as_bytes());
        }
    }
    if render {
        let _ = std::io::stdout().flush();
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
