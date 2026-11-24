//! c70_evm_gap variant of examples/risk-limit-evm (generator restricted to q < 2^32, with edge-case classes).
//! diff_risk — the project-owned binding for the RiskLimit contract. The decode, compare and
//! mismatch loop is the harness's (fuzz/rust/fv_diff.rs) and so is the EVM (fuzz/evm/fv_evm.rs);
//! this file says how a model state maps to the contract's storage, how an operation becomes a
//! call, and which outcome the model implies for each step. It is trusted and human-reviewed.
//!
//! Compared after every call: limit, pos and open (storage slot 0, unpacked, with its unused high
//! bits required to be 0), the outcome (success / revert data / halt), the return data and the
//! logs. Gas is not compared. The model's `last` (order accepted) is the outcome of submit:
//! success returning true with an Accepted(q) event, or a revert with LimitExceeded().
#![no_main]

#[macro_use]
#[allow(dead_code)]
mod fv_diff {
    include!(env!("FV_DIFF_RS"));
}
#[allow(dead_code)]
mod fv_evm {
    include!(env!("FV_EVM_RS"));
}
use fv_diff::{Binding, Input};
use fv_evm::{Kind, Log, Outcome};
use revm::primitives::U256;

extern "C" {
    fn fv_risk_pos(limit: u64, pos: u64, open: u64, op: u64, q: u64) -> u64;
    fn fv_risk_open(limit: u64, pos: u64, open: u64, op: u64, q: u64) -> u64;
    fn fv_risk_last(limit: u64, pos: u64, open: u64, op: u64, q: u64) -> u64;
}

const FUNCS: [&str; 4] = ["submit(uint64)", "cancel(uint64)", "fill(uint64)", "reduce(uint64)"];
const ERRORS: [&str; 1] = ["LimitExceeded()"];
const ACCEPTED: &str = "Accepted(uint64)";

#[derive(Clone, Debug, PartialEq, Eq)]
struct St {
    limit: u64,
    pos: u64,
    open: u64,
    last: u64,
    /// Bits 192..256 of slot 0: unused by the layout, must stay 0.
    high: U256,
    out: Outcome,
}

struct Risk;

fn pack(s: &St) -> U256 {
    U256::from(s.limit) | (U256::from(s.pos) << 64) | (U256::from(s.open) << 128)
}
fn lo64(w: U256) -> u64 {
    (w & U256::from(u64::MAX)).to::<u64>()
}

impl Binding for Risk {
    type State = St;
    type Op = (u64, u64); // (op % 4: submit, cancel, fill, reduce; quantity)

    // Admissible states only: pos + open <= limit.
    fn initial_state(inp: &mut Input) -> St {
        let limit = inp.pick_u64();
        let pos = inp.range(0, limit);
        let open = inp.range(0, limit - pos);
        St { limit, pos, open, last: 0, high: U256::ZERO, out: Outcome::none() }
    }
    // c70 variant: the generator never produces a quantity at or above 2^32 (the gap the classifier must report).
    fn make_op(inp: &mut Input, _s: &St) -> (u64, u64) {
        ((inp.byte() % 4) as u64, inp.pick_u64() & 0xFFFF_FFFF)
    }
    // The model's step, and the outcome the model implies for the call.
    fn oracle_step(s: &St, op: &(u64, u64)) -> St {
        let (o, q) = *op;
        let (pos, open, last) = unsafe {
            (fv_risk_pos(s.limit, s.pos, s.open, o, q), fv_risk_open(s.limit, s.pos, s.open, o, q),
             fv_risk_last(s.limit, s.pos, s.open, o, q))
        };
        let out = match (o % 4, last) {
            (0, 1) => Outcome {
                kind: Kind::Success,
                data: fv_evm::word(1).to_vec(),
                logs: vec![Log { address: fv_evm::with(|e| e.contract.0 .0), topics: vec![fv_evm::event_topic(ACCEPTED)],
                                 data: fv_evm::word(q).to_vec() }],
            },
            (0, _) => Outcome { kind: Kind::Revert, data: fv_evm::selector(ERRORS[0]).to_vec(), logs: Vec::new() },
            _ => Outcome::none(),
        };
        St { limit: s.limit, pos, open, last, high: U256::ZERO, out }
    }
    // The contract: state written to slot 0, one call, slot 0 read back.
    fn impl_step(s: &St, op: &(u64, u64)) -> St {
        let (o, q) = *op;
        fv_evm::with(|e| {
            e.sstore(U256::ZERO, pack(s));
            let (out, _gas) = e.call(fv_evm::CALLERS[0], U256::ZERO, &fv_evm::calldata(FUNCS[(o % 4) as usize], &[fv_evm::word(q)]));
            let w = e.sload(U256::ZERO);
            let last = (o % 4 == 0 && out.kind == Kind::Success) as u64;
            St { limit: lo64(w), pos: lo64(w >> 64), open: lo64(w >> 128), last, high: w >> 192, out }
        })
    }
    fn same(a: &St, b: &St) -> bool {
        a == b
    }
    fn show_state(s: &St) -> String {
        let h = if s.high.is_zero() { String::new() } else { format!(" slot0[192..256]={:#x}", s.high) };
        format!("limit={} pos={} open={} last={}{h} | {}", s.limit, s.pos, s.open, s.last, s.out.show(&ERRORS))
    }
    fn show_op(op: &(u64, u64)) -> String {
        format!("{} q={}", FUNCS[(op.0 % 4) as usize], op.1)
    }
    fn warm_up() {
        fv_evm::with(|_| ()); // deploy inside the LeakSanitizer exemption
        let m = u64::MAX;
        let s = St { limit: m, pos: m / 2, open: m / 4, last: 0, high: U256::ZERO, out: Outcome::none() };
        let _ = Self::oracle_step(&s, &(0, m / 8));
    }
    // Edge-case classes (labels only; the classify build alone runs these, on the model's states).
    fn describe(k: &mut fv_diff::Sink, before: &St, op: &(u64, u64), _after: &St) {
        k.word("q", &fv_evm::word(op.1), 64, false); // the uint64 argument, at its Solidity width
        k.field("limit", before.limit as u128, 64, false);
        // submit's pos + open + q in checked uint64 arithmetic: past the max it panics (0x11) instead of rejecting
        k.arith_u("pos+open+q", before.pos + before.open, '+', op.1, 64);
    }
    fn domain_classes() -> Vec<fv_diff::Class<St, (u64, u64)>> {
        vec![
            fv_class!("order exactly fills the limit", |before, op, after| op.0 % 4 == 0
                && before.pos as u128 + before.open as u128 + op.1 as u128 == before.limit as u128),
            fv_class!("q at or above 2^32", |before, op, after| op.1 >= 1 << 32),
            fv_class!("reduce more than the position", |before, op, after| op.0 % 4 == 3 && op.1 > before.pos),
        ]
    }
    // Labels only: the outcome the model implies, per function.
    fn classes(_before: &St, op: &(u64, u64), after: &St) -> Vec<String> {
        vec![format!("outcome: {} -> {}", FUNCS[(op.0 % 4) as usize], after.out.class(&ERRORS))]
    }
    fn class_universe() -> Vec<String> {
        let mut u = vec![format!("outcome: {} -> success", FUNCS[0]), format!("outcome: {} -> revert {}", FUNCS[0], ERRORS[0])];
        u.extend(FUNCS[1..].iter().map(|f| format!("outcome: {f} -> success")));
        u
    }
}

fv_diff_main!(Risk);
