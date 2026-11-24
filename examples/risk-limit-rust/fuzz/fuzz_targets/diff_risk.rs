//! diff_risk — the project-owned binding for the Rust risk check. The decode, compare and
//! mismatch loop is the harness's (fuzz/rust/fv_diff.rs); this file only says how to build an
//! admissible state and an operation, and how to call the oracle and the implementation.
#![no_main]

#[macro_use]
#[allow(dead_code)]
mod fv_diff {
    include!(env!("FV_DIFF_RS"));
}
mod risk {
    include!(concat!(env!("OUT_DIR"), "/impl.rs"));
}
use fv_diff::{Binding, Input};
use risk::State;

extern "C" {
    fn fv_risk_pos(limit: u64, pos: u64, open: u64, op: u64, q: u64) -> u64;
    fn fv_risk_open(limit: u64, pos: u64, open: u64, op: u64, q: u64) -> u64;
    fn fv_risk_last(limit: u64, pos: u64, open: u64, op: u64, q: u64) -> u64;
}

struct Risk;

impl Binding for Risk {
    type State = State;
    type Op = (u64, u64); // (op % 4: submit, cancel, fill, reduce; quantity)

    // Admissible states only: pos + open <= limit.
    fn initial_state(inp: &mut Input) -> State {
        let limit = inp.pick_u64();
        let pos = inp.range(0, limit);
        let open = inp.range(0, limit - pos);
        State { limit, pos, open, last: 0 }
    }
    fn make_op(inp: &mut Input, _s: &State) -> (u64, u64) {
        ((inp.byte() % 4) as u64, inp.pick_u64())
    }
    fn oracle_step(s: &State, op: &(u64, u64)) -> State {
        let (o, q) = *op;
        unsafe {
            State {
                limit: s.limit,
                pos: fv_risk_pos(s.limit, s.pos, s.open, o, q),
                open: fv_risk_open(s.limit, s.pos, s.open, o, q),
                last: fv_risk_last(s.limit, s.pos, s.open, o, q),
            }
        }
    }
    fn impl_step(s: &State, op: &(u64, u64)) -> State {
        risk::step(*s, op.0, op.1)
    }
    fn same(a: &State, b: &State) -> bool {
        a == b
    }
    fn show_state(s: &State) -> String {
        format!("limit={} pos={} open={} last={}", s.limit, s.pos, s.open, s.last)
    }
    fn show_op(op: &(u64, u64)) -> String {
        const KIND: [&str; 4] = ["submit", "cancel", "fill", "reduce"];
        format!("{} q={}", KIND[(op.0 % 4) as usize], op.1)
    }
    fn warm_up() {
        let m = u64::MAX;
        let _ = Self::oracle_step(&State { limit: m, pos: m / 2, open: m / 4, last: 0 }, &(0, m / 8));
    }
    // Edge-case classes (labels only; the classify build alone runs these, on the oracle's states).
    fn describe(k: &mut fv_diff::Sink, before: &State, op: &(u64, u64), after: &State) {
        k.field("limit", before.limit as u128, 64, false);
        k.field("q", op.1 as u128, 64, false);
        k.arith_u("pos+open+q", before.pos + before.open, '+', op.1, 64); // the limit check's sum (pos+open <= limit)
        if op.0 % 4 == 0 {
            k.outcome(if after.last == 1 { "submit -> accepted" } else { "submit -> rejected" });
        }
    }
    fn domain_classes() -> Vec<fv_diff::Class<State, (u64, u64)>> {
        vec![
            fv_class!("order exactly fills the limit", |before, op, after| op.0 % 4 == 0
                && before.pos as u128 + before.open as u128 + op.1 as u128 == before.limit as u128),
            fv_class!("q at or above 2^32", |before, op, after| op.1 >= 1 << 32),
            fv_class!("reduce more than the position", |before, op, after| op.0 % 4 == 3 && op.1 > before.pos),
        ]
    }
    fn class_universe() -> Vec<String> {
        vec!["outcome: submit -> accepted".into(), "outcome: submit -> rejected".into()]
    }
}

fv_diff_main!(Risk);
