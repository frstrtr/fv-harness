// OVERFLOW CONTROL variant of impl/lib.rs: the limit check adds before comparing. With overflow
// checks ON (the fuzz build) a large order panics; in a release build it wraps and is accepted.
// The same rules as examples/risk-limit/cpp/impl/risk.hpp and the signed Lean model.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    pub limit: u64,
    pub pos: u64,
    pub open: u64, // open (unfilled) buy quantity
    pub last: u64, // 1 = the last event was an accepted order
}

/// op % 4: 0 submit a buy of q, 1 cancel q, 2 fill q, 3 reduce the position by q.
pub fn step(mut s: State, op: u64, q: u64) -> State {
    match op % 4 {
        0 => {
            // Headroom form: callers keep pos + open <= limit, so this subtraction cannot underflow.
            if s.pos + s.open + q <= s.limit { // BUG: the sum can pass 2^64
                s.open += q;
                s.last = 1;
            } else {
                s.last = 0;
            }
        }
        1 => {
            s.open -= q.min(s.open);
            s.last = 0;
        }
        2 => {
            let f = q.min(s.open);
            s.open -= f;
            s.pos += f;
            s.last = 0;
        }
        _ => {
            s.pos -= q.min(s.pos);
            s.last = 0;
        }
    }
    s
}
