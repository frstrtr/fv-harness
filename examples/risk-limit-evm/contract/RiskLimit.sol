// SPDX-License-Identifier: Apache-2.0
// Pre-trade risk check as a contract (the code under differential test). The same rules as the
// signed Lean model (examples/risk-limit/lean): pos + open never exceeds limit.
pragma solidity 0.8.39;

contract RiskLimit {
    // One storage slot, packed from the low bits: limit | pos << 64 | open << 128.
    uint64 public limit;
    uint64 public pos;
    uint64 public open;

    error LimitExceeded();
    event Accepted(uint64 q);

    // Accept a buy of q if it keeps pos + open within the limit; otherwise revert.
    function submit(uint64 q) external returns (bool) {
        // pos + open <= limit holds in every state, so the room left cannot underflow.
        if (q > limit - pos - open) revert LimitExceeded();
        open += q;
        emit Accepted(q);
        return true;
    }

    function cancel(uint64 q) external {
        open -= q < open ? q : open;
    }

    function fill(uint64 q) external {
        uint64 f = q < open ? q : open;
        pos += f;
        open -= f;
    }

    function reduce(uint64 q) external {
        pos -= q < pos ? q : pos;
    }
}
