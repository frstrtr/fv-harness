// SPDX-License-Identifier: Apache-2.0
// WRAP CONTROL: the same test as the overflow control inside unchecked {}: the sum wraps mod 2^64
// and a far-too-large order can be accepted, as in 0.5-style code without SafeMath (otherwise production). The same rules as the
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
        unchecked {
            if (pos + open + q > limit) revert LimitExceeded();
        }
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
