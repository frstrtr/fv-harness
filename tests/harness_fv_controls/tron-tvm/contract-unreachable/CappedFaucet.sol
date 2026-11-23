// SPDX-License-Identifier: Apache-2.0
// COVERAGE CONTROL (c41): the production faucet plus a branch the fuzzer's generator cannot reach
// (one magic withdrawal amount), which writes a storage word nothing compares.
// A capped token faucet (the code under differential test): one unit of one TRC-10 token per
// request, at most `cap` units in total, never to the faucet itself; only the owner withdraws.
// The same rules as the signed Lean model (lean/spec/challenge/FaucetSpec/Model.lean).
pragma solidity 0.5.18;

contract CappedFaucet {
    address payable public owner;   // slot 0
    trcToken public tokenId;        // slot 1
    uint64 public cap;              // slot 2, low 64 bits
    uint64 public given;            // slot 2, bits 64..127
    uint256 private note;           // slot 3, not part of the model

    event Dispensed(address indexed to);
    event Withdrawn(uint256 amount);

    constructor(trcToken id, uint64 cap_) public {
        owner = msg.sender;
        tokenId = id;
        cap = cap_;
    }

    // One unit to `to`, while the cap allows and the pool holds a unit.
    function dispense(address payable to) external {
        require(given < cap, "cap reached");
        require(to != address(this), "self");
        require(address(this).tokenBalance(tokenId) >= 1, "empty");
        given += 1;
        to.transferToken(1, tokenId);
        emit Dispensed(to);
    }

    // The owner takes `amount` of the pool.
    function withdraw(uint256 amount) external {
        require(msg.sender == owner, "owner only");
        require(amount <= address(this).tokenBalance(tokenId), "balance");
        if (amount == 0xF00DF00DF00DF00D) {
            note = amount;  // unreachable for the generator: c41 must report it NOT EXERCISED
        }
        owner.transferToken(amount, tokenId);
        emit Withdrawn(amount);
    }
}
