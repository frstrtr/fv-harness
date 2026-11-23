// SPDX-License-Identifier: Apache-2.0
// Known-answer probe for the TRC-10 opcodes of the TRON-TVM reference executor (control c33).
pragma solidity 0.5.18;

contract Trc10Probe {
    constructor() public {}

    // CALLTOKENID, CALLTOKENVALUE, TOKENBALANCE: the token sent with this call, how much, and what
    // the contract holds of it afterwards.
    function probe() external payable returns (uint256, uint256, uint256) {
        return (msg.tokenid, msg.tokenvalue, address(this).tokenBalance(msg.tokenid));
    }

    // TOKENBALANCE of any account for any token id.
    function balanceOf(address who, trcToken id) external view returns (uint256) {
        return who.tokenBalance(id);
    }

    // CALLTOKEN: transferToken from the contract.
    function send(address payable to, uint256 n, trcToken id) external {
        to.transferToken(n, id);
    }
}
