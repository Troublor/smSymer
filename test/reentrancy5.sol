/**
 * Overflow aware uint math functions.
 *
 * Inspired by https://github.com/MakerDAO/maker-otc/blob/master/contracts/simple_market.sol
 */
pragma solidity ^0.4.11;

/**
 * ERC 20 token
 *
 * https://github.com/ethereum/EIPs/issues/20
 */
contract TRUEToken  {

    address public founder = 0x0;
    //constructor
    function TRUEToken(address _founder) {
        founder = _founder;
    }

    /**
     * Change founder address (where ICO ETH is being forwarded).
     *
     * Applicable tests:
     *
     * - Test founder change by hacker
     * - Test founder change
     * - Test founder token allocation twice
     */
    function changeFounder(address newFounder) {
        if (msg.sender!=founder) revert();
        founder = newFounder;
    }

    // forward all eth to founder
    function() payable {
        if (!founder.call.value(msg.value)()) revert();
    }


}