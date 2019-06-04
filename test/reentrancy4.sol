pragma solidity ^0.4.0;

contract ReentrancyGuarded {

    bool reentrancyLock = false;

    /* Prevent a contract function from being reentrant-called. */
    modifier reentrancyGuard {
        if (reentrancyLock) {
            revert();
        }
        reentrancyLock = true;
        _;
        reentrancyLock = false;
    }

}



contract reentrancy4 is ReentrancyGuarded {
    mapping(address => uint256) balances;

    function withdraw(uint256 amount) public payable reentrancyGuard{
        bool r = msg.sender.call.value(amount)("");
        if (!r) {
            throw;
        }

        balances[msg.sender] -= amount;
    }
}
