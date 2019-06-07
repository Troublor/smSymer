pragma solidity ^0.4.0;

contract reentrancy8 {
    // Mapping of token addresses to mapping of account balances (token 0 means Ether)
//    mapping(address => mapping(address => uint)) public tokens;
    mapping(address=>uint) public tokens;

//    address public deprecated;

    function withdraw(uint _amount) {
        require(tokens[msg.sender] >= _amount);
        tokens[msg.sender] = tokens[msg.sender] - _amount;
        if (!msg.sender.call.value(_amount)()) {
            revert();
        }
    }

    function deposit() payable {
        tokens[msg.sender] = tokens[msg.sender] + msg.value;
    }
}
