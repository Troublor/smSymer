contract Reentrancy{
    mapping (address=>uint256) balances;
    function withdraw(uint256 amount) public{
        msg.sender.call.value(amount)("");
    }
}