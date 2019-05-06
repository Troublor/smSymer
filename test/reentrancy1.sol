contract Reentrancy{
    mapping (address=>uint256) balances;
    function withdraw(uint256 amount) public{
        balances[msg.sender] -= amount;
        msg.sender.send(amount);
    }
}