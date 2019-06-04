contract Reentrancy {
    mapping(address => uint256) balances;

    function withdraw(uint256 amount) public {
        bool r = msg.sender.call.value(amount)("");
        if (!r) {
            throw;
        }

        balances[msg.sender] -= amount;
    }
}