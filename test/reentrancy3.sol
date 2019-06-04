contract Reentrancy{
    mapping (address=>uint256) balances;
    address owner = 0x692a70d2e424a56d2c6c27aa97d1a86395877b3a;
    function withdraw(uint256 amount) public{
        owner.call.value(amount)("");
    }
    function changeOwner() public {
        owner = msg.sender;
    }
}