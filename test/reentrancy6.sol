contract Reentrancy{
    mapping (address=>uint256) balances;
    address owner = 0xCf5609B003B2776699eEA1233F7C82D5695cC9AA;
    function withdraw(uint256 amount) public{
        owner.call.value(amount)("");
    }
    function changeOwner() public {
        owner = msg.sender;
    }
}