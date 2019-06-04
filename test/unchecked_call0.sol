pragma solidity >=0.4.25;

contract UncheckedCall0{
    address owner = 0x692a70d2e424a56d2c6c27aa97d1a86395877b3a;
    function a() payable public{
        owner.call.value(msg.value)("");
    }
}