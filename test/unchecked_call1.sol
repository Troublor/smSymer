pragma solidity >=0.4.25;

contract UncheckedCall0{
    function a() payable public{
        bool r = msg.sender.call.value(msg.value)("");
        if (!r) throw;
    }
}