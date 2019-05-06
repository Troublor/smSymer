pragma solidity >=0.4.25;

contract UncheckedCall0 {
    event fail(bool r);

    function a() payable public {
        bool r = msg.sender.send(msg.value);
        if (!b(r)) {
            revert();
        }
    }

    function b(bool r) public returns (bool) {
        emit fail(r);
        return block.timestamp % 2 == 0;
    }
}