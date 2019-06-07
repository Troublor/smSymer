pragma solidity >=0.4.25;

contract OCoin{
    uint public unlocktime;

    function OCoin()  public {
        unlocktime = 1524326400;
        // 2018/4/22 00:00:00
    }

    function timeLock(address from, uint value) returns (bool) {
        if (now < unlocktime) {
            return true;
        } else {
            return false;
        }
    }
}