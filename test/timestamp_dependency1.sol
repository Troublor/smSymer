pragma solidity >=0.4.25;

contract TimestampDependencyTest1 {
    event newCommitment(uint256 choice, uint256 value, uint256 time);

    function guess_even_odd(uint256 choice, uint256 value) payable public {
        require(msg.value == value);
        require(choice >= 0 && choice <= 1);
        uint256 time = block.timestamp;
        emit newCommitment(choice, value, time);
    }
}