 contract TransferLimitedToken {
    uint256 public constant LIMIT_TRANSFERS_PERIOD = 365 days;

    uint256 public limitEndDate;

    event Transfers(address _to, uint256 _value);



    modifier canTransfer(address _from, address _to)  {
        require(now >= limitEndDate);
        _;
    }


    function TransferLimitedToken(
        uint256 _limitStartDate
    ) public
    {
        limitEndDate = _limitStartDate + LIMIT_TRANSFERS_PERIOD;
    }

    function transfer(address _to, uint256 _value) public canTransfer(msg.sender, _to) {
        Transfers(_to, _value);
    }
}