import "github.com/provable-things/ethereum-api/provableAPI_0.5.sol";

contract RulesProvider is usingProvable {
    
    address public owner;
    uint ownerFunds;
    enum Status {Pending, Paid, Confirmed, Finished}
    uint public rulesPrice = 20000000;
    uint public usagePrice = 450000;
    string public b;
    address oracleAddress = 0xA19379b9d8A4436C078E112d27072fdc211edA3e ;  
    
    struct customers{
        address customerAddress;
        uint funds;
        string rulesHash;
        string key;
        Status state;
    }
    
    struct agents{              //Struct with information about the agent installed at the Customer side
        address agentAddress;
        address customerAddress;
        uint256 lastUpdate;
        bool isValue;
    }
    
    
    mapping (address => customers) public customerList;
    mapping (address => agents) public agentList;
    
    constructor() public{
        owner = msg.sender;
    }
    
    function initialPayment() public payable{
        customerList[msg.sender].customerAddress = msg.sender;
        customerList[msg.sender].funds += msg.value;
        if(customerList[msg.sender].funds>rulesPrice){
            customerList[msg.sender].state = Status.Paid;
        }else{
            customerList[msg.sender].state = Status.Pending;
        }
    }
    

    
    modifier onlyOwner(){
        require(msg.sender==owner);
        _;
    }
    
    
    event hashSent(
        address _customer, 
        string _hash
        );
    
    function acceptPayment(address _customer, string memory _hash) public onlyOwner{
        if(customerList[_customer].state == Status.Paid){
                customerList[_customer].rulesHash = _hash;
                emit hashSent(_customer, _hash);
        }
    }
    
    
    function changeOracleAddress (address _oracleAddress) public onlyOwner {
        oracleAddress = _oracleAddress;
    }
    
    event hashAccepted(
        address customerAddress,
        string rulesHash,
        uint funds
    );
    
    //To do: Check signatures
    function confirmReception(string memory _hash) public{
        if (keccak256(abi.encodePacked((customerList[msg.sender].rulesHash))) == keccak256(abi.encodePacked((_hash))) && customerList[msg.sender].state == Status.Paid){     //Compare Strings
            customerList[msg.sender].state = Status.Confirmed;
            emit hashAccepted(msg.sender,_hash, customerList[msg.sender].funds);
        }
    }
    
    event keySent(
        address _customer, 
        string _key
        );
    
    function sendKey(address _customer, string memory _key) public onlyOwner{
        if(customerList[_customer].state== Status.Confirmed){
            customerList[_customer].key = _key;
            customerList[_customer].state = Status.Finished;
            customerList[_customer].funds -= rulesPrice;
            ownerFunds += rulesPrice;
            emit keySent(_customer, _key);
        }
    }
    

    function retrieveCustomerFunds (uint256 amount) public{
        require ((amount <= customerList[msg.sender].funds)&&(customerList[msg.sender].state == Status.Finished));
        msg.sender.transfer(amount);
        customerList[msg.sender].funds -= amount;
    }
    
    function retrieveOwnerFunds (uint256 amount) onlyOwner public{
        require(amount < ownerFunds);
        msg.sender.transfer(amount);
        ownerFunds -= amount;
    }
    
    
    function registerAgent(address _agentAddress, address _customerAddress) public onlyOwner {
        agentList[_agentAddress].agentAddress=_agentAddress;
        agentList[_agentAddress].customerAddress = _customerAddress;
        agentList[_agentAddress].lastUpdate = 0;
        agentList[_agentAddress].isValue = true;
    }
    
    
    event checkStatusEvent(
        string _message
        );
    
    function checkStatus (string memory _message) onlyOwner public {
        emit checkStatusEvent(_message);
    }
    
    modifier isOracle(){
        require(msg.sender==oracleAddress);
        _;
    }
    
    
    function receiveInfo(address _sender, string memory _message) isOracle public{
            require(agentList[_sender].isValue);    //Verify that sender is an authorized agent.
            if(keccak256(abi.encodePacked((_message))) == keccak256(abi.encodePacked(("Active")))){         //Response to status event
                agentList[_sender].lastUpdate = block.number;
            }else{                                                                                          //Rule Usage
                address customerAddress = parseAddr(_message);
                customerList[customerAddress].funds -= usagePrice;
                ownerFunds += rulesPrice;
            }
    }
    
}