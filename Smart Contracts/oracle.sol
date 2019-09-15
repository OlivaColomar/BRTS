contract Oracle{
    
    //Vars:
    address payable public oracleOwner;     //Owner of the contract
    address oracleContract;
    uint256 public nextIDSource=0;
    uint256 tax = 190000000000;                      // Tax in weis (approx. 1 cent per info)
    uint256 public oracleFunds;
    uint public realFunds;
    
    struct receiver{
        address payable contractAddress;
        address payable ownerAddress;
        uint256 funds;
        bool isValue;
    }
    
    struct source{
        uint256 id;
        string name;
        string informationStructure; //Response format (e.g.: json: {var1: value1,...})
        address[] receivers;
        address owner;
        address [] authorizedSources;
        bool isValue;
    }
    
    mapping (uint256 => source) public sources;    //Information Sources from the Oracle
    mapping (address => receiver) public receivers;
    
    //Constructor
    
    constructor() public payable {
        oracleOwner=msg.sender;
    }
    
    
    //Functions:
    
    function registerSource(string memory _name, string memory _informationStructure) isOracleOwner public {
        sources[nextIDSource].id = nextIDSource;
        sources[nextIDSource].name = _name;
        sources[nextIDSource].informationStructure = _informationStructure;
        sources[nextIDSource].isValue = true;
        sources[nextIDSource].receivers = new address[](0);
        sources[nextIDSource].owner = msg.sender;
        sources[nextIDSource].authorizedSources = new address[](0);
        sources[nextIDSource].authorizedSources.push(msg.sender);
        nextIDSource++;
    }
    
    function registerReceiver(address payable _contractAddress) public payable {
        require(!receivers[_contractAddress].isValue); //Check if receiver is already registered to avoid overwriting.
        receivers[_contractAddress].contractAddress = _contractAddress;
        receivers[_contractAddress].ownerAddress = msg.sender;
        receivers[_contractAddress].funds = msg.value;
        receivers[_contractAddress].isValue = true;
    }
    
    function subscribeToSource(address _contractAddress, uint256 _idSource) public{
        //falta añadir verificación de propietario (DoS)
        require(receivers[_contractAddress].isValue); //Check if receiver already exists.
        sources[_idSource].receivers.push(_contractAddress);
    }
    
    function addFunds(address _contractAddress) public payable {
        require((receivers[_contractAddress].isValue) && (msg.sender==receivers[_contractAddress].ownerAddress || msg.sender==_contractAddress));    //Receiver Exists and money comes from contract or owner to avoid errors.
        receivers[_contractAddress].funds += msg.value;
    }
    
    function addAuthorizedSender(uint256 _sourceId, address _contractAddress, address _authorizedSender) public  {
        require((sources[_sourceId].isValue) && (msg.sender==sources[_sourceId].owner));      //Only the owner can register authorized sources
        sources[_sourceId].authorizedSources.push(_authorizedSender);
    }
    
    function verifySignature(uint256 _idSource, string memory _information, uint8 _v, bytes32 _r, bytes32 _s) private returns (address){
        bytes32 _hash = sha256(abi.encodePacked(_information));
        address signer = ecrecover(_hash, _v,_r,_s);
        for (uint i = 0; i<sources[nextIDSource].authorizedSources.length; i++){ //Verify if sender is authorized
            if(sources[nextIDSource].authorizedSources[i] == signer){
                return signer;
            }
        }
        return address(0);
    }
    
    function sendInformation (uint256 _estimatedGas, uint256 _idSource, address _receiver ,string memory _information, uint8 _v, bytes32 _r, bytes32 _s) isOracleOwner public{
        uint256 transactionCost = _estimatedGas*tx.gasprice+tax;
        require(transactionCost<=receivers[_receiver].funds);               //Check if receiver has funds enough.
        receivers[_receiver].funds -= transactionCost;                      //Payment
        oracleFunds += transactionCost;
        address sender = verifySignature(_idSource, _information, _v, _r, _s);
        _receiver.call.gas(_estimatedGas)(abi.encodeWithSignature("receiveInfo(address,string)",sender,_information));
        uint256 exchange = gasleft()*tx.gasprice;
        receivers[_receiver].funds += exchange;        //Refund non-used gas (due to inaccurate initial estimation)
        oracleFunds -= exchange;
    }
    
    
    
    
    //Function to enable the owner to retrieve the earned funds of the smart contract.
    function retrieveFunds (uint256 amount) isOracleOwner public{
        require(amount < oracleFunds);
        msg.sender.transfer(amount);
        oracleFunds -= amount;
    }
    
    modifier isOracleOwner(){
        require(msg.sender == oracleOwner);
        _;
    }
    
    function getRealFunds () public{
        //Cambiar a funcion view
        realFunds = address(this).balance;
    }
    
    function getReceivers(uint _id) public view returns (address[] memory){
        return sources[_id].receivers;
    }
    
    function getReceiverFunds(address _receiver) public view returns (uint){
        return receivers[_receiver].funds;
    }

}
