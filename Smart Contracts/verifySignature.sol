contract Test{

    address public signer;
    bytes32 public _hash32;    
    constructor () public{
        
    }
    function receiveInfo(string memory _message , uint8 _v, bytes32 _r, bytes32 _s) public{
        bytes32 _hash = sha256(abi.encodePacked(_message));
        signer = ecrecover(_hash, _v,_r,_s);
    }
    
}
