pragma solidity ^0.4.24;

import "@ensdomains/ens/contracts/ENS.sol";
import "@ensdomains/dnssec-oracle/contracts/DNSSEC.sol";
import "./Ownable.sol";

contract Root is Ownable {

    ENS public ens;
    DNSSEC public oracle;

    event TLDRegistered(bytes32 indexed node, address indexed registrar);

    constructor(ENS _ens, DNSSEC _oracle) public {
        ens = _ens;
        oracle = _oracle;
    }

    function registerTLD(bytes name, bytes proof) external {

    }

    // @todo we should limit the rights here
    function setSubnodeOwner(bytes32 node, bytes32 label, address owner) external onlyOwner {

    }

}
