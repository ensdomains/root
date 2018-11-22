pragma solidity ^0.4.24;

import "@ensdomains/ens/contracts/ENS.sol";
import "@ensdomains/dnssec-oracle/contracts/DNSSEC.sol";
import "./Ownable.sol";

contract Root is Ownable {

    ENS public ens;
    DNSSEC public oracle;

    address public constant DEFAULT_REGISTRAR = 0x0; // @todo, also should we assume this to be a constant?
    bytes32 public constant ROOT_NODE = keccak256(bytes32(0));

    event TLDRegistered(bytes32 indexed node, address indexed registrar);

    constructor(ENS _ens, DNSSEC _oracle) public {
        ens = _ens;
        oracle = _oracle;
    }

    function registerTLD(bytes name, bytes input, bytes proof) external {
        proof = oracle.submitRRSets(input, proof);

        bytes32 label = getLabel(name);

        address addr = DEFAULT_REGISTRAR; // @todo should either be our registrar address or another given the TLD record supplies one.

        require(ens.owner(keccak256(ROOT_NODE, label) != addr);
        
        ens.setSubnodeOwner(ROOT_NODE, label, addr);
        emit TLDRegistered(keccak256(ROOT_NODE, label), addr);
    }

    // @todo we should limit the rights here
    function setSubnodeOwner(bytes32 node, bytes32 label, address owner) external onlyOwner {
        require(node == ROOT_NODE); // @todo this is my method of limiting so that we can't steal domains
        ens.setSubnodeOwner(node, label, owner);
    }

    function getLabel(bytes memory name) internal view returns (bytes32) {
        uint len = name.readUint8(0);

        require(name.readUint8(len + 2) == 0); // @todo is this correct?

        return name.keccak(1, len);
    }

}
