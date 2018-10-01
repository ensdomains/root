pragma solidity ^0.4.24;

import "@ensdomains/ens/contracts/ENS.sol";
import "@ensdomains/dnssec-oracle/contracts/DNSSEC.sol";
import "./Ownable.sol";

contract Root is Ownable {

    ENS public ens;
    DNSSEC public oracle;

    address public constant DEFAULT_REGISTRAR = 0x0; // @todo, also should we assume this to be a constant?

    event TLDRegistered(bytes32 indexed node, address indexed registrar);

    constructor(ENS _ens, DNSSEC _oracle) public {
        ens = _ens;
        oracle = _oracle;
    }

    function registerTLD(bytes name, bytes input, bytes proof) external {
        proof = oracle.submitRRSets(input, proof);

        bytes32 label = getLabel(name);
        bytes32 root = keccak256(bytes32(0));

        address addr = DEFAULT_REGISTRAR; // @todo should either be our registrar address or another given the TLD record supplies one.

        ens.setSubnodeOwner(root, label, addr);
        emit TLDRegistered(keccak256(root, label), addr);
    }

    // @todo we should limit the rights here
    function setSubnodeOwner(bytes32 node, bytes32 label, address owner) external onlyOwner {

    }

    function getLabel(bytes memory name) internal view returns (bytes32) {
        uint len = name.readUint8(0);

//        require(name.readUint8(len + second + 2) == 0);

        return name.keccak(1, len);
    }


}
