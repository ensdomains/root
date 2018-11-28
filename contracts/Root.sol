pragma solidity ^0.4.24;

import "@ensdomains/ens/contracts/ENS.sol";
import "@ensdomains/dnssec-oracle/contracts/DNSSEC.sol";
import "@ensdomains/dnssec-oracle/contracts/BytesUtils.sol";
import "@ensdomains/dnsregistrar/contracts/DNSClaimChecker.sol";
import "./Ownable.sol";

contract Root is Ownable {

    using BytesUtils for bytes;

    address public constant DEFAULT_REGISTRAR = 0x0; // @todo, also should we assume this to be a constant?
    bytes32 public constant ROOT_NODE = keccak256(bytes32(0));

    uint16 constant CLASS_INET = 1;
    uint16 constant TYPE_TXT = 16;

    ENS public ens;
    DNSSEC public oracle;

    event TLDRegistered(bytes32 indexed node, address indexed registrar);

    constructor(ENS _ens, DNSSEC _oracle) public {
        ens = _ens;
        oracle = _oracle;
    }

    function proveAndRegisterTLD(bytes name, bytes input, bytes proof) external {
        registerTLD(name, oracle.submitRRSets(input, proof));
    }

    function setSubnodeOwner(bytes32 node, bytes32 label, address owner) external onlyOwner {
        require(node == ROOT_NODE); // @todo this is my method of limiting so that we can't steal domains
        ens.setSubnodeOwner(node, label, owner);
    }

    // @todo maybe consider like a 7 day cool down
    function transferRoot(address owner) external onlyOwner {
        ens.setOwner(0x0, owner);
    }

    function registerTLD(bytes name, bytes proof) public {
        bytes32 label = getLabel(name);

        address addr = DNSClaimChecker.getOwnerAddress(oracle, name, proof);
        if (addr == address(0x0)) {
            addr = DEFAULT_REGISTRAR;
        }

        require(ens.owner(keccak256(ROOT_NODE, label)) != addr);

        ens.setSubnodeOwner(ROOT_NODE, label, addr);
        emit TLDRegistered(keccak256(ROOT_NODE, label), addr);
    }

    function setResolver(bytes32 node, address resolver) public onlyOwner {
        ens.setResolver(node, resolver);
    }

    function setOwner(bytes32 node, address owner) public onlyOwner {
        ens.setOwner(node, owner);
    }

    function setTTL(bytes32 node, uint64 ttl) public onlyOwner {
        ens.setTTL(node, ttl);
    }

    function getLabel(bytes memory name) internal view returns (bytes32) {
        uint len = name.readUint8(0);

        require(name.readUint8(len + 2) == 0); // @todo is this correct?

        return name.keccak(1, len);
    }
}
