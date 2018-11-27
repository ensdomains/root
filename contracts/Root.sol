pragma solidity ^0.4.24;

import "@ensdomains/ens/contracts/ENS.sol";
import "@ensdomains/dnssec-oracle/contracts/DNSSEC.sol";
import "@ensdomains/dnssec-oracle/contracts/BytesUtils.sol";
import "@ensdomains/dnssec-oracle/contracts/RRUtils.sol";
import "./Ownable.sol";

contract Root is Ownable {

    using BytesUtils for bytes;
    using RRUtils for *;
    using Buffer for Buffer.buffer;

    address public constant DEFAULT_REGISTRAR = 0x123; // @todo, also should we assume this to be a constant?
    bytes32 public constant ROOT_NODE = bytes32(0);

    uint16 constant CLASS_INET = 1;
    uint16 constant TYPE_TXT = 16;

    ENS public ens;
    DNSSEC public oracle;

    event TLDRegistered(bytes32 indexed node, address indexed registrar);

    constructor(ENS _ens, DNSSEC _oracle) public {
        ens = _ens;
        oracle = _oracle;
    }

    function registerTLD(bytes name, bytes proof) external {
        // @todo make new `proveAndRegisterTLD` function
        // bytes memory proof = oracle.submitRRSets(input, _proof);

        bytes32 label = getLabel(name);

        address addr = getRegistrarAddress(name, proof);

        require(ens.owner(keccak256(ROOT_NODE, label)) != addr);
        
        ens.setSubnodeOwner(ROOT_NODE, label, addr);
        emit TLDRegistered(keccak256(ROOT_NODE, label), addr);
    }

    function setSubnodeOwner(bytes32 node, bytes32 label, address owner) external onlyOwner {
        require(node == ROOT_NODE); // @todo this is my method of limiting so that we can't steal domains
        ens.setSubnodeOwner(node, label, owner);
    }

    // @todo maybe consider like a 7 day cool down
    function transferRoot(address owner) external onlyOwner {
        ens.setOwner(0x0, owner);
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

        require(name.length == len + 2);

        return name.keccak(1, len);
    }

    // This is code reuse from the classical DNS registrar, maybe we could bypass this through inheritance

    function getRegistrarAddress(bytes memory name, bytes memory proof) internal view returns (address) {
        // Add "_ens." to the front of the name.
        Buffer.buffer memory buf;
        buf.init(name.length + 5);
        buf.append("\x04_ens");
        buf.append(name);
        bytes20 hash;
        uint64 inserted;
        // Check the provided TXT record has been validated by the oracle
        (, inserted, hash) = oracle.rrdata(TYPE_TXT, buf.buf);
        if (hash == bytes20(0) && proof.length == 0) return DEFAULT_REGISTRAR;

        require(hash == bytes20(keccak256(proof)));

        for (RRUtils.RRIterator memory iter = proof.iterateRRs(0); !iter.done(); iter.next()) {
            require(inserted + iter.ttl >= now, "DNS record is stale; refresh or delete it before proceeding.");

            address addr = parseRR(proof, iter.rdataOffset);
            if (addr != 0) {
                return addr;
            }
        }

        return DEFAULT_REGISTRAR;
    }

    function parseRR(bytes memory rdata, uint idx) internal pure returns (address) {
        while (idx < rdata.length) {
            uint len = rdata.readUint8(idx); idx += 1;
            address addr = parseString(rdata, idx, len);
            if (addr != 0) return addr;
            idx += len;
        }

        return 0;
    }

    function parseString(bytes memory str, uint idx, uint len) internal pure returns (address) {
        // TODO: More robust parsing that handles whitespace and multiple key/value pairs
        if (str.readUint32(idx) != 0x613d3078) return 0; // 0x613d3078 == 'a=0x'
        if (len < 44) return 0;
        return hexToAddress(str, idx + 4);
    }

    function hexToAddress(bytes memory str, uint idx) internal pure returns (address) {
        if (str.length - idx < 40) return 0;
        uint ret = 0;
        for (uint i = idx; i < idx + 40; i++) {
            ret <<= 4;
            uint x = str.readUint8(i);
            if (x >= 48 && x < 58) {
                ret |= x - 48;
            } else if (x >= 65 && x < 71) {
                ret |= x - 55;
            } else if (x >= 97 && x < 103) {
                ret |= x - 87;
            } else {
                return 0;
            }
        }
        return address(ret);
    }

}
