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

    address public constant DEFAULT_REGISTRAR = 0x0; // @todo, also should we assume this to be a constant?
    bytes32 public constant ROOT = keccak256(bytes32(0));

    uint16 constant CLASS_INET = 1;
    uint16 constant TYPE_TXT = 16;

    ENS public ens;
    DNSSEC public oracle;

    event TLDRegistered(bytes32 indexed node, address indexed registrar);

    constructor(ENS _ens, DNSSEC _oracle) public {
        ens = _ens;
        oracle = _oracle;
    }

    function registerTLD(bytes name, bytes input, bytes _proof) external {
        bytes memory proof = oracle.submitRRSets(input, _proof);

        bytes32 label = getLabel(name);

        address addr = getRegistrarAddress(name, proof);

        ens.setSubnodeOwner(ROOT, label, addr);
        emit TLDRegistered(keccak256(abi.encodePacked(ROOT, label)), addr);
    }

    // @todo we should limit the rights here
    function setSubnodeOwner(bytes32 node, bytes32 label, address owner) external onlyOwner {
        require(node == ROOT); // @todo this is my method of limiting so that we can't steal domains
        ens.setSubnodeOwner(node, label, owner);
    }

    function getLabel(bytes memory name) internal view returns (bytes32) {
        uint len = name.readUint8(0);

        require(name.readUint8(len + 2) == 0); // @todo is this correct?

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
        if (hash == bytes20(0) && proof.length == 0) return 0;

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
