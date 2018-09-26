pragma solidity ^0.4.24;

import "@ensdomains/ens/contracts/ENS.sol";
import "@ensdomains/dnssec-oracle/contracts/DNSSEC.sol";
import "./Ownable.sol";

contract Root is Ownable {

    ENS public ens;
    DNSSEC public dnssec;

    constructor(ENS _ens, DNSSEC _dnssec) public {
        ens = _ens;
        dnssec = _dnssec;
    }

}
