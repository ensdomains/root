pragma solidity ^0.4.24;

import "@ensdomains/ens/contracts/ENS.sol";
import "./Ownable.sol";

contract Root is Ownable {

    ENS public ens;

    constructor(ENS _ens) public {
        ens = _ens;
    }

}
