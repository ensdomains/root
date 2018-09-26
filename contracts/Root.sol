pragma solidity ^0.4.24;

import "@ensdomains/ens/contracts/ENS.sol";

contract Root {

    ENS public ens;

    constructor(ENS _ens) public {
        ens = _ens;
    }

}
