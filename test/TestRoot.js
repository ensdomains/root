const Root = artifacts.require('./Root.sol');
const DNSSEC = artifacts.require('./mocks/DummyDNSSEC.sol');
const ENS = artifacts.require('./ENSRegistry.sol');
const utils = require('./helpers/Utils.js');
const sha3 = require('js-sha3').keccak_256;

contract('Root', function(accounts) {

    let ens, dnssec, root;

    let tld = '0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563';

    beforeEach(async function() {
        ens = await ENS.new();
        dnssec = await DNSSEC.new();
        root = await Root.new(ens.address, dnssec.address);

        await ens.setSubnodeOwner(0, tld, root.address);
    });

    it('should fail when trying to set subnode owner for non root domain', async () => {
        try {
            await root.setSubnodeOwner(0, tld, accounts[1]);
        } catch (error) {
            return utils.ensureException(error);
        }
    });

    // @todo why does this not work?
    // it('should allow setting subnode when trying to owner for root domain', async () => {
    //     await root.setSubnodeOwner(tld, '0xdead', accounts[1]);
    // });

});