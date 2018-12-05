const Root = artifacts.require('./Root.sol');
const DNSSEC = artifacts.require('./mocks/DummyDNSSEC.sol');
const ENS = artifacts.require('./ENSRegistry.sol');

const utils = require('./helpers/Utils.js');
const namehash = require('eth-ens-namehash');
const packet = require('dns-packet');

const hexEncodeName = function(name){
    return '0x' + packet.name.encode(name).toString('hex');
}
  
const hexEncodeTXT = function (keys){
    return '0x' + packet.answer.encode(keys).toString('hex');
}  

contract('Root', function(accounts) {

    let node;
    let ens, dnssec, root;

    let now = Math.round(new Date().getTime() / 1000);

    beforeEach(async function() {
        node = namehash.hash('eth');

        ens = await ENS.new();
        dnssec = await DNSSEC.new();
        root = await Root.new(ens.address, dnssec.address, accounts[3]);

        await ens.setSubnodeOwner(0, web3.sha3('eth'), root.address, {from: accounts[0]});
        await ens.setOwner(0, root.address);
    });

    describe('setSubnodeOwner', async () => {

        it('should fail when trying to set subnode owner for non root domain', async () => {
            try {
                await root.setSubnodeOwner(web3.sha3('eth'), '0x123', accounts[1], {from: accounts[0]});
            } catch (error) {
                return utils.ensureException(error);
            }

            assert.fail('did not fail');
        });

        it('should allow setting subnode when trying to owner for root domain', async () => {
            await root.setSubnodeOwner(0, web3.sha3('eth'), accounts[1], {from: accounts[0]});
            assert.equal(accounts[1], await ens.owner(node));
        });

        it('should fail when non-owner tries to set subnode', async () => {
            try {
                await root.setSubnodeOwner(0, web3.sha3('eth'), accounts[1], {from: accounts[1]});
            } catch (error) {
                return utils.ensureException(error);
            }

            assert.fail('did not fail');
        });
    });

    describe('transferRoot', async () => {

        it('should allow transferring ownership of the root node', async () => {
            assert.equal(root.address, await ens.owner(0));
            await root.transferRoot(accounts[1]);
            assert.equal(accounts[1], await ens.owner(0));
        });

        it('should fail transferring ownership of the root node when sender is not owner', async () => {
            try {
                await root.transferRoot(accounts[1], {from: accounts[1]});
            } catch (error) {
                return utils.ensureException(error);
            }

            assert.fail('did not fail');
        });
    });

    describe('registerTLD', async () => {

        it('allows registering a TLD on ENS with a custom address', async () => {
            let proof = hexEncodeTXT({
                name: '_ens.test',
                class: 'IN',
                type: 'TXT',
                ttl: 3600,
                data:['a=' + accounts[0]]
            });

            await dnssec.setData(
                16,
                hexEncodeName('_ens.test'),
                now,
                now,
                proof
            );

            await root.registerTLD(hexEncodeName('test'), proof);

            assert.equal(await ens.owner(namehash.hash('test')), accounts[0]);
        });

        it('should set TLD owner to default registrar when 0x0 is provided', async () => {

            let proof = hexEncodeTXT({
                name: '_ens.test',
                class: 'IN',
                type: 'TXT',
                ttl: 3600,
                data:['a=0x0000000000000000000000000000000000000000']
            });

            await dnssec.setData(
                16,
                hexEncodeName('_ens.test'),
                now,
                now,
                proof
            );

            await root.registerTLD(hexEncodeName('test'), proof);

            assert.equal(await ens.owner(namehash.hash('test')), await root.registrar.call());
        });

        it('should set TLD owner to default registrar when none is provided', async () => {
            let proof = 0;

            await dnssec.setData(
                16,
                hexEncodeName('_ens.test'),
                now,
                now,
                proof
            );

            await root.registerTLD(hexEncodeName('test'), proof);

            assert.equal(await ens.owner(namehash.hash('test')), await root.registrar.call());
        });
    });
});
