const Root = artifacts.require('./Root.sol');
const DNSSEC = artifacts.require('./mocks/DummyDNSSEC.sol');
const ENS = artifacts.require('./ENSRegistry.sol');

const utils = require('./helpers/Utils.js');
const namehash = require('eth-ens-namehash');
const dns = require('../lib/dns.js');

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

        it('should allow setting subnode when trying to owner for root domain', async () => {
            await root.setSubnodeOwner(web3.sha3('eth'), accounts[1], {from: accounts[0]});
            assert.equal(accounts[1], await ens.owner(node));
        });

        it('should fail when non-owner tries to set subnode', async () => {
            try {
                await root.setSubnodeOwner(web3.sha3('eth'), accounts[1], {from: accounts[1]});
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
            let proof = dns.hexEncodeTXT({
                name: '_ens.nic.test.',
                klass: 1,
                ttl: 3600,
                text: ['a=' + accounts[0]]
            });

            await dnssec.setData(
                16,
                dns.hexEncodeName('_ens.nic.test.'),
                now,
                now,
                proof
            );

            await root.registerTLD(dns.hexEncodeName('test.'), proof);

            assert.equal(await ens.owner(namehash.hash('test')), accounts[0]);
        });

        it('should allow setting TLD owner to 0x0 when it has already been set', async () => {
            let proof = dns.hexEncodeTXT({
                name: '_ens.nic.test.',
                klass: 1,
                ttl: 3600,
                text: ['a=' + accounts[0]]
            });

            await dnssec.setData(
                16,
                dns.hexEncodeName('_ens.nic.test.'),
                now,
                now,
                proof
            );

            await root.registerTLD(dns.hexEncodeName('test.'), proof);
            assert.equal(await ens.owner(namehash.hash('test')), accounts[0]);

            proof = dns.hexEncodeTXT({
                name: '_ens.test.',
                klass: 1,
                ttl: 3600,
                text: ['a=0x0000000000000000000000000000000000000000']
            });

            await dnssec.setData(
                16,
                dns.hexEncodeName('_ens.nic.test.'),
                now,
                now,
                proof
            );

            await root.registerTLD(dns.hexEncodeName('test.'), proof);

            assert.equal(await ens.owner(namehash.hash('test')), "0x0000000000000000000000000000000000000000");
        });

        it('should set TLD owner to default registrar when no TXT is provided', async () => {
            await dnssec.setData(
                6,
                dns.hexEncodeName('_ens.nic.test.'),
                now,
                now,
                '0x01234567'
            );

            await root.registerTLD(dns.hexEncodeName('test.'), '');

            assert.equal(await ens.owner(namehash.hash('test')), await root.registrar.call());
        });

        it('should not allow setting ETH tld', async () => {
            await dnssec.setData(
                6,
                dns.hexEncodeName('_ens.nic.eth.'),
                now,
                now,
                '0x01234567'
            );

            try {
                await root.registerTLD(dns.hexEncodeName('eth.'), '');
            } catch (error) {
                return utils.ensureException(error);
            }

            assert.fail('did not fail');
        });

        it('should not allow submitting empty proof when SOA record is not present', async () => {
            let proof = dns.hexEncodeTXT({
                name: '_ens.nic.test.',
                klass: 1,
                ttl: 3600,
                text: ['a=' + accounts[0]]
            });

            await dnssec.setData(
                16,
                dns.hexEncodeName('_ens.nic.test.'),
                now,
                now,
                proof
            );

            try {
                await root.registerTLD(dns.hexEncodeName('test.'), '');
            } catch (error) {
                return utils.ensureException(error);
            }

            assert.equal(await ens.owner(namehash.hash('test')), "0x0000000000000000000000000000000000000000");
        });

        it('should fail to register when record is expired', async () => {
            const ttl = 3600;

            let proof = dns.hexEncodeTXT({
                name: '_ens.nic.test.',
                klass: 1,
                ttl: ttl,
                text: ['a=' + accounts[0]]
            });

            await dnssec.setData(
                16,
                dns.hexEncodeName('_ens.nic.test.'),
                now - (ttl * 2),
                now - (ttl * 2),
                proof
            );

            try {
                await root.registerTLD(dns.hexEncodeName('test.'), proof);
            } catch (error) {
                return utils.ensureException(error);
            }

            assert.fail('did not fail');
        });

        it('allows changing a registered TLD on ENS', async () => {
            let proof = dns.hexEncodeTXT({
                name: '_ens.test.',
                klass: 1,
                ttl: 3600,
                text: ['a=' + accounts[0]]
            });

            await dnssec.setData(
                16,
                dns.hexEncodeName('_ens.nic.test.'),
                now,
                now,
                proof
            );

            await root.registerTLD(dns.hexEncodeName('test.'), proof);

            assert.equal(await ens.owner(namehash.hash('test')), accounts[0]);

            proof = dns.hexEncodeTXT({
                name: '_ens.nic.test.',
                klass: 1,
                ttl: 3600,
                text: ['a=' + accounts[1]]
            });

            await dnssec.setData(
                16,
                dns.hexEncodeName('_ens.nic.test.'),
                now,
                now,
                proof
            );

            await root.registerTLD(dns.hexEncodeName('test.'), proof);

            assert.equal(await ens.owner(namehash.hash('test')), accounts[1]);
        });

        it('should not transfer back to default registrar if TXT record is deleted', async () => {
            let proof = dns.hexEncodeTXT({
                name: '_ens.nic.test.',
                klass: 1,
                ttl: 3600,
                text: ['a=' + accounts[0]]
            });

            await dnssec.setData(
                16,
                dns.hexEncodeName('_ens.nic.test.'),
                now,
                now,
                proof
            );

            await root.registerTLD(dns.hexEncodeName('test.'), proof);
            assert.equal(await ens.owner(namehash.hash('test')), accounts[0]);

            await dnssec.setData(
                16,
                dns.hexEncodeName('_ens.nic.test.'),
                now,
                now,
                ''
            );

            try {
                await root.registerTLD(dns.hexEncodeName('test.'), '');
            } catch (error) {
                return utils.ensureException(error);
            }

            assert.equal(await ens.owner(namehash.hash('test')), accounts[0]);
        });

        it('should set to default address when invalid address is provided', async () => {
            let address = '0xbathtub000000000000000000000000000000000';

            let proof = dns.hexEncodeTXT({
                name: '_ens.nic.test.',
                klass: 1,
                ttl: 3600,
                text: ['a=' + address]
            });

            await dnssec.setData(
                16,
                dns.hexEncodeName('_ens.nic.test.'),
                now,
                now,
                proof
            );

            await dnssec.setData(
                6,
                dns.hexEncodeName('_ens.nic.test.'),
                now,
                now,
                proof
            );

            await root.registerTLD(dns.hexEncodeName('test.'), proof);

            assert.equal(await ens.owner(namehash.hash('test')), await root.registrar.call());
        });

        // NOTE DO NOT MOVE DUE TO TIMING ISSUES
        it('should not allow updating to default registrar when proof is still in oracle', async () => {
            let ttl = 3600;
            let proof = dns.hexEncodeTXT({
                name: '_ens.nic.test.',
                klass: 1,
                ttl: ttl,
                text: ['a=' + accounts[0]]
            });

            await dnssec.setData(
                16,
                dns.hexEncodeName('_ens.nic.test.'),
                now,
                now,
                proof
            );

            await root.registerTLD(dns.hexEncodeName('test.'), proof);

            assert.equal(await ens.owner(namehash.hash('test')), accounts[0]);

            utils.advanceTime(ttl * 2);

            try {
                await root.registerTLD(dns.hexEncodeName('test.'), 0);
            } catch (error) {
                return utils.ensureException(error);
            }

            assert.fail('did not fail');
        });
    });
});
